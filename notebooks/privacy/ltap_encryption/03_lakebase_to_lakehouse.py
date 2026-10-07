# Databricks notebook source
# MAGIC %md
# MAGIC # LTAP Encryption — 03: Lakebase → Lakehouse
# MAGIC
# MAGIC The reverse direction. Encrypt a column **in Lakebase** with `pgcrypto`, bring the
# MAGIC ciphertext back into the **Lakehouse**, and **decrypt it with Spark SQL** `aes_decrypt` —
# MAGIC proving the format is symmetric.
# MAGIC
# MAGIC This direction writes ciphertext in Postgres, so it uses a **regular table** (synced
# MAGIC tables are read-only in Postgres). Same approach as notebook 02: AES-256-CBC + PKCS#7,
# MAGIC HMAC-SHA256 Encrypt-then-MAC, verified before decryption. Run `01_setup.py` first.

# COMMAND ----------

# MAGIC %pip install "psycopg[binary]>=3.1"

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 1: Configuration and key material
# MAGIC
# MAGIC Same widgets and key-loading as notebook 02. The subkeys are passed to Postgres as bound
# MAGIC parameters.

# COMMAND ----------

from base64 import b64decode
import psycopg
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

dbutils.widgets.text("catalog", "main", "Catalog")
dbutils.widgets.text("schema", "ltap_encryption", "Schema")
dbutils.widgets.text("secret_scope", "ltap_encryption", "Secret scope for key material")
dbutils.widgets.text("key_version", "1", "Key version")
dbutils.widgets.text("lakebase_project", "", "Lakebase project id")
dbutils.widgets.text("lakebase_branch", "production", "Lakebase branch id")
dbutils.widgets.text("lakebase_endpoint", "", "Lakebase endpoint id (compute)")
dbutils.widgets.text("lakebase_database", "databricks_postgres", "Lakebase Postgres database")
dbutils.widgets.text("pg_schema", "public", "Postgres schema")

catalog = dbutils.widgets.get("catalog")
schema = dbutils.widgets.get("schema")
secret_scope = dbutils.widgets.get("secret_scope")
key_version = int(dbutils.widgets.get("key_version"))
project = dbutils.widgets.get("lakebase_project")
branch = dbutils.widgets.get("lakebase_branch")
endpoint_id = dbutils.widgets.get("lakebase_endpoint")
pg_database = dbutils.widgets.get("lakebase_database")
pg_schema = dbutils.widgets.get("pg_schema")

endpoint_name = f"projects/{project}/branches/{branch}/endpoints/{endpoint_id}"
enc_secret_name = f"enc_key_v{key_version}"
mac_secret_name = f"mac_key_v{key_version}"

spark.sql(f"USE CATALOG `{catalog}`")
spark.sql(f"USE SCHEMA `{schema}`")

enc_key = b64decode(dbutils.secrets.get(secret_scope, enc_secret_name))
mac_key = b64decode(dbutils.secrets.get(secret_scope, mac_secret_name))
assert len(enc_key) == 32 and len(mac_key) == 32

# Same PII column list as 01_setup.py / 02; the rest stay in the clear.
PII_COLUMNS = ["name", "email", "phone_number", "national_id", "credit_card_number"]
CLEAR_COLUMNS = ["locale", "age", "company"]


# Context-bound HMAC message (see 02 for the rationale). Both engines build the byte-identical
# message utf-8("<customer_id>:<column>:<key_version>") || blob, so the tag minted in Postgres
# verifies in Databricks and a spliced ciphertext does not. Postgres builds the message inline
# in Section 3 (it needs the subquery alias and the key-version parameter); Databricks uses this
# helper to verify in Section 5.
def dbx_mac_message(col, alias=""):
    """Context-bound HMAC message as a Databricks SQL BINARY expression."""
    p = f"{alias}." if alias else ""
    ctx = f"concat_ws(':', cast({p}customer_id AS STRING), '{col}', cast({p}key_version AS STRING))"
    return f"concat(encode({ctx}, 'utf-8'), {p}{col}_enc)"


def lakebase_connection():
    endpoint = w.postgres.get_endpoint(name=endpoint_name)
    return psycopg.connect(
        host=endpoint.status.hosts.host,
        dbname=pg_database,
        user=w.current_user.me().user_name,
        password=w.postgres.generate_database_credential(endpoint=endpoint_name).token,
        sslmode="require",
    )

pg_table = f"{pg_schema}.lakebase_customers"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 2: Create plaintext data in Lakebase
# MAGIC
# MAGIC A regular Postgres table simulating OLTP data that originates in Lakebase. To use the same
# MAGIC realistic fake dataset, we seed it from the Delta `customers` table built in `01_setup.py`
# MAGIC (in a real app these rows would be written directly by the application). The table has a
# MAGIC plaintext column plus an `_enc` / `_mac` `bytea` pair per PII column.

# COMMAND ----------

plaintext_cols = ["customer_id"] + PII_COLUMNS
seed = spark.table(f"{catalog}.{schema}.customers").select(*plaintext_cols).collect()
seed_rows = [tuple(r[c] for c in plaintext_cols) for r in seed]

col_defs = ",\n                ".join(
    ["customer_id int PRIMARY KEY"]
    + [f"{c} text" for c in PII_COLUMNS]
    + [f"{c}_enc bytea" for c in PII_COLUMNS]
    + [f"{c}_mac bytea" for c in PII_COLUMNS]
    + ["key_version int"])
insert_cols = ", ".join(plaintext_cols)
placeholders = ", ".join(["%s"] * len(plaintext_cols))

with lakebase_connection() as conn:
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {pg_table}")
        cur.execute(f"CREATE TABLE {pg_table} (\n                {col_defs}\n            )")
        cur.executemany(
            f"INSERT INTO {pg_table} ({insert_cols}) VALUES ({placeholders})", seed_rows)
        cur.execute(f"SELECT count(*) FROM {pg_table}")
        print(f"Inserted {cur.fetchone()[0]:,} plaintext rows into {pg_table}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 3: Encrypt the PII columns in Lakebase
# MAGIC
# MAGIC For each PII column, build the same `IV(16) || ciphertext` wire format Databricks expects:
# MAGIC
# MAGIC - generate a random 16-byte IV per row with `gen_random_bytes(16)`;
# MAGIC - `encrypt_iv(convert_to(col,'utf8'), enc_key, iv, 'aes-cbc/pad:pkcs')` for the ciphertext,
# MAGIC   with the IV prepended;
# MAGIC - a context-bound Encrypt-then-MAC tag over `utf-8("<id>:<column>:<key_version>") || blob`,
# MAGIC   so the tag only verifies for this row/column/key version;
# MAGIC - record `key_version`.
# MAGIC
# MAGIC Each PII column gets its own `CROSS JOIN LATERAL gen_random_bytes(16)` so every column of
# MAGIC every row gets an independent IV. The subquery projects each blob once, so the stored
# MAGIC ciphertext and the blob fed to `hmac` are guaranteed identical.

# COMMAND ----------

blob_exprs, set_exprs = [], []
for c in PII_COLUMNS:
    blob_exprs.append(
        f"iv_{c}.iv || encrypt_iv(convert_to(s2.{c}, 'utf8'), %(enc)s, iv_{c}.iv, 'aes-cbc/pad:pkcs') AS {c}_blob")
    set_exprs.append(f"{c}_enc = e.{c}_blob")
    # Context-bound HMAC: utf-8("<id>:<column>:<key_version>") || blob. key_version is the
    # %(kv)s parameter (the column isn't set until this same statement completes).
    mac_msg = (f"convert_to(e.customer_id::text || ':' || '{c}' || ':' || %(kv)s::text, 'utf8') "
               f"|| e.{c}_blob")
    set_exprs.append(f"{c}_mac = hmac({mac_msg}, %(mac)s, 'sha256')")

laterals = "\n           ".join(
    f"CROSS JOIN LATERAL (SELECT gen_random_bytes(16) AS iv) AS iv_{c}" for c in PII_COLUMNS)

update_sql = f"""
UPDATE {pg_table} AS s
SET {", ".join(set_exprs)},
    key_version = %(kv)s
FROM (
    SELECT s2.customer_id,
           {", ".join(blob_exprs)}
    FROM {pg_table} s2
           {laterals}
) AS e
WHERE s.customer_id = e.customer_id
"""

with lakebase_connection() as conn:
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(update_sql, {"enc": enc_key, "mac": mac_key, "kv": key_version})
        cur.execute(f"SELECT count(*) FROM {pg_table} WHERE name_enc IS NOT NULL")
        print(f"Encrypted {cur.fetchone()[0]:,} rows in Lakebase across {len(PII_COLUMNS)} columns.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 4: Bring the ciphertext into the Lakehouse
# MAGIC
# MAGIC Read only the `_enc` / `_mac` ciphertext columns and key version into Spark (never the
# MAGIC plaintext) and persist as a Delta table. `bytea` columns become Spark `BINARY`.

# COMMAND ----------

from pyspark.sql.types import StructType, StructField, LongType, BinaryType, IntegerType

enc_mac_cols = [f"{c}_enc" for c in PII_COLUMNS] + [f"{c}_mac" for c in PII_COLUMNS]
select_cols = ", ".join(["customer_id"] + enc_mac_cols + ["key_version"])

with lakebase_connection() as conn:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {select_cols} FROM {pg_table} ORDER BY customer_id")
        fetched = [
            tuple([int(row[0])] + [bytes(v) for v in row[1:-1]] + [int(row[-1])])
            for row in cur.fetchall()
        ]

fields = ([StructField("customer_id", LongType(), False)]
          + [StructField(c, BinaryType(), True) for c in enc_mac_cols]
          + [StructField("key_version", IntegerType(), True)])

(spark.createDataFrame(fetched, StructType(fields))
      .write.mode("overwrite").option("overwriteSchema", "true")
      .saveAsTable(f"{catalog}.{schema}.lakebase_customers_encrypted"))

display(spark.sql(f"""
SELECT customer_id, {", ".join(f"base64({c}_enc) AS {c}_enc_b64" for c in PII_COLUMNS)}, key_version
FROM {catalog}.{schema}.lakebase_customers_encrypted ORDER BY customer_id LIMIT 20
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 5: Verify and decrypt in the Lakehouse
# MAGIC
# MAGIC For each PII column, recompute the HMAC with Databricks `hmac(mac_key, {col}_enc, 'SHA-256')`,
# MAGIC compare to the stored tag, and only then `aes_decrypt({col}_enc, enc_key, 'CBC', 'PKCS')` —
# MAGIC which reads the prepended IV automatically. The results should match the plaintext created
# MAGIC in Lakebase.

# COMMAND ----------

# The AES key goes to aes_decrypt via secret() (resolved at execution, never in the plan).
# Databricks only permits secret() as an argument to aes_encrypt/aes_decrypt, so the HMAC key
# is read from the secret store (loaded as `mac_key` in Section 1) and passed to hmac() via
# unhex(). The HMAC (integrity) key is therefore materialized in the query plan; see 02's note.
enc_key_sql = f"unbase64(secret('{secret_scope}', '{enc_secret_name}'))"
mac_key_sql = f"unhex('{mac_key.hex()}')"

dec_exprs = []
for c in PII_COLUMNS:
    dec_exprs.append(
        f"""CASE WHEN hmac({mac_key_sql}, {dbx_mac_message(c)}, 'SHA-256') = {c}_mac
                 THEN CAST(aes_decrypt({c}_enc, {enc_key_sql}, 'CBC', 'PKCS') AS STRING)
            END AS {c}""")
decrypted = spark.sql(f"""
SELECT customer_id, {", ".join(dec_exprs)}
FROM {catalog}.{schema}.lakebase_customers_encrypted
ORDER BY customer_id
""")
display(decrypted.limit(20))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Confirm against the Lakebase originals (all rows, all columns)

# COMMAND ----------

dec_pd = decrypted.toPandas().set_index("customer_id").sort_index()

with lakebase_connection() as conn:
    with conn.cursor() as cur:
        cur.execute(f"SELECT customer_id, {', '.join(PII_COLUMNS)} FROM {pg_table} ORDER BY customer_id")
        header = [d.name for d in cur.description]
        orig_rows = cur.fetchall()

import pandas as pd
orig_pd = pd.DataFrame(orig_rows, columns=header).set_index("customer_id").sort_index()

print(f"Rows decrypted in Lakehouse: {len(dec_pd):,}")
print(f"\n{'column':<22}{'mismatches':>12}")
total_bad = 0
for c in PII_COLUMNS:
    bad = int((dec_pd[c] != orig_pd[c]).sum()) + int(dec_pd[c].isna().sum())
    total_bad += bad
    print(f"{c:<22}{bad:>12,}")

assert total_bad == 0, "Lakebase → Lakehouse decryption did not match the original plaintext"
print(f"\n✅ Lakebase → Lakehouse round-trip verified for {len(dec_pd):,} rows across "
      f"{len(PII_COLUMNS)} PII columns: encrypted in Postgres, decrypted in Spark.")
</content>
