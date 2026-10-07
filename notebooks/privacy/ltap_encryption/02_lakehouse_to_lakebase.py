# Databricks notebook source
# MAGIC %md
# MAGIC # LTAP Encryption — 02: Lakehouse → Lakebase
# MAGIC
# MAGIC Encrypt a column **in the Lakehouse** with Spark SQL, move it into **Lakebase** with a
# MAGIC synced table (the native Delta → Postgres reverse-ETL path), then **decrypt it inside
# MAGIC Postgres** with `pgcrypto` — proving the ciphertext written by `aes_encrypt` round-trips.
# MAGIC
# MAGIC Approach (see `README.md`): AES-256-CBC + PKCS#7 for confidentiality, HMAC-SHA256
# MAGIC (Encrypt-then-MAC) for integrity, verified **before** decryption. Run `01_setup.py` first
# MAGIC with the same widget values.

# COMMAND ----------

# MAGIC %pip install "psycopg[binary]>=3.1"

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 1: Configuration and key material
# MAGIC
# MAGIC Re-read the widgets, rebuild the Lakebase connection helper, and load the derived subkeys
# MAGIC from Databricks Secrets. The subkeys are used as **bound `psycopg` parameters** on the
# MAGIC Postgres side — never inlined into SQL text (so they don't land in Postgres statement
# MAGIC logs) and never persisted in Lakebase.

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
dbutils.widgets.text("lakebase_catalog", "", "Lakebase UC catalog (for synced table)")
dbutils.widgets.text("pg_schema", "public", "Postgres schema for the synced table")

catalog = dbutils.widgets.get("catalog")
schema = dbutils.widgets.get("schema")
secret_scope = dbutils.widgets.get("secret_scope")
key_version = int(dbutils.widgets.get("key_version"))
project = dbutils.widgets.get("lakebase_project")
branch = dbutils.widgets.get("lakebase_branch")
endpoint_id = dbutils.widgets.get("lakebase_endpoint")
pg_database = dbutils.widgets.get("lakebase_database")
lakebase_catalog = dbutils.widgets.get("lakebase_catalog")
pg_schema = dbutils.widgets.get("pg_schema")

endpoint_name = f"projects/{project}/branches/{branch}/endpoints/{endpoint_id}"
enc_secret_name = f"enc_key_v{key_version}"
mac_secret_name = f"mac_key_v{key_version}"

spark.sql(f"USE CATALOG `{catalog}`")
spark.sql(f"USE SCHEMA `{schema}`")

# Derived subkeys as raw bytes for the Postgres (psycopg) side
enc_key = b64decode(dbutils.secrets.get(secret_scope, enc_secret_name))
mac_key = b64decode(dbutils.secrets.get(secret_scope, mac_secret_name))
assert len(enc_key) == 32 and len(mac_key) == 32

# PII columns to encrypt (same list as 01_setup.py); the rest stay in the clear.
PII_COLUMNS = ["name", "email", "phone_number", "national_id", "credit_card_number"]
CLEAR_COLUMNS = ["customer_id", "locale", "age", "company"]


def lakebase_connection():
    endpoint = w.postgres.get_endpoint(name=endpoint_name)
    return psycopg.connect(
        host=endpoint.status.hosts.host,
        dbname=pg_database,
        user=w.current_user.me().user_name,
        password=w.postgres.generate_database_credential(endpoint=endpoint_name).token,
        sslmode="require",
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 2: Encrypt the PII columns in the Lakehouse
# MAGIC
# MAGIC For each PII column, `aes_encrypt(col, enc_key, 'CBC', 'PKCS')` returns a `BINARY` blob laid
# MAGIC out as `IV(16) || ciphertext` — the IV is random per row and prepended automatically. We
# MAGIC then compute `hmac(mac_key, blob, 'SHA-256')` over that blob (Encrypt-then-MAC). Clear
# MAGIC columns (`locale`, `age`, `company`) pass through untouched, and every row is tagged with
# MAGIC `key_version`.
# MAGIC
# MAGIC > **Important — encrypt once, then MAC the stored bytes.** Because the IV is random,
# MAGIC > `aes_encrypt` is **non-deterministic**: calling it twice yields two different
# MAGIC > ciphertexts. If you computed the ciphertext and the HMAC in a single `SELECT`, the MAC
# MAGIC > would be taken over a *different* blob than the one stored and would never verify. So we
# MAGIC > do it in two passes — persist the ciphertext columns first, then compute the MACs over the
# MAGIC > materialized `*_enc` columns.
# MAGIC
# MAGIC The keys are read with `unbase64(secret(...))` so no key material appears in the notebook
# MAGIC or query text. Every `*_enc` / `*_mac` column is stored as `BINARY`, which maps cleanly to
# MAGIC Postgres `BYTEA` through the synced table (no base64 needed).

# COMMAND ----------

enc_key_sql = f"unbase64(secret('{secret_scope}', '{enc_secret_name}'))"
mac_key_sql = f"unbase64(secret('{secret_scope}', '{mac_secret_name}'))"

# Pass 1: encrypt each PII column once and persist to Delta (clear columns pass through).
enc_exprs = [f"aes_encrypt({c}, {enc_key_sql}, 'CBC', 'PKCS') AS {c}_enc" for c in PII_COLUMNS]
select_list = ",\n  ".join([*CLEAR_COLUMNS, *enc_exprs, f"CAST({key_version} AS INT) AS key_version"])
spark.sql(f"""
CREATE OR REPLACE TABLE {catalog}.{schema}.customers_encrypted AS
SELECT
  {select_list}
FROM {catalog}.{schema}.customers
""")

# Pass 2: compute the Encrypt-then-MAC tag over each now-materialized ciphertext column.
for c in PII_COLUMNS:
    spark.sql(f"ALTER TABLE {catalog}.{schema}.customers_encrypted ADD COLUMN {c}_mac BINARY")
set_clause = ",\n  ".join([f"{c}_mac = hmac({mac_key_sql}, {c}_enc, 'SHA-256')" for c in PII_COLUMNS])
spark.sql(f"""
UPDATE {catalog}.{schema}.customers_encrypted
SET
  {set_clause}
""")

# Show a sample of the ciphertext (base64 for display only)
display_cols = ["customer_id"] + [f"base64({c}_enc) AS {c}_enc_b64" for c in PII_COLUMNS] + ["key_version"]
display(spark.sql(f"""
SELECT {", ".join(display_cols)}
FROM {catalog}.{schema}.customers_encrypted
ORDER BY customer_id
LIMIT 20
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Sanity check: the Lakehouse can decrypt its own ciphertext
# MAGIC
# MAGIC Before shipping to Lakebase, confirm every PII column round-trips within Databricks.
# MAGIC `aes_decrypt` reads the prepended IV from the blob (it has no IV argument), and decryption
# MAGIC is gated on the HMAC verifying first. This counts any rows that fail to match.

# COMMAND ----------

check_exprs = []
for c in PII_COLUMNS:
    check_exprs.append(
        f"""CASE WHEN hmac({mac_key_sql}, e.{c}_enc, 'SHA-256') = e.{c}_mac
                  AND CAST(aes_decrypt(e.{c}_enc, {enc_key_sql}, 'CBC', 'PKCS') AS STRING) = c.{c}
                 THEN 0 ELSE 1 END AS {c}_bad""")
mismatch = spark.sql(f"""
SELECT {", ".join(f"sum({c}_bad) AS {c}_mismatches" for c in PII_COLUMNS)}
FROM (
  SELECT {", ".join(check_exprs)}
  FROM {catalog}.{schema}.customers_encrypted e
  JOIN {catalog}.{schema}.customers c USING (customer_id)
)
""")
display(mismatch)
assert all((v or 0) == 0 for v in mismatch.first().asDict().values()), \
    "In-Lakehouse decryption mismatch — check keys / column list"
print("✅ In-Lakehouse decrypt check passed for all PII columns.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 3: Sync the encrypted table into Lakebase
# MAGIC
# MAGIC A **Lakebase synced table** copies the Delta table into Postgres (Snapshot mode here — no
# MAGIC CDF needed). Create it once with the CLI command printed below (run it from a terminal
# MAGIC with your profile), or via the Catalog Explorer UI. `BINARY` columns arrive as `BYTEA`,
# MAGIC ready for `pgcrypto`.
# MAGIC
# MAGIC > Synced tables are **read-only** in Postgres — perfect for this direction, where we only
# MAGIC > decrypt (a SELECT). The reverse direction (writing ciphertext in Lakebase) uses a regular
# MAGIC > table in `03_lakebase_to_lakehouse.py`.

# COMMAND ----------

synced_table = f"{lakebase_catalog}.{pg_schema}.customers_encrypted"
source_table = f"{catalog}.{schema}.customers_encrypted"
cli_command = f"""databricks postgres create-synced-table {synced_table} \\
  --json '{{
    "spec": {{
      "source_table_full_name": "{source_table}",
      "primary_key_columns": ["customer_id"],
      "scheduling_policy": "SNAPSHOT",
      "branch": "projects/{project}/branches/{branch}",
      "postgres_database": "{pg_database}",
      "create_database_objects_if_missing": true,
      "new_pipeline_spec": {{
        "storage_catalog": "{catalog}",
        "storage_schema": "{schema}"
      }}
    }}
  }}' --profile <PROFILE>"""
print(cli_command)

# COMMAND ----------

# MAGIC %md
# MAGIC Wait until the synced table has materialized in Postgres before continuing. This cell
# MAGIC polls for the table and its row count.

# COMMAND ----------

import time

pg_table = f"{pg_schema}.customers_encrypted"
for attempt in range(60):
    try:
        with lakebase_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT count(*) FROM {pg_table}")
                count = cur.fetchone()[0]
        if count > 0:
            print(f"Synced table {pg_table} is ready with {count} rows.")
            break
        print(f"[{attempt}] table present but empty; waiting…")
    except Exception as e:
        print(f"[{attempt}] not ready yet: {e}")
    time.sleep(10)
else:
    raise TimeoutError(f"Synced table {pg_table} did not become ready in time.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 4: Verify and decrypt inside Lakebase
# MAGIC
# MAGIC The payoff. In Postgres we:
# MAGIC
# MAGIC 1. recompute `hmac(email_enc, mac_key, 'sha256')` and compare it to the stored `email_mac`
# MAGIC    — note pgcrypto's `hmac(data, key, ...)` argument order is the **reverse** of
# MAGIC    Databricks' `hmac(key, message, ...)`;
# MAGIC 2. only if the MAC verifies, slice the IV back off (`substring(blob from 1 for 16)`) and
# MAGIC    `decrypt_iv(..., 'aes-cbc/pad:pkcs')` the remaining ciphertext;
# MAGIC 3. `convert_from(..., 'utf8')` to recover the original string.
# MAGIC
# MAGIC The `enc`/`mac` keys are passed as bound parameters (`%(enc)s`, `%(mac)s`).

# COMMAND ----------

# Build the per-column verify+decrypt projection for every PII column.
col_exprs = []
for c in PII_COLUMNS:
    col_exprs.append(f"""
      CASE WHEN hmac({c}_enc, %(mac)s, 'sha256') = {c}_mac
           THEN convert_from(
                  decrypt_iv(
                    substring({c}_enc from 17),             -- ciphertext after the 16-byte IV
                    %(enc)s,                                  -- 32-byte AES key
                    substring({c}_enc from 1 for 16),         -- IV
                    'aes-cbc/pad:pkcs'
                  ), 'utf8')
      END AS {c}""")
query = f"SELECT customer_id,{','.join(col_exprs)} FROM {pg_table} ORDER BY customer_id"

with lakebase_connection() as conn:
    with conn.cursor() as cur:
        cur.execute(query, {"enc": enc_key, "mac": mac_key})
        pg_rows = cur.fetchall()
        pg_header = [d.name for d in cur.description]

import pandas as pd
pg_df = pd.DataFrame(pg_rows, columns=pg_header).set_index("customer_id").sort_index()

# Original plaintext held in the Lakehouse
orig_df = (spark.table(f"{catalog}.{schema}.customers")
                .select("customer_id", *PII_COLUMNS).toPandas()
                .set_index("customer_id").sort_index())

print(f"Rows decrypted in Lakebase: {len(pg_df):,}")
print(f"\n{'column':<22}{'mismatches':>12}")
total_bad = 0
for c in PII_COLUMNS:
    bad = int((pg_df[c] != orig_df[c]).sum()) + int(pg_df[c].isna().sum())
    total_bad += bad
    print(f"{c:<22}{bad:>12,}")

# Show a few decrypted sample rows next to the originals
print("\nSample (first 5 rows, decrypted in Lakebase):")
display(pg_df.head(5))

assert total_bad == 0, "Lakehouse → Lakebase decryption did not match the original plaintext"
print(f"\n✅ Lakehouse → Lakebase round-trip verified for {len(pg_df):,} rows across "
      f"{len(PII_COLUMNS)} PII columns: encrypted in Spark, decrypted in Postgres.")
</content>
