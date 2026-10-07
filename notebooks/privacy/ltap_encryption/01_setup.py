# Databricks notebook source
# MAGIC %md
# MAGIC # LTAP Encryption — 01: Setup
# MAGIC
# MAGIC Prepares everything the Lakehouse ↔ Lakebase encryption demo needs:
# MAGIC
# MAGIC 1. Configuration widgets (catalog / schema / secret scope / Lakebase project).
# MAGIC 2. A connection to Lakebase (managed Postgres) using a short-lived OAuth token.
# MAGIC 3. The `pgcrypto` extension (required for AES + HMAC on the Postgres side).
# MAGIC 4. A **master key** in Databricks Secrets, plus two derived subkeys — one for
# MAGIC    encryption (`enc`) and one for authentication (`mac`) — using HKDF-SHA256.
# MAGIC 5. A table of realistic **fake PII** in Delta (via `faker` + `mimesis`) to demonstrate with.
# MAGIC
# MAGIC See `README.md` in this folder for the full approach, the GCM-vs-CBC rationale, and the
# MAGIC security caveats. Run this notebook first, then `02_lakehouse_to_lakebase.py` and
# MAGIC `03_lakebase_to_lakehouse.py`.

# COMMAND ----------

# MAGIC %pip install -q "psycopg[binary]>=3.1" faker mimesis

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 1: Configuration
# MAGIC
# MAGIC Set the Unity Catalog location to work in, the secret scope to hold the key material, and
# MAGIC the Lakebase project/branch/endpoint to connect to.
# MAGIC
# MAGIC > **Prerequisite:** the Lakebase project and its UC catalog registration must already
# MAGIC > exist (see the "Prerequisites" section of `README.md`). This notebook connects to and
# MAGIC > configures an existing project; it does not create one.

# COMMAND ----------

from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

dbutils.widgets.text("catalog", "main", "Catalog")
dbutils.widgets.text("schema", "ltap_encryption", "Schema")
dbutils.widgets.text("secret_scope", "ltap_encryption", "Secret scope for key material")
dbutils.widgets.text("key_version", "1", "Key version")
dbutils.widgets.text("num_rows", "10000", "Number of fake PII rows to generate")

# Lakebase connection coordinates — fill these in from `databricks postgres list-*` output.
dbutils.widgets.text("lakebase_project", "", "Lakebase project id")
dbutils.widgets.text("lakebase_branch", "production", "Lakebase branch id")
dbutils.widgets.text("lakebase_endpoint", "", "Lakebase endpoint id (compute)")
dbutils.widgets.text("lakebase_database", "databricks_postgres", "Lakebase Postgres database")

catalog = dbutils.widgets.get("catalog")
schema = dbutils.widgets.get("schema")
secret_scope = dbutils.widgets.get("secret_scope")
key_version = int(dbutils.widgets.get("key_version"))
num_rows = int(dbutils.widgets.get("num_rows"))

project = dbutils.widgets.get("lakebase_project")
branch = dbutils.widgets.get("lakebase_branch")
endpoint_id = dbutils.widgets.get("lakebase_endpoint")
pg_database = dbutils.widgets.get("lakebase_database")

endpoint_name = f"projects/{project}/branches/{branch}/endpoints/{endpoint_id}"
print(f"UC target     : {catalog}.{schema}")
print(f"Secret scope  : {secret_scope}")
print(f"Lakebase endpoint: {endpoint_name}")

# COMMAND ----------

spark.sql(f"CREATE SCHEMA IF NOT EXISTS `{catalog}`.`{schema}`")
spark.sql(f"USE CATALOG `{catalog}`")
spark.sql(f"USE SCHEMA `{schema}`")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 2: Connect to Lakebase
# MAGIC
# MAGIC We connect with `psycopg` using a short-lived OAuth database credential generated from the
# MAGIC endpoint. Tokens last ~1 hour; for long-running work refresh them (see the Lakebase
# MAGIC connectivity guidance). A small helper returns a fresh connection on demand so later cells
# MAGIC never operate on a stale token.

# COMMAND ----------

import psycopg

def lakebase_connection():
    """Open a fresh psycopg connection to Lakebase using a short-lived OAuth token."""
    endpoint = w.postgres.get_endpoint(name=endpoint_name)
    host = endpoint.status.hosts.host
    token = w.postgres.generate_database_credential(endpoint=endpoint_name).token
    username = w.current_user.me().user_name
    return psycopg.connect(
        host=host,
        dbname=pg_database,
        user=username,
        password=token,
        sslmode="require",
    )

with lakebase_connection() as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT version()")
        print(cur.fetchone()[0])

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 3: Enable `pgcrypto`
# MAGIC
# MAGIC `pgcrypto` is **not** installed by default on Lakebase, but it is on the supported
# MAGIC extension allow-list. It provides `encrypt_iv` / `decrypt_iv` (AES-CBC), `hmac`
# MAGIC (HMAC-SHA256) and `gen_random_bytes` — everything the Postgres side of the demo needs.

# COMMAND ----------

with lakebase_connection() as conn:
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cur.execute("SELECT extname, extversion FROM pg_extension WHERE extname = 'pgcrypto'")
        print("pgcrypto:", cur.fetchone())

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 4: Generate and store the key material
# MAGIC
# MAGIC A single cryptographically random 256-bit **master key** is generated and stored in
# MAGIC Databricks Secrets (base64-encoded, because the SQL `secret()` function returns a STRING).
# MAGIC From it we derive two independent 256-bit subkeys with HKDF-SHA256 and distinct info
# MAGIC labels:
# MAGIC
# MAGIC - **`enc_key`** — used only for AES-256-CBC.
# MAGIC - **`mac_key`** — used only for HMAC-SHA256.
# MAGIC
# MAGIC Using separate keys for encryption and authentication is the standard Encrypt-then-MAC
# MAGIC requirement — never reuse one key for both. The subkeys are stored under version-suffixed
# MAGIC secret names (e.g. `enc_key_v1`) so key rotation can introduce a new version without
# MAGIC breaking rows written under the old one.
# MAGIC
# MAGIC > If the secrets for this `key_version` already exist, this cell leaves them untouched.

# COMMAND ----------

import hmac
import hashlib
from base64 import b64encode, b64decode
from os import urandom


def hkdf_sha256(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-Expand (single block; length <= 32 for SHA-256).

    `prk` is a high-entropy 32-byte master key, so we use it directly as the pseudo-random
    key for the expand step. Distinct `info` labels yield independent subkeys.
    """
    assert length <= 32
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


master_secret_name = f"master_key_v{key_version}"
enc_secret_name = f"enc_key_v{key_version}"
mac_secret_name = f"mac_key_v{key_version}"

# Create the scope if needed
try:
    w.secrets.create_scope(scope=secret_scope)
    print(f"Created secret scope: {secret_scope}")
except Exception as e:
    print(f"Secret scope already exists or could not be created: {e}")

existing = {s.key for s in w.secrets.list_secrets(scope=secret_scope)}
if master_secret_name in existing:
    print(f"Key material for version {key_version} already present — reusing it.")
    master_key = b64decode(dbutils.secrets.get(secret_scope, master_secret_name))
else:
    master_key = urandom(32)
    w.secrets.put_secret(scope=secret_scope, key=master_secret_name,
                         string_value=b64encode(master_key).decode())
    print(f"Generated and stored new master key: {secret_scope}/{master_secret_name}")

enc_key = hkdf_sha256(master_key, b"lakehouse-lakebase-enc")
mac_key = hkdf_sha256(master_key, b"lakehouse-lakebase-mac")

w.secrets.put_secret(scope=secret_scope, key=enc_secret_name,
                     string_value=b64encode(enc_key).decode())
w.secrets.put_secret(scope=secret_scope, key=mac_secret_name,
                     string_value=b64encode(mac_key).decode())
print(f"Stored derived subkeys: {enc_secret_name}, {mac_secret_name}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Section 5: Generate fake PII data
# MAGIC
# MAGIC Generate `num_rows` (default 10,000) realistic fake customers across several locales using
# MAGIC [`faker`](https://faker.readthedocs.io/) and [`mimesis`](https://mimesis.name/), following
# MAGIC the same `applyInPandas` pattern as `notebooks/fake_pii_data/generate_fake_pii.py`
# MAGIC (generators are created on the executors; every row is independent).
# MAGIC
# MAGIC The table has a stable integer `customer_id` primary key (required for the Lakebase synced
# MAGIC table). Five columns are **PII to be encrypted** — `name`, `email`, `phone_number`,
# MAGIC `national_id`, `credit_card_number` — and three are left in the clear (`locale`, `age`,
# MAGIC `company`) to show selective, column-level protection.

# COMMAND ----------

from pyspark.sql.types import StructType, StructField, LongType, StringType, IntegerType
from pyspark.sql.functions import spark_partition_id

# Columns the demo treats as PII (encrypted in notebooks 02 / 03). Kept here as the single
# source of truth; the other notebooks read the same list.
PII_COLUMNS = ["name", "email", "phone_number", "national_id", "credit_card_number"]
CLEAR_COLUMNS = ["customer_id", "locale", "age", "company"]
ACTIVE_LOCALES = ["en_US", "en_GB", "de_DE", "fr_FR"]

customers_schema = StructType([
    StructField("customer_id", LongType(), False),
    StructField("name", StringType(), False),
    StructField("email", StringType(), False),
    StructField("phone_number", StringType(), False),
    StructField("national_id", StringType(), False),
    StructField("credit_card_number", StringType(), False),
    StructField("locale", StringType(), False),
    StructField("age", IntegerType(), False),
    StructField("company", StringType(), False),
])

rows_per_partition = 2000
num_partitions = max(1, num_rows // rows_per_partition)


def generate_customers(pdf):
    """Generate fake PII rows for a partition. `customer_id` is carried from the input id so
    it stays unique and stable (it is the synced-table primary key)."""
    import random
    import pandas as pd
    from datetime import date
    from faker import Faker
    from mimesis import Person, Payment
    from mimesis.locales import Locale

    mimesis_locale = {"en_US": Locale.EN, "en_GB": Locale.EN, "de_DE": Locale.DE, "fr_FR": Locale.FR}
    fakers = {loc: Faker(loc) for loc in ACTIVE_LOCALES}
    persons = {loc: Person(mimesis_locale[loc]) for loc in ACTIVE_LOCALES}
    payment = Payment()

    def gen_row(customer_id):
        loc = random.choice(ACTIVE_LOCALES)
        f, p = fakers[loc], persons[loc]
        try:
            national_id = f.ssn()
        except Exception:
            national_id = p.identifier()
        dob = f.date_of_birth(minimum_age=18, maximum_age=90)
        return {
            "customer_id": int(customer_id),
            "name": random.choice([f.name(), p.full_name()]),
            "email": random.choice([f.email(), f.free_email(), p.email()]),
            "phone_number": f.phone_number(),
            "national_id": national_id,
            "credit_card_number": random.choice([f.credit_card_number(), payment.credit_card_number()]),
            "locale": loc,
            "age": (date.today() - dob).days // 365,
            "company": f.company(),
        }

    return pd.DataFrame([gen_row(cid) for cid in pdf["id"]])


customers = (
    spark.range(1, num_rows + 1, numPartitions=num_partitions)
    .withColumn("partition_id", spark_partition_id())
    .groupBy("partition_id")
    .applyInPandas(generate_customers, customers_schema)
)

(customers.write.mode("overwrite").option("overwriteSchema", "true")
          .saveAsTable(f"{catalog}.{schema}.customers"))

print(f"Generated {spark.table(f'{catalog}.{schema}.customers').count():,} rows.")
display(spark.table(f"{catalog}.{schema}.customers").limit(20))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Setup complete
# MAGIC
# MAGIC You now have: a Lakebase connection with `pgcrypto` enabled, a master key plus derived
# MAGIC `enc`/`mac` subkeys in Databricks Secrets, and a `customers` table of fake PII in Delta.
# MAGIC
# MAGIC Keep the same widget values when you run `02_lakehouse_to_lakebase.py` and
# MAGIC `03_lakebase_to_lakehouse.py`.
</content>
