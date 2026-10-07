# LTAP Column Encryption — Lakehouse ↔ Lakebase

A recommended, validated approach for **column-level encryption that round-trips between the
Databricks Lakehouse (Delta / Spark SQL) and Lakebase (managed Postgres)** — so you can
encrypt a column on one side and decrypt it on the other without copying the plaintext back
out. This is the "LTAP" (Lake Transactional/Analytical Processing) pattern: OLAP in the
Lakehouse and OLTP in Lakebase over the *same* data.

> Addresses epic **FEIP-5589** — *"Define and document a recommended approach for column
> level encryption/decryption that works for both Lakehouse and Lakebase."*

## TL;DR — the recommendation

**AES-256-CBC with PKCS#7 padding for confidentiality, wrapped with HMAC-SHA256
(Encrypt-then-MAC) for integrity**, using a master key held in Databricks Secrets and
`pgcrypto` on the Lakebase side. Verify the HMAC *before* decrypting.

### Why not just use GCM everywhere?

Databricks `aes_encrypt()` defaults to **AES-GCM**, an authenticated (AEAD) mode and the
modern best choice. The problem is the Lakebase side:

| Requirement | Status on Lakebase (managed Postgres) |
|---|---|
| `pgcrypto` available | ✅ Yes (`CREATE EXTENSION IF NOT EXISTS pgcrypto`) |
| `pgcrypto` supports AES-GCM | ❌ No — only CBC / ECB |
| A GCM/AEAD extension (e.g. `pgsodium`) | ❌ Not on Lakebase's supported-extension allow-list |
| Bring-your-own via untrusted PL (`plpython3u`) | ❌ Not permitted on managed Postgres |

So GCM cannot be decrypted inside Lakebase today. The **only AES mode both engines support is
CBC**. Keeping GCM would force all decryption to happen in Databricks — which defeats the
entire point of the epic (decrypt *in* Lakebase without round-tripping the data).

### Making CBC safe

Raw CBC is unauthenticated — it's malleable and vulnerable to padding-oracle / bit-flipping
attacks. We restore the integrity guarantee GCM would have given us using the standard
**Encrypt-then-MAC** construction, which both engines can now compute natively:

| Control | Lakehouse (Spark SQL) | Lakebase (pgcrypto) |
|---|---|---|
| AES-256-CBC + PKCS#7 | `aes_encrypt(x, key, 'CBC', 'PKCS')` / `aes_decrypt(...)` | `encrypt_iv` / `decrypt_iv(..., 'aes-cbc/pad:pkcs')` |
| Random per-row IV | Generated automatically, prepended to output | `gen_random_bytes(16)`, prepended manually |
| HMAC-SHA256 | `hmac(key, msg, 'SHA-256')` | `hmac(msg, key, 'sha256')` ⚠️ arg order swapped |
| Separate enc / MAC keys | Derived subkeys (HKDF-SHA256) | Same derived subkeys |

This is a well-established construction, not a hand-rolled oddity. The design choices a
cryptographer would check are all satisfied: random per-row IVs, Encrypt-then-MAC with the
MAC verified *before* decryption, **separate keys for encryption and authentication**, and
256-bit keys sourced from a secret store (never hardcoded, never persisted in Postgres).

## Wire format

A single canonical layout is used in both directions so the same bytes decrypt on either
engine:

```
ciphertext blob :  IV (16 bytes)  ||  AES-256-CBC-PKCS7( enc_key , plaintext )
mac             :  HMAC-SHA256( mac_key , ciphertext blob )          # 32 bytes
key_version     :  integer identifying which key generation produced this row
```

- Databricks `aes_encrypt(x, key, 'CBC', 'PKCS')` **produces** this layout (random 16-byte IV
  prepended), and `aes_decrypt(blob, key, 'CBC', 'PKCS')` **consumes** it (it reads the IV
  from the front — `aes_decrypt` has no IV argument).
- On the Postgres side, slice the IV back off explicitly:
  `decrypt_iv(substring(blob from 17), enc_key, substring(blob from 1 for 16), 'aes-cbc/pad:pkcs')`.

Store `blob` and `mac` as Delta `BINARY`, which maps to Postgres `BYTEA` through a Lakebase
synced table — no base64 round-tripping needed.

## Key management & rotation

- A single 32-byte **master key** is generated and stored in Databricks Secrets (base64).
  Two independent subkeys are derived from it with HKDF-SHA256 and distinct info labels:
  `enc_key` (AES) and `mac_key` (HMAC). Deriving means you only store/rotate one secret.
- The key is made available to Lakebase at query time as a **bound psycopg parameter** — it
  is never inlined into SQL (avoids Postgres statement logs) and **never persisted in
  Postgres**. The ciphertext lives in Lakebase; the key does not.
- Each row carries a `key_version`. New writes use the newest key; old rows stay readable
  under their original key during a background re-encrypt.
- On the Databricks side the **AES key** is supplied to `aes_encrypt`/`aes_decrypt` via the SQL
  `secret()` function, so it is resolved at execution and never appears in the query text or
  plan. The **HMAC key** can't use the same trick: Databricks only permits `secret()` as an
  argument to `aes_encrypt`/`aes_decrypt` (anything else raises `SECRET_FUNCTION_INVALID_LOCATION`),
  so the HMAC key is read from the secret store and passed to `hmac()` directly, which means it
  *is* materialized in the query plan. It's an integrity key rather than a confidentiality key;
  if even that exposure is unacceptable, compute the HMAC inside a secret-enabled Unity Catalog
  Python UDF instead.

> **Why workspace secret scopes and not Unity Catalog secrets?** Unity Catalog secrets (GA
> since August 2026) are the more governed option, but the SQL built-in `secret()` function —
> which the Databricks-side encryption uses *inline* (`aes_encrypt(col, unbase64(secret(...)))`)
> so the key is resolved at execution and never lands in the query text or plan — only supports
> **workspace secret scopes**, not UC three-part names. Keeping that property is worth more here
> than UC governance. Move to UC secrets once `secret()` supports them, or wrap the crypto in a
> Unity Catalog Python UDF with a `SECRETS` clause (reading via
> `dbutils.secrets.get(catalog=…, schema=…, key=…)`, which needs DBR 17.3 LTS+ / serverless env
> v4+).

**Does rotating the key require re-encrypting the data?** With direct encryption like this —
**yes**: the ciphertext is bound to the key, so rotation means decrypt-with-old →
encrypt-with-new (done in bulk on the Spark side, then re-synced). `key_version` lets old and
new coexist so there's no flag-day.

**The real fix for cheap rotation is envelope encryption** (KEK/DEK): encrypt data with a
Data Encryption Key, wrap the DEK with a Key Encryption Key in a KMS/Key Vault, and rotate
the KEK by re-wrapping the DEK only — **no data re-encryption**. This repo already
demonstrates that pattern against AWS KMS / Azure Key Vault in
[`../../envelope_encryption_v2/`](../../envelope_encryption_v2/README.md); the CBC data key
here can be wrapped exactly the same way.

## Notebooks (run in order)

| Notebook | What it does |
|---|---|
| `01_setup.py` | Config, connect to Lakebase, `CREATE EXTENSION pgcrypto`, generate the master key + derived subkeys into Databricks Secrets, and generate a table of realistic fake PII in Delta (`faker` + `mimesis`, 10,000 rows by default) |
| `02_lakehouse_to_lakebase.py` | Encrypt the PII columns in Delta (`aes_encrypt` CBC + `hmac`), sync them to Lakebase via a **synced table**, then verify the HMAC and `decrypt_iv` **in Postgres** for every row/column — proving Lakehouse → Lakebase |
| `03_lakebase_to_lakehouse.py` | Encrypt the PII columns in Postgres (`encrypt_iv` + `hmac`) in a regular table, read them back into Spark, then verify the HMAC and `aes_decrypt` **in Databricks** — proving Lakebase → Lakehouse |

The demo encrypts five PII columns — `name`, `email`, `phone_number`, `national_id`,
`credit_card_number` — and leaves `locale`, `age`, `company` in the clear to show selective,
column-level protection. The PII column list is defined once in each notebook (`PII_COLUMNS`),
so you can add or remove columns in one place.

Both ETL mechanisms are shown: a **Lakebase synced table** (Delta → Postgres, the native
reverse-ETL path) for direction 1, and a **direct `psycopg` table** for direction 2 (synced
tables are read-only in Postgres, so writes must use a regular table).

## Prerequisites

- Databricks CLI authenticated to a workspace with Lakebase enabled (see the `databricks-core`
  skill). Create the Lakebase project and register it as a UC catalog once up front:
  ```bash
  databricks postgres create-project <PROJECT_ID> \
    --json '{"spec": {"display_name": "LTAP Encryption Demo"}}' --profile <PROFILE>

  databricks postgres create-catalog <LAKEBASE_CATALOG> \
    --json '{"spec": {"postgres_database": "databricks_postgres",
                      "branch": "projects/<PROJECT_ID>/branches/production"}}' --profile <PROFILE>
  ```
- `psycopg` (v2 or v3) available on the cluster/serverless environment for the Postgres cells.
- Permission to create a secret scope, and `USE SCHEMA` + `CREATE TABLE` on the sync target.

## Limitations & the product ask

- **CBC, not GCM, is a deliberate interop compromise** forced by Lakebase/pgcrypto's lack of
  AEAD. It is made safe with Encrypt-then-MAC, but AEAD remains preferable where available.
- **Synced tables are read-only in Postgres** — the Lakebase→Lakehouse direction uses a
  regular table.
- **The ideal future state** (called out in FEIP-5589): Databricks `aes_encrypt`/`aes_decrypt`
  interoperating natively with Lakebase — e.g. a GCM-capable AEAD on the Postgres side, or a
  shared authenticated-encryption format across both engines — which would remove the need
  for the CBC+HMAC construction entirely.

## References

- [`aes_encrypt`](https://docs.databricks.com/aws/en/sql/language-manual/functions/aes_encrypt) /
  [`aes_decrypt`](https://docs.databricks.com/aws/en/sql/language-manual/functions/aes_decrypt) /
  [`hmac`](https://docs.databricks.com/aws/en/sql/language-manual/functions/hmac)
- [Lakebase supported PostgreSQL extensions](https://docs.databricks.com/aws/en/oltp/projects/extensions)
- [Lakebase synced tables](https://docs.databricks.com/aws/en/oltp/projects/sync-tables)
- [PostgreSQL `pgcrypto`](https://www.postgresql.org/docs/current/pgcrypto.html)
</content>
</invoke>
