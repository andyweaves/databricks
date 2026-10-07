# notebooks/privacy

Databricks notebooks for detecting, tagging, and protecting PII in Unity Catalog.

## Notebooks

### identifying_and_tagging_pii.py

Scans Unity Catalog tables for PII using Microsoft Presidio and automatically applies tags and comments to flag sensitive data.

- Presents widget selectors for catalogs, entity types, and language.
- Broadcasts a Presidio `AnalyzerEngine` across the Spark cluster.
- Enumerates all tables in selected catalogs via `system.information_schema.tables`.
- Scans each table using `PIIScanner` with a thread pool (capped at 8 workers).
- Applies Unity Catalog tags (e.g., `PII`, `EMAIL_ADDRESS`, `US_SSN`) and markdown comments to tables and columns where PII is detected.

### aes_encrypt|decrypt_table.sql

Creates two stored procedures — `aes_encrypt_table()` and `aes_decrypt_table()` — that apply AES encryption or decryption across an entire table (or a specified subset of columns).

- Encrypts/decrypts all columns or a user-specified list of columns.
- Supports tag-based encryption — encrypt columns by Unity Catalog column tags (e.g. `pii`) instead of listing column names.
- Works on tables, views, and temp views (i.e. DataFrames registered via `createOrReplaceTempView`).
- Optionally writes results to a target table, or returns a result set.
- Generates a cryptographically random AES-256 key and stores it in Databricks Secrets (or use a pre-existing secret).
- Pure SQL procedures — callable from both SQL and PySpark.

### format_preserving_encryption/

Demonstrates format-preserving encryption (FPE) using the FF3-1 algorithm, which encrypts data while preserving its original format and length.

- `format_preserving_encryption.py` — Generates fake PII data, then encrypts selected columns (name, email, SSN, IP addresses, etc.). Supports multiple character sets (numeric, alpha, alphanumeric, ASCII). Handles special characters via two modes: `TOKENIZE` (encrypt everything) or `REASSEMBLE` (preserve special character positions). Decrypts the data back to verify round-trip correctness.
- `format_preserving_encryption_tests.py` — Tests for the FPE implementation.

### ltap_encryption/

A recommended, validated approach for column-level encryption that round-trips between the **Databricks Lakehouse (Delta/Spark SQL) and Lakebase (managed Postgres)** — encrypt on one side, decrypt on the other, without copying the plaintext out. Uses AES-256-CBC + PKCS#7 (the only AES mode both engines support) wrapped with HMAC-SHA256 Encrypt-then-MAC for integrity, with `pgcrypto` on the Postgres side.

- `01_setup.py` — connect to Lakebase, enable `pgcrypto`, generate a master key + derived enc/MAC subkeys in Databricks Secrets, create sample data.
- `02_lakehouse_to_lakebase.py` — encrypt in Spark, sync to Lakebase, decrypt in Postgres.
- `03_lakebase_to_lakehouse.py` — encrypt in Postgres, read back into Spark, decrypt in Databricks.

See the folder's `README.md` for the GCM-vs-CBC rationale, security caveats, key rotation, and the wire format. (Addresses epic FEIP-5589.)

## Prerequisites

- **Pip packages**: Installed automatically via `%pip install -q -r ../../requirements.txt` at the top of each Python notebook. Key packages include `presidio_analyzer`, `presidio_anonymizer`, `faker`, `mimesis`, and `ff3` (for FPE).
- **spaCy model**: `identifying_and_tagging_pii.py` downloads `en_core_web_lg` at startup.
- **Unity Catalog access**: The notebooks require access to `system.information_schema` and `ALTER` permissions on target securables.
- **Databricks secrets**: The AES notebook stores its encryption key in a Databricks secret scope. The FPE notebook generates ephemeral keys by default but should use `dbutils.secrets` in production.

## Running

The notebooks are independent and can be run in any order. Each is self-contained with its own setup cells.
