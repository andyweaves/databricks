-- =============================================================================
-- Decrypt LTAP-encrypted columns directly in Lakebase (Postgres SQL editor)
-- =============================================================================
--
-- Run this in the Lakebase SQL editor to read the PII columns that were encrypted
-- in the Lakehouse (by 02_lakehouse_to_lakebase.py) and synced into Postgres --
-- no notebook required.
--
-- Prerequisites
--   * The `pgcrypto` extension is enabled on this branch (01_setup.py does this,
--     or run: CREATE EXTENSION IF NOT EXISTS pgcrypto;).
--   * The synced table public.customers_encrypted exists and is ONLINE.
--
-- Keys
--   Paste the 64-character hex of your two derived subkeys below. Retrieve them
--   from your Databricks secret scope (in a notebook / Databricks cell):
--
--       from base64 import b64decode
--       print("enc:", b64decode(dbutils.secrets.get("ltap_encryption", "enc_key_v1")).hex())
--       print("mac:", b64decode(dbutils.secrets.get("ltap_encryption", "mac_key_v1")).hex())
--
-- ⚠️  Security note: pasting the keys here puts them in Lakebase query history / logs
--   (the AES key especially). Fine for a one-off manual check; for anything
--   repeatable, decrypt from the notebook, where secret() keeps the AES key out of
--   the query plan.
--
-- This query matches the context-bound HMAC used by the notebooks: the tag is
-- computed over  utf-8("<customer_id>:<column>:<key_version>") || blob,  so a
-- ciphertext only verifies in the exact row / column / key version it was minted
-- for. The HMAC is checked first; a row only decrypts if its tag is valid.
-- =============================================================================

WITH keys AS (
  SELECT decode('<ENC_KEY_HEX>', 'hex') AS enc_key,   -- 64 hex chars (AES-256 key)
         decode('<MAC_KEY_HEX>', 'hex') AS mac_key    -- 64 hex chars (HMAC key)
)
SELECT
  t.customer_id,
  t.locale, t.age, t.company,          -- clear columns, queried normally
  t.key_version,

  CASE WHEN hmac(convert_to(t.customer_id::text || ':' || 'name' || ':' || t.key_version::text, 'utf8') || t.name_enc, k.mac_key, 'sha256') = t.name_mac
       THEN convert_from(decrypt_iv(substring(t.name_enc from 17), k.enc_key, substring(t.name_enc from 1 for 16), 'aes-cbc/pad:pkcs'), 'utf8')
  END AS name,

  CASE WHEN hmac(convert_to(t.customer_id::text || ':' || 'email' || ':' || t.key_version::text, 'utf8') || t.email_enc, k.mac_key, 'sha256') = t.email_mac
       THEN convert_from(decrypt_iv(substring(t.email_enc from 17), k.enc_key, substring(t.email_enc from 1 for 16), 'aes-cbc/pad:pkcs'), 'utf8')
  END AS email,

  CASE WHEN hmac(convert_to(t.customer_id::text || ':' || 'phone_number' || ':' || t.key_version::text, 'utf8') || t.phone_number_enc, k.mac_key, 'sha256') = t.phone_number_mac
       THEN convert_from(decrypt_iv(substring(t.phone_number_enc from 17), k.enc_key, substring(t.phone_number_enc from 1 for 16), 'aes-cbc/pad:pkcs'), 'utf8')
  END AS phone_number,

  CASE WHEN hmac(convert_to(t.customer_id::text || ':' || 'national_id' || ':' || t.key_version::text, 'utf8') || t.national_id_enc, k.mac_key, 'sha256') = t.national_id_mac
       THEN convert_from(decrypt_iv(substring(t.national_id_enc from 17), k.enc_key, substring(t.national_id_enc from 1 for 16), 'aes-cbc/pad:pkcs'), 'utf8')
  END AS national_id,

  CASE WHEN hmac(convert_to(t.customer_id::text || ':' || 'credit_card_number' || ':' || t.key_version::text, 'utf8') || t.credit_card_number_enc, k.mac_key, 'sha256') = t.credit_card_number_mac
       THEN convert_from(decrypt_iv(substring(t.credit_card_number_enc from 17), k.enc_key, substring(t.credit_card_number_enc from 1 for 16), 'aes-cbc/pad:pkcs'), 'utf8')
  END AS credit_card_number

FROM public.customers_encrypted t
CROSS JOIN keys k
ORDER BY t.customer_id
LIMIT 100;

-- -----------------------------------------------------------------------------
-- Notes
--   * Clear columns (locale, age, company) need no decryption -- query them as-is.
--   * A NULL in a decrypted column means its HMAC did not verify (tampered,
--     wrong key, or wrong key_version) -- the row is intentionally not decrypted.
--   * To decrypt without the integrity check, drop the "CASE WHEN hmac(...) = *_mac
--     THEN ... END" wrapper and keep only convert_from(decrypt_iv(...)).
-- -----------------------------------------------------------------------------
</content>
