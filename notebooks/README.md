# Notebooks

This directory contains Databricks notebooks organized by topic. Each subdirectory focuses on a specific aspect of data security and privacy on Databricks.

## Directory Overview

| Directory | Description |
|---|---|
| **fake_pii_data** | Generate realistic fake PII test data for use with the other notebooks. |
| **privacy** | Scan tables for PII, tag columns with classification labels, apply format-preserving encryption, and encrypt columns interchangeably across the Lakehouse and Lakebase (`ltap_encryption`). |
| **abac** | Attribute-Based Access Control -- create Unity Catalog column mask policies driven by PII tags so sensitive data is automatically redacted for unauthorized users. |
| **envelope_encryption** | Envelope encryption using Azure Key Vault for encrypting and decrypting data at the field level. |
| **envelope_encryption_v2** | Updated envelope encryption implementation with support for both AWS and Azure key management. |
| **ai_guardrails** | LLM safety tools including Llama Guard for content classification, Prompt Guard for injection detection, Code Shield for insecure code detection, and red-teaming utilities. |
| **security_genie** | Audit and monitoring queries against Databricks system tables, packaged for use with Genie. Includes IP ACL checks, example SQL queries, and ETL setup. |

## Suggested Exploration Order

1. **fake_pii_data** -- Start here to generate a test dataset with realistic PII columns.
2. **privacy** -- Scan the test data for PII and apply classification tags to columns.
3. **abac** -- Create ABAC policies that automatically mask tagged columns for unauthorized users.
4. **envelope_encryption** / **envelope_encryption_v2** -- Explore field-level encryption with cloud KMS integration.
5. **ai_guardrails** -- Set up safety guardrails for LLM-powered applications.
6. **security_genie** -- Monitor workspace activity and audit access patterns using system tables.
