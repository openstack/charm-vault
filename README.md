# Overview

Vault secures, stores, and tightly controls access to tokens,
passwords, certificates, API keys, and other secrets in modern
computing. Vault handles leasing, key revocation, key rolling, and
auditing. Through a unified API, users can access an encrypted
Key/Value store and network encryption-as-a-service, or generate
AWS IAM/STS credentials, SQL/NoSQL databases, X.509 certificates,
SSH credentials, and more.

## About the Charm

This charm installs Vault from the Ubuntu Snap Store and
supports the PostgreSQL storage backend only.

After deploying and relating the charm to postgresql, install
the vault snap locally and use "vault init" to create the
master key shards and the root token, and store them safely.
