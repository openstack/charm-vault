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
supports the PostgreSQL and MySQL storage backends. Note that Vault itself
does not support PostgreSQL 10, so neither does this charm. If you're
deploying on bionic, you'll need to deploy a 9.x version of PostgreSQL.

After deploying and relating the charm to postgresql, install
the vault snap locally and use "vault init" to create the
master key shards and the root token, and store them safely.

## Network Spaces support

The vault charm directly supports network binding via the 'access'
extra-binding and the 'cluster' peer relation. These allow the Vault
API and inter-unit Cluster addresses to be configured using Juju
network spaces.
