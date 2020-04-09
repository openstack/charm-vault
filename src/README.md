# Overview

[Vault][vault-upstream] secures, stores, and controls access to tokens,
passwords, certificates, API keys, and other secrets in modern computing. Vault
handles leasing, key revocation, key rolling, and auditing. Through a unified
API, users can access an encrypted key/value store and network
encryption-as-a-service, or generate AWS IAM/STS credentials, SQL/NoSQL
databases, X.509 certificates, SSH credentials, and more.

The charm installs Vault from a [snap][snap-upstream].

# Usage

## Configuration

This section covers common configuration options. See file `config.yaml` for
the full list of options, along with their descriptions and default values.

#### `channel`

The `channel` option sets the snap channel to use for deployment (e.g.
'latest/edge'). The default value is 'latest/stable'.

## Deployment

Deploy a single vault unit in this way:

    juju deploy vault

Then relate it to either MySQL or PostgreSQL.

For MySQL 5:

    juju add-relation vault:shared-db percona-cluster:shared-db

For MySQL 8:

    juju deploy mysql-router vault-mysql-router
    juju add-relation vault-mysql-router:db-router mysql-innodb-cluster:db-router
    juju add-relation vault-mysql-router:shared-db vault:shared-db

For PostgreSQL, its version and the underlying machine series must be
compatible (e.g. 9.5/xenial or 10/bionic). Use configuration option `version`
with the [postgresql][postgresql-charm] charm to select a version. For example,
on Xenial:

    juju deploy --config version=9.5 --series xenial postgresql
    juju add-relation vault:db postgresql:db

## Post-deployment tasks

Once the vault application is deployed the following tasks must be performed:

* Vault initialisation
* Unsealing of Vault
* Charm authorisation

These tasks are covered in appendix [Vault][cdg-app-vault] of the
[OpenStack Charms Deployment Guide][cdg].

## Actions

This section lists Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis.

* `authorize-charm`
* `disable-pki`
* `generate-root-ca`
* `get-csr`
* `get-root-ca`
* `pause`
* `refresh-secrets`
* `reissue-certificates`
* `resume`
* `upload-signed-csr`

To display action descriptions run `juju actions vault`. If the charm
is not deployed then see file ``actions.yaml``.

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-vault].

For general charm questions refer to the [OpenStack Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/
[lp-bugs-charm-vault]: https://bugs.launchpad.net/vault-charm/+filebug
[juju-docs-actions]: https://jaas.ai/docs/actions
[snap-upstream]: https://snapcraft.io/
[vault-charm]: https://jaas.ai/vault
[postgresql-charm]: https://jaas.ai/postgresql
[vault-upstream]: https://www.vaultproject.io/docs/what-is-vault/
[cdg-app-vault]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-vault.html
[cdg-app-ha-vault]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#vault
