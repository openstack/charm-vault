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

This section covers common and/or important configuration options. See file
`config.yaml` for the full list of options, along with their descriptions and
default values. See the [Juju documentation][juju-docs-config-apps] for details
on configuring applications.

#### `channel`

The `channel` option sets the snap channel to use for deployment (e.g.
'latest/edge'). The default value is 'latest/stable'.

## Deployment

Vault is often containerised. Here a single unit is deployed to a new
container on machine '1':

    juju deploy --to lxd:1 vault

> **Note**: When Vault is deployed to metal or to a KVM guest the charm will
  enable mlock (memory locking) to prevent secrets from being saved to disk via
  page swapping. The mlock feature is not available to containers.

Now connect the vault application to an existing database. This can be the
cloud's database or a separate, dedicated database.

Some database applications are influenced by the series. Prior to focal
[percona-cluster][percona-cluster-charm] is used, otherwise it is replaced by
[mysql-innodb-cluster][mysql-innodb-cluster-charm]. The
[postgresql][postgresql-charm] application can also be used.

For percona-cluster:

    juju add-relation vault:shared-db percona-cluster:shared-db

For mysql-innodb-cluster:

    juju deploy mysql-router vault-mysql-router
    juju add-relation vault-mysql-router:db-router mysql-innodb-cluster:db-router
    juju add-relation vault-mysql-router:shared-db vault:shared-db

For postgresql:

    juju add-relation vault:db postgresql:db

> **Note**: For PostgreSQL, its version and the underlying machine series must
  be compatible (e.g. 9.5/xenial or 10/bionic). The postgresql charm's
  configuration option `version` is used to select a version at deploy time.

## TLS

Communication with the Vault REST API can be encrypted with TLS. This is
configured with the following charm configuration options:

* `ssl-ca`
* `ssl-cert`
* `ssl-chain`
* `ssl-key`

> **Note**: The process of encrypting the Vault API is separate from that of
  using Vault to manage the encryption of OpenStack API services. See
  [Managing TLS certificates with Vault][cdg-vault-certs] in the
  [OpenStack Charms Deployment Guide][cdg] for details.

## Post-deployment tasks

Once the vault application is deployed the following tasks must be performed:

* Vault initialisation
* Unsealing of Vault
* Charm authorisation

These are covered in the [Vault][cdg-vault] section of the
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

To display action descriptions run `juju actions vault`. If the charm is not
deployed then see file `actions.yaml`.

## High availability

When more than one unit is deployed with the [hacluster][hacluster-charm]
application the charm will bring up an HA active/active cluster.

There are two mutually exclusive high availability options: using virtual IP(s)
or DNS. In both cases the hacluster subordinate charm is used to provide the
Corosync and Pacemaker backend HA functionality.

In addition, HA Vault will require the etcd and easyrsa applications.

See [OpenStack high availability][cdg-ha-apps] in the [OpenStack Charms
Deployment Guide][cdg] for details.

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-vault].

For general charm questions refer to the [OpenStack Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/
[lp-bugs-charm-vault]: https://bugs.launchpad.net/vault-charm/+filebug
[juju-docs-actions]: https://jaas.ai/docs/actions
[snap-upstream]: https://snapcraft.io/
[hacluster-charm]: https://jaas.ai/hacluster
[vault-charm]: https://jaas.ai/vault
[percona-cluster-charm]: https://jaas.ai/percona-cluster
[mysql-innodb-cluster-charm]: https://jaas.ai/mysql-innodb-cluster
[postgresql-charm]: https://jaas.ai/postgresql
[vault-upstream]: https://www.vaultproject.io/docs/what-is-vault/
[cdg-vault]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-vault.html
[cdg-vault-certs]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-certificate-management.html
[cdg-ha-apps]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#ha-applications
[juju-docs-config-apps]: https://juju.is/docs/configuring-applications
