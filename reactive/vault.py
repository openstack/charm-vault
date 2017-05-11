import psycopg2

from charmhelpers.core.hookenv import (
    config,
    open_port,
    status_set,
)

from charmhelpers.core.host import (
    service_start,
    service_stop,
)

from charmhelpers.core.templating import (
    render,
)

from charms.reactive import (
    hook,
    remove_state,
    set_state,
    when,
    when_not,
)

# as per https://www.vaultproject.io/docs/configuration/storage/postgresql.html

VAULT_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS vault_kv_store (
  parent_path TEXT COLLATE "C" NOT NULL,
  path        TEXT COLLATE "C",
  key         TEXT COLLATE "C",
  value       BYTEA,
  CONSTRAINT pkey PRIMARY KEY (path, key)
);
"""

VAULT_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS parent_path_idx ON vault_kv_store (parent_path);
"""

@when('snap.installed.vault')
@when_not('configured')
@when('db.master.available')
@when('vault.schema.created')
def configure_vault(psql):
    context = {
        'db_conn': psql.master,
    }
    status_set('maintenance', 'creating vault config')
    render('vault.hcl.j2', '/var/snap/vault/common/vault.hcl', context, perms=0o644)
    status_set('maintenance', 'creating vault unit file')
    render('vault.service.j2', '/etc/systemd/system/vault.service', {}, perms=0o644)
    status_set('maintenance', 'starting vault')
    service_start('vault')      # restart seals the vault
    status_set('maintenance', 'opening vault port')
    open_port(8200)
    set_state('configured')
    status_set('active', '=^_^=')

@hook('upgrade-charm')
def upgrade_charm():
    remove_state('configured')


@when('db.connected')
def request_db(pgsql):
    pgsql.set_database('vault')


@when('db.master.available')
@when_not('vault.schema.created')
def create_vault_table(pgsql):
    status_set('maintenance', 'connecting to database')
    conn = psycopg2.connect(pgsql.master)
    cur = conn.cursor()
    status_set('maintenance', 'creating vault table')
    cur.execute(VAULT_TABLE_DDL)
    status_set('maintenance', 'creating vault index')
    cur.execute(VAULT_INDEX_DDL)
    status_set('maintenance', 'committing database schema')
    conn.commit()
    cur.close()
    conn.close()
    set_state('vault.schema.created')
