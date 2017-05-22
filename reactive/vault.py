import base64
import psycopg2

from charmhelpers.core.hookenv import (
    config,
    open_port,
    status_set,
)

from charmhelpers.core.host import (
    service_start,
    service_stop,
    write_file,
)

from charmhelpers.core.templating import (
    render,
)

from charms.reactive import (
    hook,
    is_state,
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

def ssl_available(config):
    if '' in (config['ssl-cert'], config['ssl-key']):
        return False
    return True


@when('snap.installed.vault')
@when_not('configured')
@when('db.master.available')
@when('vault.schema.created')
@when('vault.ssl.configured')
def configure_vault(psql):
    context = {
        'db_conn': psql.master,
        'disable_mlock': config()['disable-mlock'],
        'ssl_available': is_state('vault.ssl.available'),
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
    if config()['disable-mlock']:
        status_set('active', 'WARNING: DISABLE-MLOCK IS SET -- SECRETS MAY BE LEAKED')
    else:
        status_set('active', '=^_^=')


@when('config.changed.disable-mlock')
def disable_mlock_changed():
    remove_state('configured')


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
    status_set('active', 'database schema created and committed')


@when('snap.installed.vault')
@when_not('vault.ssl.configured')
def configure_ssl():
    c = config()
    if ssl_available(c):
        status_set('maintenance', 'installing SSL key and cert')
        ssl_key = base64.decodestring(c['ssl-key'].encode())
        write_file('/var/snap/vault/common/vault.key', ssl_key, perms=0o600)
        ssl_cert = base64.decodestring(c['ssl-cert'].encode())
        if c['ssl-chain']:
            ssl_cert = ssl_cert + base64.decodestring(c['ssl-chain'].encode())
        write_file('/var/snap/vault/common/vault.crt', ssl_cert, perms=0o600)
        set_state('vault.ssl.available')
    else:
        remove_state('vault.ssl.available')
    set_state('vault.ssl.configured')
    status_set('active', 'SSL key and cert installed')
    remove_state('configured')


@when('config.changed.ssl-cert')
def ssl_cert_changed():
    remove_state('vault.ssl.configured')


@when('config.changed.ssl-chain')
def ssl_chain_changed():
    remove_state('vault.ssl.configured')


@when('config.changed.ssl-key')
def ssl_key_changed():
    remove_state('vault.ssl.configured')
