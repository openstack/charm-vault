import base64
import hvac
import psycopg2
import requests
import subprocess


from charmhelpers.contrib.charmsupport.nrpe import (
    NRPE,
    add_init_service_checks,
    get_nagios_hostname,
    get_nagios_unit_name,
)

from charmhelpers.core.hookenv import (
    DEBUG,
    config,
    log,
    open_port,
    status_set,
    unit_private_ip,
    application_version_set,
    atexit,
    local_unit,
)

from charmhelpers.core.host import (
    service_restart,
    service_running,
    service_start,
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

from charms.reactive.relations import (
    endpoint_from_flag,
)

# See https://www.vaultproject.io/docs/configuration/storage/postgresql.html

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

VAULT_HEALTH_URL = '{vault_addr}/v1/sys/health'


def get_client():
    return hvac.Client(url=get_api_url())


def get_vault_health():
    response = requests.get(VAULT_HEALTH_URL.format(vault_addr=get_api_url()))
    return response.json()


def can_restart():
    safe_restart = False
    if not service_running('vault'):
        safe_restart = True
    else:
        client = get_client()
        if not client.is_initialized():
            safe_restart = True
        elif client.is_sealed():
            safe_restart = True
    log("Safe to restart: {}".format(safe_restart), level=DEBUG)
    return safe_restart


def ssl_available(config):
    if '' in (config['ssl-cert'], config['ssl-key']):
        return False
    return True


def save_etcd_client_credentials(etcd, key, cert, ca):
    """Save etcd TLS key, cert and ca to disk"""
    credentials = etcd.get_client_credentials()
    write_file(key, credentials['client_key'], perms=0o600)
    write_file(cert, credentials['client_cert'], perms=0o600)
    write_file(ca, credentials['client_ca'], perms=0o600)


def configure_vault(context):
    context['disable_mlock'] = config()['disable-mlock']
    context['ssl_available'] = is_state('vault.ssl.available')
    log("Running configure_vault", level=DEBUG)
    context['disable_mlock'] = config()['disable-mlock']
    context['ssl_available'] = is_state('vault.ssl.available')
    etcd = endpoint_from_flag('etcd.available')
    if etcd:
        log("Etcd detected, adding to context", level=DEBUG)
        context['etcd_conn'] = etcd.connection_string()
        context['etcd_tls_ca_file'] = '/var/snap/vault/common/etcd-ca.pem'
        context['etcd_tls_cert_file'] = '/var/snap/vault/common/etcd-cert.pem'
        context['etcd_tls_key_file'] = '/var/snap/vault/common/etcd.key'
        save_etcd_client_credentials(etcd,
                                     key=context['etcd_tls_key_file'],
                                     cert=context['etcd_tls_cert_file'],
                                     ca=context['etcd_tls_ca_file'])
        context['vault_api_url'] = get_api_url()
        log("Etcd detected, setting vault_api_url to {}".format(
            context['vault_api_url']))
    else:
        log("Etcd not detected", level=DEBUG)
    status_set('maintenance', 'creating vault config')
    log("Rendering vault.hcl.j2", level=DEBUG)
    render(
        'vault.hcl.j2',
        '/var/snap/vault/common/vault.hcl',
        context,
        perms=0o600)
    status_set('maintenance', 'creating vault unit file')
    render(
        'vault.service.j2',
        '/etc/systemd/system/vault.service',
        {},
        perms=0o644)
    status_set('maintenance', 'starting vault')
    if can_restart():
        service_restart('vault')
    else:
        service_start('vault')      # restart seals the vault
    status_set('maintenance', 'opening vault port')
    open_port(8200)
    set_state('configured')
    if config()['disable-mlock']:
        status_set(
            'active',
            'WARNING: DISABLE-MLOCK IS SET -- SECRETS MAY BE LEAKED')
    else:
        status_set('active', '=^_^=')


def get_api_url():
    protocol = 'http'
    port = '8200'
    ip = unit_private_ip()
    if is_state('vault.ssl.available'):
        protocol = 'https'
    return '{}://{}:{}'.format(protocol, ip, port)


@when('snap.installed.vault')
@when_not('configured')
@when('db.master.available')
@when('vault.schema.created')
@when('vault.ssl.configured')
def configure_vault_psql(psql):
    context = {
        'storage_name': 'psql',
        'psql_db_conn': psql.master,
    }
    configure_vault(context)


@when('snap.installed.vault')
@when_not('configured')
@when('shared-db.available')
@when('vault.ssl.configured')
def configure_vault_mysql(mysql):
    if local_unit() not in mysql.allowed_units():
        log("Deferring vault configuration until"
            " MySQL access is granted", level=DEBUG)
        return
    context = {
        'storage_name': 'mysql',
        'mysql_db_relation': mysql,
    }
    configure_vault(context)


@when('config.changed.disable-mlock')
def disable_mlock_changed():
    remove_state('configured')


@hook('upgrade-charm')
def upgrade_charm():
    remove_state('configured')
    remove_state('vault.nrpe.configured')
    remove_state('vault.ssl.configured')


@when('db.connected')
def request_db(pgsql):
    pgsql.set_database('vault')


@when('shared-db.connected')
def mysql_setup(database):
    """Handle the default database connection setup
    """
    db = {
        'database': 'vault',
        'username': 'vault',
    }
    database.configure(**db)


@when('db.master.available')
@when_not('vault.schema.created')
def create_vault_table(pgsql):
    status_set('maintenance', 'connecting to database')
    conn = psycopg2.connect(str(pgsql.master))
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


@when_not('db.master.available')
def database_not_ready():
    remove_state('vault.schema.created')


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

    if c['ssl-ca']:
        ssl_ca = base64.decodestring(c['ssl-ca'].encode())
        write_file('/usr/local/share/ca-certificates/vault-ca.crt',
                   ssl_ca, perms=0o644)
        subprocess.check_call(['update-ca-certificates', '--fresh'])

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


@when('config.changed.ssl-ca')
def ssl_ca_changed():
    remove_state('vault.ssl.configured')


@when_not('etcd.local.configured')
@when('etcd.available')
def etcd_setup(etcd):
    log("Detected etcd.available, removing configured", level=DEBUG)
    remove_state('configured')
    remove_state('etcd.local.unconfigured')
    set_state('etcd.local.configured')


@when_not('etcd.local.unconfigured')
@when_not('etcd.available')
def etcd_not_ready():
    log("Detected etcd_not_ready, removing configured", level=DEBUG)
    set_state('etcd.local.unconfigured')
    remove_state('etcd.local.configured')
    remove_state('configured')


@when('configured')
@when('nrpe-external-master.available')
@when_not('vault.nrpe.configured')
def update_nagios(svc):
    status_set('maintenance', 'configuring Nagios checks')
    hostname = get_nagios_hostname()
    current_unit = get_nagios_unit_name()
    nrpe = NRPE(hostname=hostname)
    add_init_service_checks(nrpe, ['vault'], current_unit)
    write_file(
        '/usr/lib/nagios/plugins/check_vault_version.py',
        open('files/nagios/check_vault_version.py', 'rb').read(),
        perms=0o755)
    nrpe.add_check(
        'vault_version',
        'Check running vault server version is same as installed snap',
        '/usr/lib/nagios/plugins/check_vault_version.py',
    )
    nrpe.write()
    set_state('vault.nrpe.configured')
    status_set('active', 'Nagios checks configured')


@when('config.changed.nagios_context')
def nagios_context_changed():
    remove_state('vault.nrpe.configured')


@when('config.changed.nagios_servicegroups')
def nagios_servicegroups_changed():
    remove_state('vault.nrpe.configured')


@when('snap.installed.vault')
def prime_assess_status():
    atexit(_assess_status)


def _assess_status():
    if service_running('vault'):
        health = get_vault_health()
        application_version_set(health.get('version'))


@when('ha.connected')
def cluster_connected(hacluster):
    """Configure HA resources in corosync"""
    vip = config('vip')
    hacluster.add_vip('vault', vip)
    hacluster.bind_resources()
