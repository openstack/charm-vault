import base64
import functools
import hvac
import psycopg2
import requests
import subprocess
import tenacity


from charmhelpers.contrib.charmsupport.nrpe import (
    NRPE,
    add_init_service_checks,
    get_nagios_hostname,
    get_nagios_unit_name,
)

from charmhelpers.core.hookenv import (
    DEBUG,
    ERROR,
    config,
    log,
    open_port,
    status_set,
    unit_private_ip,
    application_version_set,
    atexit,
    local_unit,
    network_get_primary_address,
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

from charms.reactive.flags import (
    is_flag_set,
    set_flag,
    clear_flag,
)

from charms.layer import snap

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

OPTIONAL_INTERFACES = [
    ['etcd'],
]
REQUIRED_INTERFACES = [
    ['shared-db', 'db.master']
]


def get_client():
    return hvac.Client(url=get_api_url())


@tenacity.retry(wait=tenacity.wait_exponential(multiplier=1, max=10),
                stop=tenacity.stop_after_attempt(10),
                reraise=True)
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


def validate_snap_channel(channel):
    """Validate a provided snap channel

    Any prefix is ignored ('0.10' in '0.10/stable' for example).

    :param: channel: string of the snap channel to validate
    :returns: boolean: whether provided channel is valid
    """
    channel_suffix = channel.split('/')[-1]
    if channel_suffix not in ('stable', 'candidate', 'beta', 'edge'):
        return False
    return True


@when_not('snap.installed.vault')
def snap_install():
    channel = config('channel') or 'stable'
    if validate_snap_channel(channel):
        clear_flag('snap.channel.invalid')
        snap.install('vault', channel=channel)
    else:
        set_flag('snap.channel.invalid')


@when('config.changed.channel')
@when('snap.installed.vault')
def snap_refresh():
    channel = config('channel') or 'stable'
    if validate_snap_channel(channel):
        clear_flag('snap.channel.invalid')
        snap.refresh('vault', channel=channel)
        if can_restart():
            log("Restarting vault", level=DEBUG)
            service_restart('vault')
    else:
        set_flag('snap.channel.invalid')


def configure_vault(context):
    context['disable_mlock'] = config()['disable-mlock']
    context['ssl_available'] = is_state('vault.ssl.available')
    log("Running configure_vault", level=DEBUG)
    context['disable_mlock'] = config()['disable-mlock']
    context['ssl_available'] = is_state('vault.ssl.available')

    if is_flag_set('etcd.tls.available'):
        etcd = endpoint_from_flag('etcd.available')
        log("Etcd detected, adding to context", level=DEBUG)
        context['etcd_conn'] = etcd.connection_string()
        context['etcd_tls_ca_file'] = '/var/snap/vault/common/etcd-ca.pem'
        context['etcd_tls_cert_file'] = '/var/snap/vault/common/etcd-cert.pem'
        context['etcd_tls_key_file'] = '/var/snap/vault/common/etcd.key'
        save_etcd_client_credentials(etcd,
                                     key=context['etcd_tls_key_file'],
                                     cert=context['etcd_tls_cert_file'],
                                     ca=context['etcd_tls_ca_file'])
        context['api_addr'] = get_api_url()
        context['cluster_addr'] = get_cluster_url()
        log("Etcd detected, setting api_addr to {}".format(
            context['api_addr']))
    else:
        log("Etcd not detected", level=DEBUG)
    log("Rendering vault.hcl.j2", level=DEBUG)
    render(
        'vault.hcl.j2',
        '/var/snap/vault/common/vault.hcl',
        context,
        perms=0o600)
    log("Rendering vault systemd configuation", level=DEBUG)
    render(
        'vault.service.j2',
        '/etc/systemd/system/vault.service',
        {},
        perms=0o644)
    if can_restart():
        log("Restarting vault", level=DEBUG)
        service_restart('vault')
    else:
        service_start('vault')      # restart seals the vault
    log("Opening vault port", level=DEBUG)
    open_port(8200)


def binding_address(binding):
    try:
        return network_get_primary_address(binding)
    except NotImplementedError:
        return unit_private_ip()


def get_vault_url(binding, port):
    protocol = 'http'
    ip = binding_address(binding)
    if is_state('vault.ssl.available'):
        protocol = 'https'
    return '{}://{}:{}'.format(protocol, ip, port)


get_api_url = functools.partial(get_vault_url,
                                binding='access', port=8200)
get_cluster_url = functools.partial(get_vault_url,
                                    binding='cluster', port=8201)


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


@when('config.changed.nagios_context')
def nagios_context_changed():
    remove_state('vault.nrpe.configured')


@when('config.changed.nagios_servicegroups')
def nagios_servicegroups_changed():
    remove_state('vault.nrpe.configured')


@when('ha.connected')
def cluster_connected(hacluster):
    """Configure HA resources in corosync"""
    vip = config('vip')
    dns_record = config('dns-ha-access-record')
    if vip and dns_record:
        set_flag('config.dns_vip.invalid')
        log("Unsupported configuration. vip and dns-ha cannot both be set",
            level=ERROR)
        return
    else:
        clear_flag('config.dns_vip.invalid')
    if vip:
        hacluster.add_vip('vault', vip)
    elif dns_record:
        try:
            ip = network_get_primary_address('access')
        except NotImplementedError:
            ip = unit_private_ip()
        hacluster.add_dnsha('vault', ip, dns_record, 'access')
    hacluster.bind_resources()


@when('snap.installed.vault')
def prime_assess_status():
    atexit(_assess_status)


def _assess_interface(interface, optional,
                      missing_interfaces, incomplete_interfaces):
    """Assess a named interface for presence and completeness

    Uses reactive flags 'connected' and 'available' to indicate whether
    an interface is present and complete.

    :param: interface: Name of interface to assess.
    :param: options: Boolean indicating whether interface is optional
    :param: missing_interfaces: List of missing interfaces to update
    :param: incomplete_interfaces: List of incomplete interfaces to update
    :returns: bool, bool: Tuple of booleans indicating (missing, incomplete)
    """
    log("Assessing interface {}".format(interface), level=DEBUG)
    base_name = interface.split('.')[0]
    connected = (
        is_flag_set('{}.connected'.format(interface)) or
        is_flag_set('{}.connected'.format(base_name))
    )
    missing = False
    incomplete = False
    if not connected:
        if not optional:
            missing_interfaces.append(base_name)
        missing = True
        incomplete = True
    elif connected and not is_flag_set('{}.available'.format(interface)):
        incomplete_interfaces.append(base_name)
        incomplete = True
    return (missing, incomplete)


def _assess_interface_groups(interfaces, optional,
                             missing_interfaces, incomplete_interfaces):
    """Assess the relation state of a list of interface groups

    :param: interfaces: List of interface groups
    :param: options: Boolean indicating whether interfaces are optional
    :param: missing_interfaces: List of missing interfaces to update
    :param: incomplete_interfaces: List of incomplete interfaces to update
    """
    for interface_group in interfaces:
        log("Processing interface group: {}".format(interface_group),
            level=DEBUG)
        _potentially_missing = []
        _potentially_incomplete = []
        for interface in interface_group:
            missing, incomplete = _assess_interface(
                interface=interface, optional=optional,
                missing_interfaces=_potentially_missing,
                incomplete_interfaces=_potentially_incomplete)
            if not missing and not incomplete:
                break
        else:
            # NOTE(jamespage): If an interface group has an incomplete
            #                  interface then the end user has made a
            #                  choice as to which interface to use, so
            #                  don't flag any interfaces as missing.
            if (not optional and
                    _potentially_missing and not _potentially_incomplete):
                formatted_interfaces = [
                    "'{}'".format(i) for i in _potentially_missing
                ]
                missing_interfaces.append(
                    "{} missing".format(' or '.join(formatted_interfaces))
                )

            # NOTE(jamespage): Only display interfaces as incomplete if
            #                  if they are not in the missing interfaces
            #                  list for this interface group.
            if _potentially_incomplete:
                filtered_interfaces = [
                    i for i in _potentially_incomplete
                    if i not in _potentially_missing
                ]
                formatted_interfaces = [
                    "'{}'".format(i) for i in filtered_interfaces
                ]
                incomplete_interfaces.append(
                    "{} incomplete".format(' or '.join(formatted_interfaces))
                )


def _assess_status():
    """Assess status of relations and services for local unit"""
    if is_flag_set('snap.channel.invalid'):
        status_set('blocked',
                   'Invalid snap channel '
                   'configured: {}'.format(config('channel')))
        return
    if is_flag_set('config.dns_vip.invalid'):
        status_set('blocked',
                   'vip and dns-ha-access-record configured')
        return

    health = None
    if service_running('vault'):
        health = get_vault_health()
        application_version_set(health.get('version'))

    _missing_interfaces = []
    _incomplete_interfaces = []

    _assess_interface_groups(REQUIRED_INTERFACES, optional=False,
                             missing_interfaces=_missing_interfaces,
                             incomplete_interfaces=_incomplete_interfaces)

    _assess_interface_groups(OPTIONAL_INTERFACES, optional=True,
                             missing_interfaces=_missing_interfaces,
                             incomplete_interfaces=_incomplete_interfaces)

    if _missing_interfaces or _incomplete_interfaces:
        state = 'blocked' if _missing_interfaces else 'waiting'
        status_set(state, ', '.join(_missing_interfaces +
                                    _incomplete_interfaces))
        return

    if not service_running('vault'):
        status_set('blocked', 'Vault service not running')
        return

    if not health['initialized']:
        status_set('blocked', 'Vault needs to be initialized')
        return

    if health['sealed']:
        status_set('blocked', 'Unit is sealed')
        return

    if config('disable-mlock'):
        status_set(
            'active',
            'WARNING: DISABLE-MLOCK IS SET -- SECRETS MAY BE LEAKED'
        )
    else:
        status_set(
            'active',
            'Unit is ready '
            '(active: {})'.format(str(not health['standby']).lower())
        )
