from charmhelpers.core.hookenv import (
    config,
    open_port,
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


@when('snap.installed.vault')
@when_not('configured')
@when('db.master.available')
def configure_vault(psql):
    context = {
        'db_conn': psql.master,
    }
    render('vault.hcl.j2', '/var/snap/vault/common/vault.hcl', context, perms=0o644)
    render('vault.service.j2', '/etc/systemd/system/vault.service', {}, perms=0o644)
    service_start('vault')      # restart seals the vault
    open_port(8200)
    set_state('configured')


@hook('upgrade-charm')
def upgrade_charm():
    remove_state('configured')


@when('db.connected')
def request_db(pgsql):
    pgsql.set_database('vault')

