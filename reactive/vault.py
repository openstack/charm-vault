from charmhelpers.core.hookenv import (
    open_port,
)

from charmhelpers.core.host import (
    service_stop,
    service_restart,
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
def configure_vault():
    render('vault.hcl.j2', '/var/snap/vault/common/vault.hcl', {}, perms=0o644)
    render('vault.service.j2', '/etc/systemd/system/vault.service', {}, perms=0o644)
    service_restart('vault')
    open_port(8200)
    set_state('configured')


@hook('upgrade-charm')
def upgrade_charm():
    remove_state('configured')
