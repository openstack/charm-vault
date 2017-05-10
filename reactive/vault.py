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
    set_state('configured')

@hook('upgrade-charm')
def upgrade_charm():
    remove_state('configured')
