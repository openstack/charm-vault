#!/usr/local/sbin/charm-env python3
# Copyright 2018 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

# Load modules from $CHARM_DIR/lib
sys.path.append('lib')

from charms.layer import basic
basic.bootstrap_charm_deps()
basic.init_config_states()

import charmhelpers.core.hookenv as hookenv

import charm.vault as vault

import charms.reactive


def authorize_charm_action(*args):
    """Create a role allowing the charm to perform certain vault actions.
    """
    if not hookenv.is_leader():
        hookenv.action_fail('Please run action on lead unit')
    action_config = hookenv.action_get()
    role_id = vault.setup_charm_vault_access(action_config['token'])
    hookenv.leader_set({vault.CHARM_ACCESS_ROLE_ID: role_id})

# Actions to function mapping, to allow for illegal python action names that
# can map to a python function.
ACTIONS = {
    "authorize-charm": authorize_charm_action,
}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            hookenv.action_fail(str(e))
        else:
            charms.reactive.main()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
