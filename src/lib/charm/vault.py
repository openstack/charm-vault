import functools
import json
import requests

import hvac
import tenacity

import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as host
import charms.reactive

CHARM_ACCESS_ROLE = 'local-charm-access'
CHARM_ACCESS_ROLE_ID = 'local-charm-access-id'
CHARM_POLICY_NAME = 'local-charm-policy'
CHARM_POLICY = """
# Allow managment of policies starting with charm- prefix
path "sys/policy/charm-*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Allow discovery of all policies
path "sys/policy/" {
  capabilities = ["list"]
}

# Allow management of approle's with charm- prefix
path "auth/approle/role/charm-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow discovery of approles
path "auth/approle/role" {
  capabilities = ["read"]
}
path "auth/approle/role/" {
  capabilities = ["list"]
}

# Allow charm- prefixes secrets backends to be mounted and managed
path "sys/mounts/charm-*" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

# Allow discovery of secrets backends
path "sys/mounts" {
  capabilities = ["read"]
}
path "sys/mounts/" {
  capabilities = ["list"]
}"""

VAULT_HEALTH_URL = '{vault_addr}/v1/sys/health'


def binding_address(binding):
    try:
        return hookenv.network_get_primary_address(binding)
    except NotImplementedError:
        return hookenv.unit_private_ip()


def get_vault_url(binding, port):
    protocol = 'http'
    ip = binding_address(binding)
    if charms.reactive.is_state('vault.ssl.available'):
        protocol = 'https'
    return '{}://{}:{}'.format(protocol, ip, port)


get_api_url = functools.partial(get_vault_url,
                                binding='access', port=8200)
get_cluster_url = functools.partial(get_vault_url,
                                    binding='cluster', port=8201)


def enable_approle_auth(client):
    """Enable the approle auth method within vault

    :param client: Vault client
    :type client: hvac.Client"""
    if 'approle/' not in client.list_auth_backends():
        client.enable_auth_backend('approle')


def create_local_charm_access_role(client, policies):
    """Create a role within vault associating the supplied policies

    :param client: Vault client
    :type client: hvac.Client
    :param policies: List of policy names
    :type policies: [str, str, ...]
    :returns: Id of created role
    :rtype: str"""
    client.create_role(
        CHARM_ACCESS_ROLE,
        token_ttl='60s',
        token_max_ttl='60s',
        policies=policies,
        bind_secret_id='false',
        bound_cidr_list='127.0.0.1/32')
    return client.get_role_id(CHARM_ACCESS_ROLE)


def setup_charm_vault_access(token=None):
    """Create policies and role. Grant role to charm.

    :param token: Token to use to authenticate with vault
    :type token: str
    :returns: Id of created role
    :rtype: str"""
    if not token:
        token = hookenv.leader_get('token')
    vault_url = get_api_url()
    client = hvac.Client(
        url=vault_url,
        token=token)
    enable_approle_auth(client)
    policies = [CHARM_POLICY_NAME]
    client.set_policy(CHARM_POLICY_NAME, CHARM_POLICY)
    return create_local_charm_access_role(client, policies=policies)


def get_local_charm_access_role_id():
    """Retrieve the id of the role for local charm access

    :returns: Id of local charm access role
    :rtype: str
    """
    return hookenv.leader_get(CHARM_ACCESS_ROLE_ID)


def get_client():
    """Provide a client for talking to the vault api

    :returns: vault client
    :rtype: hvac.Client
    """
    return hvac.Client(url=get_api_url())


@tenacity.retry(wait=tenacity.wait_exponential(multiplier=1, max=10),
                stop=tenacity.stop_after_attempt(10),
                reraise=True)
def get_vault_health():
    """Query vault to retrieve health

    :returns: Vault health
    :rtype: dict
    """
    response = requests.get(
        VAULT_HEALTH_URL.format(vault_addr=get_api_url()))
    return response.json()


def opportunistic_restart():
    """Restart vault if possible"""
    if can_restart():
        hookenv.log("Restarting vault", level=hookenv.DEBUG)
        host.service_restart('vault')
    else:
        hookenv.log("Starting vault", level=hookenv.DEBUG)
        host.service_start('vault')


def prepare_vault():
    """Setup vault as much as possible

    Attempt to prepare vault for operation. Where possible, initialise, unseal
    and create role for local charm access to vault.
    """
    if not host.service_running('vault'):
        hookenv.log("Defering unlock vault not running ", level=hookenv.DEBUG)
        return
    vault_health = get_vault_health()
    if not vault_health['initialized'] and hookenv.is_leader():
        initialize_vault()
    if vault_health['sealed']:
        unseal_vault()
    if hookenv.is_leader():
        setup_charm_vault_access()


def initialize_vault(shares=1, threshold=1):
    """Initialise vault

    Initialise vault and store the resulting key(s) and token in the leader db.
    :param shares: Number of shares to create
    :type shares: int
    :param threshold: Minimum number of shares needed to unlock
    :type threshold: int
    """
    client = get_client()
    result = client.initialize(shares, threshold)
    client.token = result['root_token']
    hookenv.leader_set(
        root_token=result['root_token'],
        keys=json.dumps(result['keys']))


def unseal_vault(keys=None):
    """Unseal vault with provided keys. If no keys are provided retrieve from
    leader db"""
    client = get_client()
    if not keys:
        keys = json.loads(hookenv.leader_get()['keys'])
    for key in keys:
        client.unseal(key)


def can_restart():
    """Check if vault can be restarted

    :returns: Can vault be restarted
    :rtype: bool
    """
    safe_restart = False
    if not host.service_running('vault'):
        safe_restart = True
    elif hookenv.config('auto-unlock'):
        safe_restart = True
    else:
        client = get_client()
        if not client.is_initialized():
            safe_restart = True
        elif client.is_sealed():
            safe_restart = True
    hookenv.log(
        "Safe to restart: {}".format(safe_restart),
        level=hookenv.DEBUG)
    return safe_restart
