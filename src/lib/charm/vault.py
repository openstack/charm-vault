import functools
import hvac

import charmhelpers.core.hookenv as hookenv
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


def setup_charm_vault_access(token):
    """Create policies and role. Grant role to charm.

    :param token: Token to use to authenticate with vault
    :type token: str
    :returns: Id of created role
    :rtype: str"""
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
