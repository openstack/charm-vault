import mock
from unittest.mock import patch

import lib.charm.vault as vault
import unit_tests.test_utils


class TestLibCharmVault(unit_tests.test_utils.CharmTestCase):

    _health_response = {
        "initialized": True,
        "sealed": False,
        "standby": False,
        "server_time_utc": 1523952750,
        "version": "0.9.0",
        "cluster_name": "vault-cluster-9dd8dd12",
        "cluster_id": "1ea3d74c-3819-fbaf-f780-bae0babc998f"
    }

    def setUp(self):
        super(TestLibCharmVault, self).setUp()
        self.obj = vault
        self.patches = []
        self.patch_all()

    def test_enable_approle_auth(self):
        client_mock = mock.MagicMock()
        client_mock.list_auth_backends.return_value = []
        vault.enable_approle_auth(client_mock)
        client_mock.enable_auth_backend.assert_called_once_with('approle')

    def test_enable_approle_auth_mounted(self):
        client_mock = mock.MagicMock()
        client_mock.list_auth_backends.return_value = ['approle/']
        vault.enable_approle_auth(client_mock)
        self.assertFalse(client_mock.enable_auth_backend.called)

    def test_create_local_charm_access_role(self):
        client_mock = mock.MagicMock()
        client_mock.get_role_id.return_value = '123'
        policies = ['policy1', 'pilicy2']
        role_id = vault.create_local_charm_access_role(client_mock, policies)
        self.assertEqual(role_id, '123')
        client_mock.create_role.assert_called_once_with(
            'local-charm-access',
            bind_secret_id='false',
            bound_cidr_list='127.0.0.1/32',
            policies=['policy1', 'pilicy2'],
            token_max_ttl='60s',
            token_ttl='60s')

    @patch.object(vault.hvac, 'Client')
    @patch.object(vault, 'get_api_url')
    @patch.object(vault, 'enable_approle_auth')
    @patch.object(vault, 'create_local_charm_access_role')
    def test_setup_charm_vault_access(self,
                                      mock_create_local_charm_access_role,
                                      mock_enable_approle_auth,
                                      mock_get_api_url,
                                      mock_Client):
        client_mock = mock.MagicMock()
        mock_Client.return_value = client_mock
        vault.setup_charm_vault_access('mytoken')
        mock_enable_approle_auth.assert_called_once_with(client_mock)
        policy_calls = [
            mock.call('local-charm-policy', mock.ANY)]
        client_mock.set_policy.assert_has_calls(policy_calls)
        mock_create_local_charm_access_role.assert_called_once_with(
            client_mock,
            policies=['local-charm-policy'])

    @patch.object(vault.hookenv, 'leader_get')
    def test_get_local_charm_access_role_id(self, mock_leader_get):
        leader_db = {'local-charm-access-id': '12'}
        mock_leader_get.side_effect = lambda x: leader_db[x]
        self.assertEqual(vault.get_local_charm_access_role_id(), '12')

    @patch.object(vault.hookenv, 'network_get_primary_address')
    @patch.object(vault.charms.reactive, 'is_state')
    def test_get_api_url_ssl(self, is_state, network_get_primary_address):
        is_state.return_value = True
        network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(vault.get_api_url(), 'https://1.2.3.4:8200')
        network_get_primary_address.assert_called_with('access')

    @patch.object(vault.hookenv, 'network_get_primary_address')
    @patch.object(vault.charms.reactive, 'is_state')
    def test_get_api_url_nossl(self, is_state, network_get_primary_address):
        is_state.return_value = False
        network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(vault.get_api_url(), 'http://1.2.3.4:8200')
        network_get_primary_address.assert_called_with('access')

    @patch.object(vault.hookenv, 'network_get_primary_address')
    @patch.object(vault.charms.reactive, 'is_state')
    def test_get_cluster_url_ssl(self, is_state, network_get_primary_address):
        is_state.return_value = True
        network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(vault.get_cluster_url(), 'https://1.2.3.4:8201')
        network_get_primary_address.assert_called_with('cluster')

    @patch.object(vault.hookenv, 'network_get_primary_address')
    @patch.object(vault.charms.reactive, 'is_state')
    def test_get_cluster_url_nossl(self, is_state,
                                   network_get_primary_address):
        is_state.return_value = False
        network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(vault.get_cluster_url(), 'http://1.2.3.4:8201')
        network_get_primary_address.assert_called_with('cluster')

    @patch.object(vault.hvac, 'Client')
    @patch.object(vault, 'get_api_url')
    def test_get_client(self, get_api_url, hvac_Client):
        get_api_url.return_value = 'http://this-unit'
        vault.get_client()
        hvac_Client.assert_called_once_with(url='http://this-unit')

    @patch.object(vault.host, 'service_running')
    def test_can_restart_vault_down(self, service_running):
        service_running.return_value = False
        self.assertTrue(vault.can_restart())

    @patch.object(vault.host, 'service_running')
    @patch.object(vault.hookenv, 'config')
    @patch.object(vault, 'get_client')
    def test_can_restart_not_initialized(self, get_client, config,
                                         service_running):
        config.return_value = False
        service_running.return_value = True
        hvac_mock = mock.MagicMock()
        hvac_mock.is_initialized.return_value = False
        get_client.return_value = hvac_mock
        self.assertTrue(vault.can_restart())
        hvac_mock.is_initialized.assert_called_once_with()

    @patch.object(vault.host, 'service_running')
    @patch.object(vault.hookenv, 'config')
    @patch.object(vault, 'get_client')
    def test_can_restart_sealed(self, get_client, config, service_running):
        config.return_value = False
        service_running.return_value = True
        hvac_mock = mock.MagicMock()
        hvac_mock.is_initialized.return_value = True
        hvac_mock.is_sealed.return_value = True
        get_client.return_value = hvac_mock
        self.assertTrue(vault.can_restart())
        hvac_mock.is_initialized.assert_called_once_with()
        hvac_mock.is_sealed.assert_called_once_with()

    @patch.object(vault.host, 'service_running')
    @patch.object(vault.hookenv, 'config')
    @patch.object(vault, 'get_client')
    def test_can_restart_unsealed(self, get_client, config, service_running):
        config.return_value = False
        service_running.return_value = True
        hvac_mock = mock.MagicMock()
        hvac_mock.is_initialized.return_value = True
        hvac_mock.is_sealed.return_value = False
        get_client.return_value = hvac_mock
        self.assertFalse(vault.can_restart())

    @patch.object(vault.host, 'service_running')
    @patch.object(vault.hookenv, 'config')
    def test_can_restart_auto_unlock(self, config, service_running):
        config.return_value = True
        service_running.return_value = True
        self.assertTrue(vault.can_restart())

    @patch.object(vault, 'get_api_url')
    @patch.object(vault, 'requests')
    def test_get_vault_health(self, requests, get_api_url):
        get_api_url.return_value = "https://vault.demo.com:8200"
        mock_response = mock.MagicMock()
        mock_response.json.return_value = self._health_response
        requests.get.return_value = mock_response
        self.assertEqual(vault.get_vault_health(),
                         self._health_response)
        requests.get.assert_called_with(
            "http://127.0.0.1:8220/v1/sys/health")
        mock_response.json.assert_called_once()

    @patch.object(vault.hookenv, 'leader_get')
    @patch.object(vault.hookenv, 'leader_set')
    @patch.object(vault, 'setup_charm_vault_access')
    @patch.object(vault.hookenv, 'is_leader')
    @patch.object(vault, 'unseal_vault')
    @patch.object(vault, 'initialize_vault')
    @patch.object(vault, 'get_vault_health')
    @patch.object(vault.hookenv, 'log')
    @patch.object(vault.host, 'service_running')
    def test_prepare_vault(self, service_running, log, get_vault_health,
                           initialize_vault, unseal_vault, is_leader,
                           setup_charm_vault_access, leader_set,
                           leader_get):
        is_leader.return_value = True
        leader_get.return_value = "[]"
        service_running.return_value = True
        get_vault_health.return_value = {
            'initialized': False,
            'sealed': True}
        vault.prepare_vault()
        initialize_vault.assert_called_once_with()
        setup_charm_vault_access.assert_called_once_with()
        unseal_vault.assert_called_once_with()
        setup_charm_vault_access.assert_called_once_with()
        leader_set.assert_called_once_with(
            {vault.CHARM_ACCESS_ROLE_ID: mock.ANY}
        )

    @patch.object(vault.hookenv, 'leader_get')
    @patch.object(vault.hookenv, 'leader_set')
    @patch.object(vault.hookenv, 'is_leader')
    @patch.object(vault, 'unseal_vault')
    @patch.object(vault, 'initialize_vault')
    @patch.object(vault, 'get_vault_health')
    @patch.object(vault.hookenv, 'log')
    @patch.object(vault.host, 'service_running')
    def test_prepare_vault_non_leader(self, service_running, log,
                                      get_vault_health, initialize_vault,
                                      unseal_vault, is_leader, leader_set,
                                      leader_get):
        leader_get.return_value = "[]"
        is_leader.return_value = False
        service_running.return_value = True
        get_vault_health.return_value = {
            'initialized': False,
            'sealed': True}
        vault.prepare_vault()
        self.assertFalse(initialize_vault.called)
        unseal_vault.assert_called_once_with()

    @patch.object(vault, 'unseal_vault')
    @patch.object(vault, 'initialize_vault')
    @patch.object(vault.hookenv, 'log')
    @patch.object(vault.host, 'service_running')
    def test_prepare_vault_svc_down(self, service_running, log,
                                    initialize_vault, unseal_vault):
        service_running.return_value = False
        vault.prepare_vault()
        self.assertFalse(initialize_vault.called)
        self.assertFalse(unseal_vault.called)

    @patch.object(vault.hookenv, 'leader_get')
    @patch.object(vault.hookenv, 'leader_set')
    @patch.object(vault, 'setup_charm_vault_access')
    @patch.object(vault.hookenv, 'is_leader')
    @patch.object(vault, 'unseal_vault')
    @patch.object(vault, 'initialize_vault')
    @patch.object(vault, 'get_vault_health')
    @patch.object(vault.hookenv, 'log')
    @patch.object(vault.host, 'service_running')
    def test_prepare_vault_initialised(self, service_running, log,
                                       get_vault_health, initialize_vault,
                                       unseal_vault, is_leader,
                                       setup_charm_vault_access,
                                       leader_set, leader_get):
        leader_get.return_value = "[]"
        is_leader.return_value = False
        service_running.return_value = True
        get_vault_health.return_value = {
            'initialized': True,
            'sealed': True}
        vault.prepare_vault()
        self.assertFalse(initialize_vault.called)
        unseal_vault.assert_called_once_with()
        leader_set.assert_not_called()

    @patch.object(vault.hookenv, 'leader_set')
    @patch.object(vault, 'setup_charm_vault_access')
    @patch.object(vault.hookenv, 'is_leader')
    @patch.object(vault, 'unseal_vault')
    @patch.object(vault, 'initialize_vault')
    @patch.object(vault, 'get_vault_health')
    @patch.object(vault.hookenv, 'log')
    @patch.object(vault.host, 'service_running')
    def test_prepare_vault_unsealed(self, service_running, log,
                                    get_vault_health, initialize_vault,
                                    unseal_vault, is_leader,
                                    setup_charm_vault_access,
                                    leader_set):
        is_leader.return_value = False
        service_running.return_value = True
        get_vault_health.return_value = {
            'initialized': True,
            'sealed': False}
        vault.prepare_vault()
        self.assertFalse(initialize_vault.called)
        self.assertFalse(unseal_vault.called)
        leader_set.assert_not_called()

    @patch.object(vault.hookenv, 'leader_set')
    @patch.object(vault, 'get_client')
    def test_initialize_vault(self, get_client, leader_set):
        hvac_mock = mock.MagicMock()
        hvac_mock.is_initialized.return_value = True
        hvac_mock.initialize.return_value = {
            'keys': ['c579a143d55423483b9076ea7bba49b63ae432bf74729f77afb4e'],
            'keys_base64': ['xX35oUPVVCNIO5B26nu6SbY65DK/dHKfd6+05y1Afcw='],
            'root_token': 'dee94df7-23a3-9bf2-cb96-e943537c2b76'
        }
        get_client.return_value = hvac_mock
        vault.initialize_vault()
        hvac_mock.initialize.assert_called_once_with(1, 1)
        leader_set.assert_called_once_with(
            keys='["c579a143d55423483b9076ea7bba49b63ae432bf74729f77afb4e"]',
            root_token='dee94df7-23a3-9bf2-cb96-e943537c2b76')

    @patch.object(vault.hookenv, 'leader_get')
    @patch.object(vault, 'get_client')
    def test_unseal_vault(self, get_client, leader_get):
        hvac_mock = mock.MagicMock()
        get_client.return_value = hvac_mock
        leader_get.return_value = {
            'root_token': 'dee94df7-23a3-9bf2-cb96-e943537c2b76',
            'keys': '["c579a143d55423483b9076ea7bba49b63ae432bf74729f77afb4e"]'
        }
        vault.unseal_vault()
        hvac_mock.unseal.assert_called_once_with(
            'c579a143d55423483b9076ea7bba49b63ae432bf74729f77afb4e')

    @patch.object(vault.hookenv, 'log')
    @patch.object(vault.host, 'service_restart')
    @patch.object(vault, 'can_restart')
    def test_opportunistic_restart(self, can_restart, service_restart, log):
        can_restart.return_value = True
        vault.opportunistic_restart()
        service_restart.assert_called_once_with('vault')

    @patch.object(vault.hookenv, 'log')
    @patch.object(vault.host, 'service_start')
    @patch.object(vault, 'can_restart')
    def test_opportunistic_restart_no_restart(self, can_restart, service_start,
                                              log):
        can_restart.return_value = False
        vault.opportunistic_restart()
        service_start.assert_called_once_with('vault')

    def test_configure_secret_backend(self):
        hvac_client = mock.MagicMock()
        hvac_client.list_secret_backends.return_value = ['secrets/']
        vault.configure_secret_backend(hvac_client, 'test')
        hvac_client.enable_secret_backend.assert_called_once_with(
            backend_type='kv',
            description=mock.ANY,
            mount_point='test',
            options={'version': 2})

    def test_configure_secret_backend_noop(self):
        hvac_client = mock.MagicMock()
        hvac_client.list_secret_backends.return_value = ['secrets/']
        vault.configure_secret_backend(hvac_client, 'secrets')
        hvac_client.enable_secret_backend.assert_not_called()

    def test_generate_role_secret_id(self):
        hvac_client = mock.MagicMock()
        hvac_client.write.return_value = {'wrap_info': {'token': 'foo'}}
        self.assertEqual(
            vault.generate_role_secret_id(hvac_client,
                                          'testrole',
                                          '10.5.10.10/32'),
            'foo'
        )
        hvac_client.write.assert_called_with(
            'auth/approle/role/testrole/secret-id',
            wrap_ttl='1h', cidr_list='10.5.10.10/32'
        )

    def test_configure_policy(self):
        hvac_client = mock.MagicMock()
        vault.configure_policy(hvac_client, 'test-policy', 'test-hcl')
        hvac_client.set_policy.assert_called_once_with(
            'test-policy',
            'test-hcl',
        )

    def test_configure_approle(self):
        hvac_client = mock.MagicMock()
        hvac_client.get_role_id.return_value = 'some-UUID'
        self.assertEqual(
            vault.configure_approle(hvac_client,
                                    'test-role',
                                    '10.5.0.20/32',
                                    ['test-policy']),
            'some-UUID'
        )
        hvac_client.create_role.assert_called_once_with(
            'test-role',
            token_ttl='60s',
            token_max_ttl='60s',
            policies=['test-policy'],
            bind_secret_id='true',
            bound_cidr_list='10.5.0.20/32'
        )
        hvac_client.get_role_id.assert_called_with('test-role')
