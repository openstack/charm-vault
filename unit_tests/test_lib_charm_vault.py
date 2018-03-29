import mock
from unittest.mock import patch

import lib.charm.vault as vault
import unit_tests.test_utils


class TestLibCharmVault(unit_tests.test_utils.CharmTestCase):

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
