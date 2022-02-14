from unittest.mock import patch

import src.actions.actions as actions
import unit_tests.test_utils

import mock
import hvac


class TestActions(unit_tests.test_utils.CharmTestCase):

    def setUp(self):
        super(TestActions, self).setUp()
        self.patches = []
        self.patch_all()
        self.patch_object(actions, 'hookenv', name='mock_hookenv')
        self.patch_object(actions.vault, 'get_local_client')
        self.client = mock.MagicMock()
        self.get_local_client.return_value = self.client

    def test_generate_cert_not_leader(self):
        """Test when not leader, action fails"""
        self.mock_hookenv.is_leader.return_value = False

        actions.generate_cert()

        # Action should fail
        self.mock_hookenv.action_fail.assert_called_with(
            'Please run action on lead unit'
        )
        self.mock_hookenv.action_set.assert_not_called()

    @patch.object(actions, 'vault_pki')
    def test_generate_cert(self, mock_vault_pki):
        self.mock_hookenv.is_leader.return_value = True
        self.mock_hookenv.action_get.return_value = {
            'sans': 'foobar 1.2.3.4',
            'common-name': 'bazbuz',
            'ttl': '5m',
            'max-ttl': '5y',
        }
        mock_vault_pki.generate_certificate.return_value = 'shiny-cert'

        actions.generate_cert()

        # Validate the request for the cert was called
        mock_vault_pki.generate_certificate.assert_called_with(
            cert_type='server', common_name='bazbuz',
            sans=['foobar', '1.2.3.4'], ttl='5m', max_ttl='5y',
        )
        self.mock_hookenv.action_set.assert_called_with({
            'output': 'shiny-cert',
        })

    @patch.object(actions, 'vault_pki')
    def test_generate_cert_vault_failure(self, mock_vault_pki):
        """Test failure interacting with vault_pki"""
        self.mock_hookenv.is_leader.return_value = True
        self.mock_hookenv.action_get.return_value = {
            'sans': 'foobar',
            'common-name': 'bazbuz',
            'ttl': '5m',
            'max-ttl': '5y',
        }
        mock_vault_pki.generate_certificate.side_effect = \
            actions.vault.VaultNotReady(1)

        actions.generate_cert()

        # Validate the request for the cert was called
        self.mock_hookenv.action_set.assert_not_called
        self.mock_hookenv.action_fail.assert_called_with(
            'Vault is not ready (1)'
        )

    def test_get_intermediate_csrs(self):
        self.mock_hookenv.is_leader.return_value = True
        self.client.read.return_value = None
        actions.get_intermediate_csrs()
        self.mock_hookenv.leader_set.assert_called_once_with({'root-ca': None})
        self.assertFalse(self.mock_hookenv.action_fail.called)

    def test_get_intermediate_csrs_invalid_ca(self):
        self.mock_hookenv.is_leader.return_value = True
        self.client.read.side_effect = hvac.exceptions.InternalServerError(
            errors=['stored CA information not able to be parsed'])
        actions.get_intermediate_csrs()
        self.mock_hookenv.leader_set.assert_called_once_with({'root-ca': None})
        self.assertFalse(self.mock_hookenv.action_fail.called)

    def test_get_intermediate_csrs_existing_cert(self):
        self.mock_hookenv.is_leader.return_value = True
        self.mock_hookenv.action_get.return_value = {'force': False}
        self.client.read.return_value = 'a-chain'
        actions.get_intermediate_csrs()
        self.assertFalse(self.mock_hookenv.leader_set.called)
        self.mock_hookenv.action_fail.assert_called()

    def test_get_intermediate_csrs_existing_cert_force(self):
        self.mock_hookenv.is_leader.return_value = True
        self.mock_hookenv.action_get.return_value = {'force': True}
        self.client.read.return_value = 'a-chain'
        actions.get_intermediate_csrs()
        self.mock_hookenv.leader_set.assert_called_once_with({'root-ca': None})
        self.assertFalse(self.mock_hookenv.action_fail.called)

    def test_get_intermediate_csrs_non_leader(self):
        self.mock_hookenv.is_leader.return_value = False
        actions.get_intermediate_csrs()
        self.assertFalse(self.mock_hookenv.leader_set.called)
        self.mock_hookenv.action_fail.assert_called()
