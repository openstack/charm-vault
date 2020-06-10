import mock
from unittest.mock import patch

import hvac

import lib.charm.vault_pki as vault_pki
import unit_tests.test_utils


class TestLibCharmVaultPKI(unit_tests.test_utils.CharmTestCase):

    def setUp(self):
        super(TestLibCharmVaultPKI, self).setUp()
        self.obj = vault_pki
        self.patches = []
        self.patch_all()

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = False
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend',
            ttl=42, max_ttl=42)
        client_mock.enable_secret_backend.assert_called_once_with(
            backend_type='pki',
            config={
                'default_lease_ttl': 42,
                'max_lease_ttl': 42},
            description='Charm created PKI backend',
            mount_point='my_backend')

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend_default_ttl(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = False
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend')
        client_mock.enable_secret_backend.assert_called_once_with(
            backend_type='pki',
            config={
                'default_lease_ttl': '8759h',
                'max_lease_ttl': '87600h'},
            description='Charm created PKI backend',
            mount_point='my_backend')

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend_noop(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = True
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend',
            ttl=42)
        self.assertFalse(client_mock.enable_secret_backend.called)

    def test_is_ca_ready(self):
        client_mock = mock.MagicMock()
        vault_pki.is_ca_ready(client_mock, 'my_backend', 'local')
        client_mock.read.assert_called_once_with('my_backend/roles/local')

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_chain(self, get_local_client):
        client_mock = mock.MagicMock()
        client_mock.read.return_value = {
            'data': {
                'certificate': 'somecert'}}
        get_local_client.return_value = client_mock
        self.assertEqual(
            vault_pki.get_chain('my_backend'),
            'somecert')
        client_mock.read.assert_called_once_with(
            'my_backend/cert/ca_chain')

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_chain_default_pki(self, get_local_client):
        client_mock = mock.MagicMock()
        client_mock.read.return_value = {
            'data': {
                'certificate': 'somecert'}}
        get_local_client.return_value = client_mock
        self.assertEqual(
            vault_pki.get_chain(),
            'somecert')
        client_mock.read.assert_called_once_with(
            'charm-pki-local/cert/ca_chain')

    @patch.object(vault_pki.hookenv, 'leader_get')
    def test_get_ca(self, leader_get):
        leader_get.return_value = 'ROOTCA'
        self.assertEqual(vault_pki.get_ca(), 'ROOTCA')

    @patch.object(vault_pki, 'sort_sans')
    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_generate_certificate(self, get_local_client,
                                  configure_pki_backend,
                                  is_ca_ready,
                                  sort_sans):
        client_mock = mock.MagicMock()
        client_mock.write.return_value = {'data': 'data'}
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        sort_sans.side_effect = lambda l: (l[0], l[1])
        write_calls = [
            mock.call(
                'charm-pki-local/issue/local',
                common_name='example.com',
            ),
            mock.call(
                'charm-pki-local/issue/local',
                common_name='example.com',
                ip_sans='ip1',
                alt_names='alt1',
            ),
            mock.call(
                'charm-pki-local/issue/local-client',
                common_name='example.com',
                ip_sans='ip1,ip2',
                alt_names='alt1,alt2',
            ),
        ]
        vault_pki.generate_certificate('server',
                                       'example.com',
                                       ([], []),
                                       ttl='3456h', max_ttl='3456h')
        vault_pki.generate_certificate('server',
                                       'example.com',
                                       (['ip1'], ['alt1']),
                                       ttl='3456h', max_ttl='3456h')
        vault_pki.generate_certificate('client',
                                       'example.com',
                                       (['ip1', 'ip2'], ['alt1', 'alt2']),
                                       ttl='3456h', max_ttl='3456h')
        client_mock.write.assert_has_calls(write_calls)

    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_generate_certificate_not_ready(self, get_local_client,
                                            configure_pki_backend,
                                            is_ca_ready):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = False
        with self.assertRaises(vault_pki.vault.VaultNotReady):
            vault_pki.generate_certificate('server', 'exmaple.com', [],
                                           ttl='3456h', max_ttl='3456h')

    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_generate_certificate_invalid_type(self, get_local_client,
                                               configure_pki_backend,
                                               is_ca_ready):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        with self.assertRaises(vault_pki.vault.VaultInvalidRequest):
            vault_pki.generate_certificate('unknown', 'exmaple.com', [],
                                           '3456h', '3456h')

    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_generate_certificate_invalid_request(self, get_local_client,
                                                  configure_pki_backend,
                                                  is_ca_ready):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        client_mock.write.side_effect = hvac.exceptions.InvalidRequest
        with self.assertRaises(vault_pki.vault.VaultInvalidRequest):
            vault_pki.generate_certificate('server', 'exmaple.com', [],
                                           ttl='3456h', max_ttl='3456h')

    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr(self, get_local_client, configure_pki_backend):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.write.return_value = {
            'data': {
                'csr': 'somecert'}}
        self.assertEqual(vault_pki.get_csr(), 'somecert')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/intermediate/generate/internal',
            common_name=('Vault Intermediate Certificate Authority'
                         ' (charm-pki-local)'),
            ttl='87599h')

    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr_explicit(self, get_local_client, configure_pki_backend):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.write.return_value = {
            'data': {
                'csr': 'somecert'}}
        self.assertEqual(
            vault_pki.get_csr(
                ttl='2h',
                country='GB',
                locality='here',
                province='Kent',
                organizational_unit='My Department',
                organization='My Company'),
            'somecert')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/intermediate/generate/internal',
            common_name=('Vault Intermediate Certificate Authority '
                         '(charm-pki-local)'),
            country='GB',
            locality='here',
            organization='My Company',
            ou='My Department',
            province='Kent',
            ttl='2h')

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr(self, get_local_client, get_access_address):
        get_access_address.return_value = 'https://vault.local:8200'
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        local_url = 'https://vault.local:8200/v1/charm-pki-local'
        write_calls = [
            mock.call(
                'charm-pki-local/config/urls',
                issuing_certificates='{}/ca'.format(local_url),
                crl_distribution_points='{}/crl'.format(local_url)),
            mock.call(
                'charm-pki-local/roles/local',
                allowed_domains='exmaple.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=True,
                client_flag=True),
            mock.call(
                'charm-pki-local/roles/local-client',
                allowed_domains='exmaple.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=False,
                client_flag=True),
        ]
        vault_pki.upload_signed_csr('MYPEM', 'exmaple.com')
        client_mock._post.assert_called_once_with(
            'v1/charm-pki-local/intermediate/set-signed',
            json={'certificate': 'MYPEM'})
        client_mock.write.assert_has_calls(write_calls)

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr_explicit(self, get_local_client,
                                        get_access_address):
        client_mock = mock.MagicMock()
        get_access_address.return_value = 'https://vault.local:8200'
        get_local_client.return_value = client_mock
        local_url = 'https://vault.local:8200/v1/charm-pki-local'
        write_calls = [
            mock.call(
                'charm-pki-local/config/urls',
                issuing_certificates='{}/ca'.format(local_url),
                crl_distribution_points='{}/crl'.format(local_url)),
            mock.call(
                'charm-pki-local/roles/local',
                allowed_domains='exmaple.com',
                allow_subdomains=False,
                enforce_hostnames=True,
                allow_any_name=False,
                max_ttl='42h',
                server_flag=True,
                client_flag=True),
            mock.call(
                'charm-pki-local/roles/local-client',
                allowed_domains='exmaple.com',
                allow_subdomains=False,
                enforce_hostnames=True,
                allow_any_name=False,
                max_ttl='42h',
                server_flag=False,
                client_flag=True),
        ]
        vault_pki.upload_signed_csr(
            'MYPEM',
            'exmaple.com',
            allow_subdomains=False,
            enforce_hostnames=True,
            allow_any_name=False,
            max_ttl='42h')
        client_mock._post.assert_called_once_with(
            'v1/charm-pki-local/intermediate/set-signed',
            json={'certificate': 'MYPEM'})
        client_mock.write.assert_has_calls(write_calls)

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_generate_root_ca(self,
                              get_local_client,
                              configure_pki_backend,
                              is_ca_ready,
                              get_access_address):
        mock_client = get_local_client.return_value
        mock_client.write.return_value = {'data': {'certificate': 'cert'}}
        is_ca_ready.return_value = False
        get_access_address.return_value = 'addr'
        rv = vault_pki.generate_root_ca(ttl='0h',
                                        allow_any_name=True,
                                        allowed_domains='domains',
                                        allow_bare_domains=True,
                                        allow_subdomains=True,
                                        allow_glob_domains=False,
                                        enforce_hostnames=True,
                                        max_ttl='0h')
        self.assertEqual(rv, 'cert')
        mock_client.write.assert_has_calls([
            mock.call('charm-pki-local/root/generate/internal',
                      common_name='Vault Root Certificate Authority '
                                  '(charm-pki-local)',
                      ttl='0h'),
            mock.call('charm-pki-local/config/urls',
                      issuing_certificates='addr/v1/charm-pki-local/ca',
                      crl_distribution_points='addr/v1/charm-pki-local/crl'),
            mock.call('charm-pki-local/roles/local',
                      allow_any_name=True,
                      allowed_domains='domains',
                      allow_bare_domains=True,
                      allow_subdomains=True,
                      allow_glob_domains=False,
                      enforce_hostnames=True,
                      max_ttl='0h',
                      server_flag=True,
                      client_flag=True),
            mock.call('charm-pki-local/roles/local-client',
                      allow_any_name=True,
                      allowed_domains='domains',
                      allow_bare_domains=True,
                      allow_subdomains=True,
                      allow_glob_domains=False,
                      enforce_hostnames=True,
                      max_ttl='0h',
                      server_flag=False,
                      client_flag=True),
        ])

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_generate_root_ca_already_init(self,
                                           get_local_client,
                                           configure_pki_backend,
                                           is_ca_ready,
                                           get_access_address):
        is_ca_ready.return_value = True
        with self.assertRaises(vault_pki.vault.VaultError):
            vault_pki.generate_root_ca()

    def test_sort_sans(self):
        self.assertEqual(
            vault_pki.sort_sans([
                '10.0.0.10',
                '10.0.0.20',
                '10.0.0.10',
                'admin.local',
                'admin.local',
                'public.local']),
            (['10.0.0.10', '10.0.0.20'], ['admin.local', 'public.local']))

    @patch.object(vault_pki.vault, 'get_local_client')
    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_tune_secret_backend(self,
                                 is_backend_mounted,
                                 get_local_client):
        is_backend_mounted.return_value = True
        mock_client = mock.MagicMock()
        get_local_client.return_value = mock_client
        vault_pki.tune_pki_backend(ttl='3456h', max_ttl='3456h')
        is_backend_mounted.assert_called_with(mock_client,
                                              vault_pki.CHARM_PKI_MP)
        mock_client.tune_secret_backend.assert_called_with(
            backend_type='pki',
            mount_point=vault_pki.CHARM_PKI_MP,
            max_lease_ttl='3456h',
            default_lease_ttl='3456h'
        )

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_update_roles(self, get_local_client):
        mock_client = mock.MagicMock()
        get_local_client.return_value = mock_client
        mock_client.read.return_value = {
            'data': {
                'allow_any_name': True,
                'allowed_domains': 'domains',
                'allow_bare_domains': True,
                'allow_subdomains': True,
                'allow_glob_domains': False,
                'enforce_hostnames': True,
                'max_ttl': '10h',
                'server_flag': True,
                'client_flag': True,
            }
        }
        vault_pki.update_roles(max_ttl='20h')
        mock_client.write.assert_has_calls([
            mock.call('{}/roles/{}'.format(
                vault_pki.CHARM_PKI_MP, vault_pki.CHARM_PKI_ROLE),
                allow_any_name=True,
                allowed_domains='domains',
                allow_bare_domains=True,
                allow_subdomains=True,
                allow_glob_domains=False,
                enforce_hostnames=True,
                max_ttl='20h',
                server_flag=True,
                client_flag=True),
            mock.call('{}/roles/{}'.format(
                vault_pki.CHARM_PKI_MP, vault_pki.CHARM_PKI_ROLE_CLIENT),
                allow_any_name=True,
                allowed_domains='domains',
                allow_bare_domains=True,
                allow_subdomains=True,
                allow_glob_domains=False,
                enforce_hostnames=True,
                max_ttl='20h',
                server_flag=False,
                client_flag=True),
        ])
