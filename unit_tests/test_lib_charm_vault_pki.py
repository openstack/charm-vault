import collections
import json
from unittest import mock
from unittest.mock import call, patch, MagicMock

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
            vault_pki.generate_certificate('server', 'example.com', [],
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
            vault_pki.generate_certificate('unknown', 'example.com', [],
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
            vault_pki.generate_certificate('server', 'example.com', [],
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
                allowed_domains='example.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=True,
                client_flag=True),
            mock.call(
                'charm-pki-local/roles/local-client',
                allowed_domains='example.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=False,
                client_flag=True),
        ]
        vault_pki.upload_signed_csr('MYPEM', 'example.com')
        client_mock._post.assert_called_once_with(
            'v1/charm-pki-local/intermediate/set-signed',
            json={'certificate': 'MYPEM'})
        client_mock.write.assert_has_calls(write_calls)

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr_ipv4(
        self, get_local_client, get_access_address
    ):
        get_access_address.return_value = 'https://127.0.0.1:8200'
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        local_url = 'https://127.0.0.1:8200/v1/charm-pki-local'
        write_calls = [
            mock.call(
                'charm-pki-local/config/urls',
                issuing_certificates='{}/ca'.format(local_url),
                crl_distribution_points='{}/crl'.format(local_url)),
            mock.call(
                'charm-pki-local/roles/local',
                allowed_domains='example.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=True,
                client_flag=True),
            mock.call(
                'charm-pki-local/roles/local-client',
                allowed_domains='example.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=False,
                client_flag=True),
        ]
        vault_pki.upload_signed_csr('MYPEM', 'example.com')
        client_mock._post.assert_called_once_with(
            'v1/charm-pki-local/intermediate/set-signed',
            json={'certificate': 'MYPEM'})
        client_mock.write.assert_has_calls(write_calls)

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr_ipv6(
        self, get_local_client, get_access_address
    ):
        get_access_address.return_value = 'https://[::1]:8200'
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        local_url = 'https://[::1]:8200/v1/charm-pki-local'
        write_calls = [
            mock.call(
                'charm-pki-local/config/urls',
                issuing_certificates='{}/ca'.format(local_url),
                crl_distribution_points='{}/crl'.format(local_url)),
            mock.call(
                'charm-pki-local/roles/local',
                allowed_domains='example.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=True,
                client_flag=True),
            mock.call(
                'charm-pki-local/roles/local-client',
                allowed_domains='example.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h',
                server_flag=False,
                client_flag=True),
        ]
        vault_pki.upload_signed_csr('MYPEM', 'example.com')
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
                allowed_domains='example.com',
                allow_subdomains=False,
                enforce_hostnames=True,
                allow_any_name=False,
                max_ttl='42h',
                server_flag=True,
                client_flag=True),
            mock.call(
                'charm-pki-local/roles/local-client',
                allowed_domains='example.com',
                allow_subdomains=False,
                enforce_hostnames=True,
                allow_any_name=False,
                max_ttl='42h',
                server_flag=False,
                client_flag=True),
        ]
        vault_pki.upload_signed_csr(
            'MYPEM',
            'example.com',
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

    @patch.object(vault_pki, 'get_serial_number_from_cert')
    def test_is_cert_from_vault_no_serial(
        self,
        mock_get_serial_number_from_cert,
    ):
        mock_get_serial_number_from_cert.return_value = None
        self.assertFalse(vault_pki.is_cert_from_vault('the-cert'))
        mock_get_serial_number_from_cert.assert_called_once_with('the-cert')

    @patch.object(vault_pki, 'get_serial_number_from_cert')
    @patch.object(vault_pki.vault, 'get_local_client')
    @patch.object(vault_pki.hookenv, 'log')
    def test_is_cert_from_vault_not_from_vault(
        self,
        mock_log,
        mock_get_local_client,
        mock_get_serial_number_from_cert,
    ):
        mock_get_serial_number_from_cert.return_value = "1234567890"
        mock_client = MagicMock()
        mock_get_local_client.return_value = mock_client
        mock_client.secrets.pki.list_certificates.return_value = {
            "data": {
                "keys": []
            }
        }

        self.assertFalse(
            vault_pki.is_cert_from_vault('the-cert', name='a-name'))
        mock_get_serial_number_from_cert.assert_called_once_with('the-cert')
        mock_client.secrets.pki.list_certificates.assert_called_once_with(
            mount_point='a-name')
        mock_log.assert_called_once_with(
            "Certificate with serial 1234567890 not issed by vault.",
            level=vault_pki.hookenv.DEBUG
        )

    @patch.object(vault_pki, 'get_serial_number_from_cert')
    @patch.object(vault_pki.vault, 'get_local_client')
    @patch.object(vault_pki, 'get_revoked_serials_from_vault')
    @patch.object(vault_pki.hookenv, 'log')
    def test_is_cert_from_vault_not_revoked_serial(
        self,
        mock_log,
        mock_get_revoked_serials_from_vault,
        mock_get_local_client,
        mock_get_serial_number_from_cert,
    ):
        mock_get_serial_number_from_cert.return_value = "1234567890"
        mock_client = MagicMock()
        mock_get_local_client.return_value = mock_client
        mock_client.secrets.pki.list_certificates.return_value = {
            "data": {
                "keys": ["1234567890"]
            }
        }
        mock_get_revoked_serials_from_vault.return_value = []

        self.assertTrue(
            vault_pki.is_cert_from_vault('the-cert', name='a-name'))

        mock_get_revoked_serials_from_vault.assert_called_once_with('a-name')
        mock_log.assert_not_called()

    @patch.object(vault_pki, 'get_serial_number_from_cert')
    @patch.object(vault_pki.vault, 'get_local_client')
    @patch.object(vault_pki, 'get_revoked_serials_from_vault')
    @patch.object(vault_pki.hookenv, 'log')
    def test_is_cert_from_vault_revoked_serial(
        self,
        mock_log,
        mock_get_revoked_serials_from_vault,
        mock_get_local_client,
        mock_get_serial_number_from_cert,
    ):
        mock_get_serial_number_from_cert.return_value = "1234567890"
        mock_client = MagicMock()
        mock_get_local_client.return_value = mock_client
        mock_client.secrets.pki.list_certificates.return_value = {
            "data": {
                "keys": ["12-34-56-78-90"]
            }
        }
        mock_get_revoked_serials_from_vault.return_value = [
            "DEADBEEF",
            "1234567890",
            "notme",
        ]

        self.assertFalse(
            vault_pki.is_cert_from_vault('the-cert', name='a-name'))

        mock_log.assert_called_once_with(
            "Serial 1234567890 is revoked.", level=vault_pki.hookenv.DEBUG)

    @patch.object(vault_pki, 'get_serial_number_from_cert')
    @patch.object(vault_pki.vault, 'get_local_client')
    @patch.object(vault_pki, 'get_revoked_serials_from_vault')
    @patch.object(vault_pki.hookenv, 'log')
    def test_is_cert_from_vault_raised_exceptions(
        self,
        mock_log,
        mock_get_revoked_serials_from_vault,
        mock_get_local_client,
        mock_get_serial_number_from_cert,
    ):
        mock_get_serial_number_from_cert.return_value = "1234567890"
        mock_client = MagicMock()
        mock_get_local_client.return_value = mock_client
        mock_client.secrets.pki.list_certificates.return_value = {
            "data": {
                "keys": ["12-34-56-78-90"]
            }
        }
        mock_get_revoked_serials_from_vault.return_value = [
            "DEADBEEF",
            "1234567890",
            "notme",
        ]

        def make_raiser(exc):
            def _raiser(*args, **kwargs):
                raise exc
            return _raiser

        exceptions = [
            vault_pki.vault.hvac.exceptions.InvalidPath('wrong-path'),
            vault_pki.vault.hvac.exceptions.InternalServerError('bang'),
            vault_pki.vault.hvac.exceptions.VaultDown(),
            vault_pki.vault.VaultNotReady("really-not-ready"),
        ]

        for exception in exceptions:
            mock_get_local_client.side_effect = make_raiser(exception)
            self.assertFalse(
                vault_pki.is_cert_from_vault('the-cert', name='a-name'))
            mock_log.assert_not_called()

        class OtherException(Exception):
            pass

        mock_get_local_client.side_effect = make_raiser(
            OtherException("on noes"))
        self.assertFalse(
            vault_pki.is_cert_from_vault('the-cert', name='a-name'))
        mock_log.assert_called_once_with(
            "General failure verifying cert: on noes",
            level=vault_pki.hookenv.DEBUG)

    @patch.object(vault_pki, 'check_output')
    @patch.object(vault_pki, 'NamedTemporaryFile')
    @patch.object(vault_pki.hookenv, 'log')
    def test_get_serial_number_from_cert(
        self,
        mock_log,
        mock_named_temporary_file,
        mock_check_output
    ):
        mock_f = MagicMock()
        mock_f.name = "filename"
        mock_named_temporary_file.return_value.__enter__.return_value = mock_f
        mock_check_output.return_value = b"    serial=12345678   "
        self.assertEqual(vault_pki.get_serial_number_from_cert(
            "this is a cert"), "12345678")
        mock_f.write.assert_called_once_with(b"this is a cert")
        mock_f.flush.assert_called_once_with()
        mock_check_output.assert_called_once_with(
            ['openssl', 'x509', '-in', 'filename', '-noout', '-serial'])

    @patch.object(vault_pki, 'check_output')
    @patch.object(vault_pki, 'NamedTemporaryFile')
    @patch.object(vault_pki.hookenv, 'log')
    def test_get_serial_number_from_cert_subprocess_error(
        self,
        mock_log,
        mock_named_temporary_file,
        mock_check_output
    ):
        mock_f = MagicMock()
        mock_f.name = "filename"
        mock_named_temporary_file.return_value.__enter__.return_value = mock_f
        mock_check_output.return_value = b"    serial=12345678   "

        def _raise(*args, **kwargs):
            raise vault_pki.CalledProcessError(cmd="bang", returncode=1)

        mock_check_output.side_effect = _raise

        self.assertEqual(vault_pki.get_serial_number_from_cert(
            "this is a cert"), None)

        mock_log.assert_called_once_with(
            "Couldn't process certificate: reason: Command 'bang' returned "
            "non-zero exit status 1.",
            level=vault_pki.hookenv.DEBUG)

    @patch.object(vault_pki, 'check_output')
    @patch.object(vault_pki, 'NamedTemporaryFile')
    @patch.object(vault_pki.hookenv, 'log')
    def test_get_serial_number_from_cert_other_error(
        self,
        mock_log,
        mock_named_temporary_file,
        mock_check_output
    ):
        mock_f = MagicMock()
        mock_f.name = "filename"
        mock_named_temporary_file.return_value.__enter__.return_value = mock_f
        mock_check_output.return_value = b"thing"

        self.assertEqual(vault_pki.get_serial_number_from_cert(
            "this is a cert"), None)

        mock_log.assert_called_once_with(
            "Couldn't extract serial number from passed certificate",
            level=vault_pki.hookenv.DEBUG)

    @patch.object(vault_pki, 'check_output')
    @patch.object(vault_pki, 'NamedTemporaryFile')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_revoked_serials_from_vault_no_serials(
        self,
        mock_get_local_client,
        mock_named_temporary_file,
        mock_check_output
    ):
        mock_f = MagicMock()
        mock_f.name = "filename"
        mock_named_temporary_file.return_value.__enter__.return_value = mock_f
        mock_check_output.return_value = b"\n\n\n"

        mock_client = MagicMock()
        mock_get_local_client.return_value = mock_client
        mock_client.secrets.pki.read_crl.return_value = "the crl"

        self.assertEqual(vault_pki.get_revoked_serials_from_vault(
            name=vault_pki.CHARM_PKI_MP), [])

        mock_check_output.assert_called_once_with(
            ['openssl', 'crl', '-in', 'filename', '-noout', '-text'])
        mock_f.write.assert_called_once_with(b"the crl")
        mock_client.secrets.pki.read_crl.assert_called_once_with(
            mount_point=vault_pki.CHARM_PKI_MP)

    @patch.object(vault_pki, 'check_output')
    @patch.object(vault_pki, 'NamedTemporaryFile')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_revoked_serials_from_vault_some_serials(
        self,
        mock_get_local_client,
        mock_named_temporary_file,
        mock_check_output
    ):
        mock_f = MagicMock()
        mock_f.name = "filename"
        mock_named_temporary_file.return_value.__enter__.return_value = mock_f
        mock_check_output.return_value = "\n".join([
            "Some interesting line",
            "   Serial Number: DEADBEEF",
            "another interesting line.",
            "   and another.",
            "   Serial Number: 1234567890",
            " and finally this one."
        ]).encode()

        mock_client = MagicMock()
        mock_get_local_client.return_value = mock_client
        mock_client.secrets.pki.read_crl.return_value = "the crl"

        self.assertEqual(vault_pki.get_revoked_serials_from_vault(
            name=vault_pki.CHARM_PKI_MP), ['DEADBEEF', '1234567890'])

    def test_certcache__init(self):
        item = vault_pki.CertCache('a-request')
        self.assertEqual(item._request, 'a-request')

    class ReadOnlyDict(collections.OrderedDict):
        """The ReadOnly dictionary accessible via attributes."""

        def __init__(self, data):
            for k, v in data.items():
                super().__setitem__(k, v)

        def __getitem__(self, key):
            return super().__getitem__(key)

        def __setattr__(self, *_):
            raise TypeError("{} does not allow setting of attributes"
                            .format(self.__class__.__name__))

        def __setitem__(self, *_):
            raise TypeError("{} does not allow setting of items"
                            .format(self.__class__.__name__))

        __getattr__ = __getitem__

    def _default_request(self):
        return self.ReadOnlyDict({
            'unit_name': 'the-name',
            '_is_top_level_server_cert': False,
            '_publish_key': "subbed",
            'common_name': 'cn1'
        })

    def test_certcache__cache_key_for(self):

        request = self.ReadOnlyDict({
            'unit_name': 'the-name',
            '_is_top_level_server_cert': True,
            '_publish_key': None,
            'common_name': 'cn1'
        })
        self.assertEqual(vault_pki.CertCache(request)._cache_key_for('cert'),
                         "pki:the-name:top_level_publish_key:cn1:cert")
        self.assertEqual(vault_pki.CertCache(request)._cache_key_for('key'),
                         "pki:the-name:top_level_publish_key:cn1:key")

        request = self._default_request()
        self.assertEqual(vault_pki.CertCache(request)._cache_key_for('cert'),
                         "pki:the-name:subbed:cn1:cert")
        self.assertEqual(vault_pki.CertCache(request)._cache_key_for('key'),
                         "pki:the-name:subbed:cn1:key")

        with self.assertRaises(AssertionError):
            vault_pki.CertCache(request)._cache_key_for('thing')

    @patch.object(vault_pki.hookenv, 'leader_get')
    def test_certcache__fetch(self, mock_leader_get):
        mock_leader_get.return_value = None
        request = self._default_request()
        self.assertEqual(vault_pki.CertCache(request)._fetch("mine"), "")
        mock_leader_get.assert_called_once_with('mine')

        mock_leader_get.reset_mock()
        mock_leader_get.return_value = '"the-value"'
        self.assertEqual(vault_pki.CertCache(request)._fetch("mine"),
                         'the-value')

    @patch.object(vault_pki.hookenv, 'leader_set')
    def test_certcache__store(self, mock_leader_set):
        request = self._default_request()
        vault_pki.CertCache(request)._store("mine", "a value")
        mock_leader_set.assert_called_once_with({"mine": '"a value"'})

        # type error
        class A:
            pass

        with self.assertRaises(TypeError):
            vault_pki.CertCache(request)._store("mine", A())

        # leader-set failure (subprocess call!)
        def _raise(*args, **kwargs):
            raise vault_pki.CalledProcessError(cmd="bang", returncode=1)

        mock_leader_set.side_effect = _raise

        with self.assertRaises(RuntimeError):
            vault_pki.CertCache(request)._store("mine", "thing")

    @patch.object(vault_pki.hookenv, 'leader_set')
    def test_certcache__clear(self, mock_leader_set):
        request = self._default_request()
        vault_pki.CertCache(request)._clear("mine")
        mock_leader_set.assert_called_once_with({"mine": None})

        # leader-set failure (subprocess call!)
        def _raise(*args, **kwargs):
            raise vault_pki.CalledProcessError(cmd="bang", returncode=1)

        mock_leader_set.side_effect = _raise

        with self.assertRaises(RuntimeError):
            vault_pki.CertCache(request)._clear("mine")

    @patch.object(vault_pki.CertCache, '_clear')
    def test_certcache_clear(self, mock__clear):
        request = self._default_request()
        vault_pki.CertCache(request).clear()
        mock__clear.assert_has_calls([
            call('pki:the-name:subbed:cn1:key'),
            call('pki:the-name:subbed:cn1:cert'),
        ])

        # leader-set failure (subprocess call!)
        def _raise(*args, **kwargs):
            raise RuntimeError("bang")

        mock__clear.side_effect = _raise

        with self.assertRaises(RuntimeError):
            vault_pki.CertCache(request).clear()

    @patch.object(vault_pki.CertCache, '_store')
    @patch.object(vault_pki.CertCache, '_fetch')
    @patch.object(vault_pki.CertCache, '_cache_key_for')
    def test_certcache__key_property(
        self,
        mock__cache_key_for,
        mock__fetch,
        mock__store,
    ):
        request = self._default_request()
        mock__cache_key_for.return_value = "cache-key"
        mock__fetch.return_value = "the-value"

        # read
        self.assertEqual(vault_pki.CertCache(request).key, "the-value")
        mock__cache_key_for.assert_called_once_with('key')
        mock__fetch.assert_called_once_with('cache-key')

        # write
        vault_pki.CertCache(request).key = 'new-value'
        mock__store.assert_called_once_with('cache-key', 'new-value')

    @patch.object(vault_pki.CertCache, '_store')
    @patch.object(vault_pki.CertCache, '_fetch')
    @patch.object(vault_pki.CertCache, '_cache_key_for')
    def test_certcache__cert_property(
        self,
        mock__cache_key_for,
        mock__fetch,
        mock__store,
    ):
        request = self._default_request()
        mock__cache_key_for.return_value = "cache-key"
        mock__fetch.return_value = "the-value"

        # read
        self.assertEqual(vault_pki.CertCache(request).cert, "the-value")
        mock__cache_key_for.assert_called_once_with('cert')
        mock__fetch.assert_called_once_with('cache-key')

        # write
        vault_pki.CertCache(request).cert = 'new-value'
        mock__store.assert_called_once_with('cache-key', 'new-value')

    @patch.object(vault_pki.CertCache, '_clear')
    @patch.object(vault_pki.CertCache, '_fetch')
    def test_certcache__remove_all_for(
        self,
        mock__fetch,
        mock__clear,
    ):
        mock__fetch.return_value = {
            'pki:the-name:subbed:cn1:key': "thing1",
            'pki:the-name:subbed:cn1:cert': "thing2",
            'pki:the-name2:subbed:cn1:key': "thing3",
            'pki:the-name2:subbed:cn1:cert': "thing4",
        }
        vault_pki.CertCache.remove_all_for('the-name')
        mock__clear.assert_has_calls([
            call('pki:the-name:subbed:cn1:key'),
            call('pki:the-name:subbed:cn1:cert'),
        ])

    @patch.object(vault_pki.hookenv, 'log')
    @patch.object(vault_pki, 'is_cert_from_vault')
    @patch.object(vault_pki, 'CertCache')
    def test_find_cert_in_cache(self,
                                mock_cert_cache,
                                mock_is_cert_from_vault,
                                mock_log):
        mock_cert_cache_object = MagicMock()
        mock_cert_cache_object.cert = "a-cert"
        mock_cert_cache_object.key = "a-key"
        mock_cert_cache.return_value = mock_cert_cache_object
        mock_is_cert_from_vault.return_value = True
        request = MagicMock()

        cert, key = vault_pki.find_cert_in_cache(request)
        self.assertEqual((cert, key), ("a-cert", "a-key"))
        mock_cert_cache.assert_called_once_with(request)

    @patch.object(vault_pki.hookenv, 'log')
    @patch.object(vault_pki, 'is_cert_from_vault')
    @patch.object(vault_pki.CertCache, 'cert', new_callable=mock.PropertyMock)
    @patch.object(vault_pki.CertCache, 'key', new_callable=mock.PropertyMock)
    def test_find_cert_in_cache_not_found(self,
                                          mock_key, mock_cert,
                                          mock_is_cert_from_vault,
                                          mock_log):
        mock_cert.return_value = None
        mock_key.return_value = "a-key"
        mock_is_cert_from_vault.return_value = True
        request = MagicMock()

        cert, key = vault_pki.find_cert_in_cache(request)
        self.assertEqual((cert, key), (None, None))

        mock_cert.return_value = "a-cert"
        mock_key.return_value = None
        cert, key = vault_pki.find_cert_in_cache(request)
        self.assertEqual((cert, key), (None, None))

    @patch.object(vault_pki.hookenv, 'log')
    @patch.object(vault_pki, 'is_cert_from_vault')
    @patch.object(vault_pki.CertCache, 'cert', new_callable=mock.PropertyMock)
    @patch.object(vault_pki.CertCache, 'key', new_callable=mock.PropertyMock)
    def test_find_cert_in_cache_not_in_vault(self,
                                             mock_key, mock_cert,
                                             mock_is_cert_from_vault,
                                             mock_log):
        mock_cert.return_value = "a-cert"
        mock_key.return_value = "a-key"
        mock_is_cert_from_vault.return_value = False
        request = MagicMock()

        cert, key = vault_pki.find_cert_in_cache(request)
        self.assertEqual((cert, key), ("a-cert", "a-key"))
        mock_is_cert_from_vault.assert_called_once_with(
            'a-cert', name=vault_pki.CHARM_PKI_MP)

    @patch.object(vault_pki.CertCache, 'cert', new_callable=mock.PropertyMock)
    @patch.object(vault_pki.CertCache, 'key', new_callable=mock.PropertyMock)
    def test_update_cert_cache_top_level_cert(self, mock_key, mock_cert):
        """Test storing top-level cert in cache."""
        cert_data = "cert data"
        key_data = "key data"
        cert_name = "server.cert"
        key_name = "server.key"
        client_name = "client_unit_0"

        # setup cert request
        request = MagicMock()
        request.unit_name = client_name
        request.common_name = client_name
        request._is_top_level_server_cert = True
        request._server_cert_key = cert_name
        request._server_key_key = key_name

        vault_pki.update_cert_cache(request, cert_data, key_data)
        mock_cert.assert_called_once_with(cert_data)
        mock_key.assert_called_once_with(key_data)

    @patch.object(vault_pki.CertCache, 'remove_all_for')
    def test_remove_unit_from_cache(self, mock_remove_all_for):
        """Test removing unit certificates from cache."""
        vault_pki.remove_unit_from_cache('client_0')
        mock_remove_all_for.assert_called_once_with('client_0')

    @patch.object(vault_pki, 'update_cert_cache')
    def test_populate_cert_cache(self, update_cert_cache):
        # Define data for top level certificate and key
        top_level_cert_name = "server.crt"
        top_level_key_name = "server.key"
        top_level_cert_data = "top level cert"
        top_level_key_data = "top level key"

        # Define data for non-top level certificate
        processed_request_cn = "juju_unit_service.crt"
        processed_request_publish_key = "juju_unit_service.processed"
        processed_cert_data = "processed cert"
        processed_key_data = "processed key"

        # Mock request for top level certificate
        top_level_request = MagicMock()
        top_level_request._is_top_level_server_cert = True
        top_level_request._server_cert_key = top_level_cert_name
        top_level_request._server_key_key = top_level_key_name
        top_level_request._unit.relation.to_publish_raw = {
            top_level_cert_name: top_level_cert_data,
            top_level_key_name: top_level_key_data,
        }

        # Mock request for non-top level certificate
        processed_request = MagicMock()
        processed_request._is_top_level_server_cert = False
        processed_request.common_name = processed_request_cn
        processed_request._publish_key = processed_request_publish_key
        processed_request._unit.relation.to_publish = {
            processed_request_publish_key: {processed_request_cn: {
                "cert": processed_cert_data,
                "key": processed_key_data
            }}
        }

        tls_endpoint = MagicMock()
        tls_endpoint.all_requests = [top_level_request, processed_request]

        vault_pki.populate_cert_cache(tls_endpoint)

        expected_update_calls = [
            call(top_level_request, top_level_cert_data, top_level_key_data),
            call(processed_request, processed_cert_data, processed_key_data),
        ]
        update_cert_cache.assert_has_calls(expected_update_calls)

    @patch.object(vault_pki.hookenv, 'leader_set')
    def test_set_global_client_cert(self, mock_leader_set):
        bundle = {
            'key1': 'value1',
            'key2': 'value2',
        }
        vault_pki.set_global_client_cert(bundle)
        mock_leader_set.assert_called_once_with(
            {'charm.vault.global-client-cert': mock.ANY})
        v = mock_leader_set.call_args[0][0]['charm.vault.global-client-cert']
        self.assertEqual(json.loads(v), bundle)

        # Type error
        class A:
            pass

        with self.assertRaises(TypeError):
            vault_pki.set_global_client_cert(A())

        # leader-set error.
        def _raise(*args, **kwargs):
            raise vault_pki.CalledProcessError(cmd="bang", returncode=1)

        mock_leader_set.side_effect = _raise
        with self.assertRaises(RuntimeError):
            vault_pki.set_global_client_cert(bundle)

    @patch.object(vault_pki.hookenv, 'leader_get')
    def test_get_global_client_cert(self, mock_leader_get):
        mock_leader_get.return_value = '{"a":"a-value"}'
        self.assertEqual(vault_pki.get_global_client_cert(), {'a': 'a-value'})
        mock_leader_get.return_value = None
        self.assertEqual(vault_pki.get_global_client_cert(), {})
