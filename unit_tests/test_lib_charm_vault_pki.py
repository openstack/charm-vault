from unittest import mock
from unittest.mock import call, patch, MagicMock

import hvac

import lib.charm.vault_pki as vault_pki
import unit_tests.test_utils


class TestLibCharmVaultPKI(unit_tests.test_utils.CharmTestCase):

    def setUp(self):
        super(TestLibCharmVaultPKI, self).setUp()
        self.obj = vault_pki
        self.patches = [
            'endpoint_from_name',
        ]
        self.patch_all()

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = False
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend',
            ttl=42, max_ttl=42)
        client_mock.sys.enable_secrets_engine.assert_called_once_with(
            backend_type='pki',
            config={
                'default_lease_ttl': 42,
                'max_lease_ttl': 42},
            description='Charm created PKI backend',
            path='my_backend')

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend_default_ttl(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = False
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend')
        client_mock.sys.enable_secrets_engine.assert_called_once_with(
            backend_type='pki',
            config={
                'default_lease_ttl': '8759h',
                'max_lease_ttl': '87600h'},
            description='Charm created PKI backend',
            path='my_backend')

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

        def read_role(role, mount_point=None):
            if role != "role":
                raise hvac.exceptions.InvalidPath()

        client_mock.secrets.pki.read_role.side_effect = read_role
        self.assertTrue(vault_pki.is_ca_ready(client_mock, 'mp', 'role'))
        self.assertFalse(
            vault_pki.is_ca_ready(client_mock, 'mp', 'doesnotexist')
        )

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_chain(self, get_local_client):
        client_mock = mock.MagicMock()
        client_mock.secrets.pki.read_certificate.return_value = {
            'data': {
                'certificate': 'somecert'}}
        get_local_client.return_value = client_mock
        self.assertEqual(
            vault_pki.get_chain('my_backend'),
            'somecert')
        client_mock.secrets.pki.read_certificate.assert_called_once_with(
            'ca_chain', mount_point='my_backend')

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_chain_nonexisting(self, get_local_client):
        client_mock = mock.MagicMock()
        client_mock.secrets.pki.read_certificate.side_effect = (
            hvac.exceptions.InvalidPath)
        get_local_client.return_value = client_mock
        with self.assertRaises(hvac.exceptions.InvalidPath):
            vault_pki.get_chain('my_backend')

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_chain_default_pki(self, get_local_client):
        client_mock = mock.MagicMock()
        client_mock.secrets.pki.read_certificate.return_value = {
            'data': {
                'certificate': 'somecert'}}
        get_local_client.return_value = client_mock
        self.assertEqual(
            vault_pki.get_chain(),
            'somecert')
        client_mock.secrets.pki.read_certificate.assert_called_once_with(
            'ca_chain', mount_point=vault_pki.CHARM_PKI_MP)

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
        client_mock.secrets.pki.generate_certificate.return_value = {
            'data': 'data'}
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        sort_sans.side_effect = lambda l: (l[0], l[1])
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
        client_mock.secrets.pki.generate_certificate.assert_has_calls([
            mock.call(
                vault_pki.CHARM_PKI_ROLE, 'example.com',
                mount_point=vault_pki.CHARM_PKI_MP,
                extra_params={},
            ),
            mock.call(
                vault_pki.CHARM_PKI_ROLE, 'example.com',
                mount_point=vault_pki.CHARM_PKI_MP,
                extra_params={
                    'ip_sans': 'ip1',
                    'alt_names': 'alt1',
                }
            ),
            mock.call(
                vault_pki.CHARM_PKI_ROLE_CLIENT, 'example.com',
                mount_point=vault_pki.CHARM_PKI_MP,
                extra_params={
                    'ip_sans': 'ip1,ip2',
                    'alt_names': 'alt1,alt2',
                }
            ),
        ])

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
        client_mock.secrets.pki.generate_certificate.side_effect = (
            hvac.exceptions.InvalidRequest
        )
        with self.assertRaises(vault_pki.vault.VaultInvalidRequest):
            vault_pki.generate_certificate('server', 'example.com', [],
                                           ttl='3456h', max_ttl='3456h')

    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr(self, get_local_client, configure_pki_backend):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.secrets.pki.generate_intermediate.return_value = {
            'data': {
                'csr': 'somecert'}}
        self.assertEqual(vault_pki.get_csr(), 'somecert')
        client_mock.secrets.pki.generate_intermediate.assert_called_once_with(
            'internal',
            'Vault Intermediate Certificate Authority (charm-pki-local)',
            extra_params={'ttl': '87599h'},
            mount_point=vault_pki.CHARM_PKI_MP)

    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr_explicit(self, get_local_client, configure_pki_backend):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.secrets.pki.generate_intermediate.return_value = {
            'data': {'csr': 'somecert'}}
        self.assertEqual(
            vault_pki.get_csr(
                ttl='2h',
                country='GB',
                locality='here',
                province='Kent',
                organizational_unit='My Department',
                organization='My Company'),
            'somecert')
        client_mock.secrets.pki.generate_intermediate.assert_called_once_with(
            'internal',
            'Vault Intermediate Certificate Authority (charm-pki-local)',
            extra_params=dict(
                country='GB',
                locality='here',
                organization='My Company',
                ou='My Department',
                province='Kent',
                ttl='2h'
            ),
            mount_point=vault_pki.CHARM_PKI_MP
        )

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr(self, get_local_client, get_access_address):
        get_access_address.return_value = 'https://vault.local:8200'
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        vault_pki.upload_signed_csr('MYPEM', 'example.com')
        client_mock.secrets.pki.set_signed_intermediate.\
            assert_called_once_with(
                'MYPEM', mount_point=vault_pki.CHARM_PKI_MP
            )

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr_ipv4(
        self, get_local_client, get_access_address
    ):
        get_access_address.return_value = 'https://127.0.0.1:8200'
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        local_url = 'https://127.0.0.1:8200/v1/charm-pki-local'
        vault_pki.upload_signed_csr('MYPEM', 'example.com')
        client_mock.secrets.pki.set_signed_intermediate.\
            assert_called_once_with(
                'MYPEM', mount_point=vault_pki.CHARM_PKI_MP
            )
        client_mock.secrets.pki.set_urls.assert_called_once_with({
            'issuing_certificates': '{}/ca'.format(local_url),
            'crl_distribution_points': '{}/crl'.format(local_url),
        }, mount_point=vault_pki.CHARM_PKI_MP)
        client_mock.secrets.pki.create_or_update_role.assert_has_calls([
            mock.call(
                vault_pki.CHARM_PKI_ROLE,
                extra_params=dict(
                    allowed_domains='example.com',
                    allow_subdomains=True,
                    enforce_hostnames=False,
                    allow_any_name=True,
                    max_ttl='87598h',
                    server_flag=True,
                    client_flag=True,
                ),
                mount_point=vault_pki.CHARM_PKI_MP,
            ),
            mock.call(
                vault_pki.CHARM_PKI_ROLE_CLIENT,
                extra_params=dict(
                    allowed_domains='example.com',
                    allow_subdomains=True,
                    enforce_hostnames=False,
                    allow_any_name=True,
                    max_ttl='87598h',
                    server_flag=False,
                    client_flag=True,
                ),
                mount_point=vault_pki.CHARM_PKI_MP,
            ),
        ])

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr_ipv6(
        self, get_local_client, get_access_address
    ):
        get_access_address.return_value = 'https://[::1]:8200'
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        vault_pki.upload_signed_csr('MYPEM', 'example.com')
        client_mock.secrets.pki.set_signed_intermediate.\
            assert_called_once_with(
                'MYPEM', mount_point=vault_pki.CHARM_PKI_MP
            )

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr_explicit(self, get_local_client,
                                        get_access_address):
        client_mock = mock.MagicMock()
        get_access_address.return_value = 'https://vault.local:8200'
        get_local_client.return_value = client_mock
        local_url = 'https://vault.local:8200/v1/charm-pki-local'
        vault_pki.upload_signed_csr(
            'MYPEM',
            'example.com',
            allow_subdomains=False,
            enforce_hostnames=True,
            allow_any_name=False,
            max_ttl='42h')
        client_mock.secrets.pki.set_signed_intermediate.\
            assert_called_once_with(
                'MYPEM', mount_point='charm-pki-local'
            )
        client_mock.secrets.pki.set_urls.assert_called_once_with(
            {
                'issuing_certificates': '{}/ca'.format(local_url),
                'crl_distribution_points': '{}/crl'.format(local_url),
            },
            mount_point=vault_pki.CHARM_PKI_MP
        )

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
        mock_client.secrets.pki.generate_root.return_value = {
            'data': {'certificate': 'cert'}}
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
        mock_client.sys.tune_mount_configuration.assert_called_with(
            path=vault_pki.CHARM_PKI_MP,
            max_lease_ttl='3456h',
            default_lease_ttl='3456h'
        )

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_update_roles(self, get_local_client):
        mock_client = mock.MagicMock()
        get_local_client.return_value = mock_client
        mock_client.secrets.pki.read_role.return_value = {
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
        mock_client.secrets.pki.create_or_update_role.assert_has_calls([
            mock.call(
                vault_pki.CHARM_PKI_ROLE,
                mount_point=vault_pki.CHARM_PKI_MP,
                extra_params=dict(
                    allow_any_name=True,
                    allowed_domains='domains',
                    allow_bare_domains=True,
                    allow_subdomains=True,
                    allow_glob_domains=False,
                    enforce_hostnames=True,
                    max_ttl='20h',
                    server_flag=True,
                    client_flag=True)
            ),
            mock.call(
                vault_pki.CHARM_PKI_ROLE_CLIENT,
                mount_point=vault_pki.CHARM_PKI_MP,
                extra_params=dict(
                    allow_any_name=True,
                    allowed_domains='domains',
                    allow_bare_domains=True,
                    allow_subdomains=True,
                    allow_glob_domains=False,
                    enforce_hostnames=True,
                    max_ttl='20h',
                    server_flag=False,
                    client_flag=True)
            ),
        ])

    def test_get_pki_cache(self):
        """Test retrieving PKI from cache."""
        expected_pki = {
            vault_pki.TOP_LEVEL_CERT_KEY: {
                "client_unit_0.server.cert": "cert_data",
                "client_unit_0.server.key": "key_data",
            }
        }
        cluster_relation = MagicMock()
        self.endpoint_from_name.return_value = cluster_relation
        cluster_relation.get_unit_pki.return_value = expected_pki

        pki = vault_pki.get_pki_cache('client_unit_0')
        cluster_relation.get_unit_pki.assert_called_once_with(
            'pki_client_unit_0')
        self.assertEqual(pki, expected_pki)

        # test retrieval if the PKI is not set
        cluster_relation.get_unit_pki.return_value = {}
        cluster_relation.get_unit_pki.reset_mock()

        pki = vault_pki.get_pki_cache('client_unit_0')
        cluster_relation.get_unit_pki.assert_called_once_with(
            'pki_client_unit_0')
        self.assertEqual(pki, {})

    @patch.object(vault_pki, 'get_pki_cache')
    @patch.object(vault_pki, 'get_chain')
    @patch.object(vault_pki, 'get_ca')
    def test_find_cert_in_cache_no_ca(self, get_ca, get_chain, get_pki_cache):
        """Test getting cert from cache when CA is missing."""
        get_ca.return_value = None
        get_chain.return_value = None

        cert, key = vault_pki.find_cert_in_cache(MagicMock())

        # assert that CA cert or chain was retrieved
        get_ca.assert_called_once_with()
        get_chain.assert_called_once_with()
        # assert that function does not proceed due to the missing CA
        get_pki_cache.assert_not_called()

        self.assertIsNone(cert)
        self.assertIsNone(key)

    @patch.object(vault_pki, 'verify_cert')
    @patch.object(vault_pki, 'get_pki_cache')
    @patch.object(vault_pki, 'get_chain')
    @patch.object(vault_pki, 'get_ca')
    def test_find_cert_in_cache_missing(self, get_ca, get_chain,
                                        get_pki_cache, verify_cache):
        """Test use case when searched certificate is not in cache."""
        request = MagicMock()
        request.unit_name = "client_unit_0"
        request._is_top_level_server_cert = True

        get_ca.return_value = MagicMock()
        get_pki_cache.return_value = {}

        cert, key = vault_pki.find_cert_in_cache(request)

        # assert that verification of cert is not attempted when
        # cert is not found
        verify_cache.assert_not_called()

        self.assertIsNone(cert)
        self.assertIsNone(key)

        # Same scenario, but with non-top-level certificate
        request._is_top_level_server_cert = False

        cert, key = vault_pki.find_cert_in_cache(request)

        verify_cache.assert_not_called()
        self.assertIsNone(cert)
        self.assertIsNone(key)

    @patch.object(vault_pki, 'get_pki_cache')
    @patch.object(vault_pki, 'get_chain')
    @patch.object(vault_pki, 'get_ca')
    def test_find_cert_in_cache_err(self, get_ca, get_chain, get_pki_cache):
        """Test getting cert from cache when CA is missing."""
        get_ca.return_value = None
        get_chain.side_effect = hvac.exceptions.InvalidPath

        cert, key = vault_pki.find_cert_in_cache(MagicMock())

        # assert that CA cert or chain was retrieved
        get_ca.assert_called_once_with()
        get_chain.assert_called_once_with()
        # assert that function does not proceed due to the missing CA
        get_pki_cache.assert_not_called()

        self.assertIsNone(cert)
        self.assertIsNone(key)

    @patch.object(vault_pki, 'verify_cert')
    @patch.object(vault_pki, 'get_pki_cache')
    @patch.object(vault_pki, 'get_chain')
    @patch.object(vault_pki, 'get_ca')
    def test_find_cert_in_cache_top_level(self, get_ca, get_chain,
                                          get_pki_cache, verify_cache):
        """Test fetching top level cert from cache.

        Additional test scenario: Test that nothing is returned if cert fails
        CA verification.
        """
        ca_cert = "CA cert data"
        expected_cert = "cert data"
        expected_key = "key data"
        cert_name = "server.cert"
        key_name = "server.key"
        client_name = "client_unit_0"

        # setup cert request
        request = MagicMock()
        request.unit_name = client_name
        request._is_top_level_server_cert = True
        request._server_cert_key = cert_name
        request._server_key_key = key_name

        # PKI cache content
        pki = {
            vault_pki.TOP_LEVEL_CERT_KEY: {
                cert_name: expected_cert,
                key_name: expected_key
            }
        }

        get_ca.return_value = ca_cert
        get_chain.return_value = ca_cert
        get_pki_cache.return_value = pki
        verify_cache.return_value = True

        cert, key = vault_pki.find_cert_in_cache(request)

        verify_cache.assert_called_once_with(ca_cert, expected_cert)
        self.assertEqual(cert, expected_cert)
        self.assertEqual(key, expected_key)

        # Additional test: Nothing should be returned if cert failed
        # CA verification.
        verify_cache.reset_mock()
        verify_cache.return_value = False

        cert, key = vault_pki.find_cert_in_cache(request)

        verify_cache.assert_called_once_with(ca_cert, expected_cert)
        self.assertIsNone(cert)
        self.assertIsNone(key)

    @patch.object(vault_pki, 'verify_cert')
    @patch.object(vault_pki, 'get_pki_cache')
    @patch.object(vault_pki, 'get_chain')
    @patch.object(vault_pki, 'get_ca')
    def test_find_cert_in_cache_not_top_level(self, get_ca, get_chain,
                                              get_pki_cache, verify_cache):
        """Test fetching non-top level cert from cache.

        Additional test scenario: Test that nothing is returned if cert fails
        CA verification.
        """
        ca_cert = "CA cert data"
        expected_cert = "cert data"
        expected_key = "key data"
        client_name = "client_unit_0"
        publish_key = client_name + ".processed_client_requests"
        common_name = "client.0"

        # setup cert request
        request = MagicMock()
        request.unit_name = client_name
        request._is_top_level_server_cert = False
        request._publish_key = publish_key
        request.common_name = common_name

        # PKI cache content
        pki = {
            publish_key: {
                common_name: {
                    "cert": expected_cert,
                    "key": expected_key,
                }
            }
        }

        get_ca.return_value = ca_cert
        get_chain.return_value = ca_cert
        get_pki_cache.return_value = pki
        verify_cache.return_value = True

        cert, key = vault_pki.find_cert_in_cache(request)

        verify_cache.assert_called_once_with(ca_cert, expected_cert)
        self.assertEqual(cert, expected_cert)
        self.assertEqual(key, expected_key)

        # Additional test: Nothing should be returned if cert failed
        # CA verification.
        verify_cache.reset_mock()
        verify_cache.return_value = False

        cert, key = vault_pki.find_cert_in_cache(request)

        verify_cache.assert_called_once_with(ca_cert, expected_cert)
        self.assertIsNone(cert)
        self.assertIsNone(key)

    @patch.object(vault_pki, 'get_pki_cache')
    def test_update_cert_cache_top_level_cert(self, get_pki_cache):
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

        cluster_relation = MagicMock()
        self.endpoint_from_name.return_value = cluster_relation

        # PKI structure
        initial_pki = {}
        expected_pki = {
            vault_pki.TOP_LEVEL_CERT_KEY: {
                cert_name: cert_data,
                key_name: key_data
            }
        }

        get_pki_cache.return_value = initial_pki

        vault_pki.update_cert_cache(request, cert_data, key_data)
        key = "{}_{}".format(vault_pki.PKI_CACHE_KEY, client_name)
        cluster_relation.set_unit_pki.assert_called_once_with(
            key, expected_pki)

    @patch.object(vault_pki, 'get_pki_cache')
    def test_update_cert_cache_non_top_level_cert(self, get_pki_cache):
        """Test storing non-top-level cert in cache."""
        cert_data = "cert data"
        key_data = "key data"
        client_name = "client_unit_0"
        publish_key = client_name + ".processed_client_requests"
        common_name = "client.0"

        cluster_relation = MagicMock()
        self.endpoint_from_name.return_value = cluster_relation

        # setup cert request
        request = MagicMock()
        request.unit_name = client_name
        request._is_top_level_server_cert = False
        request._publish_key = publish_key
        request.common_name = common_name

        # PKI structure
        initial_pki = {}
        expected_pki = {
            publish_key: {
                common_name: {
                    "cert": cert_data,
                    "key": key_data,
                }
            }
        }

        get_pki_cache.return_value = initial_pki

        vault_pki.update_cert_cache(request, cert_data, key_data)
        key = "{}_{}".format(vault_pki.PKI_CACHE_KEY, client_name)
        cluster_relation.set_unit_pki.assert_called_once_with(
            key, expected_pki)

    def test_remove_unit_from_cache(self):
        """Test removing unit certificates from cache."""
        cluster_relation = MagicMock()
        self.endpoint_from_name.return_value = cluster_relation
        vault_pki.remove_unit_from_cache('client_0')
        key = "{}_{}".format(vault_pki.PKI_CACHE_KEY, 'client_0')
        cluster_relation.set_unit_pki.assert_called_once_with(key, None)

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
