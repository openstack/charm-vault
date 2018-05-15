import datetime
import json
import mock
from unittest.mock import patch
from cryptography.x509.extensions import ExtensionNotFound

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
            ttl=42)
        client_mock.enable_secret_backend.assert_called_once_with(
            backend_type='pki',
            config={'max-lease-ttl': 42},
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
            config={'max-lease-ttl': '87600h'},
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

    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_server_certificate(self, get_local_client,
                                    configure_pki_backend, is_ca_ready):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        vault_pki.get_server_certificate('bob.example.com')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/issue/local',
            common_name='bob.example.com'
        )

    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_server_certificate_sans(self, get_local_client,
                                         configure_pki_backend,
                                         is_ca_ready):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        vault_pki.get_server_certificate(
            'bob.example.com',
            ip_sans=['10.10.10.10', '192.197.45.23'],
            alt_names=['localunit', 'public.bob.example.com'])
        client_mock.write.assert_called_once_with(
            'charm-pki-local/issue/local',
            alt_names='localunit,public.bob.example.com',
            common_name='bob.example.com',
            ip_sans='10.10.10.10,192.197.45.23'
        )

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr(self, get_local_client, is_backend_mounted):
        is_backend_mounted.return_value = True
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
    @patch.object(vault_pki.vault, 'is_backend_mounted')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr_config_backend(self, get_local_client, is_backend_mounted,
                                    configure_pki_backend):
        is_backend_mounted.return_value = False
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
        configure_pki_backend.assert_called_once_with(
            client_mock,
            'charm-pki-local')

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr_explicit(self, get_local_client, is_backend_mounted):
        is_backend_mounted.return_value = False
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.write.return_value = {
            'data': {
                'csr': 'somecert'}}
        self.assertEqual(
            vault_pki.get_csr(
                ttl='2h',
                country='GB',
                province='Kent',
                organizational_unit='My Department',
                organization='My Company'),
            'somecert')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/intermediate/generate/internal',
            common_name=('Vault Intermediate Certificate Authority '
                         '(charm-pki-local)'),
            country='GB',
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
                max_ttl='87598h')
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
                max_ttl='42h')
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

    @patch.object(vault_pki.hookenv, 'related_units')
    @patch.object(vault_pki.hookenv, 'relation_ids')
    @patch.object(vault_pki.hookenv, 'local_unit')
    def test_get_vault_units(self, local_unit, relation_ids, related_units):
        local_unit.return_value = 'vault/3'
        relation_ids.return_value = 'certificates:34'
        related_units.return_value = ['vault/1', 'vault/5']
        self.assertEqual(
            vault_pki.get_vault_units(),
            ['vault/3', 'vault/1', 'vault/5'])

    def _get_matching_cert_from_relation(self, vault_relation, cert_match,
                                         func_args,
                                         expected_bundle,
                                         expected_newest_calls):
        self.patch_object(vault_pki.hookenv, 'relation_get')
        self.patch_object(vault_pki.hookenv, 'relation_id')
        self.patch_object(vault_pki, 'select_newest')
        self.patch_object(vault_pki, 'cert_matches_request')
        self.patch_object(vault_pki, 'get_vault_units')
        self.relation_get.side_effect = lambda unit, rid: vault_relation[unit]
        self.cert_matches_request.side_effect = \
            lambda w, x, y, z: cert_match[w]
        self.get_vault_units.return_value = ['vault/3', 'vault/1', 'vault/5']
        self.relation_id.return_value = 'certificates:23'
        self.select_newest.side_effect = lambda x: x[0]
        rget_calls = [
            mock.call(unit='vault/3', rid='certificates:23'),
            mock.call(unit='vault/1', rid='certificates:23'),
            mock.call(unit='vault/5', rid='certificates:23')]
        self.assertEqual(
            vault_pki.get_matching_cert_from_relation(*func_args),
            expected_bundle)
        self.relation_get.assert_has_calls(rget_calls)
        self.select_newest.assert_called_once_with(expected_newest_calls)

    def test_get_matching_cert_from_relation(self):
        _rinfo = {
            'vault/1': {
                'keystone_0.server.cert': 'V1CERT',
                'keystone_0.server.key': 'V1KEY'},
            'vault/3': {},
            'vault/5': {},
        }
        _cmatch = {
            'V1CERT': True
        }
        self._get_matching_cert_from_relation(
            _rinfo,
            _cmatch,
            ('keystone/0', 'ks.bob.com', ['10.0.0.23'], ['junit1.maas.local']),
            {'private_key': 'V1KEY', 'certificate': 'V1CERT'},
            [{'private_key': 'V1KEY', 'certificate': 'V1CERT'}])

    def test_get_matching_cert_from_relation_batch_single(self):
        _rinfo = {
            'vault/1': {},
            'vault/3': {
                'processed_requests': json.dumps({
                    'ks.bob.com': {
                        'cert': 'V3CERT',
                        'key': 'V3KEY'}})},
            'vault/5': {},
        }
        _cmatch = {
            'V3CERT': True
        }
        self._get_matching_cert_from_relation(
            _rinfo,
            _cmatch,
            ('keystone/0', 'ks.bob.com', ['10.0.0.23'], ['junit1.maas.local']),
            {'private_key': 'V3KEY', 'certificate': 'V3CERT'},
            [{'private_key': 'V3KEY', 'certificate': 'V3CERT'}])

    def test_get_matching_cert_from_relation_batch_multi_one_match(self):
        _rinfo = {
            'vault/1': {},
            'vault/3': {
                'processed_requests': json.dumps({
                    'ks.bob.com': {
                        'cert': 'V3CERT',
                        'key': 'V3KEY'}})},
            'vault/5': {
                'processed_requests': json.dumps({
                    'glance.bob.com': {
                        'cert': 'V5CERT',
                        'key': 'V5KEY'}})},
        }
        _cmatch = {
            'V3CERT': True
        }
        self._get_matching_cert_from_relation(
            _rinfo,
            _cmatch,
            ('keystone/0', 'ks.bob.com', ['10.0.0.23'], ['junit1.maas.local']),
            {'private_key': 'V3KEY', 'certificate': 'V3CERT'},
            [{'private_key': 'V3KEY', 'certificate': 'V3CERT'}])

    def test_get_matching_cert_from_relation_batch_multi_two_match(self):
        _rinfo = {
            'vault/1': {},
            'vault/3': {
                'processed_requests': json.dumps({
                    'ks.bob.com': {
                        'cert': 'V3CERT',
                        'key': 'V3KEY'}})},
            'vault/5': {
                'processed_requests': json.dumps({
                    'ks.bob.com': {
                        'cert': 'V5CERT',
                        'key': 'V5KEY'}})},
        }
        _cmatch = {
            'V3CERT': True,
            'V5CERT': True
        }
        self._get_matching_cert_from_relation(
            _rinfo,
            _cmatch,
            ('keystone/0', 'ks.bob.com', ['10.0.0.23'], ['junit1.maas.local']),
            {'private_key': 'V3KEY', 'certificate': 'V3CERT'},
            [
                {'private_key': 'V3KEY', 'certificate': 'V3CERT'},
                {'private_key': 'V5KEY', 'certificate': 'V5CERT'}])

    def test_get_matching_cert_from_relation_batch_multi_sans_mismatch(self):
        _rinfo = {
            'vault/1': {},
            'vault/3': {
                'processed_requests': json.dumps({
                    'ks.bob.com': {
                        'cert': 'V3CERT',
                        'key': 'V3KEY'}})},
            'vault/5': {
                'processed_requests': json.dumps({
                    'ks.bob.com': {
                        'cert': 'V5CERT',
                        'key': 'V5KEY'}})},
        }
        _cmatch = {
            'V3CERT': False,
            'V5CERT': True
        }
        self._get_matching_cert_from_relation(
            _rinfo,
            _cmatch,
            ('keystone/0', 'ks.bob.com', ['10.0.0.23'], ['junit1.maas.local']),
            {'private_key': 'V5KEY', 'certificate': 'V5CERT'},
            [{'private_key': 'V5KEY', 'certificate': 'V5CERT'}])

    @patch.object(vault_pki, 'certificate_information')
    def test_cert_matches_request(self, certificate_information):
        certificate_information.return_value = {
            'cn': 'ks.bob.com',
            'ip_sans': ['10.0.0.10'],
            'alt_names': ['unit1.bob.com']}
        self.assertTrue(
            vault_pki.cert_matches_request(
                'pem', 'ks.bob.com', ['10.0.0.10'], ['unit1.bob.com']))

    @patch.object(vault_pki, 'certificate_information')
    def test_cert_matches_request_mismatch_cn(self, certificate_information):
        certificate_information.return_value = {
            'cn': 'glance.bob.com',
            'ip_sans': ['10.0.0.10'],
            'alt_names': ['unit1.bob.com']}
        self.assertFalse(
            vault_pki.cert_matches_request(
                'pem', 'ks.bob.com', ['10.0.0.10'], ['unit1.bob.com']))

    @patch.object(vault_pki, 'certificate_information')
    def test_cert_matches_request_mismatch_ipsan(self,
                                                 certificate_information):
        certificate_information.return_value = {
            'cn': 'glance.bob.com',
            'ip_sans': ['10.0.0.10', '10.0.0.20'],
            'alt_names': ['unit1.bob.com']}
        self.assertFalse(
            vault_pki.cert_matches_request(
                'pem', 'ks.bob.com', ['10.0.0.10'], ['unit1.bob.com']))

    @patch.object(vault_pki, 'certificate_information')
    def test_cert_matches_request_cn_in_san(self, certificate_information):
        certificate_information.return_value = {
            'cn': 'ks.bob.com',
            'ip_sans': ['10.0.0.10'],
            'alt_names': ['ks.bob.com', 'unit1.bob.com']}
        self.assertTrue(
            vault_pki.cert_matches_request(
                'pem', 'ks.bob.com', ['10.0.0.10'], ['unit1.bob.com']))

    @patch.object(vault_pki.x509, 'load_pem_x509_certificate')
    def test_certificate_information(self, load_pem_x509_certificate):
        x509_mock = mock.MagicMock(not_valid_after="10 Mar 1976")
        x509_name_mock = mock.MagicMock(value='ks.bob.com')
        x509_mock.subject.get_attributes_for_oid.return_value = [
            x509_name_mock]
        x509_sans_mock = mock.MagicMock()
        sans = [
            ['10.0.0.0.10'],
            ['sans1.bob.com']]
        x509_sans_mock.value.get_values_for_type = lambda x: sans.pop()
        x509_mock.extensions.get_extension_for_oid.return_value = \
            x509_sans_mock
        load_pem_x509_certificate.return_value = x509_mock
        self.assertEqual(
            vault_pki.certificate_information('pem'),
            {
                'cn': 'ks.bob.com',
                'not_valid_after': '10 Mar 1976',
                'ip_sans': ['10.0.0.0.10'],
                'alt_names': ['sans1.bob.com']})

    @patch.object(vault_pki.x509, 'load_pem_x509_certificate')
    def test_certificate_information_no_sans(self, load_pem_x509_certificate):
        x509_mock = mock.MagicMock(not_valid_after="10 Mar 1976")
        x509_name_mock = mock.MagicMock(value='ks.bob.com')
        x509_mock.subject.get_attributes_for_oid.return_value = [
            x509_name_mock]
        x509_mock.extensions.get_extension_for_oid.side_effect = \
            ExtensionNotFound('msg', 'oid')
        load_pem_x509_certificate.return_value = x509_mock
        self.assertEqual(
            vault_pki.certificate_information('pem'),
            {
                'cn': 'ks.bob.com',
                'not_valid_after': '10 Mar 1976',
                'ip_sans': [],
                'alt_names': []})

    @patch.object(vault_pki.x509, 'load_pem_x509_certificate')
    def test_select_newest(self, load_pem_x509_certificate):
        def _load_pem_x509(pem):
            pem = pem.decode()
            cmock1 = mock.MagicMock(
                not_valid_after=datetime.datetime(2018, 5, 3))
            cmock2 = mock.MagicMock(
                not_valid_after=datetime.datetime(2018, 5, 4))
            cmock3 = mock.MagicMock(
                not_valid_after=datetime.datetime(2018, 5, 5))
            certs = {
                'cert1': cmock1,
                'cert2': cmock2,
                'cert3': cmock3}
            return certs[pem]
        load_pem_x509_certificate.side_effect = lambda x, y: _load_pem_x509(x)
        certs = [
            {'certificate': 'cert1'},
            {'certificate': 'cert2'},
            {'certificate': 'cert3'}]
        self.assertEqual(
            vault_pki.select_newest(certs),
            {'certificate': 'cert3'})

    @patch.object(vault_pki, 'get_matching_cert_from_relation')
    @patch.object(vault_pki, 'get_server_certificate')
    def test_process_cert_request(self, get_server_certificate,
                                  get_matching_cert_from_relation):
        get_matching_cert_from_relation.return_value = 'cached_bundle'
        self.assertEqual(
            vault_pki.process_cert_request(
                'ks.bob.com',
                ['10.0.0.10', 'sans1.bob.com'],
                'keystone_0',
                False),
            'cached_bundle')
        get_matching_cert_from_relation.assert_called_once_with(
            'keystone_0',
            'ks.bob.com',
            ['10.0.0.10'],
            ['sans1.bob.com'])
        get_server_certificate.assert_not_called()

    @patch.object(vault_pki, 'get_matching_cert_from_relation')
    @patch.object(vault_pki, 'get_server_certificate')
    def test_process_cert_request_reissue(self, get_server_certificate,
                                          get_matching_cert_from_relation):
        get_server_certificate.return_value = 'new_bundle'
        self.assertEqual(
            vault_pki.process_cert_request(
                'ks.bob.com',
                ['10.0.0.10', 'sans1.bob.com'],
                'keystone_0',
                True),
            'new_bundle')
        get_matching_cert_from_relation.assert_not_called()
        get_server_certificate.assert_called_once_with(
            'ks.bob.com',
            ip_sans=['10.0.0.10'],
            alt_names=['sans1.bob.com'])
