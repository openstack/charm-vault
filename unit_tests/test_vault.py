import mock
import unittest
from unittest.mock import patch

import charms.reactive

# Mock out reactive decorators prior to importing reactive.vault
dec_mock = mock.MagicMock()
dec_mock.return_value = lambda x: x
charms.reactive.hook = dec_mock
charms.reactive.when = dec_mock
charms.reactive.when_not = dec_mock

import reactive.vault as handlers  # noqa: E402


class TestHandlers(unittest.TestCase):

    def setUp(self):
        super(TestHandlers, self).setUp()
        self.patches = [
            'config',
            'endpoint_from_flag',
            'is_state',
            'log',
            'open_port',
            'service_restart',
            'service_running',
            'service_start',
            'set_state',
            'status_set',
            'remove_state',
            'render',
            'unit_private_ip',
        ]
        self.patch_all()

    def _patch(self, method):
        _m = patch.object(handlers, method)
        mock = _m.start()
        self.addCleanup(_m.stop)
        return mock

    def patch_all(self):
        for method in self.patches:
            setattr(self, method, self._patch(method))

    def test_ssl_available(self):
        self.assertFalse(handlers.ssl_available({
            'ssl-cert': '',
            'ssl-key': ''}))
        self.assertFalse(handlers.ssl_available({
            'ssl-cert': 'acert',
            'ssl-key': ''}))
        self.assertFalse(handlers.ssl_available({
            'ssl-cert': '',
            'ssl-key': 'akey'}))
        self.assertTrue(handlers.ssl_available({
            'ssl-cert': 'acert',
            'ssl-key': 'akey'}))

    @patch.object(handlers, 'can_restart')
    def test_configure_vault(self, can_restart):
        can_restart.return_value = True
        self.config.return_value = {'disable-mlock': False}
        self.is_state.return_value = True
        db_context = {
            'storage_name': 'psql',
            'psql_db_conn': 'myuri'}
        self.endpoint_from_flag.return_value = None
        handlers.configure_vault(db_context)
        expected_context = {
            'storage_name': 'psql',
            'psql_db_conn': 'myuri',
            'disable_mlock': False,
            'ssl_available': True,
        }
        status_set_calls = [
            mock.call('maintenance', 'creating vault config'),
            mock.call('maintenance', 'creating vault unit file'),
            mock.call('maintenance', 'starting vault'),
            mock.call('maintenance', 'opening vault port'),
            mock.call('active', '=^_^='),
        ]
        render_calls = [
            mock.call(
                'vault.hcl.j2',
                '/var/snap/vault/common/vault.hcl',
                expected_context,
                perms=0o600),
            mock.call(
                'vault.service.j2',
                '/etc/systemd/system/vault.service',
                {},
                perms=0o644)
        ]
        self.open_port.assert_called_once_with(8200)
        self.status_set.assert_has_calls(status_set_calls)
        self.render.assert_has_calls(render_calls)

        # Check flipping disable-mlock makes it to the context
        self.config.return_value = {'disable-mlock': True}
        expected_context['disable_mlock'] = True
        handlers.configure_vault(db_context)
        render_calls = [
            mock.call(
                'vault.hcl.j2',
                '/var/snap/vault/common/vault.hcl',
                expected_context,
                perms=0o600),
            mock.call(
                'vault.service.j2',
                '/etc/systemd/system/vault.service',
                {},
                perms=0o644)
        ]
        self.render.assert_has_calls(render_calls)

    @patch.object(handlers, 'configure_vault')
    def test_configure_vault_psql(self, configure_vault):
        psql = mock.MagicMock()
        psql.master = 'myuri'
        handlers.configure_vault_psql(psql)
        configure_vault.assert_called_once_with({
            'storage_name': 'psql',
            'psql_db_conn': 'myuri'})

    @patch.object(handlers, 'configure_vault')
    def test_configure_vault_msql(self, configure_vault):
        mysql = mock.MagicMock()
        handlers.configure_vault_mysql(mysql)
        configure_vault.assert_called_once_with({
            'storage_name': 'mysql',
            'mysql_db_relation': mysql})

    def test_disable_mlock_changed(self):
        handlers.disable_mlock_changed()
        self.remove_state.assert_called_once_with('configured')

    def test_upgrade_charm(self):
        calls = [mock.call('configured'),
                 mock.call('vault.nrpe.configured'),
                 mock.call('vault.ssl.configured')]
        handlers.upgrade_charm()
        self.remove_state.assert_has_calls(calls)

    def test_request_db(self):
        psql = mock.MagicMock()
        handlers.request_db(psql)
        psql.set_database.assert_called_once_with('vault')

    @patch.object(handlers, 'psycopg2')
    def test_create_vault_table(self, psycopg2):
        psql = mock.MagicMock()
        psql.master = 'myuri'
        handlers.create_vault_table(psql)
        db_calls = [
            mock.call(handlers.VAULT_TABLE_DDL),
            mock.call(handlers.VAULT_INDEX_DDL),
        ]
        psycopg2.connect().cursor().execute.assert_has_calls(db_calls)

    def test_database_not_ready(self):
        handlers.database_not_ready()
        self.remove_state.assert_called_once_with('vault.schema.created')

    @patch.object(handlers, 'can_restart')
    @patch.object(handlers, 'get_api_url')
    def test_configure_vault_etcd(self, get_api_url, can_restart):
        can_restart.return_value = True
        get_api_url.return_value = 'http://this-unit'
        self.config.return_value = {'disable-mlock': False}
        etcd_mock = mock.MagicMock()
        etcd_mock.connection_string.return_value = 'http://etcd'
        self.endpoint_from_flag.return_value = etcd_mock
        self.is_state.return_value = True
        handlers.configure_vault({})
        expected_context = {
            'disable_mlock': False,
            'ssl_available': True,
            'etcd_conn': 'http://etcd',
            'etcd_tls_ca_file': '/var/snap/vault/common/etcd-ca.pem',
            'etcd_tls_cert_file': '/var/snap/vault/common/etcd-cert.pem',
            'etcd_tls_key_file': '/var/snap/vault/common/etcd.key',
            'vault_api_url': 'http://this-unit'}
        render_calls = [
            mock.call(
                'vault.hcl.j2',
                '/var/snap/vault/common/vault.hcl',
                expected_context,
                perms=0o600),
            mock.call(
                'vault.service.j2',
                '/etc/systemd/system/vault.service',
                {},
                perms=0o644)
        ]
        self.render.assert_has_calls(render_calls)

    @patch.object(handlers.hvac, 'Client')
    @patch.object(handlers, 'get_api_url')
    def test_get_client(self, get_api_url, hvac_Client):
        get_api_url.return_value = 'http://this-unit'
        handlers.get_client()
        hvac_Client.assert_called_once_with(url='http://this-unit')

    def test_can_restart_vault_down(self):
        self.service_running.return_value = False
        self.assertTrue(handlers.can_restart())

    @patch.object(handlers, 'get_client')
    def test_can_restart_not_initialized(self, get_client):
        hvac_mock = mock.MagicMock()
        hvac_mock.is_initialized.return_value = False
        get_client.return_value = hvac_mock
        self.assertTrue(handlers.can_restart())

    @patch.object(handlers, 'get_client')
    def test_can_restart_sealed(self, get_client):
        hvac_mock = mock.MagicMock()
        hvac_mock.is_initialized.return_value = True
        hvac_mock.is_sealed.return_value = True
        get_client.return_value = hvac_mock
        self.assertTrue(handlers.can_restart())

    @patch.object(handlers, 'get_client')
    def test_can_restart_unsealed(self, get_client):
        hvac_mock = mock.MagicMock()
        hvac_mock.is_initialized.return_value = True
        hvac_mock.is_sealed.return_value = False
        get_client.return_value = hvac_mock
        self.assertFalse(handlers.can_restart())

    def test_get_api_url_ssl(self):
        self.is_state.return_value = True
        self.unit_private_ip.return_value = '1.2.3.4'
        self.assertEqual(handlers.get_api_url(), 'https://1.2.3.4:8200')

    def test_get_api_url_nossl(self):
        self.is_state.return_value = False
        self.unit_private_ip.return_value = '1.2.3.4'
        self.assertEqual(handlers.get_api_url(), 'http://1.2.3.4:8200')
