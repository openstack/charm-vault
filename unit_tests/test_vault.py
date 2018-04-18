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

    _health_response = {
        "initialized": True,
        "sealed": False,
        "standby": False,
        "server_time_utc": 1523952750,
        "version": "0.9.0",
        "cluster_name": "vault-cluster-9dd8dd12",
        "cluster_id": "1ea3d74c-3819-fbaf-f780-bae0babc998f"
    }

    _health_response_needs_init = {
        "initialized": False,
        "sealed": False,
        "standby": False,
        "server_time_utc": 1523952750,
        "version": "0.9.0",
        "cluster_name": "vault-cluster-9dd8dd12",
        "cluster_id": "1ea3d74c-3819-fbaf-f780-bae0babc998f"
    }

    _health_response_sealed = {
        "initialized": True,
        "sealed": True,
        "standby": False,
        "server_time_utc": 1523952750,
        "version": "0.9.0",
        "cluster_name": "vault-cluster-9dd8dd12",
        "cluster_id": "1ea3d74c-3819-fbaf-f780-bae0babc998f"
    }

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
            'application_version_set',
            'local_unit',
            'network_get_primary_address',
            'snap',
            'is_flag_set',
            'set_flag',
            'clear_flag',
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
        mysql.allowed_units.return_value = ['vault/0']
        self.local_unit.return_value = 'vault/0'
        handlers.configure_vault_mysql(mysql)
        configure_vault.assert_called_once_with({
            'storage_name': 'mysql',
            'mysql_db_relation': mysql})

    @patch.object(handlers, 'configure_vault')
    def test_configure_vault_msql_noacl(self, configure_vault):
        mysql = mock.MagicMock()
        mysql.allowed_units.return_value = ['vault/1']
        self.local_unit.return_value = 'vault/0'
        handlers.configure_vault_mysql(mysql)
        configure_vault.assert_not_called()

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

    @patch.object(handlers, 'write_file')
    def test_save_etcd_client_credentials(self, write_file):
        etcd_mock = mock.MagicMock()
        etcd_mock.get_client_credentials.return_value = {
            'client_cert': 'test-cert',
            'client_key': 'test-key',
            'client_ca': 'test-ca',
        }
        handlers.save_etcd_client_credentials(etcd_mock,
                                              key='key',
                                              cert='cert',
                                              ca='ca')
        etcd_mock.get_client_credentials.assert_called_once_with()
        write_file.assert_has_calls([
            mock.call('key', 'test-key', perms=0o600),
            mock.call('cert', 'test-cert', perms=0o600),
            mock.call('ca', 'test-ca', perms=0o600),
        ])

    @patch.object(handlers, 'save_etcd_client_credentials')
    @patch.object(handlers, 'get_cluster_url')
    @patch.object(handlers, 'can_restart')
    @patch.object(handlers, 'get_api_url')
    def test_configure_vault_etcd(self, get_api_url, can_restart,
                                  get_cluster_url,
                                  save_etcd_client_credentials):
        can_restart.return_value = True
        get_api_url.return_value = 'http://this-unit:8200'
        get_cluster_url.return_value = 'http://this-unit:8201'
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
            'api_addr': 'http://this-unit:8200',
            'cluster_addr': 'http://this-unit:8201'}
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
        save_etcd_client_credentials.assert_called_with(
            etcd_mock,
            key=expected_context['etcd_tls_key_file'],
            cert=expected_context['etcd_tls_cert_file'],
            ca=expected_context['etcd_tls_ca_file'],
        )

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
        self.network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(handlers.get_api_url(), 'https://1.2.3.4:8200')
        self.network_get_primary_address.assert_called_with('access')

    def test_get_api_url_nossl(self):
        self.is_state.return_value = False
        self.network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(handlers.get_api_url(), 'http://1.2.3.4:8200')
        self.network_get_primary_address.assert_called_with('access')

    def test_get_cluster_url_ssl(self):
        self.is_state.return_value = True
        self.network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(handlers.get_cluster_url(), 'https://1.2.3.4:8201')
        self.network_get_primary_address.assert_called_with('cluster')

    def test_get_cluster_url_nossl(self):
        self.is_state.return_value = False
        self.network_get_primary_address.return_value = '1.2.3.4'
        self.assertEqual(handlers.get_cluster_url(), 'http://1.2.3.4:8201')
        self.network_get_primary_address.assert_called_with('cluster')

    def test_cluster_connected(self):
        self.config.return_value = '10.1.1.1'
        hacluster_mock = mock.MagicMock()
        handlers.cluster_connected(hacluster_mock)
        hacluster_mock.add_vip.assert_called_once_with('vault', '10.1.1.1')
        hacluster_mock.bind_resources.assert_called_once_with()

    @patch.object(handlers, 'get_api_url')
    @patch.object(handlers, 'requests')
    def test_get_vault_health(self, requests, get_api_url):
        get_api_url.return_value = "https://vault.demo.com:8200"
        mock_response = mock.MagicMock()
        mock_response.json.return_value = self._health_response
        requests.get.return_value = mock_response
        self.assertEqual(handlers.get_vault_health(),
                         self._health_response)
        requests.get.assert_called_with(
            "https://vault.demo.com:8200/v1/sys/health")
        mock_response.json.assert_called_once()

    @patch.object(handlers, '_assess_interface_groups')
    @patch.object(handlers, 'get_vault_health')
    def test_assess_status(self, get_vault_health,
                           _assess_interface_groups):
        self.is_flag_set.return_value = False
        get_vault_health.return_value = self._health_response
        _assess_interface_groups.return_value = []
        self.config.return_value = False
        self.service_running.return_value = True
        handlers._assess_status()
        self.application_version_set.assert_called_with(
            self._health_response['version'])
        self.status_set.assert_called_with(
            'active', 'Unit is ready (active: true)')
        self.config.assert_called_with('disable-mlock')
        _assess_interface_groups.assert_has_calls([
            mock.call(handlers.REQUIRED_INTERFACES,
                      optional=False,
                      missing_interfaces=mock.ANY,
                      incomplete_interfaces=mock.ANY),
            mock.call(handlers.OPTIONAL_INTERFACES,
                      optional=True,
                      missing_interfaces=mock.ANY,
                      incomplete_interfaces=mock.ANY),
        ])

    def test_assess_status_invalid_channel(self):
        self.is_flag_set.return_value = True
        self.config.return_value = 'foorbar'
        handlers._assess_status()
        self.status_set.assert_called_with(
            'blocked', 'Invalid snap channel configured: foorbar')
        self.is_flag_set.assert_called_with('snap.channel.invalid')
        self.config.assert_called_with('channel')

    @patch.object(handlers, '_assess_interface_groups')
    @patch.object(handlers, 'get_vault_health')
    def test_assess_status_not_running(self, get_vault_health,
                                       _assess_interface_groups):
        self.is_flag_set.return_value = False
        get_vault_health.return_value = self._health_response
        self.service_running.return_value = False
        handlers._assess_status()
        self.application_version_set.assert_not_called()
        self.status_set.assert_called_with(
            'blocked', 'Vault service not running')

    @patch.object(handlers, '_assess_interface_groups')
    @patch.object(handlers, 'get_vault_health')
    def test_assess_status_vault_init(self, get_vault_health,
                                      _assess_interface_groups):
        self.is_flag_set.return_value = False
        get_vault_health.return_value = self._health_response_needs_init
        _assess_interface_groups.return_value = []
        self.service_running.return_value = True
        handlers._assess_status()
        self.status_set.assert_called_with(
            'blocked', 'Vault needs to be initialized')

    @patch.object(handlers, '_assess_interface_groups')
    @patch.object(handlers, 'get_vault_health')
    def test_assess_status_vault_sealed(self, get_vault_health,
                                        _assess_interface_groups):
        self.is_flag_set.return_value = False
        get_vault_health.return_value = self._health_response_sealed
        _assess_interface_groups.return_value = []
        self.service_running.return_value = True
        handlers._assess_status()
        self.status_set.assert_called_with(
            'blocked', 'Unit is sealed')

    def test_assess_interface_groups(self):
        flags = {
            'db.master.available': True,
            'db.connected': True,
            'etcd.connected': True,
            'baz.connected': True,
        }
        self.is_flag_set.side_effect = lambda flag: flags.get(flag, False)

        missing_interfaces = []
        incomplete_interfaces = []
        handlers._assess_interface_groups(
            [['db.master', 'shared-db'],
             ['etcd'],
             ['foo', 'bar'],
             ['baz', 'boo']],
            optional=False,
            missing_interfaces=missing_interfaces,
            incomplete_interfaces=incomplete_interfaces
        )
        self.assertEqual(missing_interfaces,
                         ["'foo' or 'bar' missing"])
        self.assertEqual(incomplete_interfaces,
                         ["'etcd' incomplete",
                          "'baz' incomplete"])

    def test_snap_install(self):
        self.config.return_value = None
        handlers.snap_install()
        self.snap.install.assert_called_with('vault', channel='stable')
        self.config.assert_called_with('channel')
        self.clear_flag.assert_called_with('snap.channel.invalid')

    def test_snap_install_channel_set(self):
        self.config.return_value = 'edge'
        handlers.snap_install()
        self.snap.install.assert_called_with('vault', channel='edge')
        self.config.assert_called_with('channel')
        self.clear_flag.assert_called_with('snap.channel.invalid')

    def test_snap_install_invalid_channel(self):
        self.config.return_value = 'foorbar'
        handlers.snap_install()
        self.snap.install.assert_not_called()
        self.config.assert_called_with('channel')
        self.set_flag.assert_called_with('snap.channel.invalid')

    @patch.object(handlers, 'can_restart')
    def test_snap_refresh_restartable(self, can_restart):
        self.config.return_value = 'edge'
        can_restart.return_value = True
        handlers.snap_refresh()
        self.snap.refresh.assert_called_with('vault', channel='edge')
        self.config.assert_called_with('channel')
        self.service_restart.assert_called_with('vault')
        self.clear_flag.assert_called_with('snap.channel.invalid')

    @patch.object(handlers, 'can_restart')
    def test_snap_refresh_not_restartable(self, can_restart):
        self.config.return_value = 'edge'
        can_restart.return_value = False
        handlers.snap_refresh()
        self.snap.refresh.assert_called_with('vault', channel='edge')
        self.config.assert_called_with('channel')
        self.service_restart.assert_not_called()
        self.clear_flag.assert_called_with('snap.channel.invalid')

    def test_snap_refresh_invalid_channel(self):
        self.config.return_value = 'foorbar'
        handlers.snap_refresh()
        self.snap.refresh.assert_not_called()
        self.config.assert_called_with('channel')
        self.set_flag.assert_called_with('snap.channel.invalid')

    def test_validate_snap_channel(self):
        self.assertTrue(handlers.validate_snap_channel('stable'))
        self.assertTrue(handlers.validate_snap_channel('0.10/stable'))
        self.assertTrue(handlers.validate_snap_channel('edge'))
        self.assertTrue(handlers.validate_snap_channel('beta'))
        self.assertTrue(handlers.validate_snap_channel('candidate'))
        self.assertFalse(handlers.validate_snap_channel('foobar'))
        self.assertFalse(handlers.validate_snap_channel('0.10/foobar'))
