import mock
from unittest.mock import patch

import charms.reactive

# Mock out reactive decorators prior to importing reactive.vault
dec_mock = mock.MagicMock()
dec_mock.return_value = lambda x: x
charms.reactive.hook = dec_mock
charms.reactive.when = dec_mock
charms.reactive.when_not = dec_mock

import reactive.vault_handlers as handlers  # noqa: E402
import unit_tests.test_utils


class TestHandlers(unit_tests.test_utils.CharmTestCase):

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
        self.obj = handlers
        self.patches = [
            'config',
            'endpoint_from_flag',
            'is_state',
            'log',
            'network_get_primary_address',
            'open_port',
            'service_restart',
            'service_running',
            'service',
            'set_state',
            'status_set',
            'remove_state',
            'render',
            'application_version_set',
            'local_unit',
            'snap',
            'is_flag_set',
            'set_flag',
            'clear_flag',
            'is_container',
            'unitdata',
        ]
        self.patch_all()
        self.is_container.return_value = False

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

    @patch.object(handlers.vault, 'can_restart')
    def test_configure_vault(self, can_restart):
        can_restart.return_value = True
        self.config.return_value = False
        self.is_state.return_value = True
        db_context = {
            'storage_name': 'psql',
            'psql_db_conn': 'myuri'}
        self.is_flag_set.return_value = False
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
        self.config.assert_called_with('disable-mlock')

        # Check flipping disable-mlock makes it to the context
        self.config.return_value = True
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
        self.service.assert_called_with('enable', 'vault')
        self.config.assert_called_with('disable-mlock')

        # Ensure is_container will override config option
        self.config.return_value = False
        self.is_container.return_value = True
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
        self.service.assert_called_with('enable', 'vault')
        self.config.assert_called_with('disable-mlock')
        self.is_container.assert_called_with()

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
    @patch.object(handlers.vault, 'get_cluster_url')
    @patch.object(handlers.vault, 'can_restart')
    @patch.object(handlers.vault, 'get_api_url')
    def test_configure_vault_etcd(self, get_api_url, can_restart,
                                  get_cluster_url,
                                  save_etcd_client_credentials):
        can_restart.return_value = True
        get_api_url.return_value = 'http://this-unit:8200'
        get_cluster_url.return_value = 'http://this-unit:8201'
        self.config.return_value = False
        etcd_mock = mock.MagicMock()
        etcd_mock.connection_string.return_value = 'http://etcd'
        self.is_flag_set.return_value = True
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
        self.is_flag_set.assert_called_with('etcd.tls.available')
        self.config.assert_called_with('disable-mlock')

    @patch.object(handlers, '_assess_interface_groups')
    @patch.object(handlers.vault, 'get_vault_health')
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
            'active', 'Unit is ready (active: true, mlock: enabled)')
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

    @patch.object(handlers.vault, 'get_vault_health')
    def test_assess_status_service_not_running(self, get_vault_health):
        self.is_flag_set.return_value = False
        self.service_running.return_value = False
        handlers._assess_status()
        self.status_set.assert_called_with(
            'blocked', 'Vault service not running')

    @patch.object(handlers.vault, 'get_vault_health')
    def test_assess_status_empty_health(self, get_vault_health):
        self.is_flag_set.return_value = False
        self.service_running.return_value = True
        get_vault_health.return_value = {}
        handlers._assess_status()
        self.application_version_set.assert_called_with(
            'Unknown')
        self.status_set.assert_called_with(
            'blocked', 'Vault health check failed')

    def test_assess_status_invalid_channel(self):
        statuses = {
            'snap.channel.invalid': True,
            'config.dns_vip.invalid': False}
        self.is_flag_set.side_effect = lambda x: statuses[x]
        self.config.return_value = 'foorbar'
        handlers._assess_status()
        self.status_set.assert_called_with(
            'blocked', 'Invalid snap channel configured: foorbar')
        self.is_flag_set.assert_called_with('snap.channel.invalid')
        self.config.assert_called_with('channel')

    def test_assess_status_invalid_haconfig(self):
        statuses = {
            'snap.channel.invalid': False,
            'config.dns_vip.invalid': True}
        self.is_flag_set.side_effect = lambda x: statuses[x]
        handlers._assess_status()
        self.status_set.assert_called_with(
            'blocked', 'vip and dns-ha-access-record configured')
        self.is_flag_set.assert_called_with('config.dns_vip.invalid')

    @patch.object(handlers, '_assess_interface_groups')
    @patch.object(handlers.vault, 'get_vault_health')
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
    @patch.object(handlers.vault, 'get_vault_health')
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
    @patch.object(handlers.vault, 'get_vault_health')
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

    @patch.object(handlers.vault, 'can_restart')
    def test_snap_refresh_restartable(self, can_restart):
        conf = {
            'channel': 'edge',
            'totally-unsecure-auto-unlock': False}
        self.config.side_effect = lambda x: conf[x]
        can_restart.return_value = True
        handlers.snap_refresh()
        self.snap.refresh.assert_called_with('vault', channel='edge')
        self.service_restart.assert_called_with('vault')
        self.clear_flag.assert_called_with('snap.channel.invalid')
        config_calls = [
            mock.call('channel'),
            mock.call('totally-unsecure-auto-unlock')]
        self.config.assert_has_calls(config_calls)

    @patch.object(handlers.vault, 'can_restart')
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

    def test_cluster_connected_vip(self):
        charm_config = {
            'vip': '10.1.1.1'}
        self.config.side_effect = lambda x: charm_config.get(x)
        hacluster_mock = mock.MagicMock()
        handlers.cluster_connected(hacluster_mock)
        hacluster_mock.add_vip.assert_called_once_with('vault', '10.1.1.1')
        hacluster_mock.bind_resources.assert_called_once_with()
        self.clear_flag.assert_called_once_with('config.dns_vip.invalid')

    def test_cluster_connected_dnsha(self):
        charm_config = {
            'dns-ha-access-record': 'myrecord.mycopany.co.uk'}
        self.config.side_effect = lambda x: charm_config.get(x)
        self.network_get_primary_address.return_value = '10.1.100.1'
        hacluster_mock = mock.MagicMock()
        handlers.cluster_connected(hacluster_mock)
        hacluster_mock.add_dnsha.assert_called_once_with(
            'vault', '10.1.100.1', 'myrecord.mycopany.co.uk', 'access')
        hacluster_mock.bind_resources.assert_called_once_with()
        self.clear_flag.assert_called_once_with('config.dns_vip.invalid')

    def test_cluster_connected_vip_and_dnsha(self):
        charm_config = {
            'vip': '10.1.1.1',
            'dns-ha-access-record': 'myrecord.mycopany.co.uk'}
        self.config.side_effect = lambda x: charm_config.get(x)
        self.network_get_primary_address.return_value = '10.1.100.1'
        hacluster_mock = mock.MagicMock()
        handlers.cluster_connected(hacluster_mock)
        self.assertFalse(hacluster_mock.add_vip.called)
        self.assertFalse(hacluster_mock.add_dnsha.called)
        self.assertFalse(hacluster_mock.bind_resources.called)
        self.set_flag.assert_called_once_with('config.dns_vip.invalid')

    def fixture_test_requests(self):
        test_requests = []
        test_requests.append({
            'secret_backend': 'charm-vaultlocker',
            'hostname': 'juju-123456-0',
            'isolated': True,
            'access_address': '10.20.4.5',
            'unit': mock.MagicMock()
        })
        test_requests[-1]['unit'].unit_name = 'ceph-osd/0'

        test_requests.append({
            'secret_backend': 'charm-supersecrets',
            'hostname': 'juju-789012-0',
            'isolated': True,
            'access_address': '10.20.4.20',
            'unit': mock.MagicMock()
        })
        test_requests[-1]['unit'].unit_name = 'omg/0'

        return test_requests

    @mock.patch.object(handlers, 'vault')
    def test_configure_secrets_backend(self, _vault):
        hvac_client = mock.MagicMock()
        _vault.get_client.return_value = hvac_client
        # Vault is up and running, init'ed and unsealed
        hvac_client.is_initialized.return_value = True
        hvac_client.is_sealed.return_value = False
        self.service_running.return_value = True

        _vault.get_local_charm_access_role_id.return_value = 'local-approle'

        secrets_interface = mock.MagicMock()
        self.endpoint_from_flag.return_value = secrets_interface
        secrets_interface.requests.return_value = self.fixture_test_requests()
        _vault.configure_approle.side_effect = ['role_a', 'role_b']
        self.is_flag_set.return_value = False
        _vault.get_api_url.return_value = "http://vault:8200"
        hvac_client.list_roles.return_value = []
        _vault.generate_role_secret_id.return_value = 'mysecret'

        handlers.configure_secrets_backend()

        hvac_client.auth_approle.assert_called_once_with('local-approle')
        _vault.configure_secret_backend.assert_has_calls([
            mock.call(hvac_client, name='charm-vaultlocker'),
            mock.call(hvac_client, name='charm-supersecrets')
        ])

        _vault.configure_policy.assert_has_calls([
            mock.call(hvac_client, name='charm-ceph-osd-0', hcl=mock.ANY),
            mock.call(hvac_client, name='charm-omg-0', hcl=mock.ANY)
        ])

        _vault.configure_approle.assert_has_calls([
            mock.call(hvac_client, name='charm-ceph-osd-0',
                      cidr="10.20.4.5/32",
                      policies=mock.ANY),
            mock.call(hvac_client, name='charm-omg-0',
                      cidr="10.20.4.20/32",
                      policies=mock.ANY)
        ])

        secrets_interface.set_role_id.assert_has_calls([
            mock.call(unit=mock.ANY,
                      role_id='role_a',
                      token='mysecret'),
            mock.call(unit=mock.ANY,
                      role_id='role_b',
                      token='mysecret'),
        ])

        self.clear_flag.assert_has_calls([
            mock.call('endpoint.secrets.new-request'),
            mock.call('secrets.refresh'),
        ])

    @mock.patch.object(handlers, 'vault')
    def send_vault_url_and_ca(self, _vault):
        _test_config = {
            'vip': '10.5.100.1',
            'ssl-ca': 'test-ca',
        }
        self.config.side_effect = lambda key: _test_config.get(key)
        mock_secrets = mock.MagicMock()
        self.endpoint_from_flag.return_value = mock_secrets
        self.is_flag_set.return_value = False
        _vault.get_api_url.return_value = 'http://10.5.0.23:8200'
        handlers.send_vault_url_and_ca()
        self.endpoint_from_flag.assert_called_with('secrets.connected')
        self.is_flag_set.assert_called_with('ha.available')
        _vault.get_api_url.assert_called_once_with()
        mock_secrets.publish_url.assert_called_once_with(
            vault_url='http://10.5.0.23:8200'
        )
        mock_secrets.publish_ca.assert_called_once_with(
            vault_ca='test-ca'
        )

    @mock.patch.object(handlers, 'vault')
    def send_vault_url_and_ca_ha(self, _vault):
        _test_config = {
            'vip': '10.5.100.1',
            'ssl-ca': 'test-ca',
        }
        self.config.side_effect = lambda key: _test_config.get(key)
        mock_secrets = mock.MagicMock()
        self.endpoint_from_flag.return_value = mock_secrets
        self.is_flag_set.return_value = True
        _vault.get_api_url.return_value = 'http://10.5.100.1:8200'
        handlers.send_vault_url_and_ca()
        self.endpoint_from_flag.assert_called_with('secrets.connected')
        self.is_flag_set.assert_called_with('ha.available')
        _vault.get_api_url.assert_called_once_with(address='10.5.100.1')
        mock_secrets.publish_url.assert_called_once_with(
            vault_url='http://10.5.100.1:8200'
        )
        mock_secrets.publish_ca.assert_called_once_with(
            vault_ca='test-ca'
        )

    @mock.patch.object(handlers, 'vault_pki')
    def test_publish_ca_info(self, vault_pki):
        tls = self.endpoint_from_flag.return_value
        vault_pki.get_ca.return_value = 'ca'
        vault_pki.get_chain.return_value = 'chain'
        handlers.publish_ca_info()
        tls.set_ca.assert_called_with('ca')
        tls.set_chain.assert_called_with('chain')

    @mock.patch.object(handlers, 'vault_pki')
    def test_publish_global_client_cert_already_gend(self, vault_pki):
        tls = self.endpoint_from_flag.return_value
        self.is_flag_set.side_effect = [True, False]
        self.unitdata.kv().get.return_value = {'certificate': 'crt',
                                               'private_key': 'key'}
        handlers.publish_global_client_cert()
        assert not vault_pki.generate_certificate.called
        assert not self.set_flag.called
        self.unitdata.kv().get.assert_called_with('charm.vault.'
                                                  'global-client-cert')
        tls.set_client_cert.assert_called_with('crt', 'key')

    @mock.patch.object(handlers, 'vault_pki')
    def test_publish_global_client_cert_reissue(self, vault_pki):
        tls = self.endpoint_from_flag.return_value
        self.is_flag_set.side_effect = [True, True]
        bundle = {'certificate': 'crt',
                  'private_key': 'key'}
        vault_pki.generate_certificate.return_value = bundle
        handlers.publish_global_client_cert()
        vault_pki.generate_certificate.assert_called_with('client',
                                                          'global-client',
                                                          [])
        self.unitdata.kv().set.assert_called_with('charm.vault.'
                                                  'global-client-cert',
                                                  bundle)
        self.set_flag.assert_called_with('charm.vault.'
                                         'global-client-cert.created')
        tls.set_client_cert.assert_called_with('crt', 'key')

    @mock.patch.object(handlers, 'vault_pki')
    def test_publish_global_client_certe(self, vault_pki):
        tls = self.endpoint_from_flag.return_value
        self.is_flag_set.side_effect = [False, False]
        bundle = {'certificate': 'crt',
                  'private_key': 'key'}
        vault_pki.generate_certificate.return_value = bundle
        handlers.publish_global_client_cert()
        vault_pki.generate_certificate.assert_called_with('client',
                                                          'global-client',
                                                          [])
        self.unitdata.kv().set.assert_called_with('charm.vault.'
                                                  'global-client-cert',
                                                  bundle)
        self.set_flag.assert_called_with('charm.vault.'
                                         'global-client-cert.created')
        tls.set_client_cert.assert_called_with('crt', 'key')

    @mock.patch.object(handlers, 'vault_pki')
    def test_create_certs(self, vault_pki):
        tls = self.endpoint_from_flag.return_value
        self.is_flag_set.return_value = False
        tls.new_requests = [mock.Mock(cert_type='cert_type1',
                                      common_name='common_name1',
                                      sans='sans1'),
                            mock.Mock(cert_type='invalid',
                                      common_name='invalid',
                                      sans='invalid'),
                            mock.Mock(cert_type='cert_type2',
                                      common_name='common_name2',
                                      sans='sans2')]
        vault_pki.generate_certificate.side_effect = [
            {'certificate': 'crt1', 'private_key': 'key1'},
            handlers.vault.VaultInvalidRequest,
            {'certificate': 'crt2', 'private_key': 'key2'},
        ]
        handlers.create_certs()
        vault_pki.generate_certificate.assert_has_calls([
            mock.call('cert_type1', 'common_name1', 'sans1'),
            mock.call('invalid', 'invalid', 'invalid'),
            mock.call('cert_type2', 'common_name2', 'sans2'),
        ])
        tls.new_requests[0].set_cert.assert_has_calls([
            mock.call('crt1', 'key1'),
        ])
        assert not tls.new_requests[1].called
        tls.new_requests[2].set_cert.assert_has_calls([
            mock.call('crt2', 'key2'),
        ])
