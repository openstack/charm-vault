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

    @patch.object(handlers, 'is_state')
    @patch.object(handlers, 'config')
    @patch.object(handlers, 'open_port')
    @patch.object(handlers, 'service_start')
    @patch.object(handlers, 'render')
    @patch.object(handlers, 'status_set')
    @patch.object(handlers, 'remove_state')
    def test_configure_vault(self, remove_state, status_set, render,
                             service_start, open_port, config, is_state):
        config.return_value = {'disable-mlock': False}
        is_state.return_value = True
        psql = mock.MagicMock()
        psql = mock.MagicMock()
        psql.master = 'myuri'
        handlers.configure_vault(psql)
        expected_context = {
            'db_conn': 'myuri',
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
        open_port.assert_called_once_with(8200)
        status_set.assert_has_calls(status_set_calls)
        render.assert_has_calls(render_calls)

        # Check flipping disable-mlock makes it to the context
        config.return_value = {'disable-mlock': True}
        expected_context['disable_mlock'] = True
        handlers.configure_vault(psql)
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
        render.assert_has_calls(render_calls)

    @patch.object(handlers, 'remove_state')
    def test_disable_mlock_changed(self, remove_state):
        handlers.disable_mlock_changed()
        remove_state.assert_called_once_with('configured')

    @patch.object(handlers, 'remove_state')
    def test_upgrade_charm(self, remove_state):
        calls = [mock.call('configured'),
                 mock.call('vault.nrpe.configured'),
                 mock.call('vault.ssl.configured')]
        handlers.upgrade_charm()
        remove_state.assert_has_calls(calls)

    def test_request_db(self):
        psql = mock.MagicMock()
        handlers.request_db(psql)
        psql.set_database.assert_called_once_with('vault')

    @patch.object(handlers, 'set_state')
    @patch.object(handlers, 'psycopg2')
    @patch.object(handlers, 'status_set')
    def test_create_vault_table(self, status_set, psycopg2, set_state):
        psql = mock.MagicMock()
        psql.master = 'myuri'
        handlers.create_vault_table(psql)
        db_calls = [
            mock.call(handlers.VAULT_TABLE_DDL),
            mock.call(handlers.VAULT_INDEX_DDL),
        ]
        psycopg2.connect().cursor().execute.assert_has_calls(db_calls)

    @patch.object(handlers, 'remove_state')
    def test_database_not_ready(self, remove_state):
        handlers.database_not_ready()
        remove_state.assert_called_once_with('vault.schema.created')
