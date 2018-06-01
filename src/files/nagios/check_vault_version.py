#!/usr/bin/python3

#
# Copyright 2017 Canonical Ltd.
#
# Author:
#   Paul Collins <paul.collins@canonical.com>
#

import json
import socket
import ssl
import sys

from textwrap import dedent
from urllib.request import urlopen

VAULT_HEALTH_URL = 'https://127.0.0.1:8200/v1/sys/health'
VAULT_VERIFY_SSL = False

SNAPD_INFO_REQUEST = dedent("""\
    GET /v2/snaps/{snap} HTTP/1.1\r
    Host:\r
    \r
    """)

SNAPD_SOCKET = '/run/snapd.socket'


def get_vault_snap_version():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as snapd:
        snapd.connect(SNAPD_SOCKET)
        snapd.sendall(SNAPD_INFO_REQUEST.format(snap='vault').encode('utf-8'))
        # TODO(pjdc): This should be a loop.
        info = json.loads(
            snapd.recv(1024 * 1024).decode('utf-8').split('\n')[-1])
        version = info['result']['version']
        if version.startswith('v'):
            version = version[1:]
        return version


def get_vault_server_version(verify=True):
    ctx = None
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urlopen(VAULT_HEALTH_URL, context=ctx) as health:
        return json.loads(health.read().decode('utf-8'))['version']


if __name__ == '__main__':
    try:
        snapv = get_vault_snap_version()
    except Exception as e:
        print('CRITICAL: failed to fetch version of '
              'installed vault snap: {}'.format(e))
        sys.exit(2)

    try:
        serverv = get_vault_server_version(verify=VAULT_VERIFY_SSL)
    except Exception as e:
        print('CRITICAL: failed to fetch version of '
              'running vault server: {}'.format(e))
        sys.exit(2)

    if serverv == snapv:
        print('OK: running vault ({}) is the same '
              'as the installed snap ({})'.format(
                  serverv, snapv))
        sys.exit(0)

    print('CRITICAL: running vault ({}) is not the same '
          'as the installed snap ({})'.format(
              serverv, snapv))
    sys.exit(2)
