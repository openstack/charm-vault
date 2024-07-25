#!/usr/bin/python3

#
# Copyright 2017 Canonical Ltd.
#
# Author:
#   Paul Collins <paul.collins@canonical.com>
#

import json
import re
import ssl
import subprocess
import sys

from urllib.request import urlopen

VAULT_HEALTH_URL = 'http://127.0.0.1:8220/v1/sys/health?standbycode=200&'\
                   'drsecondarycode=200&'\
                   'performancestandbycode=200&'\
                   'sealedcode=200&'\
                   'uninitcode=200'
VAULT_VERIFY_SSL = False


def get_vault_snap_version():
    """Returns the vault snap version installed.

    Returns the version of the vault snap installed. This is taken
    from the output of the `snap info vault` command.

    :returns: the version string for the snap installed
    :raises: subprocess.CalledProcessError if the command to get the
             snap version information fails
    :raises: ValueError if the version string cannot be determined.
    """
    try:
        output = subprocess.check_output(["snap", "info", "vault"],
                                         encoding=("utf-8"))
    except subprocess.CalledProcessError:
        # This is captured in the calling code and results in a
        # CRITICAL printed to the output
        raise

    # Search for the line that starts with "installed: ..."
    # to parse the version string. If the snap is not installed,
    # this line will not be present in the output.
    match = re.search(r'^installed:\s*(?P<version>[version:\w.-]*).*$',
                      output, flags=re.M)
    version = None
    if match:
        version = match.group('version')

    if version is None:
        raise ValueError("Unable to determine version from output. "
                         "Is vault snap installed?")

    # The snap versions adopt the actual vault version. If for some reason
    # this starts with a v, then strip it off. Note: this is carry over
    # from the previous incarnation of this code and likely unnecessary.
    if version.startswith("v"):
        version = version[1:]

    return version


def get_vault_server_health(verify=True):
    ctx = None
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    with urlopen(VAULT_HEALTH_URL, context=ctx) as health:
        return json.loads(health.read().decode('utf-8'))


if __name__ == '__main__':
    try:
        snapv = get_vault_snap_version()
    except Exception as e:
        print('CRITICAL: failed to fetch version of '
              'installed vault snap: {}'.format(e))
        sys.exit(2)

    try:
        health = get_vault_server_health(verify=VAULT_VERIFY_SSL)
    except Exception as e:
        print('CRITICAL: failed to fetch health of '
              'running vault server: {}'.format(e))
        sys.exit(2)

    if health['sealed'] is True:
        print('CRITICAL: vault is sealed.')
        sys.exit(2)

    serverv = health['version']
    if serverv == snapv:
        print('OK: running vault ({}) is the same '
              'as the installed snap ({})'.format(
                  serverv, snapv))
        sys.exit(0)

    print('WARNING: running vault ({}) is not the same '
          'as the installed snap ({})'.format(
              serverv, snapv))
    sys.exit(1)
