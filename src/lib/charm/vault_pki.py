import json
import re
from subprocess import check_output, CalledProcessError
from tempfile import NamedTemporaryFile

import hvac

import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.core.hookenv as hookenv

from . import vault

CHARM_PKI_MP = "charm-pki-local"
CHARM_PKI_ROLE = "local"
CHARM_PKI_ROLE_CLIENT = "local-client"


def configure_pki_backend(client, name, ttl=None, max_ttl=None):
    """Ensure a pki backend is enabled

    :param client: Vault client
    :type client: hvac.Client
    :param name: Name of backend to enable
    :type name: str
    :param ttl: TTL
    :type ttl: str
    """
    if not vault.is_backend_mounted(client, name):
        client.sys.enable_secrets_engine(
            backend_type='pki',
            description='Charm created PKI backend',
            path=name,
            # Default ttl to 10 years
            config={
                'default_lease_ttl': ttl or '8759h',
                'max_lease_ttl': max_ttl or '87600h'})


def disable_pki_backend():
    """Ensure a pki backend is disabled
    """
    client = vault.get_local_client()
    if vault.is_backend_mounted(client, CHARM_PKI_MP):
        client.secrets.pki.delete_root(mount_point=CHARM_PKI_MP)
        client.secrets.pki.delete_role(CHARM_PKI_ROLE_CLIENT,
                                       mount_point=CHARM_PKI_MP)
        client.secrets.pki.delete_role(CHARM_PKI_ROLE,
                                       mount_point=CHARM_PKI_MP)
        client.sys.disable_secrets_engine(CHARM_PKI_MP)


def tune_pki_backend(ttl=None, max_ttl=None):
    """Assert tuning options for Charm PKI backend

    :param ttl: TTL
    :type ttl: str
    """
    client = vault.get_local_client()
    if vault.is_backend_mounted(client, CHARM_PKI_MP):
        client.sys.tune_mount_configuration(
            path=CHARM_PKI_MP,
            default_lease_ttl=ttl or '8759h',
            max_lease_ttl=max_ttl or '87600h')


def is_ca_ready(client, name, role):
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
    """
    try:
        # read_role raises InvalidPath is the role is not available
        client.secrets.pki.read_role(role, mount_point=name)
        return True
    except hvac.exceptions.InvalidPath:
        return False


def get_chain(name=None):
    """Get the certificate chain

    :raises hvac.exceptions.VaultDown: vault is not ready
    :raises hvac.exceptions.InvalidPath: certificate chain not found
    :returns: certificate chain data
    :rtype: str
    """
    client = vault.get_local_client()
    if not name:
        name = CHARM_PKI_MP
    response = client.secrets.pki.read_certificate('ca_chain',
                                                   mount_point=name)
    return response['data']['certificate']


def get_ca():
    """Get the root CA certificate.

    :returns: Root CA certificate
    :rtype: str
    """
    return hookenv.leader_get('root-ca')


def generate_certificate(cert_type, common_name, sans, ttl, max_ttl):
    """
    Create a certificate and key for the given CN and SANs, if requested.

    May raise VaultNotReady if called too early, or VaultInvalidRequest if
    something is wrong with the request.

    :param request: Certificate request from the tls-certificates interface.
    :type request: CertificateRequest
    :returns: The newly created cert, issuing ca and key
    :rtype: tuple
    """
    client = vault.get_local_client()
    configure_pki_backend(client, CHARM_PKI_MP, ttl, max_ttl)
    if not is_ca_ready(client, CHARM_PKI_MP, CHARM_PKI_ROLE):
        raise vault.VaultNotReady("CA not ready")
    role = None
    if cert_type == 'server':
        role = CHARM_PKI_ROLE
    elif cert_type == 'client':
        role = CHARM_PKI_ROLE_CLIENT
    else:
        raise vault.VaultInvalidRequest('Unsupported cert_type: '
                                        '{}'.format(cert_type))
    config = {}
    if sans:
        ip_sans, alt_names = sort_sans(sans)
        if ip_sans:
            config['ip_sans'] = ','.join(ip_sans)
        if alt_names:
            config['alt_names'] = ','.join(alt_names)
    try:
        response = client.secrets.pki.generate_certificate(
            role,
            common_name,
            extra_params=config,
            mount_point=CHARM_PKI_MP,
        )
        if not response['data']:
            raise vault.VaultError(response.get('warnings', 'unknown error'))
    except hvac.exceptions.InvalidRequest as e:
        raise vault.VaultInvalidRequest(str(e)) from e
    return response['data']


def get_csr(ttl=None, common_name=None, locality=None,
            country=None, province=None,
            organization=None, organizational_unit=None):
    """Generate a csr for the vault Intermediate Authority

    Depending on the configuration of the CA signing this CR some of the
    fields embedded in the CSR may have to match the CA.

    :param ttl: TTL
    :type ttl: string
    :param country: The C (Country) values in the subject field of the CSR
    :type country: string
    :param province: The ST (Province) values in the subject field of the CSR.
    :type province: string
    :param organization: The O (Organization) values in the subject field of
                         the CSR
    :type organization: string
    :param organizational_unit: The OU (OrganizationalUnit) values in the
                                subject field of the CSR.
    :type organizational_unit: string
    :param common_name: The CN (Common_Name) values in the
                                subject field of the CSR.
    :param locality: The L (Locality) values in the
                                subject field of the CSR.
    :returns: Certificate signing request
    :rtype: string
    """
    client = vault.get_local_client()
    configure_pki_backend(client, CHARM_PKI_MP)
    if common_name is None:
        common_name = (
            "Vault Intermediate Certificate Authority "
            "({})".format(CHARM_PKI_MP)
        )
    config = {
        #  Year - 1 hour
        'ttl': ttl or '87599h',
        'country': country,
        'province': province,
        'ou': organizational_unit,
        'organization': organization,
        'locality': locality}
    config = {k: v for k, v in config.items() if v}
    csr_info = client.secrets.pki.generate_intermediate(
        'internal',
        common_name,
        extra_params=config,
        mount_point=CHARM_PKI_MP,
    )
    if not csr_info['data']:
        raise vault.VaultError(csr_info.get('warnings', 'unknown error'))
    return csr_info['data']['csr']


def upload_signed_csr(pem, allowed_domains, allow_subdomains=True,
                      enforce_hostnames=False, allow_any_name=True,
                      max_ttl=None):
    """Upload signed csr to intermediate pki

    :param pem: signed csr in pem format
    :type pem: string
    :param allow_subdomains: Specifies if clients can request certificates with
                             CNs that are subdomains of the CNs:
    :type allow_subdomains: bool
    :param enforce_hostnames: Specifies if only valid host names are allowed
                              for CNs, DNS SANs, and the host part of email
                              addresses.
    :type enforce_hostnames: bool
    :param allow_any_name: Specifies if clients can request any CN
    :type allow_any_name: bool
    :param max_ttl: Specifies the maximum Time To Live
    :type max_ttl: str
    """
    client = vault.get_local_client()
    # Set the intermediate certificate authorities signing certificate to the
    # signed certificate.
    client.secrets.pki.set_signed_intermediate(
        pem.rstrip(),
        mount_point=CHARM_PKI_MP
    )
    # Generated certificates can have the CRL location and the location of the
    # issuing certificate encoded.
    addr = vault.get_access_address()
    client.secrets.pki.set_urls(
        {
            "issuing_certificates": "{}/v1/{}/ca".format(addr, CHARM_PKI_MP),
            "crl_distribution_points":
            "{}/v1/{}/crl".format(addr, CHARM_PKI_MP),
        },
        mount_point=CHARM_PKI_MP
    )
    # Configure a role which maps to a policy for accessing this pki
    if not max_ttl:
        max_ttl = '87598h'
    write_roles(client,
                allow_any_name=allow_any_name,
                allowed_domains=allowed_domains,
                allow_subdomains=allow_subdomains,
                enforce_hostnames=enforce_hostnames,
                max_ttl=max_ttl,
                client_flag=True)


def generate_root_ca(ttl='87599h', allow_any_name=True, allowed_domains=None,
                     allow_bare_domains=False, allow_subdomains=False,
                     allow_glob_domains=True, enforce_hostnames=False,
                     max_ttl='87598h'):
    """Configure Vault to generate a self-signed root CA.

    :param ttl: TTL of the root CA certificate
    :type ttl: string
    :param allow_any_name: Specifies if clients can request certs for any CN.
    :type allow_any_name: bool
    :param allow_any_name: List of CNs for which clients can request certs.
    :type allowed_domains: list
    :param allow_bare_domains: Specifies if clients can request certs for CNs
                               exactly matching those in allowed_domains.
    :type allow_bare_domains: bool
    :param allow_subdomains: Specifies if clients can request certificates with
                             CNs that are subdomains of those in
                             allowed_domains, including wildcard subdomains.
    :type allow_subdomains: bool
    :param allow_glob_domains: Specifies whether CNs in allowed-domains can
                               contain glob patterns (e.g.,
                               'ftp*.example.com'), in which case clients will
                               be able to request certificates for any CN
                               matching the glob pattern.
    :type allow_glob_domains: bool
    :param enforce_hostnames: Specifies if only valid host names are allowed
                              for CNs, DNS SANs, and the host part of email
                              addresses.
    :type enforce_hostnames: bool
    :param max_ttl: Specifies the maximum Time To Live for generated certs.
    :type max_ttl: str
    """
    client = vault.get_local_client()
    configure_pki_backend(client, CHARM_PKI_MP)
    if is_ca_ready(client, CHARM_PKI_MP, CHARM_PKI_ROLE):
        raise vault.VaultError('PKI CA already configured')
    config = {
        'ttl': ttl,
    }
    common_name = "Vault Root Certificate Authority ({})".format(CHARM_PKI_MP)
    csr_info = client.secrets.pki.generate_root(
        'internal',
        common_name,
        extra_params=config,
        mount_point=CHARM_PKI_MP,
    )
    if not csr_info['data']:
        raise vault.VaultError(csr_info.get('warnings', 'unknown error'))
    cert = csr_info['data']['certificate']
    # Generated certificates can have the CRL location and the location of the
    # issuing certificate encoded.
    addr = vault.get_access_address()
    client.secrets.pki.set_urls(
        {
            "issuing_certificates": "{}/v1/{}/ca".format(addr, CHARM_PKI_MP),
            "crl_distribution_points":
            "{}/v1/{}/crl".format(addr, CHARM_PKI_MP),
        },
        mount_point=CHARM_PKI_MP
    )

    write_roles(client,
                allow_any_name=allow_any_name,
                allowed_domains=allowed_domains,
                allow_bare_domains=allow_bare_domains,
                allow_subdomains=allow_subdomains,
                allow_glob_domains=allow_glob_domains,
                enforce_hostnames=enforce_hostnames,
                max_ttl=max_ttl,
                client_flag=True)
    return cert


def sort_sans(sans):
    """
    Split SANs into IP SANs and name SANs

    :param sans: List of SANs
    :type sans: list
    :returns: List of IP SANs and list of name SANs
    :rtype: ([], [])
    """
    ip_sans = {s for s in sans if ch_ip.is_ip(s)}
    alt_names = set(sans).difference(ip_sans)
    return sorted(list(ip_sans)), sorted(list(alt_names))


def write_roles(client, **kwargs):
    # Configure a role for using this PKI to issue server certs
    client.secrets.pki.create_or_update_role(
        CHARM_PKI_ROLE,
        extra_params={
            'server_flag': True,
            **kwargs,
        },
        mount_point=CHARM_PKI_MP,
    )
    # Configure a role for using this PKI to issue client-only certs
    client.secrets.pki.create_or_update_role(
        CHARM_PKI_ROLE_CLIENT,
        extra_params={
            # client certs cannot be used as server certs
            'server_flag': False,
            **kwargs,
        },
        mount_point=CHARM_PKI_MP,
    )


def update_roles(**kwargs):
    client = vault.get_local_client()
    # local and local-client contain the same data except for server_flag,
    # so we only need to read one, but update both
    local = client.secrets.pki.read_role(
        CHARM_PKI_ROLE, mount_point=CHARM_PKI_MP
    )['data']
    # the reason we handle as kwargs here is because updating n-1 fields
    # causes all the others to reset. Therefore we always need to read what
    # the current values of all fields are, and apply all of them as well
    # so they are not reset. In case of new fields are added in the future,
    # this code makes sure that they are not reset automatically (if set
    # somewhere else in code) when this function is invoked.
    local.update(**kwargs)
    del local['server_flag']
    write_roles(client, **local)


def is_cert_from_vault(cert, name=None):
    """Return True if the cert is issued by vault and not revoked.

    Looking at the cert, check to see if it was issued by Vault and not on the
    revoked list.  In order to do this, the cert must be in x509 format as
    openssl is used to extract the ID of the cert. Then the certificate is
    extracted from vault and the signatures compared.

    :param cert: the certificate in x509 form
    :type cert: str
    :param name: the mount point in value, default CHARM_PKI_MP
    :type name: str
    :returns: True if issued by vault, False if unknown.
    :raises VaultDown: if vault is down.
    :raises VaultNotReady: if vault is sealed.
    :raises VaultError: for any other vault issue.
    """
    # first get the ID from the client
    serial = get_serial_number_from_cert(cert)
    if serial is None:
        return False

    try:
        # now get a list of serial numbers from vault.
        client = vault.get_local_client()
        if not name:
            name = CHARM_PKI_MP
        vault_certs_response = client.secrets.pki.list_certificates(
            mount_point=name)
        vault_certs = [k.replace('-', '').upper()
                       for k in vault_certs_response['data']['keys']]

        if serial not in vault_certs:
            hookenv.log("Certificate with serial {} not issed by vault."
                        .format(serial), level=hookenv.DEBUG)
            return False
        revoked_serials = get_revoked_serials_from_vault(name)
        if serial in revoked_serials:
            hookenv.log("Serial {} is revoked.".format(serial),
                        level=hookenv.DEBUG)
            return False
        return True
    except (
        vault.hvac.exceptions.InvalidPath,
        vault.hvac.exceptions.InternalServerError,
        vault.hvac.exceptions.VaultDown,
        vault.VaultNotReady,
    ):
        # vault is not available for some reason, return None, None as nothing
        # else is particularly useful here.
        return False
    except Exception as e:
        hookenv.log("General failure verifying cert: {}".format(str(e)),
                    level=hookenv.DEBUG)
        return False


def get_serial_number_from_cert(cert, name=None):
    """Extract the serial number from the cert, or return None.

    :param cert: the certificate in x509 form
    :type cert: str
    :returns: the cert serial number or None.
    :rtype: str | None
    """
    with NamedTemporaryFile() as f:
        f.write(cert.encode())
        f.flush()
        command = ["openssl", "x509", "-in", f.name, "-noout", "-serial"]
        try:
            # output in form of 'serial=xxxxx'
            output = check_output(command).decode().strip()
            serial = output.split("=")[1]
            return serial
        except CalledProcessError as e:
            hookenv.log("Couldn't process certificate: reason: {}"
                        .format(str(e)),
                        level=hookenv.DEBUG)
        except (TypeError, IndexError):
            hookenv.log(
                "Couldn't extract serial number from passed certificate",
                level=hookenv.DEBUG)
    return None


def get_revoked_serials_from_vault(name=None):
    """Get a list of revoked serial numbers from vault.

    This fetches the CRL from vault; this is in PEM format. We ought to use
    python cryptography.x509.load_pem_x509_crl(), but adding cryptography
    requires converting the charm to binary, and seems a lot for one function.

    Thus, the format for no certificates revoked is:

    .. code-block:: text

       Certificate Revocation List (CRL):
               Version 2 (0x1)
               Signature Algorithm: sha256WithRSAEncryption
               Issuer: CN = Vault Intermediate Certificate Authority ...
               Last Update: Jul 17 11:58:57 2023 GMT
               Next Update: Jul 20 11:58:57 2023 GMT
       No Revoked Certificates.
           Signature Algorithm: sha256WithRSAEncryption
           Signature Value:
               ...

    And for two (and the pattern repeats):

    .. code-block:: text

       Certificate Revocation List (CRL):
               Version 2 (0x1)
               Signature Algorithm: sha256WithRSAEncryption
               Issuer: CN = Vault Intermediate Certificate Authority ...
               Last Update: Jul 18 11:38:17 2023 GMT
               Next Update: Jul 21 11:38:17 2023 GMT
       Revoked Certificates:
           Serial Number: 6EAE52225CB7AB452F37D4FBAC127DDF9542D3DC
               Revocation Date: Jul 18 11:38:17 2023 GMT
           Serial Number: 78FBEEE4E419C5A335113E4F1EF41F463534B698
               Revocation Date: Jul 18 11:33:36 2023 GMT
           Signature Algorithm: sha256WithRSAEncryption
           Signature Value:

    Thus we just need to grep the output for "Serial Number:"

    :param name: the mount point in value, default CHARM_PKI_MP
    :type name: str
    :returns: a list of serial numbers, uppercase, no hyphens
    :rtype: List[str]
    :raises VaultDown: if vault is down.
    :raises VaultNotReady: if vault is sealed.
    :raises VaultError: for any other vault issue.
    :raises subprocess.CalledProcessError: if openssl command fails
    """
    client = vault.get_local_client()
    revoked_certs_response = client.secrets.pki.read_crl(mount_point=name)
    with NamedTemporaryFile() as f:
        f.write(revoked_certs_response.encode())
        f.flush()
        command = ["openssl", "crl", "-in", f.name, "-noout", "-text"]
        output = check_output(command).decode().strip()
    pattern = re.compile(r"Serial Number: (\S+)$")
    serials = []
    # for line in output.split("\n"):
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            serials.append(match[1])
    return serials


class CertCache:
    """A class to store the cert and key for a request.

    This class provides a mechanism to CRUD a cached pair of (cert, key) in
    storage, which is as loosely coupled to leader storage as possible.

    As the key and cert is stored in leader settings, it's available across the
    units and therefore, any unit can access the key and cert for any unit that
    is related to the application.

    The actually storing of the key and cert is done in as flat a way as
    possible in leader-settings.  This is to minimise the size of the
    get and store operations for units that might have many certificate
    requests.  The key and cert are stored as values to a key which is
    constructed from the unit_name, publish_key, common_name and item.  See
    PUBLISH_KEY_FORMAT for details.

    Although, it has a dependency on the request (from tls_certificates), this
    was deemed acceptable to keep the interface obvious and pleasing to use.
    """
    PUBLISH_KEY_FORMAT = "pki:{unit_name}:{publish_key}:{common_name}:{item}"
    PUBLISH_KEY_PREFIX = "pki:{unit_name}:"
    TOP_LEVEL_PUBLISH_KEY = "top_level_publish_key"

    def __init__(self, request):
        """Initialise a proxy for the the cert and key in leader-settings.

        :param request: the request from which the cert/cache is cached.
        :type request: tls_certificates_common.CertificateRequest
        """
        self._request = request

    def _cache_key_for(self, item):
        """
        Return a cache key for the request by the item.

        :param item: the item to return a key for, either 'cert' or 'key'
        :type item: str
        :returns: the unique key for the unit, request, and item
        :rtype: str
        """
        assert item in ('cert', 'key'), "Error in argument passed"
        if self._request._is_top_level_server_cert:
            return self.PUBLISH_KEY_FORMAT.format(
                unit_name=self._request.unit_name,
                publish_key=self.TOP_LEVEL_PUBLISH_KEY,
                common_name=self._request.common_name,
                item=item)
        else:
            return self.PUBLISH_KEY_FORMAT.format(
                unit_name=self._request.unit_name,
                publish_key=self._request._publish_key,
                common_name=self._request.common_name,
                item=item)

    @staticmethod
    def _fetch(key):
        """Fetch from the storage using a store pre key and key.

        Note the _store() method dumps it as json so it is fetched as json.

        :param key: the key value to fetch from leader settings
        :type key: str
        :returns: the value from leader settings or ""
        :rtype: str
        """
        value = hookenv.leader_get(key)
        if value:
            if key is not None:
                # load the value that was json serialised in _store()
                return json.loads(value)
            else:
                # due to a weird asymetry been leader_set and leader_get,
                # leader_get() already deserialises as json so if no key was
                # specified, it's already been deserialised.
                return value
        return ""

    @staticmethod
    def _store(key, value):
        """Store a value by key into the actual storage.

        :param key: the key value to set in leader settings
        :type key: str
        :param value: the value to store.
        :type value: str
        :raises: RuntimeError if not the leader
        :raises: TypeError if value couldn't be converted.
        """
        try:
            hookenv.leader_set({key: json.dumps(value)})
        except TypeError:
            raise
        except Exception as e:
            raise RuntimeError(str(e))

    @staticmethod
    def _clear(key):
        """Explicitly clear a valye in the actual storage.

        :param key: the key value to clear.
        :type key: str
        :raises: RuntimeError if not the leader
        :raises: TypeError if value couldn't be converted.
        """
        try:
            hookenv.leader_set({key: None})
        except Exception as e:
            raise RuntimeError(str(e))

    def clear(self):
        self._clear(self._cache_key_for('key'))
        self._clear(self._cache_key_for('cert'))

    @property
    def key(self):
        """Get the key."""
        return self._fetch(self._cache_key_for('key'))

    @key.setter
    def key(self, key_value):
        """Set the key value."""
        self._store(self._cache_key_for('key'), key_value)

    @property
    def cert(self):
        """The the cert."""
        return self._fetch(self._cache_key_for('cert'))

    @cert.setter
    def cert(self, cert_value):
        """Set the cert value."""
        self._store(self._cache_key_for('cert'), cert_value)

    @classmethod
    def remove_all_for(cls, unit_name):
        """Remove all the cached keys for a unit name.

        This is an awkward function, as the cache in leader settings is 'flat'
        to ensure that the set payloads are as small as possible.

        This iterates through all the keys and if they match the prefix for the
        unit_name, it clears them.

        :param unit_name: The unit_name to clear.
        :type unit_name: str
        """
        prefix = cls.PUBLISH_KEY_PREFIX.format(unit_name=unit_name)
        leader_keys = (cls._fetch(None) or {}).keys()
        for key in leader_keys:
            if key.startswith(prefix):
                cls._clear(key)


def find_cert_in_cache(request):
    """Return certificate and key from cache that match the request.

    Returned certificate is validated against the current CA cert. If CA cert
    is missing then the function returns (None, None).

    If the certificate can't be found in vault, then a warning is logged, but
    the cert is still returned as it is in leader_settings; the leader may
    decide to remove it at a later date.

    :param request: Request for certificate from "client" unit.
    :type request: tls_certificates_common.CertificateRequest
    :return: Certificate and private key from cache
    :rtype: (str, str) | (None, None)
    """
    request_pki_cache = CertCache(request)
    cert = request_pki_cache.cert
    key = request_pki_cache.key
    if cert is None or key is None:
        return None, None

    if not is_cert_from_vault(cert, name=CHARM_PKI_MP):
        hookenv.log('Certificate from cache for "{}" (cn: "{}") was not found '
                    'in vault, but is in the cache. Using, but may not be '
                    'valid.'.format(request.unit_name, request.common_name),
                    level=hookenv.WARNING)
    return cert, key


def update_cert_cache(request, cert, key):
    """Store certificate and key in the cache.

    Stored values are associated with the request from "client" unit,
    so it can be later retrieved when the request is handled again.

    :param request: Request for certificate from "client" unit.
    :type request: tls_certificates_common.CertificateRequest
    :param cert: Issued certificate for the "client" request (in PEM format)
    :type cert: str
    :param key: Issued private key from the "client" request (in PEM format)
    :type key: str
    :return: None
    """
    request_pki_cache = CertCache(request)
    hookenv.log('Saving certificate for "{}" '
                '(cn: "{}") into cache.'.format(request.unit_name,
                                                request.common_name),
                hookenv.DEBUG)

    request_pki_cache.key = key
    request_pki_cache.cert = cert


def remove_unit_from_cache(unit_name):
    """Clear certificates and keys related to the unit from the cache.

    :param unit_name: Name of the unit to be removed from the cache.
    :type unit_name: str
    :return: None
    """
    hookenv.log('Removing certificates for unit "{}" from '
                'cache.'.format(unit_name), hookenv.DEBUG)
    CertCache.remove_all_for(unit_name)


def populate_cert_cache(tls_endpoint):
    """Store previously issued certificates in the cache.

    This function is used when vault charm is upgraded from older version
    that may not have a certificate cache to a version that has it. It
    goes through all previously issued certificates and stores them in
    cache.

    :param tls_endpoint: Endpoint of "certificates" relation
    :type tls_endpoint: interface_tls_certificates.provides.TlsProvides
    :return: None
    """
    hookenv.log(
        "Populating certificate cache with data from relations", hookenv.INFO
    )

    for request in tls_endpoint.all_requests:
        try:
            if request._is_top_level_server_cert:
                relation_data = request._unit.relation.to_publish_raw
                cert = relation_data[request._server_cert_key]
                key = relation_data[request._server_key_key]
            else:
                relation_data = request._unit.relation.to_publish
                cert = relation_data[request._publish_key][
                    request.common_name
                ]['cert']
                key = relation_data[request._publish_key][
                    request.common_name
                ]['key']
        except (KeyError, TypeError):
            if request._is_top_level_server_cert:
                cert_id = request._server_cert_key
            else:
                cert_id = request.common_name
            hookenv.log(
                'Certificate "{}" (or associated key) issued for unit "{}" '
                'not found in relation data.'.format(
                    cert_id, request._unit.unit_name
                ),
                hookenv.WARNING
            )
            continue

        update_cert_cache(request, cert, key)


def set_global_client_cert(bundle):
    """Set the global cert for all units in the app.

    :param bundle: the bundle returned from generate_certificates()
    :type bundle: Dict[str, str]
    :raises: RuntimeError if leader_set fails.
    :raises: TypeError if the bundle can't be serialised.
    """
    try:
        hookenv.leader_set(
            {'charm.vault.global-client-cert': json.dumps(bundle)})
    except TypeError:
        raise
    except Exception as e:
        raise RuntimeError("Couldn't run leader_settings: {}".format(str(e)))


def get_global_client_cert():
    """Return the bundle returned from leader_settings.

    Will return an empty dictionary if key is not present.

    :returns: the bundle previously stored, or {}
    :rtype: Dict[str, str]
    """
    bundle = hookenv.leader_get('charm.vault.global-client-cert')
    if bundle:
        return json.loads(bundle)
    return {}
