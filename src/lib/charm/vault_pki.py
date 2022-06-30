import hvac
import json

from subprocess import check_output, CalledProcessError
from tempfile import NamedTemporaryFile

import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.core.hookenv as hookenv

from . import vault

CHARM_PKI_MP = "charm-pki-local"
CHARM_PKI_ROLE = "local"
CHARM_PKI_ROLE_CLIENT = "local-client"

PKI_CACHE_KEY = "pki"
TOP_LEVEL_CERT_KEY = "top_level"


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
    return client.secrets.pki.read_role(role, mount_point=name) is not None


def get_chain(name=None):
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
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


def verify_cert(ca_cert, untrusted_cert):
    """Verify that the 'untrusted_cert' is signed by the 'ca_cert'.

    :param ca_cert: CA certificate that should sign the untrusted cert.
    :param untrusted_cert: Certificate that is verified by the CA cert.
    :return: True if CA cert can verify the untrusted cert
    :rtype: bool
    """
    with NamedTemporaryFile() as ca_file, NamedTemporaryFile() as cert_file:
        ca_file.write(ca_cert.encode("UTF-8"))
        ca_file.flush()

        cert_file.write(untrusted_cert.encode("UTF-8"))
        cert_file.flush()

        try:
            verify_cmd = ['openssl', 'verify', '-CAfile',
                          ca_file.name, cert_file.name]
            check_output(verify_cmd)
        except CalledProcessError as exc:
            hookenv.log(
                "Certificate verification failed: {}".format(exc.output),
                hookenv.WARNING
            )
            return False
        else:
            return True


def get_pki_cache():
    """Fetch and parse PKI from the leader storage.

    Returned dictionary contains certificates and keys issued by the vault
    leader unit as a response to requests from other charms. The structure
    loosely matches the format in which the certificates are shared via data
    in the `tls-certificates` relation.
    See `tls_certificates_common.CertificateRequest.set_cert()` for more info
    on the structure.

    :return: Dictionary containing certs and keys generated by the leader unit
    :rtype: dict
    """
    raw_cache = hookenv.leader_get(PKI_CACHE_KEY) or '{}'
    return json.loads(raw_cache)


def find_cert_in_cache(request):
    """Return certificate and key from cache that match the request.

    Returned certificate is validated against the current CA cert. If CA cert
    is missing, or certificate fails validation or it's simply not found,
    returned value is None, None

    :param request: Request for certificate from "client" unit.
    :type request: tls_certificates_common.CertificateRequest
    :return: Certificate and private key from cache
    :rtype: Union[(str, str), (None, None)]
    """
    try:
        ca_chain = get_chain()
    except (hvac.exceptions.VaultDown, TypeError):
        # Fetching CA chain may fail
        ca_chain = None

    ca_cert = ca_chain or get_ca()
    if not ca_cert:
        hookenv.log('CA cert not found. Skipping certificate cache lookup.',
                    hookenv.DEBUG)
        return None, None

    pki_cache = get_pki_cache()
    unit_data = pki_cache.get(request.unit_name, {})

    try:
        if request._is_top_level_server_cert:
            cert = unit_data[TOP_LEVEL_CERT_KEY][request._server_cert_key]
            key = unit_data[TOP_LEVEL_CERT_KEY][request._server_key_key]
        else:
            cert = unit_data[request._publish_key][request.common_name]['cert']
            key = unit_data[request._publish_key][request.common_name]['key']
    except (KeyError, TypeError):
        hookenv.log('Certificate for "{}" (cn: "{}") not found in '
                    'cache.'.format(request.unit_name, request.common_name),
                    hookenv.DEBUG)
        return None, None

    if verify_cert(ca_cert, cert):
        return cert, key
    else:
        hookenv.log('Certificate from cache for "{}" (cn: "{}") is no longer'
                    'valid and wont be reused.'.format(request.unit_name,
                                                       request.common_name))
        return None, None


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
    pki_cache = get_pki_cache()
    unit_cache = pki_cache.get(request.unit_name, {})

    if request._is_top_level_server_cert:
        unit_cache[TOP_LEVEL_CERT_KEY] = {
            request._server_cert_key: cert,
            request._server_key_key: key,
        }
    else:
        structured_certs = unit_cache.get(request._publish_key, {})
        structured_certs[request.common_name] = {
            'cert': cert,
            'key': key,
        }
        unit_cache[request._publish_key] = structured_certs

    hookenv.log('Saving certificate for "{}" '
                '(cn: "{}") into cache.'.format(request.unit_name,
                                                request.common_name),
                hookenv.DEBUG)
    pki_cache[request.unit_name] = unit_cache
    hookenv.leader_set({PKI_CACHE_KEY: json.dumps(pki_cache)})


def remove_unit_from_cache(unit_name):
    """Clear certificates and keys related to the unit from the cache.

    :param unit_name: Name of the unit to be removed from the cache.
    :type unit_name: str
    :return: None
    """
    hookenv.log('Removing certificates for unit "{}" from '
                'cache.'.format(unit_name), hookenv.DEBUG)
    pki_cache = get_pki_cache()
    pki_cache.pop(unit_name, None)
    hookenv.leader_set({PKI_CACHE_KEY: json.dumps(pki_cache)})


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
