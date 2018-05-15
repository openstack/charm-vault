import datetime
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID, ExtensionOID

import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.core.hookenv as hookenv

from . import vault

CHARM_PKI_MP = "charm-pki-local"
CHARM_PKI_ROLE = "local"


def configure_pki_backend(client, name, ttl=None):
    """Ensure a pki backend is enabled

    :param client: Vault client
    :type client: hvac.Client
    :param name: Name of backend to enable
    :type name: str
    :param ttl: TTL
    :type ttl: str
    """
    if not vault.is_backend_mounted(client, name):
        client.enable_secret_backend(
            backend_type='pki',
            description='Charm created PKI backend',
            mount_point=name,
            # Default ttl to 1 Year
            config={'max-lease-ttl': ttl or '87600h'})


def is_ca_ready(client, name, role):
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
    """
    return client.read('{}/roles/{}'.format(name, role)) is not None


def get_chain(name=None):
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
    """
    client = vault.get_local_client()
    if not name:
        name = CHARM_PKI_MP
    return client.read('{}/cert/ca_chain'.format(name))['data']['certificate']


def get_ca():
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
    """
    return hookenv.leader_get('root-ca')


def get_server_certificate(cn, ip_sans=None, alt_names=None):
    """Create a certificate and key for the given cn inc sans if requested

    :param cn: Common name to use for certifcate
    :type cn: string
    :param ip_sans: List of IP address to create san records for
    :type ip_sans: [str1,...]
    :param alt_names: List of names to create san records for
    :type alt_names: [str1,...]
    :raises: vault.VaultNotReady
    :returns: The newly created cert, issuing ca and key
    :rtype: tuple
    """
    client = vault.get_local_client()
    configure_pki_backend(client, CHARM_PKI_MP)
    if is_ca_ready(client, CHARM_PKI_MP, CHARM_PKI_ROLE):
        config = {
            'common_name': cn}
        if ip_sans:
            config['ip_sans'] = ','.join(ip_sans)
        if alt_names:
            config['alt_names'] = ','.join(alt_names)
        bundle = client.write(
            '{}/issue/{}'.format(CHARM_PKI_MP, CHARM_PKI_ROLE),
            **config)['data']
    else:
        raise vault.VaultNotReady("CA not ready")
    return bundle


def get_csr(ttl=None, country=None, province=None,
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
    :returns: Certificate signing request
    :rtype: string
    """
    client = vault.get_local_client()
    if not vault.is_backend_mounted(client, CHARM_PKI_MP):
        configure_pki_backend(client, CHARM_PKI_MP)
    config = {
        'common_name': ("Vault Intermediate Certificate Authority "
                        "({})".format(CHARM_PKI_MP)),
        #  Year - 1 hour
        'ttl': ttl or '87599h',
        'country': country,
        'province': province,
        'ou': organizational_unit,
        'organization': organization}
    config = {k: v for k, v in config.items() if v}
    csr_info = client.write(
        '{}/intermediate/generate/internal'.format(CHARM_PKI_MP),
        **config)
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
    # (hvac module doesn't expose a method for this, hence the _post call)
    client._post(
        'v1/{}/intermediate/set-signed'.format(CHARM_PKI_MP),
        json={'certificate': pem})
    # Generated certificates can have the CRL location and the location of the
    # issuing certificate encoded.
    addr = vault.get_access_address()
    client.write(
        '{}/config/urls'.format(CHARM_PKI_MP),
        issuing_certificates="{}/v1/{}/ca".format(addr, CHARM_PKI_MP),
        crl_distribution_points="{}/v1/{}/crl".format(addr, CHARM_PKI_MP)
    )
    # Configure a role which maps to a policy for accessing this pki
    if not max_ttl:
        max_ttl = '87598h'
    client.write(
        '{}/roles/{}'.format(CHARM_PKI_MP, CHARM_PKI_ROLE),
        allowed_domains=allowed_domains,
        allow_subdomains=allow_subdomains,
        enforce_hostnames=enforce_hostnames,
        allow_any_name=allow_any_name,
        max_ttl=max_ttl)


def sort_sans(sans):
    """Split SANS into IP sans and name SANS

    :param sans: List of SANS
    :type sans: list
    :returns: List of IP sans and list of Name SANS
    :rtype: ([], [])
    """
    ip_sans = {s for s in sans if ch_ip.is_ip(s)}
    alt_names = set(sans).difference(ip_sans)
    return sorted(list(ip_sans)), sorted(list(alt_names))


def get_vault_units():
    """Return all vault units related to this one

    :returns: List of vault units
    :rtype: []
    """
    peer_rid = hookenv.relation_ids('cluster')[0]
    vault_units = [hookenv.local_unit()]
    vault_units.extend(hookenv.related_units(relid=peer_rid))
    return vault_units


def get_matching_cert_from_relation(unit_name, cn, ip_sans, alt_names):
    """Scan vault units relation data for a cert that matches

       Scan the relation data that each vault unit has sent to the clients
       to find a cert that matchs the cn and sans. If one exists return it.
       If mutliple are found then return the one with the lastest valid_to
       date

    :param unit_name: Return the unit_name to look for serts for.
    :type unit_name: string
    :param cn: Common name to use for certifcate
    :type cn: string
    :param ip_sans: List of IP address to create san records for
    :type ip_sans: [str1,...]
    :param alt_names: List of names to create san records for
    :type alt_names: [str1,...]
    :returns: Cert and key if found
    :rtype: {}
    """
    vault_units = get_vault_units()
    rid = hookenv.relation_id('certificates', unit_name)
    match = []
    for vunit in vault_units:
        sent_data = hookenv.relation_get(unit=vunit, rid=rid)
        name = unit_name.replace('/', '_')
        cert_name = '{}.server.cert'.format(name)
        cert_key = '{}.server.key'.format(name)
        candidate_cert = sent_data.get(cert_name)
        if candidate_cert and cert_matches_request(candidate_cert, cn,
                                                   ip_sans, alt_names):
            match.append({
                'certificate': sent_data.get(cert_name),
                'private_key': sent_data.get(cert_key)})
        batch_request_raw = sent_data.get('processed_requests')
        if batch_request_raw:
            batch_request = json.loads(batch_request_raw)
            for sent_cn in batch_request.keys():
                if sent_cn == cn:
                    candidate_cert = batch_request[cn]['cert']
                    candidate_key = batch_request[cn]['key']
                    if cert_matches_request(candidate_cert, cn, ip_sans,
                                            alt_names):
                        match.append({
                            'certificate': candidate_cert,
                            'private_key': candidate_key})
    return select_newest(match)


def cert_matches_request(cert_pem, cn, ip_sans, alt_names):
    """Test if the cert matches the supplied attributes

       If the cn is duplicated in either the cert or the supplied alt_names
       it is removed before performing the check.

    :param cert_pem: Certificate in pem format to check
    :type cert_pem: string
    :param cn: Common name to use for certifcate
    :type cn: string
    :param ip_sans: List of IP address to create san records for
    :type ip_sans: [str1,...]
    :param alt_names: List of names to create san records for
    :type alt_names: [str1,...]
    :returns: Whether cert matches criteria
    :rtype: bool
    """
    cert_data = certificate_information(cert_pem)
    if cn == cert_data['cn']:
        try:
            cert_data['alt_names'].remove(cn)
        except ValueError:
            pass
        try:
            alt_names.remove(cn)
        except ValueError:
            pass
    else:
        return False
    if sorted(cert_data['alt_names']) == sorted(alt_names) and \
            sorted(cert_data['ip_sans']) == sorted(ip_sans):
        return True
    else:
        return False


def certificate_information(cert_pem):
    """Extract cn, sans and expiration info from certificate

    :param cert_pem: Certificate in pem format to check
    :type cert_pem: string
    :returns: Certificate information in a dictionary
    :rtype: {}
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    bundle = {
        'cn': cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value,
        'not_valid_after': cert.not_valid_after}
    try:
        sans = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        alt_names = sans.value.get_values_for_type(x509.DNSName)
        ip_sans = sans.value.get_values_for_type(x509.IPAddress)
        ip_sans = [str(ip) for ip in ip_sans]
    except ExtensionNotFound:
        alt_names = ip_sans = []
    bundle['ip_sans'] = ip_sans
    bundle['alt_names'] = alt_names
    return bundle


def select_newest(certs):
    """Iterate over the certificate bundle and return the one with the latest
       not_valid_after date

    :returns: Certificate bundle
    :rtype: {}
    """
    latest = datetime.datetime.utcfromtimestamp(0)
    candidate = None
    for bundle in certs:
        cert = x509.load_pem_x509_certificate(
            bundle['certificate'].encode(),
            default_backend())
        not_valid_after = cert.not_valid_after
        if not_valid_after > latest:
            latest = not_valid_after
            candidate = bundle
    return candidate


def process_cert_request(cn, sans, unit_name, reissue_requested):
    """Return a certificate and key matching the requeest

    Return a certificate and key matching the request. This may be an existing
    certificate and key if one exists and reissue_requested is False.

    :param cn: Common name to use for certifcate
    :type cn: string
    :param sans: List of SANS
    :type sans: list
    :param unit_name: Return the unit_name to look for serts for.
    :type unit_name: string
    :returns: Cert and key
    :rtype: {}
    """
    bundle = {}
    ip_sans, alt_names = sort_sans(sans)
    if not reissue_requested:
        bundle = get_matching_cert_from_relation(
            unit_name,
            cn,
            list(ip_sans),
            list(alt_names))
        hookenv.log(
            "Found existing cert for {}, reusing".format(cn),
            level=hookenv.DEBUG)
    if not bundle:
        hookenv.log(
            "Requesting new cert for {}".format(cn),
            level=hookenv.DEBUG)
        # Create the server certificate based on the info in request.
        bundle = get_server_certificate(
            cn,
            ip_sans=ip_sans,
            alt_names=alt_names)
    return bundle
