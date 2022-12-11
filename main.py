from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
import csv
import datetime


from socket import socket
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

HOSTS = []

def read_hosts(HOSTS):
    with open('file.csv', newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=';', quotechar='|')
        for i in spamreader:
            HOSTS.append((i[0], 443))

def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_public_key(cert):
    try:
        key = cert.public_key()
        return key
    except x509.ExtensionNotFound:
        return None

def print_basic_info(hostinfo):
    peername=hostinfo.peername
    commonname=get_common_name(hostinfo.cert)
    SAN=get_alt_names(hostinfo.cert)
    issuer=get_issuer(hostinfo.cert)
    notbefore=hostinfo.cert.not_valid_before
    notafter=hostinfo.cert.not_valid_after
    public_key=get_public_key(hostinfo.cert)
    s = '''{peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    \tPublic Key: {public_key}
    \tSerial: {serial}
    '''.format(
            peername=hostinfo.peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after,
            public_key=get_public_key(hostinfo.cert),
            serial=hostinfo.cert.serial_number
    )
    print(s)
    now = datetime.datetime.now()
    if now > notafter or now < notbefore:
        print('''Sertificate of resource {hostname} is out of date'''.format(hostname=hostinfo.hostname))
    if (notafter-notbefore).days > 365:
        print('''Sertificate of resource {hostname} issued for too long'''.format(hostname=hostinfo.hostname))


def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


import concurrent.futures
if __name__ == '__main__':
    read_hosts(HOSTS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        for hostinfo in e.map(lambda x: get_certificate(x[0], x[1]), HOSTS):
            print_basic_info(hostinfo)
