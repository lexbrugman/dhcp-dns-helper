import dns.exception
import dns.query
import dns.rcode
import dns.tsigkeyring
import dns.update
import functools
import hashlib
import socket
from flask import current_app as app

QUERY_TIMEOUT = 10


@functools.cache
def _resolve(hostname):
    # prefer IPv6, otherwise fall back to the last address returned;
    # cached for the process lifetime, so a nameserver IP change needs a restart
    ip_address = None
    for (family, type, proto, canonname, sockaddr) in socket.getaddrinfo(hostname, None):
        ip_address = sockaddr[0]
        if family == socket.AddressFamily.AF_INET6:
            return ip_address

    return ip_address


def _create_update(zone):
    keyring = dns.tsigkeyring.from_text(app.config["KEYRING"])
    return dns.update.Update(zone, keyring=keyring, keyalgorithm="hmac-sha256")


def _query(q):
    return dns.query.tcp(q, _resolve(app.config["NAMESERVER"]), timeout=QUERY_TIMEOUT)


def _network_octet_count():
    return app.config["PREFIX_LENGTH"] // 8


def _record_secret(name):
    digest = hashlib.sha256(f"{name}-{app.config['RECORD_SALT']}".encode("utf-8")).hexdigest()
    return f"{app.config['MARKER_PREFIX']}{digest}"


def _to_ptr_zone(ip_address):
    network_octets = ip_address.split(".")[:_network_octet_count()]
    reverse_network_address = ".".join(reversed(network_octets))
    return f"{reverse_network_address}.in-addr.arpa"


def _to_reverse_host_address(ip_address):
    host_octets = ip_address.split(".")[_network_octet_count():]
    return ".".join(reversed(host_octets))


def _to_fqdn(name):
    return f"{name}.{app.config['ZONE']}."


def _succeeded(operation, zone, name, response):
    if response.rcode() == dns.rcode.NOERROR:
        return True

    app.logger.warning("%s of %s in %s failed: %s", operation, name, zone, dns.rcode.to_text(response.rcode()))
    return False


def _is_absent(zone, name):
    check = _create_update(zone)
    check.absent(name)
    return _query(check).rcode() == dns.rcode.NOERROR


def _upsert(zone, name, rdtype, value):
    marker = _record_secret(name)

    update = _create_update(zone)
    update.absent(name)
    update.add(name, app.config["TTL"], "TXT", marker)
    update.add(name, app.config["TTL"], rdtype, value)

    response = _query(update)

    if response.rcode() == dns.rcode.YXDOMAIN:
        update = _create_update(zone)
        update.present(name, "TXT", marker)
        update.replace(name, app.config["TTL"], rdtype, value)

        response = _query(update)

    return _succeeded("upsert", zone, name, response)


def _remove(zone, name, rdtype, value):
    update = _create_update(zone)
    update.present(name, rdtype, value)
    update.present(name, "TXT", _record_secret(name))
    update.delete(name)

    response = _query(update)

    if response.rcode() == dns.rcode.NXRRSET and _is_absent(zone, name):
        return True

    return _succeeded("removal", zone, name, response)


def add_record(name, ip_address):
    if not name:
        return False

    try:
        return _upsert(app.config["ZONE"], name, "A", ip_address) and _upsert(
            _to_ptr_zone(ip_address), _to_reverse_host_address(ip_address), "PTR", _to_fqdn(name)
        )
    except (dns.exception.DNSException, OSError) as e:
        app.logger.error("registration of %s (%s) failed: %s", name, ip_address, e)
        return False


def remove_record(name, ip_address):
    if not name:
        return False

    try:
        forward_removed = _remove(app.config["ZONE"], name, "A", ip_address)
        reverse_removed = _remove(
            _to_ptr_zone(ip_address), _to_reverse_host_address(ip_address), "PTR", _to_fqdn(name)
        )
        return forward_removed and reverse_removed
    except (dns.exception.DNSException, OSError) as e:
        app.logger.error("deregistration of %s (%s) failed: %s", name, ip_address, e)
        return False
