import dns.query
import dns.rcode
import dns.tsigkeyring
import dns.update
import hashlib
import socket
from flask import current_app as app


def _resolve(hostname):
    ip_address = None
    for (family, type, proto, canonname, sockaddr) in socket.getaddrinfo(hostname, None):
        ip_address = sockaddr[0]
        if type == socket.AddressFamily.AF_INET6:
            return ip_address

    return ip_address


def _create_update(zone=None):
    zone = zone or app.config["ZONE"]
    keyring = dns.tsigkeyring.from_text(app.config["KEYRING"])
    return dns.update.Update(zone, keyring=keyring, keyalgorithm="hmac-md5.sig-alg.reg.int")


def _query(q):
    return dns.query.tcp(q, _resolve(app.config["NAMESERVER"]))


def _network_octet_count():
    return round(app.config["PREFIX_LENGTH"] / 8)


def _record_secret(name):
    return hashlib.sha256(f"{name}-{app.config['RECORD_SALT']}".encode("utf-8")).hexdigest()


def _to_ptr_zone(ip_address):
    network_octets = ip_address.split(".")[:_network_octet_count()]
    reverse_network_address = ".".join(reversed(network_octets))
    return f"{reverse_network_address}.in-addr.arpa"


def _to_reverse_host_address(ip_address):
    host_octets = ip_address.split(".")[_network_octet_count():]
    return ".".join(reversed(host_octets))


def _add_a_record(name, ip_address):
    update = _create_update()
    update.absent(name)
    update.add(name, app.config["TTL"], "TXT", _record_secret(name))
    update.add(name, app.config["TTL"], "A", ip_address)

    response = _query(update)

    if response.rcode() == dns.rcode.YXDOMAIN:
        update = _create_update()
        update.present(name, "TXT", _record_secret(name))
        update.replace(name, app.config["TTL"], "A", ip_address)

        response = _query(update)

    return response.rcode() == dns.rcode.NOERROR


def _add_ptr_record(name, ip_address):
    record_value = f"{name}.{app.config['ZONE']}."
    zone = _to_ptr_zone(ip_address)
    reverse_host_address = _to_reverse_host_address(ip_address)

    update = _create_update(zone)
    update.add(reverse_host_address, app.config["TTL"], "PTR", record_value)

    response = _query(update)

    if response.rcode() == dns.rcode.YXDOMAIN:
        update = _create_update(zone)
        update.replace(reverse_host_address, app.config["TTL"], "PTR", record_value)

        response = _query(update)

    return response.rcode() == dns.rcode.NOERROR


def add_record(name, ip_address):
    return _add_a_record(name, ip_address) and _add_ptr_record(name, ip_address)


def _remove_a_record(name, ip_address):
    update = _create_update()
    update.present(name, "A", ip_address)
    update.present(name, "TXT", _record_secret(name))
    update.delete(name)

    response = _query(update)

    return response.rcode() == dns.rcode.NOERROR


def _remove_ptr_record(name, ip_address):
    zone = _to_ptr_zone(ip_address)
    reverse_host_address = _to_reverse_host_address(ip_address)

    update = _create_update(zone)
    update.present(reverse_host_address, "PTR", f"{name}.{app.config['ZONE']}.")
    update.delete(reverse_host_address)

    response = _query(update)

    return response.rcode() == dns.rcode.NOERROR


def remove_record(name, ip_address):
    return _remove_a_record(name, ip_address) and _remove_ptr_record(name, ip_address)
