import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.tsigkeyring
import dns.update
import dns.zone
import hashlib
import ipaddress
import time
from flask import current_app as app

QUERY_TIMEOUT = 10
TRANSFER_TIMEOUT = 60

_resolver = dns.resolver.Resolver()
_resolver.cache = dns.resolver.Cache()


def _resolve(hostname):
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    # prefer IPv6; the resolver cache honors record TTLs
    try:
        return _resolver.resolve(hostname, "AAAA")[0].address
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return _resolver.resolve(hostname, "A")[0].address


def _create_update(zone):
    keyring = dns.tsigkeyring.from_text(app.config["KEYRING"])
    return dns.update.Update(zone, keyring=keyring, keyalgorithm="hmac-sha256")


def _query(q):
    server = _resolve(app.config["NAMESERVER"])
    return dns.query.tcp(q, server, port=app.config["NAMESERVER_PORT"], timeout=QUERY_TIMEOUT)


def _network_octet_count():
    return app.config["PREFIX_LENGTH"] // 8


def _record_secret(name):
    digest = hashlib.sha256(f"{name}-{app.config['RECORD_SALT']}".encode("utf-8")).hexdigest()
    return f"{app.config['MARKER_PREFIX']}{digest}"


def _timestamp_record():
    return f"{app.config['TIMESTAMP_PREFIX']}{int(time.time())}"


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


def _lookup(zone, name, rdtype):
    query = dns.message.make_query(f"{name}.{zone}.", rdtype)
    response = _query(query)
    return [rdata for answer in response.answer if answer.rdtype == rdtype for rdata in answer]


def _current_addresses(name):
    return {rdata.address for rdata in _lookup(app.config["ZONE"], name, dns.rdatatype.A)}


def _owned_txt_values(zone, name):
    """Current TXT values at the name, or None when our marker isn't among them.

    RFC 2136 value-dependent prerequisites compare the entire RRset, so guarded
    updates must assert every observed TXT value, not just the marker.
    """
    values = [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in _lookup(zone, name, dns.rdatatype.TXT)]
    if _record_secret(name) not in values:
        return None
    return values


def _is_absent(zone, name):
    check = _create_update(zone)
    check.absent(name)
    return _query(check).rcode() == dns.rcode.NOERROR


def _upsert(zone, name, rdtype, value):
    marker = _record_secret(name)

    update = _create_update(zone)
    update.absent(name)
    update.add(name, app.config["TTL"], "TXT", marker)
    update.add(name, app.config["TTL"], "TXT", _timestamp_record())
    update.add(name, app.config["TTL"], rdtype, value)

    response = _query(update)

    if response.rcode() == dns.rcode.YXDOMAIN:
        owned = _owned_txt_values(zone, name)
        if owned is None:
            app.logger.warning("upsert of %s in %s failed: name exists without our marker", name, zone)
            return False

        update = _create_update(zone)
        for value_ in owned:
            update.present(name, "TXT", value_)
        update.replace(name, app.config["TTL"], "TXT", marker)
        update.add(name, app.config["TTL"], "TXT", _timestamp_record())
        update.replace(name, app.config["TTL"], rdtype, value)

        response = _query(update)

    return _succeeded("upsert", zone, name, response)


def refresh_timestamp(zone, name):
    owned = _owned_txt_values(zone, name)
    if owned is None:
        app.logger.warning("refresh of %s in %s failed: name has no verified marker", name, zone)
        return False

    update = _create_update(zone)
    for value in owned:
        update.present(name, "TXT", value)
    update.replace(name, app.config["TTL"], "TXT", _record_secret(name))
    update.add(name, app.config["TTL"], "TXT", _timestamp_record())

    return _succeeded("refresh", zone, name, _query(update))


def axfr(zone):
    keyring = dns.tsigkeyring.from_text(app.config["KEYRING"])
    xfr = dns.query.xfr(
        _resolve(app.config["NAMESERVER"]),
        zone,
        port=app.config["NAMESERVER_PORT"],
        keyring=keyring,
        keyalgorithm="hmac-sha256",
        timeout=QUERY_TIMEOUT,
        lifetime=TRANSFER_TIMEOUT,
        relativize=False,
    )
    return dns.zone.from_xfr(xfr, relativize=False)


def _remove(zone, name, rdtype, value):
    owned = _owned_txt_values(zone, name)
    if owned is None:
        if _is_absent(zone, name):
            return True
        app.logger.warning("removal of %s in %s failed: name has no verified marker", name, zone)
        return False

    update = _create_update(zone)
    update.present(name, rdtype, value)
    for txt_value in owned:
        update.present(name, "TXT", txt_value)
    update.delete(name)

    response = _query(update)

    if response.rcode() == dns.rcode.NXRRSET and _is_absent(zone, name):
        return True

    return _succeeded("removal", zone, name, response)


def add_record(name, ip_address):
    if not name:
        return False

    try:
        previous_addresses = _current_addresses(name) - {ip_address}
        if previous_addresses:
            app.logger.warning(
                "registration of %s (%s) replaces existing address %s",
                name,
                ip_address,
                ", ".join(sorted(previous_addresses)),
            )

        registered = _upsert(app.config["ZONE"], name, "A", ip_address) and _upsert(
            _to_ptr_zone(ip_address), _to_reverse_host_address(ip_address), "PTR", _to_fqdn(name)
        )

        if registered:
            # best effort: the marker prerequisites make this a no-op if the old address was never ours
            for previous_address in previous_addresses:
                _remove(_to_ptr_zone(previous_address), _to_reverse_host_address(previous_address), "PTR", _to_fqdn(name))

        return registered
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
