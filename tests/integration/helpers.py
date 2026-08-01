import base64
import hashlib
import logging

import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import dns.zone

BIND_IMAGE = "docker.io/internetsystemsconsortium/bind9:9.20"
FORWARD = "example.internal"
REVERSE = "1.42.10.in-addr.arpa"
NETWORK = "10.42.1.0/24"
MARKER_PREFIX = "x-dyn:"
TIMESTAMP_PREFIX = "x-dyn-ts:"
RECORD_SALT = "integration-salt"
UPDATE_SECRET = base64.b64encode(b"integration-update-secret-32byte").decode()
TOKEN = "integration-token"
AUTH = {"Authorization": f"Basic {TOKEN}"}

NAMED_CONF = f"""
options {{
    directory "/var/cache/bind";
    recursion no;
    allow-query {{ any; }};
    listen-on {{ any; }};
    listen-on-v6 {{ any; }};
}};
key "update-key" {{ algorithm hmac-sha256; secret "{UPDATE_SECRET}"; }};
"""

ZONE_CONF = """
zone "{zone}" {{
    type primary;
    file "/var/lib/bind/{zone}.zone";
    allow-update {{ key "update-key"; }};
    allow-transfer {{ key "update-key"; }};
    check-names ignore;
}};
"""

FORWARD_SEED = """
$TTL 3600
@       IN SOA  ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600
@       IN NS   ns1.example.net.
static  IN A    10.42.1.7
"""

REVERSE_SEED = f"""
$TTL 3600
@       IN SOA  ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600
@       IN NS   ns1.example.net.
7       IN PTR  static.{FORWARD}.
"""


def docker_api_available():
    try:
        from testcontainers.core.docker_client import DockerClient

        return DockerClient().client.ping()
    except Exception:
        return False


class RecordingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def register(client, hostname, ip_address):
    return client.post("/register_host", data=dict(hostname=hostname, ip_address=ip_address), headers=AUTH)


def deregister(client, hostname, ip_address):
    return client.post("/deregister_host", data=dict(hostname=hostname, ip_address=ip_address), headers=AUTH)


def sync_hosts(client, networks, hosts, dry_run=False):
    payload = dict(networks=networks, hosts=hosts)
    if dry_run:
        payload["dry_run"] = True
    return client.post("/sync_hosts", json=payload, headers=AUTH)


def keyring():
    return dns.tsigkeyring.from_text({"update-key": UPDATE_SECRET})


def axfr(zone, bind_server):
    host, port = bind_server
    xfr = dns.query.xfr(host, zone, port=port, keyring=keyring(), keyalgorithm="hmac-sha256", relativize=False)
    return dns.zone.from_xfr(xfr, relativize=False)


def rrset(zone_obj, name, rdtype):
    return zone_obj.get_rdataset(dns.name.from_text(name), rdtype)


def values(zone_obj, name, rdtype):
    rds = rrset(zone_obj, name, rdtype)
    return {rd.to_text() for rd in rds} if rds else None


def raw_marker(name):
    digest = hashlib.sha256(f"{name}-{RECORD_SALT}".encode("utf-8")).hexdigest()
    return f"{MARKER_PREFIX}{digest}"


def marker(name):
    return f'"{raw_marker(name)}"'


def timestamp_value(zone_obj, name):
    txt = values(zone_obj, name, dns.rdatatype.TXT) or set()
    for value in txt:
        if value.startswith(f'"{TIMESTAMP_PREFIX}'):
            return int(value.strip('"')[len(TIMESTAMP_PREFIX):])
    return None


def assert_marked(zone_obj, name, label):
    txt = values(zone_obj, name, dns.rdatatype.TXT)
    assert txt is not None
    assert marker(label) in txt
    assert sum(value.startswith(f'"{TIMESTAMP_PREFIX}') for value in txt) == 1
    assert len(txt) == 2


def write_orphan_ptr(bind_server, label, target):
    host, port = bind_server
    update = dns.update.Update(REVERSE, keyring=keyring(), keyalgorithm="hmac-sha256")
    update.add(label, 300, "PTR", target)
    update.add(label, 300, "TXT", raw_marker(label))
    response = dns.query.tcp(update, host, port=port, timeout=10)
    assert response.rcode() == dns.rcode.NOERROR
