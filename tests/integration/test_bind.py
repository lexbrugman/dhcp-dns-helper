"""End-to-end tests against a throwaway BIND managed by testcontainers.

Skipped automatically when no container API socket is reachable (docker, or
rootless podman via `systemctl --user enable --now podman.socket` plus
DOCKER_HOST pointing at the podman socket). The container serves the forward
zone plus the reverse zone, seeded with an unmarked static record for the
clobber-protection assertions.
"""

import base64
import hashlib
import json
import logging
import os
import time

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsigkeyring
import dns.zone
import pytest

BIND_IMAGE = "docker.io/internetsystemsconsortium/bind9:9.20"
FORWARD = "example.internal"
REVERSE = "1.42.10.in-addr.arpa"
MARKER_PREFIX = "x-dyn:"
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


pytestmark = pytest.mark.skipif(not docker_api_available(), reason="no container API socket reachable")


@pytest.fixture(scope="module")
def bind_server(tmp_path_factory):
    from testcontainers.core.container import DockerContainer

    root = tmp_path_factory.mktemp("bind")
    conf = root / "conf"
    zones = root / "zones"
    conf.mkdir()
    zones.mkdir()

    named_conf = NAMED_CONF + "".join(ZONE_CONF.format(zone=z) for z in (FORWARD, REVERSE))
    (conf / "named.conf").write_text(named_conf)
    (zones / f"{FORWARD}.zone").write_text(FORWARD_SEED)
    (zones / f"{REVERSE}.zone").write_text(REVERSE_SEED)
    zones.chmod(0o777)
    for zone_file in zones.iterdir():
        zone_file.chmod(0o666)

    container = (
        DockerContainer(BIND_IMAGE)
        .with_volume_mapping(str(conf / "named.conf"), "/etc/bind/named.conf", "ro")
        .with_volume_mapping(str(zones), "/var/lib/bind", "rw")
        .with_exposed_ports(53)  # the app only ever speaks TCP (updates and queries)
    )
    with container:
        host = container.get_container_host_ip()
        if host == "localhost":  # dnspython's query functions want an IP literal
            host = "127.0.0.1"
        port = int(container.get_exposed_port(53))
        _wait_for_bind(host, port, container)
        yield host, port


def _wait_for_bind(host, port, container):
    query = dns.message.make_query(FORWARD, dns.rdatatype.SOA)
    for _ in range(60):
        try:
            response = dns.query.tcp(query, host, port=port, timeout=2)
            if response.rcode() == dns.rcode.NOERROR:
                return
        except (OSError, dns.exception.DNSException):
            pass
        time.sleep(0.5)
    stdout, stderr = container.get_logs()
    raise RuntimeError(f"BIND did not become ready:\n{stdout.decode()}\n{stderr.decode()}")


@pytest.fixture(scope="module")
def flask_app(bind_server):
    host, port = bind_server
    os.environ.update(
        NAMESERVER=host,
        NAMESERVER_PORT=str(port),
        ZONE=FORWARD,
        PREFIX_LENGTH="24",
        TTL="300",
        RECORD_SALT=RECORD_SALT,
        MARKER_PREFIX=MARKER_PREFIX,
        KEYRING_JSON=json.dumps({"update-key": UPDATE_SECRET}),
        AUTHENTICATION_TOKENS_JSON=json.dumps([TOKEN]),
    )

    from dhcp_dns_helper.app import app

    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


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


def axfr(zone, bind_server):
    host, port = bind_server
    keyring = dns.tsigkeyring.from_text({"update-key": UPDATE_SECRET})
    xfr = dns.query.xfr(host, zone, port=port, keyring=keyring, keyalgorithm="hmac-sha256", relativize=False)
    return dns.zone.from_xfr(xfr, relativize=False)


def rrset(zone_obj, name, rdtype):
    return zone_obj.get_rdataset(dns.name.from_text(name), rdtype)


def values(zone_obj, name, rdtype):
    rds = rrset(zone_obj, name, rdtype)
    return {rd.to_text() for rd in rds} if rds else None


def marker(name):
    digest = hashlib.sha256(f"{name}-{RECORD_SALT}".encode("utf-8")).hexdigest()
    return f'"{MARKER_PREFIX}{digest}"'


def test_health_needs_no_auth(client):
    assert client.get("/health").status_code == 200


def test_requests_require_auth(client):
    response = client.post("/register_host", data=dict(hostname="host0", ip_address="10.42.1.2"))
    assert response.status_code == 403


def test_invalid_input_is_rejected(client):
    assert register(client, "bad_name!", "10.42.1.2").status_code == 400
    assert register(client, "host0", "999.1.1.1").status_code == 400


def test_register_creates_marked_records(client, bind_server):
    assert register(client, "host1", "10.42.1.10").get_json() == dict(success=True)

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"host1.{FORWARD}", dns.rdatatype.A) == {"10.42.1.10"}
    assert values(forward, f"host1.{FORWARD}", dns.rdatatype.TXT) == {marker("host1")}

    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"10.{REVERSE}", dns.rdatatype.PTR) == {f"host1.{FORWARD}."}
    assert values(reverse, f"10.{REVERSE}", dns.rdatatype.TXT) == {marker("10")}


def test_reregistration_is_idempotent(client, bind_server):
    assert register(client, "host2", "10.42.1.20").get_json() == dict(success=True)
    assert register(client, "host2", "10.42.1.20").get_json() == dict(success=True)

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"host2.{FORWARD}", dns.rdatatype.A) == {"10.42.1.20"}


def test_new_address_moves_ptr_and_logs_replacement(client, flask_app, bind_server):
    assert register(client, "host3", "10.42.1.30").get_json() == dict(success=True)

    handler = RecordingHandler()
    flask_app.logger.addHandler(handler)
    try:
        assert register(client, "host3", "10.42.1.31").get_json() == dict(success=True)
    finally:
        flask_app.logger.removeHandler(handler)

    assert any("replaces existing address" in m and "10.42.1.30" in m for m in handler.messages)

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"host3.{FORWARD}", dns.rdatatype.A) == {"10.42.1.31"}

    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"31.{REVERSE}", dns.rdatatype.PTR) == {f"host3.{FORWARD}."}
    assert rrset(reverse, f"30.{REVERSE}", dns.rdatatype.PTR) is None
    assert rrset(reverse, f"30.{REVERSE}", dns.rdatatype.TXT) is None


def test_deregister_removes_both_directions(client, bind_server):
    assert register(client, "host4", "10.42.1.40").get_json() == dict(success=True)
    assert deregister(client, "host4", "10.42.1.40").get_json() == dict(success=True)

    forward = axfr(FORWARD, bind_server)
    assert rrset(forward, f"host4.{FORWARD}", dns.rdatatype.A) is None
    assert rrset(forward, f"host4.{FORWARD}", dns.rdatatype.TXT) is None

    reverse = axfr(REVERSE, bind_server)
    assert rrset(reverse, f"40.{REVERSE}", dns.rdatatype.PTR) is None
    assert rrset(reverse, f"40.{REVERSE}", dns.rdatatype.TXT) is None


def test_deregistering_absent_host_succeeds(client):
    assert deregister(client, "ghost", "10.42.1.99").get_json() == dict(success=True)


def test_cannot_clobber_unmarked_record(client, bind_server):
    assert register(client, "static", "10.42.1.50").get_json() == dict(success=False)

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"static.{FORWARD}", dns.rdatatype.A) == {"10.42.1.7"}
    assert rrset(forward, f"static.{FORWARD}", dns.rdatatype.TXT) is None

    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"7.{REVERSE}", dns.rdatatype.PTR) == {f"static.{FORWARD}."}
    assert rrset(reverse, f"50.{REVERSE}", dns.rdatatype.PTR) is None


def test_cannot_deregister_unmarked_record(client, bind_server):
    assert deregister(client, "static", "10.42.1.7").get_json() == dict(success=False)

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"static.{FORWARD}", dns.rdatatype.A) == {"10.42.1.7"}

    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"7.{REVERSE}", dns.rdatatype.PTR) == {f"static.{FORWARD}."}
