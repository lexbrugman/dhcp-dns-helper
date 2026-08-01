import json
import os
import time

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import pytest

from tests.integration import helpers


@pytest.fixture(scope="session")
def bind_server(tmp_path_factory):
    from testcontainers.core.container import DockerContainer

    root = tmp_path_factory.mktemp("bind")
    conf = root / "conf"
    zones = root / "zones"
    conf.mkdir()
    zones.mkdir()

    named_conf = helpers.NAMED_CONF + "".join(
        helpers.ZONE_CONF.format(zone=z) for z in (helpers.FORWARD, helpers.REVERSE)
    )
    (conf / "named.conf").write_text(named_conf)
    (zones / f"{helpers.FORWARD}.zone").write_text(helpers.FORWARD_SEED)
    (zones / f"{helpers.REVERSE}.zone").write_text(helpers.REVERSE_SEED)
    zones.chmod(0o777)
    for zone_file in zones.iterdir():
        zone_file.chmod(0o666)

    container = (
        DockerContainer(helpers.BIND_IMAGE)
        .with_volume_mapping(str(conf / "named.conf"), "/etc/bind/named.conf", "ro")
        .with_volume_mapping(str(zones), "/var/lib/bind", "rw")
        .with_exposed_ports(53)  # the app only ever speaks TCP (updates, queries and AXFR)
    )
    with container:
        host = container.get_container_host_ip()
        if host == "localhost":  # dnspython's query functions want an IP literal
            host = "127.0.0.1"
        port = int(container.get_exposed_port(53))
        _wait_for_bind(host, port, container)
        yield host, port


def _wait_for_bind(host, port, container):
    query = dns.message.make_query(helpers.FORWARD, dns.rdatatype.SOA)
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


@pytest.fixture(scope="session")
def flask_app(bind_server):
    host, port = bind_server
    os.environ.update(
        NAMESERVER=host,
        NAMESERVER_PORT=str(port),
        ZONE=helpers.FORWARD,
        PREFIX_LENGTH="24",
        TTL="300",
        RECORD_SALT=helpers.RECORD_SALT,
        MARKER_PREFIX=helpers.MARKER_PREFIX,
        TIMESTAMP_PREFIX=helpers.TIMESTAMP_PREFIX,
        SYNC_GRACE_SECONDS="2",
        KEYRING_JSON=json.dumps({"update-key": helpers.UPDATE_SECRET}),
        AUTHENTICATION_TOKENS_JSON=json.dumps([helpers.TOKEN]),
    )

    from dhcp_dns_helper.app import app

    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()
