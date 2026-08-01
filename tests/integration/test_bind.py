"""End-to-end tests of the lease-event endpoints against a throwaway BIND.

Skipped automatically when no container API socket is reachable (docker, or
rootless podman via `systemctl --user enable --now podman.socket` plus
DOCKER_HOST pointing at the podman socket). Fixtures live in conftest.py; the
zones are seeded with an unmarked static record for the clobber-protection
assertions.
"""

import dns.rdatatype
import pytest

from tests.integration.helpers import (
    AUTH,
    FORWARD,
    REVERSE,
    RecordingHandler,
    assert_marked,
    axfr,
    deregister,
    docker_api_available,
    register,
    rrset,
    values,
)

pytestmark = pytest.mark.skipif(not docker_api_available(), reason="no container API socket reachable")


def test_health_needs_no_auth(client):
    assert client.get("/health").status_code == 200


def test_requests_require_auth(client):
    response = client.post("/register_host", data=dict(hostname="host0", ip_address="10.42.1.2"))
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("hostname", "ip_address"),
    [
        ("bad_name!", "10.42.1.2"),
        ("host0", "999.1.1.1"),
        ("", "10.42.1.2"),
        ("host0", ""),
    ],
)
def test_invalid_input_is_rejected(client, hostname, ip_address):
    assert register(client, hostname, ip_address).status_code == 400


def test_register_creates_marked_records(client, bind_server):
    assert register(client, "host1", "10.42.1.10").get_json() == dict(success=True)

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"host1.{FORWARD}", dns.rdatatype.A) == {"10.42.1.10"}
    assert_marked(forward, f"host1.{FORWARD}", "host1")

    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"10.{REVERSE}", dns.rdatatype.PTR) == {f"host1.{FORWARD}."}
    assert_marked(reverse, f"10.{REVERSE}", "10")


def test_reregistration_is_idempotent(client, bind_server):
    assert register(client, "host2", "10.42.1.20").get_json() == dict(success=True)
    assert register(client, "host2", "10.42.1.20").get_json() == dict(success=True)

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"host2.{FORWARD}", dns.rdatatype.A) == {"10.42.1.20"}
    assert_marked(forward, f"host2.{FORWARD}", "host2")


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
