"""End-to-end tests of /sync_hosts against a throwaway BIND.

SYNC_GRACE_SECONDS is 2 in the test environment (see conftest.py), so a
3-second sleep makes a record stale. Each test declares a distinct /28 as its
authority so tests cannot expunge each other's records; the final tests sweep
the whole /24 deliberately and therefore run last.
"""

import time

import dns.rdatatype
import pytest

from tests.integration.helpers import (
    AUTH,
    FORWARD,
    NETWORK,
    REVERSE,
    assert_marked,
    axfr,
    docker_api_available,
    register,
    rrset,
    sync_hosts,
    timestamp_value,
    values,
    write_orphan_ptr,
)

pytestmark = pytest.mark.skipif(not docker_api_available(), reason="no container API socket reachable")


def test_sync_heals_missing_host(client, bind_server):
    report = sync_hosts(client, ["10.42.1.64/28"], [dict(hostname="sync1", ip_address="10.42.1.65")]).get_json()
    assert report["success"] is True
    assert report["healed"] == ["sync1 (10.42.1.65)"]
    assert report["expunged"] == []
    assert report["unverifiable"] == []

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"sync1.{FORWARD}", dns.rdatatype.A) == {"10.42.1.65"}
    assert_marked(forward, f"sync1.{FORWARD}", "sync1")

    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"65.{REVERSE}", dns.rdatatype.PTR) == {f"sync1.{FORWARD}."}
    assert_marked(reverse, f"65.{REVERSE}", "65")


def test_sync_expunges_stale_but_spares_fresh(client, bind_server):
    assert register(client, "sync2", "10.42.1.81").get_json() == dict(success=True)
    time.sleep(3)
    assert register(client, "sync3", "10.42.1.82").get_json() == dict(success=True)

    report = sync_hosts(client, ["10.42.1.80/28"], []).get_json()
    assert report["success"] is True
    assert report["expunged"] == [
        f"sync2.{FORWARD} (10.42.1.81)",
        f"81.{REVERSE} (sync2.{FORWARD}.)",
    ]

    forward = axfr(FORWARD, bind_server)
    assert rrset(forward, f"sync2.{FORWARD}", dns.rdatatype.A) is None
    assert rrset(forward, f"sync2.{FORWARD}", dns.rdatatype.TXT) is None
    assert values(forward, f"sync3.{FORWARD}", dns.rdatatype.A) == {"10.42.1.82"}

    reverse = axfr(REVERSE, bind_server)
    assert rrset(reverse, f"81.{REVERSE}", dns.rdatatype.PTR) is None
    assert values(reverse, f"82.{REVERSE}", dns.rdatatype.PTR) == {f"sync3.{FORWARD}."}


def test_sync_expunges_orphaned_ptr(client, bind_server):
    write_orphan_ptr(bind_server, "97", f"ghost.{FORWARD}.")

    report = sync_hosts(client, ["10.42.1.96/28"], []).get_json()
    assert report["success"] is True
    assert report["expunged"] == [f"97.{REVERSE} (ghost.{FORWARD}.)"]

    reverse = axfr(REVERSE, bind_server)
    assert rrset(reverse, f"97.{REVERSE}", dns.rdatatype.PTR) is None
    assert rrset(reverse, f"97.{REVERSE}", dns.rdatatype.TXT) is None


def test_truncated_body_rejected_and_nothing_expunged(client, bind_server):
    assert register(client, "sync4", "10.42.1.113").get_json() == dict(success=True)
    time.sleep(3)

    truncated = '{"networks":["10.42.1.112/28"],"hosts":[{"hostname":"sy'
    response = client.post("/sync_hosts", data=truncated, headers=AUTH, content_type="application/json")
    assert response.status_code == 400

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"sync4.{FORWARD}", dns.rdatatype.A) == {"10.42.1.113"}


@pytest.mark.parametrize(
    ("networks", "hosts"),
    [
        ([NETWORK], [dict(hostname="x1", ip_address="10.42.2.5")]),  # host outside declared networks
        (["10.42.0.0/16"], []),  # wider than PREFIX_LENGTH
        (["not-a-network"], []),
        ([], []),
        ("10.42.1.0/24", []),
        ([NETWORK], [dict(hostname="bad_name!", ip_address="10.42.1.5")]),
        ([NETWORK], [dict(hostname="x1")]),
        ([NETWORK], ["not-an-object"]),
        ([NETWORK], "not-a-list"),
    ],
)
def test_invalid_sync_payloads_rejected(client, networks, hosts):
    assert sync_hosts(client, networks, hosts).status_code == 400


def test_sync_refreshes_listed_hosts(client, bind_server):
    assert register(client, "sync5", "10.42.1.129").get_json() == dict(success=True)
    first = timestamp_value(axfr(FORWARD, bind_server), f"sync5.{FORWARD}")
    assert first is not None
    time.sleep(3)  # past grace: being listed must both protect and re-vouch it

    report = sync_hosts(client, ["10.42.1.128/28"], [dict(hostname="sync5", ip_address="10.42.1.129")]).get_json()
    assert report["success"] is True
    assert report["healed"] == []
    assert report["refreshed"] == 2  # forward + reverse
    assert report["expunged"] == []

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"sync5.{FORWARD}", dns.rdatatype.A) == {"10.42.1.129"}
    second = timestamp_value(forward, f"sync5.{FORWARD}")
    assert second > first
    assert timestamp_value(axfr(REVERSE, bind_server), f"129.{REVERSE}") > first


def test_dry_run_reports_without_changes(client, bind_server):
    assert register(client, "sync6", "10.42.1.145").get_json() == dict(success=True)
    time.sleep(3)

    report = sync_hosts(client, ["10.42.1.144/28"], [], dry_run=True).get_json()
    assert report["dry_run"] is True
    assert report["expunged"] == [
        f"sync6.{FORWARD} (10.42.1.145)",
        f"145.{REVERSE} (sync6.{FORWARD}.)",
    ]

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"sync6.{FORWARD}", dns.rdatatype.A) == {"10.42.1.145"}
    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"145.{REVERSE}", dns.rdatatype.PTR) == {f"sync6.{FORWARD}."}


def test_sync_leaves_unmarked_records_alone(client, bind_server):
    report = sync_hosts(client, [NETWORK], []).get_json()
    assert report["success"] is True

    forward = axfr(FORWARD, bind_server)
    assert values(forward, f"static.{FORWARD}", dns.rdatatype.A) == {"10.42.1.7"}
    assert rrset(forward, f"static.{FORWARD}", dns.rdatatype.TXT) is None

    reverse = axfr(REVERSE, bind_server)
    assert values(reverse, f"7.{REVERSE}", dns.rdatatype.PTR) == {f"static.{FORWARD}."}


def test_health_reports_last_sync(client):
    health = client.get("/health").get_json()
    assert health["status"] == "ok"
    assert health["last_sync"]["success"] is True
    assert health["last_sync"]["age_seconds"] >= 0
