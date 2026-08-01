import ipaddress
import threading
import time

import dns.name
import dns.rdataclass
import dns.rdatatype
from flask import current_app as app

from dhcp_dns_helper import nsupdate

LOCK = threading.Lock()
last_sync = {}


def reverse_block(network):
    return ipaddress.IPv4Network(f"{network.network_address}/{app.config['PREFIX_LENGTH']}", strict=False)


def _txt_strings(node):
    rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.TXT)
    if rdataset is None:
        return []
    return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in rdataset]


def _classify(strings):
    timestamp_prefix = app.config["TIMESTAMP_PREFIX"]
    timestamps = [s for s in strings if s.startswith(timestamp_prefix)]
    # exclude timestamps in case TIMESTAMP_PREFIX is configured nested under MARKER_PREFIX
    markers = [s for s in strings if s.startswith(app.config["MARKER_PREFIX"]) and s not in timestamps]

    newest = 0
    for value in timestamps:
        try:
            newest = max(newest, int(value[len(timestamp_prefix):]))
        except ValueError:
            pass

    return markers, newest


def _scan(zone_name, rdtype):
    zone_obj = nsupdate.axfr(zone_name)
    managed = {}
    unverifiable = []
    for name, node in zone_obj.nodes.items():
        relative = name.relativize(zone_obj.origin)
        if relative == dns.name.empty:
            continue
        label = relative.to_text()

        markers, ts = _classify(_txt_strings(node))
        if not markers:
            continue
        if nsupdate._record_secret(label) not in markers:
            unverifiable.append(f"{label}.{zone_name}")
            continue

        rdataset = node.get_rdataset(dns.rdataclass.IN, rdtype)
        if rdataset is None:
            continue
        managed[label] = dict(values=sorted(rdata.to_text() for rdata in rdataset), ts=ts)
    return managed, unverifiable


def _reverse_ip(block, label):
    network_octets = str(block.network_address).split(".")[: nsupdate._network_octet_count()]
    host_octets = list(reversed(label.split(".")))
    if len(host_octets) != 4 - len(network_octets):
        return None

    candidate = ".".join(network_octets + host_octets)
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        return None
    return candidate


def synchronise(networks, hosts, dry_run):
    grace = app.config["SYNC_GRACE_SECONDS"]
    zone = app.config["ZONE"]
    now = int(time.time())

    desired_forward = {}
    for host in hosts:
        if desired_forward.get(host["hostname"], host["ip_address"]) != host["ip_address"]:
            app.logger.warning(
                "duplicate hostname %s in sync payload; keeping %s", host["hostname"], host["ip_address"]
            )
        desired_forward[host["hostname"]] = host["ip_address"]
    desired_reverse = {host["ip_address"]: host["hostname"] for host in hosts}

    forward_managed, unverifiable = _scan(zone, dns.rdatatype.A)

    reverse_managed = {}
    for block in sorted({reverse_block(network) for network in networks}, key=str):
        reverse_zone = nsupdate._to_ptr_zone(str(block.network_address))
        scanned, bad = _scan(reverse_zone, dns.rdatatype.PTR)
        unverifiable.extend(bad)
        for label, record in scanned.items():
            ip_address = _reverse_ip(block, label)
            if ip_address is not None:
                reverse_managed[ip_address] = dict(zone=reverse_zone, label=label, **record)

    def in_scope(ip_address):
        address = ipaddress.IPv4Address(ip_address)
        return any(address in network for network in networks)

    healed = []
    healed_pairs = set()
    refreshed = 0
    failures = 0

    for name, ip_address in desired_forward.items():
        forward_ok = forward_managed.get(name, {}).get("values") == [ip_address]
        reverse_ok = reverse_managed.get(ip_address, {}).get("values") == [nsupdate._to_fqdn(name)]
        if forward_ok and reverse_ok:
            refreshed += 1
            if not dry_run and not nsupdate.refresh_timestamp(zone, name):
                failures += 1
            continue
        healed_pairs.add((name, ip_address))
        healed.append(f"{name} ({ip_address})")
        if not dry_run and not nsupdate.add_record(name, ip_address):
            failures += 1

    for ip_address, name in desired_reverse.items():
        if (name, ip_address) in healed_pairs:
            continue
        if reverse_managed.get(ip_address, {}).get("values") == [nsupdate._to_fqdn(name)]:
            refreshed += 1
            if not dry_run and not nsupdate.refresh_timestamp(
                nsupdate._to_ptr_zone(ip_address), nsupdate._to_reverse_host_address(ip_address)
            ):
                failures += 1

    expunged = []

    for name, record in forward_managed.items():
        if name in desired_forward:
            continue
        if not all(in_scope(ip_address) for ip_address in record["values"]):
            continue
        if now - record["ts"] <= grace:
            continue
        expunged.append(f"{name}.{zone} ({', '.join(record['values'])})")
        if not dry_run and not nsupdate._remove(zone, name, "A", record["values"][0]):
            failures += 1

    for ip_address, record in reverse_managed.items():
        if ip_address in desired_reverse:
            continue  # refreshed above, or healed when its PTR was wrong
        if not in_scope(ip_address):
            continue
        if now - record["ts"] <= grace:
            continue
        expunged.append(f"{record['label']}.{record['zone']} ({', '.join(record['values'])})")
        if not dry_run and not nsupdate._remove(record["zone"], record["label"], "PTR", record["values"][0]):
            failures += 1

    report = dict(
        success=failures == 0,
        dry_run=dry_run,
        healed=healed,
        refreshed=refreshed,
        expunged=expunged,
        unverifiable=sorted(unverifiable),
    )
    if not dry_run:
        last_sync.clear()
        last_sync.update(time=now, success=report["success"])
    return report
