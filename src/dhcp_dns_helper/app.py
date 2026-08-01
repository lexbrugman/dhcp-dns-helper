from flask import abort
from flask import Flask
from flask import jsonify
from flask import request
import dns.exception
import ipaddress
import os
import re
import secrets
import time
from logging import config as log_config

from dhcp_dns_helper import nsupdate
from dhcp_dns_helper import settings
from dhcp_dns_helper import sync

app = Flask(__name__)
app.config.from_object(settings)

if app.config["PREFIX_LENGTH"] not in (8, 16, 24):
    raise RuntimeError("PREFIX_LENGTH must be 8, 16 or 24")

if app.config["SYNC_GRACE_SECONDS"] <= 0:
    raise RuntimeError("SYNC_GRACE_SECONDS must be positive")

conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../logging.conf")
log_config.fileConfig(conf_file)

app.logger.info("app initialised")


@app.before_request
def check_authentication_if_applicable():
    if request.endpoint == "health":
        return

    authorization = request.headers.get("Authorization", "")
    authenticated = any(
        secrets.compare_digest(authorization.encode("utf-8"), f"Basic {token}".encode("utf-8"))
        for token in app.config["AUTHENTICATION_TOKENS"]
    )
    if not authenticated:
        abort(403)


@app.route("/health", methods=["GET"])
def health():
    status = dict(status="ok")
    if sync.last_sync:
        status["last_sync"] = dict(
            age_seconds=int(time.time()) - sync.last_sync["time"],
            success=sync.last_sync["success"],
        )
    return jsonify(status)


HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$")


def _valid_hostname(value):
    hostname = value.lower() if isinstance(value, str) else ""
    return hostname if HOSTNAME_RE.match(hostname) else None


def _valid_ip_address(value):
    try:
        ipaddress.IPv4Address(value if isinstance(value, str) else None)
    except ValueError:
        return None
    return value


def _parse_hostname(value):
    hostname = _valid_hostname(value)
    if hostname is None:
        abort(400, description="hostname must be a single DNS label")
    return hostname


def _parse_ip_address(value):
    ip_address = _valid_ip_address(value)
    if ip_address is None:
        abort(400, description="ip_address must be a valid IPv4 address")
    return ip_address


def _update_host(action, update_record):
    hostname = _parse_hostname(request.form["hostname"])
    ip_address = _parse_ip_address(request.form["ip_address"])

    success = update_record(
        name=hostname,
        ip_address=ip_address,
    )

    app.logger.info("%s: %s (%s) via %s: %s", action, hostname, ip_address, request.remote_addr, success)

    return jsonify(dict(success=success))


@app.route("/register_host", methods=["POST"])
def register_host():
    return _update_host("register", nsupdate.add_record)


@app.route("/deregister_host", methods=["POST"])
def deregister_host():
    return _update_host("deregister", nsupdate.remove_record)


def _parse_networks(values):
    if not isinstance(values, list) or not values:
        abort(400, description="networks must be a non-empty list")

    networks = []
    for value in values:
        try:
            network = ipaddress.IPv4Network(value if isinstance(value, str) else None)
        except ValueError:
            abort(400, description=f"invalid network: {value}")
        if network.prefixlen < app.config["PREFIX_LENGTH"]:
            abort(400, description=f"network {network} is wider than PREFIX_LENGTH /{app.config['PREFIX_LENGTH']}")
        networks.append(network)

    return networks


def _describe(value):
    return str(value)[:64]


def _parse_hosts(values, networks):
    if not isinstance(values, list):
        abort(400, description="hosts must be a list")

    hosts = []
    skipped = []
    for entry in values:
        if not isinstance(entry, dict):
            skipped.append(dict(entry=_describe(entry), reason="host must be an object"))
            continue

        hostname = _valid_hostname(entry.get("hostname"))
        ip_address = _valid_ip_address(entry.get("ip_address"))
        entry_description = dict(hostname=_describe(entry.get("hostname")), ip_address=_describe(entry.get("ip_address")))

        if hostname is None:
            skipped.append(dict(**entry_description, reason="hostname must be a single DNS label"))
        elif ip_address is None:
            skipped.append(dict(**entry_description, reason="ip_address must be a valid IPv4 address"))
        elif not any(ipaddress.IPv4Address(ip_address) in network for network in networks):
            skipped.append(dict(**entry_description, reason="outside the declared networks"))
        else:
            hosts.append(dict(hostname=hostname, ip_address=ip_address))

    return hosts, skipped


@app.route("/sync_hosts", methods=["POST"])
def sync_hosts():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="body must be a JSON object")

    networks = _parse_networks(payload.get("networks"))
    hosts, skipped = _parse_hosts(payload.get("hosts"), networks)
    dry_run = bool(payload.get("dry_run", False))

    if not sync.LOCK.acquire(blocking=False):
        abort(409, description="a sync is already running")
    try:
        report = sync.synchronise(networks, hosts, dry_run)
    except (dns.exception.DNSException, OSError) as e:
        app.logger.error("sync failed: %s", e)
        abort(502, description="sync failed against the nameserver")
    finally:
        sync.LOCK.release()

    report["skipped"] = skipped

    for entry in skipped:
        app.logger.warning("sync skipped host %s: %s", entry.get("hostname", entry.get("entry")), entry["reason"])

    app.logger.info(
        "sync of %d host(s) in %s via %s: healed=%d refreshed=%d expunged=%d unverifiable=%d skipped=%d dry_run=%s success=%s",
        len(hosts),
        ", ".join(str(network) for network in networks),
        request.remote_addr,
        len(report["healed"]),
        report["refreshed"],
        len(report["expunged"]),
        len(report["unverifiable"]),
        len(skipped),
        report["dry_run"],
        report["success"],
    )

    return jsonify(report)
