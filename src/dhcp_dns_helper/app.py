from flask import abort
from flask import Flask
from flask import jsonify
from flask import request
import ipaddress
import os
import re
import secrets
from logging import config as log_config

from dhcp_dns_helper import nsupdate
from dhcp_dns_helper import settings

app = Flask(__name__)
app.config.from_object(settings)

if app.config["PREFIX_LENGTH"] not in (8, 16, 24):
    raise RuntimeError("PREFIX_LENGTH must be 8, 16 or 24")

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
    return jsonify(dict(status="ok"))


HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _update_host(action, update_record):
    hostname = request.form["hostname"].lower()
    ip_address = request.form["ip_address"]

    if not HOSTNAME_RE.match(hostname):
        abort(400, description="hostname must be a single DNS label")

    try:
        ipaddress.IPv4Address(ip_address)
    except ValueError:
        abort(400, description="ip_address must be a valid IPv4 address")

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
