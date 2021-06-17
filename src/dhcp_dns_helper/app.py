from flask import abort
from flask import Flask
from flask import jsonify
from flask import request
import logging
import os
from logging import config as log_config

from dhcp_dns_helper import nsupdate
import settings

app = Flask(__name__)
app.config.from_object(settings)

conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../logging.conf")
log_config.fileConfig(conf_file)
logger = logging.getLogger(__name__)

app.logger.info("app initialised")


@app.before_request
def check_authentication_if_applicable():
    valid_tokens = [f"Basic {token}" for token in app.config["AUTHENTICATION_TOKENS"]]
    if request.headers.get("Authorization") not in valid_tokens:
        abort(403)


@app.route("/register_host", methods=["POST"])
def register_host():
    hostname = request.form["hostname"]
    ip_address = request.form["ip_address"]

    success = nsupdate.add_record(
        name=hostname,
        ip_address=ip_address,
    )

    app.logger.info("register: %s (%s) via %s: %s", hostname, ip_address, request.remote_addr, success)

    return jsonify(dict(success=success))


@app.route("/deregister_host", methods=["POST"])
def deregister_host():
    hostname = request.form["hostname"]
    ip_address = request.form["ip_address"]

    success = nsupdate.remove_record(
        name=hostname,
        ip_address=ip_address,
    )

    app.logger.info("deregister: %s (%s) via %s: %s", hostname, ip_address, request.remote_addr, success)

    return jsonify(dict(success=success))
