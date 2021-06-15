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


@app.route("/register_host", methods=["POST"])
def register_host():
    success = nsupdate.add_record(
        name=request.form["hostname"],
        ip_address=request.form["ip_address"],
    )

    return jsonify(dict(success=success))


@app.route("/deregister_host", methods=["POST"])
def deregister_host():
    success = nsupdate.remove_record(
        name=request.form["hostname"],
        ip_address=request.form["ip_address"],
    )

    return jsonify(dict(success=success))
