import json
import os


def _required_env(name):
    value = os.environ.get(name)
    if value is None or value == "":
        raise RuntimeError(f"{name} is required")
    return value


def _json_env(name):
    return json.loads(_required_env(name))


NAMESERVER = _required_env("NAMESERVER")
ZONE = _required_env("ZONE")
PREFIX_LENGTH = int(os.environ.get("PREFIX_LENGTH", "24"))
TTL = int(os.environ.get("TTL", "3600"))
RECORD_SALT = os.environ.get("RECORD_SALT", f"{ZONE}-dhcp-dns")
KEYRING = _json_env("KEYRING_JSON")
AUTHENTICATION_TOKENS = _json_env("AUTHENTICATION_TOKENS_JSON")
