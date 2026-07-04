# dhcp-dns-helper

This application creates an HTTP interface into nsupdate for managing DNS host records in (for example) [Bind](https://www.isc.org/bind/). Intended to be used together with a DHCP server to provide DNS host records for DHCP leases.

`VERSION` is the single source of truth for the image version. CI reads it for the Docker build argument and image tag.

## Image

CI publishes:

```text
ghcr.io/slim-it/dhcp-dns-helper:<version>
ghcr.io/slim-it/dhcp-dns-helper:latest
ghcr.io/slim-it/dhcp-dns-helper:sha-<git-sha>
```

## Configuration

Configuration is read from environment variables:

```text
NAMESERVER=localhost
ZONE=xxx.local
PREFIX_LENGTH=24
TTL=3600
RECORD_SALT=xxx
KEYRING_JSON={"xxx":"xxx"}
AUTHENTICATION_TOKENS_JSON=["xxx"]
```

`PREFIX_LENGTH` defaults to `24` and `TTL` defaults to `3600`.

## Build locally

```sh
docker build --build-arg DHCP_DNS_HELPER_VERSION="$(cat VERSION)" -t ghcr.io/slim-it/dhcp-dns-helper:"$(cat VERSION)" .
```

## Run locally

```sh
docker run --rm --env-file env.example -p 8080:8080 ghcr.io/slim-it/dhcp-dns-helper:"$(cat VERSION)"
```

Mikrotik RouterOS
-----------------
Script for using as a Mikrotik [RouterOS DHCP Server](https://wiki.mikrotik.com/wiki/Manual:IP/DHCP_Server#General) lease script:
```
:local webservice "https://dhcp-dns.example.local"
:local token "xxx"

if ([:len $"lease-hostname"] > 0) do={
  :local action
  if ($leaseBound = "1") do={
    :set action "register_host"
  } else={
    :set action "deregister_host"
  }

  /tool fetch http-method=post keep-result=no http-header-field="Authorization: Basic $($token)" http-data="hostname=$($"lease-hostname")&ip_address=$($leaseActIP)" url="$($webservice)/$($action)"
}
```
(this script needs `read` and `test` permissions if run as a system script)
