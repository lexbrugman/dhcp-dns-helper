# dhcp-dns-helper

This application creates an HTTP interface into nsupdate for managing DNS host records in (for example) [Bind](https://www.isc.org/bind/). Intended to be used together with a DHCP server to provide DNS host records for DHCP leases.

## Image

CI publishes:

```text
ghcr.io/lexbrugman/dhcp-dns-helper:sha-<git-sha>
ghcr.io/lexbrugman/dhcp-dns-helper:latest
```

## Configuration

Configuration is read from environment variables:

```text
NAMESERVER=localhost
ZONE=xxx.local
PREFIX_LENGTH=24
TTL=3600
KEYRING_JSON={"xxx":"xxx"}
AUTHENTICATION_TOKENS_JSON=["xxx"]
```

`PREFIX_LENGTH` defaults to `24`, `TTL` defaults to `3600`, and
`RECORD_SALT` defaults to `<ZONE>-dhcp-dns`.

## Build locally

```sh
docker build --build-arg GIT_SHA="$(git rev-parse HEAD)" -t ghcr.io/lexbrugman/dhcp-dns-helper:sha-"$(git rev-parse --short HEAD)" .
```

## Run locally

```sh
docker run --rm --env-file env.example -p 8080:8080 ghcr.io/lexbrugman/dhcp-dns-helper:sha-"$(git rev-parse --short HEAD)"
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
