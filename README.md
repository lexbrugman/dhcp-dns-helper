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
NAMESERVER=127.0.0.1
ZONE=xxx.local
PREFIX_LENGTH=24
TTL=3600
MARKER_PREFIX=x-dyn:
KEYRING_JSON={"xxx":"xxx"}
AUTHENTICATION_TOKENS_JSON=["xxx"]
```

`PREFIX_LENGTH` defaults to `24` and must be `8`, `16` or `24`, `TTL` defaults
to `3600`, `RECORD_SALT` defaults to `<ZONE>-dhcp-dns`, and `MARKER_PREFIX`
defaults to `x-dyn:`.

Keys in `KEYRING_JSON` must be `hmac-sha256` TSIG keys, and the nameserver's
update policy must allow this application to write `A`, `PTR` and `TXT`
records in the forward and reverse zones.

## Record ownership marker

Every name this application writes — forward `A` records and reverse `PTR`
records alike — carries a sibling `TXT` record whose value is `MARKER_PREFIX`
followed by a salted hash of the record name. The marker and the data record
are always written in a single DNS UPDATE message, so a name is never
observable without its marker.

The marker serves two purposes:

- this application only replaces or deletes names whose marker matches,
  so it cannot clobber records it does not own
- zone reconcilers that purge undeclared records (e.g. static-dns-helper)
  must treat any name carrying a `TXT` value starting with `MARKER_PREFIX`
  as dynamically managed and leave it alone

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
