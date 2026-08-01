# dhcp-dns-helper

This application creates an HTTP interface into nsupdate for managing DNS host records in (for example) [Bind](https://www.isc.org/bind/). Intended to be used together with a DHCP server to provide DNS host records for DHCP leases.

## Configuration

Configuration is read from environment variables:

| Variable                     | Default            | Description                                              |
| ---------------------------- | ------------------ | -------------------------------------------------------- |
| `NAMESERVER`                 | *required*         | Nameserver to send DNS UPDATE and zone transfers to       |
| `NAMESERVER_PORT`            | `53`               |                                                           |
| `ZONE`                       | *required*         | Forward zone, e.g. `xxx.local`                            |
| `PREFIX_LENGTH`              | `24`               | Reverse zone width; must be `8`, `16` or `24`             |
| `TTL`                        | `3600`             | TTL of the records written                                |
| `RECORD_SALT`                | `<ZONE>-dhcp-dns`  | Salt for the ownership marker hash                        |
| `MARKER_PREFIX`              | `x-dyn:`           | `TXT` prefix identifying records this app owns            |
| `TIMESTAMP_PREFIX`           | `x-dyn-ts:`        | `TXT` prefix carrying the last-vouched timestamp          |
| `SYNC_GRACE_SECONDS`         | `3600`             | How long an unvouched record survives a sync              |
| `KEYRING_JSON`               | *required*         | TSIG keyring, e.g. `{"keyname":"secret"}`                 |
| `AUTHENTICATION_TOKENS_JSON` | *required*         | Accepted API tokens, e.g. `["xxx"]`                       |

See [`env.example`](env.example) for a copy-pasteable starting point.

Keys in `KEYRING_JSON` must be `hmac-sha256` TSIG keys, and the nameserver's
update policy must allow this application to write `A`, `PTR` and `TXT`
records in the forward and reverse zones. The sync endpoint additionally
requires zone transfers (`allow-transfer`) for the same key on both zones.
Hostnames containing underscores additionally need `check-names ignore` on the
zone — BIND otherwise refuses the update, which surfaces as `success: false`
rather than a rejected request.

## API

Every endpoint except `/health` requires an `Authorization` header holding the
literal string `Basic <token>`, where `<token>` is one of
`AUTHENTICATION_TOKENS_JSON`. Despite the scheme name this is a bare shared
token, not RFC 7617 credentials — do not base64-encode it. A mismatch is `403`.

| Endpoint             | Body                                    | Purpose                                     |
| -------------------- | --------------------------------------- | ------------------------------------------- |
| `POST /register_host`   | form: `hostname`, `ip_address`       | Create/replace the records for one lease    |
| `POST /deregister_host` | form: `hostname`, `ip_address`       | Remove the records for one lease            |
| `POST /sync_hosts`      | JSON (see [Full table sync](#full-table-sync)) | Reconcile the zones against the full lease table |
| `GET /health`           | —                                    | Liveness, plus age and result of the last sync |

`hostname` must be a single DNS label — letters, digits, `-` and `_`, starting
and ending alphanumeric, at most 63 characters, lowercased on the way in — and
`ip_address` a valid IPv4 address. On the single-host endpoints anything else
is `400`; `/sync_hosts` skips the offending host instead. `/register_host` and
`/deregister_host` respond with `{"success": <bool>}`.

## Record ownership marker

Every name this application writes — forward `A` records and reverse `PTR`
records alike — carries two sibling `TXT` records:

- an ownership marker: `MARKER_PREFIX` followed by a salted hash of the
  record name
- a last-vouched timestamp: `TIMESTAMP_PREFIX` followed by a unix epoch,
  rewritten on every registration and every sync

Both are always written or replaced together with the data record in single
DNS UPDATE messages, so a name is never observable with a timestamp but
without its marker.

The marker serves two purposes:

- this application only replaces or deletes names whose marker matches,
  so it cannot clobber records it does not own
- zone reconcilers that purge undeclared records (e.g. static-dns-helper)
  must treat any name carrying a `TXT` value starting with `MARKER_PREFIX`
  as dynamically managed and leave the **entire name** alone — this per-name
  exclusion is what also protects the timestamp record, so reconcilers must
  not purge per record type, and both tools must agree on `MARKER_PREFIX`

## Full table sync

`POST /sync_hosts` reconciles the zones against the DHCP server's complete
bound-lease table, catching whatever the lease-event endpoints missed: it
re-adds missing or wrong records, re-vouches (timestamps) every listed host,
and expunges managed records that are absent from the table **and** have not
been vouched for within `SYNC_GRACE_SECONDS`. Records without a timestamp
(written before this feature) count as maximally stale.

```json
{
  "networks": ["10.0.0.0/24"],
  "hosts": [
    {"hostname": "host-a", "ip_address": "10.0.0.10"},
    {"hostname": "host-b", "ip_address": "10.0.0.11"}
  ],
  "dry_run": false
}
```

- `networks` scopes authority: only records whose address falls inside are
  vouched or expunged; each network must be at least as narrow as
  `PREFIX_LENGTH`
- a truncated request body fails JSON parsing and is rejected whole, and a
  merely incomplete host list cannot cause deletions either: every record
  vouched within `SYNC_GRACE_SECONDS` is protected until a later complete
  sync stops vouching for it
- a host that fails validation — malformed hostname, bad address, or an
  address outside `networks` — is skipped with a logged warning rather than
  failing the request, so one odd lease can't block the whole reconciliation;
  a skipped host is simply an undeclared one, protected by
  `SYNC_GRACE_SECONDS` like any other absence. A malformed payload *envelope*
  (bad JSON, bad `networks`, `hosts` not a list) is still rejected whole
- `dry_run: true` reports what would happen without writing anything
- the response lists `healed`, `refreshed`, `expunged`, `unverifiable`
  (marker-prefixed records whose hash doesn't verify; these are never touched
  and need manual cleanup) and `skipped` (rejected hosts, with the reason)
- syncs do not overlap: a request arriving while one is running is `409`, and
  a failure talking to the nameserver is `502`

Set `SYNC_GRACE_SECONDS` to 2–3× the sync schedule interval: a host missing
from a single sync (snapshot race, failed request) stays protected until well
past the next one. `/health` reports the age and result of the last applied
sync. Roll out by running a sync with `dry_run` first and reviewing the
response before enabling the schedule.

## Mikrotik RouterOS

### Lease script

For use as a [RouterOS DHCP Server](https://wiki.mikrotik.com/wiki/Manual:IP/DHCP_Server#General)
lease script, firing `/register_host` and `/deregister_host` on lease events:

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

### Sync scheduler script

For use as a scheduler script feeding `/sync_hosts` the full lease table:

```
:local webservice "https://dhcp-dns.example.local"
:local token "xxx"

:local networks ""
/ip dhcp-server network
:foreach network in=[find] do={
  :local address [get $network address]
  :if ([:len $networks] > 0) do={ :set networks ($networks . ",") }
  :set networks ($networks . "\"$address\"")
}

:local hosts ""
/ip dhcp-server lease
:foreach lease in=[find where status="bound"] do={
  :local hostname [get $lease host-name]
  :local address [get $lease address]
  :if ([:len $hostname] > 0) do={
    :if ([:len $hosts] > 0) do={ :set hosts ($hosts . ",") }
    :set hosts ($hosts . "{\"hostname\":\"$hostname\",\"ip_address\":\"$address\"}")
  }
}

:local body "{\"networks\":[$networks],\"hosts\":[$hosts]}"
/tool fetch http-method=post keep-result=no http-header-field="Authorization: Basic $token,Content-Type: application/json" http-data=$body url="$webservice/sync_hosts"
```

(this script needs `read`, `test` and `policy` permissions appropriate for
scheduler use)

The declared networks are derived from `/ip dhcp-server network`, so the
script never duplicates subnet configuration. If only some DHCP networks
should feed DNS, filter the `find` (e.g. by `comment`) — the lease loop then
needs the same filter, since a posted host outside the declared networks
rejects the request. Each DHCP network must also be at least as narrow as
the app's `PREFIX_LENGTH`.

## Running

CI publishes:

```text
ghcr.io/lexbrugman/dhcp-dns-helper:sha-<git-sha>
ghcr.io/lexbrugman/dhcp-dns-helper:latest
```

Build locally:

```sh
docker build --build-arg GIT_SHA="$(git rev-parse HEAD)" -t ghcr.io/lexbrugman/dhcp-dns-helper:sha-"$(git rev-parse --short HEAD)" .
```

Run locally:

```sh
docker run --rm --env-file env.example -p 8080:8080 ghcr.io/lexbrugman/dhcp-dns-helper:sha-"$(git rev-parse --short HEAD)"
```

## Tests

```sh
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

The integration tests spin up a throwaway BIND via testcontainers and are
skipped automatically when no container API socket is reachable.
