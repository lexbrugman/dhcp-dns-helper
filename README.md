# dhcp-dns-helper

This application creates an HTTP interface into nsupdate for managing DNS host records in (for example) [Bind](https://www.isc.org/bind/). Intended to be used together with a DHCP server to provide DNS host records for DHCP leases.

Start server using: `gunicorn dhcp_dns:app`

Mikrotik RouterOS
-----------------
Script for using as a Mikrotik [RouterOS DHCP Server](https://wiki.mikrotik.com/wiki/Manual:IP/DHCP_Server#General) lease script:
```
:local webservice "xxx:8855"
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
