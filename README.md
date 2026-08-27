# wireproxy

[![ISC licensed](https://img.shields.io/badge/license-ISC-blue)](./LICENSE)
[![Build status](https://github.com/octeep/wireproxy/actions/workflows/build.yml/badge.svg)](https://github.com/octeep/wireproxy/actions)
[![Documentation](https://img.shields.io/badge/godoc-wireproxy-blue)](https://pkg.go.dev/github.com/octeep/wireproxy)

A wireguard client that exposes itself as a socks5/http proxy or tunnels.

# What is this

`wireproxy` is a completely userspace application that connects to a wireguard peer,
and exposes a socks5/http proxy or tunnels on the machine. This can be useful if you need
to connect to certain sites via a wireguard peer, but can't be bothered to setup a new network
interface for whatever reasons.

# Main Sponsor

<a href="https://www.rapidproxy.io/?ref=wire"><img src="./assets/rapidproxy.png" width="300" alt="Rapidproxy"></a>

[RapidProxy](https://www.rapidproxy.io/?ref=wire) is a residential proxy platform with 90M+ real IPs across 200+ countries. It supports rotation, geo-targeting, and high concurrency to improve scraping success and reduce bans. Start your free trial today!

# Why you might want this

- You simply want to use wireguard as a way to proxy some traffic.
- You don't want root permission just to change wireguard settings.

Currently, I'm running wireproxy connected to a wireguard server in another country,
and configured my browser to use wireproxy for certain sites. It's pretty useful since
wireproxy is completely isolated from my network interfaces, and I don't need root to configure
anything.

Users who want something similar but for Amnezia VPN can use [this fork](https://github.com/artem-russkikh/wireproxy-awg)
of wireproxy by [@artem-russkikh](https://github.com/artem-russkikh).

# Feature

- TCP static routing for client and server
- SOCKS5/HTTP proxy (currently only CONNECT is supported)
- Transparent TLS ([SNI](https://en.wikipedia.org/wiki/Server_Name_Indication)) proxy
- Multiple connections in one process (WireGuard and/or Tailscale), each with its own proxies
- Tailscale support via embedded [tsnet](https://pkg.go.dev/tailscale.com/tsnet) (`-tags tsnet` build)

# TODO

- UDP Support in SOCKS5
- UDP static routing

# Usage

```bash
./wireproxy [-c path to config]
```

```bash
usage: wireproxy [-h|--help] [-c|--config "<value>"] [-s|--silent]
                 [-d|--daemon] [-i|--info "<value>"] [-v|--version]
                 [-n|--configtest]

                 Userspace wireguard client for proxying

Arguments:

  -h  --help        Print help information
  -c  --config      Path of configuration file
                    Default paths: /etc/wireproxy/wireproxy.conf, $HOME/.config/wireproxy.conf
  -s  --silent      Silent mode
  -d  --daemon      Make wireproxy run in background
  -i  --info        Specify the address and port for exposing health status
  -v  --version     Print version
  -n  --configtest  Configtest mode. Only check the configuration file for
                    validity.
```

# Build instruction

```bash
git clone https://github.com/octeep/wireproxy
cd wireproxy
make
```

To also enable Tailscale connections:

```bash
make wireproxy-tsnet   # builds with -tags tsnet (~3x binary size)
```

# Install

```bash
go install github.com/windtf/wireproxy/cmd/wireproxy@v1.1.2 # or @latest
```

# Use with VPN

Instructions for using wireproxy with Firefox container tabs and auto-start on MacOS can be found [here](/UseWithVPN.md).

# Sample config file

```ini
# The [Interface] and [Peer] configurations follow the same semantics and meaning
# of a wg-quick configuration. To understand what these fields mean, please refer to:
# https://wiki.archlinux.org/title/WireGuard#Persistent_configuration
# https://www.wireguard.com/#simple-network-interface
[Interface]
Address = 10.200.200.2/32 # The subnet should be /32 and /128 for IPv4 and v6 respectively
# MTU = 1420 (optional)
PrivateKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=
# PrivateKey = $MY_WIREGUARD_PRIVATE_KEY # Alternatively, reference environment variables
DNS = 10.200.200.1

[Peer]
PublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
# PresharedKey = UItQuvLsyh50ucXHfjF0bbR4IIpVBd74lwKc8uIPXXs= (optional)
Endpoint = my.ddns.example.com:51820
# PersistentKeepalive = 25 (optional)

# TCPClientTunnel is a tunnel listening on your machine,
# and it forwards any TCP traffic received to the specified target via wireguard.
# Flow:
# <an app on your LAN> --> localhost:25565 --(wireguard)--> play.cubecraft.net:25565
[TCPClientTunnel]
BindAddress = 127.0.0.1:25565
Target = play.cubecraft.net:25565

# TCPServerTunnel is a tunnel listening on wireguard,
# and it forwards any TCP traffic received to the specified target via local network.
# Flow:
# <an app on your wireguard network> --(wireguard)--> 172.16.31.2:3422 --> localhost:25545
[TCPServerTunnel]
ListenPort = 3422
Target = localhost:25545

# STDIOTunnel is a tunnel connecting the standard input and output of the wireproxy
# process to the specified TCP target via wireguard.
# This is especially useful to use wireproxy as a ProxyCommand parameter in openssh
# For example:
#    ssh -o ProxyCommand='wireproxy -c myconfig.conf' ssh.myserver.net
# Flow:
# Piped command -->(wireguard)--> ssh.myserver.net:22
[STDIOTunnel]
Target = ssh.myserver.net:22

# Socks5 creates a socks5 proxy on your LAN, and all traffic would be routed via wireguard.
[Socks5]
BindAddress = 127.0.0.1:25344

# Socks5 authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...

# Domain whitelist routing (optional). When TunnelDomains is set, only connections
# whose destination host matches one of the patterns are routed through wireguard;
# every other connection is dialed directly over your normal network. When
# TunnelDomains is unset, all traffic is routed through wireguard (default).
# Each TunnelDomains line is a single, full Go regular expression (RE2). Repeat
# the key for multiple patterns; do NOT comma-separate (so quantifiers like {2,4}
# keep working). Matching is case-insensitive and a trailing dot is ignored.
#TunnelDomains = ^(.*\.)?example\.com$
#TunnelDomains = ^ipinfo\.io$
# Set LogDomains = true to log every connection's destination host and whether it
# was routed to the TUNNEL or DIRECT. Useful for discovering which domains your
# apps reach before writing TunnelDomains. Off by default.
#LogDomains = true

# http creates a http proxy on your LAN, and all traffic would be routed via wireguard.
[http]
BindAddress = 127.0.0.1:25345

# HTTP authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...

# Specifying certificate and key enables HTTPS
#CertFile = ...
#KeyFile = ...

# TunnelDomains / LogDomains work here too (same semantics as [Socks5] above).
#TunnelDomains = ^(.*\.)?example\.com$
#LogDomains = true

# SNI creates a transparent TLS proxy on your LAN, and all traffic would be routed via wireguard,
# using Server Name Indication as routing destination.
[SNI]
BindAddress = 0.0.0.0:443

# TunnelDomains / LogDomains work here too, matched against the TLS SNI hostname.
#TunnelDomains = ^(.*\.)?example\.com$
#LogDomains = true
```

Alternatively, if you already have a wireguard config, you can import it in the
wireproxy config file like this:

```ini
WGConfig = <path to the wireguard config>

# Same semantics as above
[TCPClientTunnel]
...

[TCPServerTunnel]
...

[Socks5]
...
```

You can override specific Interface fields from the imported file:

```ini
WGConfig = /etc/wireproxy/my-vpn.conf

[Interface]
MTU = 1240            ; override the imported MTU
DNS = 1.1.1.1         ; override DNS
CheckAlive = 1.1.1.1  ; add health monitoring
CheckAliveInterval = 10

[Socks5]
BindAddress = 127.0.0.1:1084
```

Override fields: `MTU`, `DNS`, `ListenPort`, `CheckAlive`, `CheckAliveInterval`.
Identity fields (`PrivateKey`, `Address`) cannot be overridden — they must
come from the imported file.

Having multiple peers is also supported. `AllowedIPs` would need to be specified
such that wireproxy would know which peer to forward to.

```ini
[Interface]
Address = 10.254.254.40/32
PrivateKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=

[Peer]
Endpoint = 192.168.0.204:51820
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 10.254.254.100/32
PersistentKeepalive = 25

[Peer]
PublicKey = ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=
AllowedIPs = 10.254.254.1/32, fdee:1337:c000:d00d::1/128
Endpoint = 172.16.0.185:44044
PersistentKeepalive = 25


[TCPServerTunnel]
ListenPort = 5000
Target = service-one.servicenet:5000

[TCPServerTunnel]
ListenPort = 5001
Target = service-two.servicenet:5001

[TCPServerTunnel]
ListenPort = 5080
Target = service-three.servicenet:80

[UDPProxyTunnel]
BindAddress = 127.0.0.1:53
Target = 1.1.1.1:53
InactivityTimeout = 30 # If its set to 0, it will never timeout

[Resolve]
# Set DNS Resovle Strategy
# `ipv4`: Prioritize A records.
# `ipv6`: Prioritize AAAA records       .
# `auto` (Default): If the WireGuard interface has IPv4 address only, it's equivalent to `ipv4`, otherwise it's equivalent to `ipv6`.
ResolveStrategy = auto 
```

Wireproxy can also allow peers to connect to it:

```ini
[Interface]
ListenPort = 5400
...

[Peer]
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 10.254.254.100/32
# Note there is no Endpoint defined here.
```

# Multiple connections

wireproxy can run several independent connections (different VPN servers, or a
mix of WireGuard and Tailscale) inside one process. Each connection gets its
own proxies/tunnels on distinct local ports.

There are two ways to define multiple connections:

## 1. Repeated `-c` flags or a directory

```bash
./wireproxy -c vpn1.conf -c vpn2.conf -c vpn3.conf -i 127.0.0.1:9080
# or point at a directory of *.conf files:
./wireproxy -c /etc/wireproxy/connections/
```

Each file keeps the classic format shown above. A connection is named after
its file stem (`vpn1.conf` → `vpn1`), overridable with a root-level `Name =`
key.

## 2. Named groups inside one file

Sections prefixed with `<name>.` form their own connection; unprefixed
sections form the default connection:

```ini
[Interface]
Address = 10.200.200.2/32
PrivateKey = ...
[Peer]
Endpoint = vpn1.example.com:51820
...
[Socks5]
BindAddress = 127.0.0.1:1081

[de.Interface]
Address = 10.201.201.2/32
PrivateKey = ...
[de.Peer]
Endpoint = vpn2.example.com:51820
...
[de.Socks5]
BindAddress = 127.0.0.1:1082
```

Notes:

- Group names are case-insensitive (lowercased).
- Each group may import a plain WireGuard config via a `WGConfig` key inside
  its `[<name>.Interface]` section.
- `[Resolve]` is global by default; `[<name>.Resolve]` overrides it per
  connection.
- See [examples/multi-vpn.conf](examples/multi-vpn.conf).

## Failure handling

Startup validation is strict: duplicate connection names, conflicting bind
ports across connections, or invalid sections abort before anything starts
(`--configtest` checks all of this without starting). At runtime, failures are
best-effort: if one connection cannot start (bad key, port taken), wireproxy
logs an error and keeps serving the remaining connections.

# Tailscale support

Wireproxy can embed a Tailscale node inside the process using
[tsnet](https://tailscale.com/kb/1244/tsnet). This lets you expose
SOCKS5/HTTP proxies and tunnels that dial **into your tailnet** (or
listen **on the tailnet** for other peers) — all without requiring a
system Tailscale installation.

## How it works

```
┌─────────────────────────────────────────────┐
│  wireproxy process (no root, no TUN device) │
│                                             │
│  ┌──────────┐   ┌────────────────────────┐  │
│  │ tsnet    │   │ SOCKS5 / HTTP / Tunnel │  │
│  │ node ◄───┼───┤ proxy routines         │  │
│  └────┬─────┘   └────────────────────────┘  │
│       │                                     │
└───────┼─────────────────────────────────────┘
        │  tsnet dials through the Tailscale
        │  overlay network (DERP + WireGuard)
        ▼
   Tailnet peers / MagicDNS / internet
```

Unlike WireGuard mode, the tsnet node is a full Tailscale client:
it handles key exchange, DERP relaying, and MagicDNS internally.
The proxy routines dial hostnames like `nas.tail1234.ts.net` and
tsnet resolves them through the Tailscale peer list.

## Prerequisites

- **Tailscale account**: free at [login.tailscale.com](https://login.tailscale.com).
- **Optional**: [Headscale](https://headscale.net/) self-hosted control server.

## Step 1: Build with tsnet support

```bash
make wireproxy-tsnet
```

This compiles with `-tags tsnet` and produces a binary that accepts
`[Tailscale]` config sections. The binary is ~30 MB (vs ~15 MB without).

To verify tsnet is enabled:

```bash
./wireproxy-tsnet --version
# should print something like: v1.0.8-dev-tsnet
```

Without `-tags tsnet`, a `[Tailscale]` section still **validates**
(`--configtest` passes), but starting the connection fails with:

```
this binary was built without Tailscale support; rebuild with `-tags tsnet`
```

## Step 2: Get a Tailscale auth key

Go to [Tailscale admin console](https://login.tailscale.com/admin/settings/keys)
and generate an **auth key** (Settings → Keys → Generate auth key).

- Check **Reusable** if you want to start multiple nodes with the same key.
- Check **Ephemeral** if the node should auto-remove after disconnect.

Export the key:

```bash
export TS_AUTHKEY="tskey-auth-..."
```

Or write it directly in the config (less secure):

```ini
AuthKey = tskey-auth-...
```

## Step 3: Write the config

```ini
[Tailscale]
Hostname = wireproxy-proxy
AuthKey = $TS_AUTHKEY          ; env interpolation works everywhere
ControlURL =                   ; empty = Tailscale cloud; set URL for Headscale
Ephemeral = false
StateDir = $HOME/.local/share/wireproxy/tsnet-proxy

[Socks5]
BindAddress = 127.0.0.1:1084

[http]
BindAddress = 127.0.0.1:1085
```

See [examples/tailscale.conf](examples/tailscale.conf) for a full
reference.

## Step 4: Start

```bash
./wireproxy-tsnet -c tailscale.conf
```

**First run without AuthKey** prints a login URL to stderr:

```
[proxy] waiting for Tailscale login; authorize via the printed URL
[proxy] To authenticate, visit:
  https://login.tailscale.com/a/abcdef1234567890
```

Open the URL in a browser and authorize the node. Once authorized,
the connection comes up automatically. State is persisted in `StateDir`
so subsequent starts skip the login step.

With an AuthKey, the node starts immediately:

```
[proxy] tsnet node running
```

## Step 5: Use the proxy

Point your application at the SOCKS5 or HTTP proxy:

```bash
# SOCKS5
curl -x socks5://127.0.0.1:1084 http://nas.tail1234.ts.net:5000/api/data

# HTTP
curl -x http://127.0.0.1:1085 http://nas.tail1234.ts.net/api/data

# System-wide (Linux)
export ALL_PROXY=socks5://127.0.0.1:1084
```

Any hostname in your tailnet (MagicDNS names, Tailscale IPs) resolves
through tsnet and routes via the Tailscale overlay.

## Headscale (self-hosted) configuration

To use a Headscale server instead of Tailscale cloud, set `ControlURL`:

```ini
[Tailscale]
Hostname = wireproxy-proxy
AuthKey = $HS_AUTHKEY
ControlURL = https://hs.example.com:8080
```

The `ControlURL` is the base URL of your Headscale instance (no trailing slash).

## Mixing WireGuard and Tailscale

You can run WireGuard and Tailscale connections side-by-side:

```bash
./wireproxy-tsnet -c wg.conf -c tailscale.conf -i 127.0.0.1:9080
```

Or in a single named-group config:

```ini
[netguard.Socks5]
BindAddress = 127.0.0.1:1081

[netguard.Tailscale]
Hostname = wireproxy-ng
AuthKey = $TS_AUTHKEY

[warp.Socks5]
BindAddress = 127.0.0.1:1082

[warp.Interface]
WGConfig = /etc/wireproxy/wgcf-profile.conf

[Resolve]
ResolveStrategy = ipv4
```

Each connection gets its own health entry in `/readyz` and `/metrics`.

## Listening on the tailnet

Use `TCPServerTunnel` to expose a local service to other tailnet peers:

```ini
[Tailscale]
Hostname = wireproxy-server
AuthKey = $TS_AUTHKEY

[TCPServerTunnel]
ListenPort = 8080
Target = localhost:3000
```

Other tailnet peers can now reach `wireproxy-server:8080` directly.

## Limitations

| Feature | WireGuard | Tailscale (tsnet) |
|---|---|---|
| TCPClientTunnel / STDIOTunnel | Yes | Yes |
| TCPServerTunnel | Yes | Yes (on tailnet) |
| Socks5 / HTTP / SNI | Yes | Yes |
| UDPProxyTunnel | Yes | **No** |
| CheckAlive (ICMP ping) | Yes | **No** |
| /metrics details | Full `wg show` | Basic (no handshake data) |
| TunnelDomains filtering | Yes | Yes |
| Build required | `-tags wireguard` (default) | `-tags tsnet` |

## Troubleshooting

**"this binary was built without Tailscale support"**
Rebuild with `make wireproxy-tsnet`.

**Node stuck in "Starting" state**
Check that `ControlURL` is correct (leave empty for Tailscale cloud).
Ensure outbound UDP (DERP) is not blocked by a firewall.

**Auth expired / node unauthorized**
Delete the `StateDir` contents and restart. A new login URL will be printed.

**MagicDNS names not resolving**
Verify the hostname you're querying exists in your tailnet.
The `LookupContextHost` function first checks the Tailscale peer list,
then falls back to the system resolver.

See [examples/tailscale.conf](examples/tailscale.conf) for a complete
working example.

# Health endpoint

Wireproxy supports exposing a health endpoint for monitoring purposes.
The argument `--info/-i` specifies an address and port (e.g. `localhost:9080`), which exposes a HTTP server that provides health status metric of the server.

Currently two endpoints are implemented:

`/metrics`: Exposes information of the wireguard daemon, this provides the same information you would get with `wg show`. [This](https://www.wireguard.com/xplatform/#example-dialog) shows an example of what the response would look like. With multiple connections the output contains one `# connection: <name>` block per connection.

`/readyz`: This responds with a json which shows the last time a pong is received from an IP specified with `CheckAlive`, keyed by connection name. When `CheckAlive` is set, a ping is sent out to addresses in `CheckAlive` per `CheckAliveInterval` seconds (defaults to 5) via wireguard. If a pong has not been received from one of the addresses within the last `CheckAliveInterval` seconds (+2 seconds for some leeway to account for latency), then it would respond with a 503, otherwise a 200. Connections without `CheckAlive` contribute an empty object and never affect the status code.

For example:

```ini
[Interface]
PrivateKey = censored
Address = 10.2.0.2/32
DNS = 10.2.0.1
CheckAlive = 1.1.1.1, 3.3.3.3
CheckAliveInterval = 3

[Peer]
PublicKey = censored
AllowedIPs = 0.0.0.0/0
Endpoint = 149.34.244.174:51820

[Socks5]
BindAddress = 127.0.0.1:25344
```

`/readyz` would respond with

```text
< HTTP/1.1 503 Service Unavailable
< Date: Thu, 11 Apr 2024 00:54:59 GMT
< Content-Length: 35
< Content-Type: text/plain; charset=utf-8
<
{"1.1.1.1":1712796899,"3.3.3.3":0}
```

And for:

```ini
[Interface]
PrivateKey = censored
Address = 10.2.0.2/32
DNS = 10.2.0.1
CheckAlive = 1.1.1.1
```

`/readyz` would respond with

```text
< HTTP/1.1 200 OK
< Date: Thu, 11 Apr 2024 00:56:21 GMT
< Content-Length: 23
< Content-Type: text/plain; charset=utf-8
<
{"1.1.1.1":1712796979}
```

If nothing is set for `CheckAlive`, an empty JSON object with 200 will be the response.

The peer which the ICMP ping packet is routed to depends on the `AllowedIPs` set for each peers.

# Secondary sponsors 
<p>This project is supported by the DigitalOcean Open Source Credits Program:</p>
<p>
  <a href="https://www.digitalocean.com/">
    <img src="https://opensource.nyc3.cdn.digitaloceanspaces.com/attribution/assets/SVG/DO_Logo_horizontal_blue.svg" width="201px">
  </a>
</p>

# Stargazers over time

[![Stargazers over time](https://starchart.cc/octeep/wireproxy.svg)](https://starchart.cc/octeep/wireproxy)
