# gvcp-repeater

**Your GigE Vision cameras don't show up in Basler pylon Viewer / pylon IP Configurator on macOS — but you can open them by IP address just fine? This repairs that.**

A tiny root daemon that fixes GigE Vision (GVCP) camera discovery on multi-NIC macOS
machines by re-injecting mis-routed discovery broadcasts onto the network interface they
were actually meant for. No routing changes, no kernel extensions, no dependencies —
one Python file using the OS's own BPF devices.

Verified against Basler pylon 10.0.2 / pylon IP Configurator on macOS 26.5 with
Basler a2A1920-165g5m cameras. The bug it works around is not Basler-specific: **any**
GigE Vision client that enumerates via limited broadcast without pinning its sockets to
a device is affected on macOS.

---

## The symptom

* pylon Viewer and pylon IP Configurator list **no cameras** (or only cameras on your
  primary network, e.g. Wi-Fi/office LAN).
* Adding the camera **manually by IP address works perfectly** — control, streaming,
  everything.
* `ping` to the camera works. The camera's IP configuration is correct. Firewall is off.
* The same camera enumerates instantly from a Linux/Windows box on the same switch.
* It feels flaky: occasionally (e.g. with Wi-Fi disabled) discovery suddenly works,
  then breaks again.

## The root cause

GigE Vision discovery is strictly request/response: the client sends a GVCP
`DISCOVERY_CMD` datagram to UDP port **3956**, cameras answer with a `DISCOVERY_ACK`.
Cameras **never announce themselves unsolicited** — if the request never reaches the
wire, the camera list stays empty forever.

pylon's transport layer enumerates by sending that request to the **limited broadcast
address `255.255.255.255`**, once per network interface, from a UDP socket bound to that
interface's IP — but **without binding the socket to the device** (`IP_BOUND_IF`).

macOS, however, routes limited-broadcast packets by the routing table alone. There is a
single unscoped host route for `255.255.255.255/32`, and it points at the **primary**
interface. The source address of the socket does not matter:

```
$ netstat -rn -f inet | grep 255.255.255.255
255.255.255.255/32 link#12  UCS  en0      ← ALL limited broadcasts leave here
```

So the discovery packet intended for your camera NIC physically leaves through the
wrong port — carrying a source IP that doesn't even belong to that network:

```
# captured while pylon IP Configurator scans; camera LAN is en5 (10.48.0.0/24)
$ sudo tcpdump -i en0 -n 'udp port 3956'
11:38:45.956764 IP 192.0.0.2.52043  > 255.255.255.255.3956: UDP, length 8   ← en0's scan, fine
11:38:45.956795 IP 10.48.0.64.54890 > 255.255.255.255.3956: UDP, length 8   ← en5's scan, WRONG WIRE

$ sudo tcpdump -i en5 -n 'udp port 3956'
(nothing. not one packet.)
```

The camera never sees a single discovery request → it is never listed. Opening it by IP
works because unicast follows the normal subnet route to the right interface.

```
                              255.255.255.255/32 → en0 (primary)
                                        │
   pylon socket bound to 10.48.0.64 ────┘──────────────▶ en0 ──▶ office LAN   ✗ camera never sees it
                                                         en5 ──▶ camera LAN   (silence)

   pylon "open by IP 10.48.0.40"  ──── 10.48/24 route ─▶ en5 ──▶ camera LAN   ✓ works
```

## The fix: repeat the broadcast onto the right wire

`gvcp-repeater` opens a BPF tap on every active Ethernet interface with a kernel-side
filter matching exactly one packet shape: **UDP to `255.255.255.255:3956`**. For every
captured packet it looks at the *source IP*, determines which local interface owns that
address, and — if the packet was captured on a *different* interface — re-injects the
identical frame onto the owning interface.

```
2026-07-08 12:04:12 repeated GVCP discovery: src 10.48.0.64 captured on en0 -> re-sent on en5 (#1)
```

One millisecond later, on the camera wire:

```
$ sudo tcpdump -i en5 -n 'udp port 3956'
12:04:12.209607 IP 10.48.0.64.50000 > 255.255.255.255.3956: UDP, length 8    ← repeated request
12:04:12.210402 IP 10.48.0.41.3956  > 10.48.0.64.50000: UDP, length 256      ← DISCOVERY_ACK
12:04:12.210407 IP 10.48.0.42.3956  > 10.48.0.64.50000: UDP, length 256      ← DISCOVERY_ACK
12:04:12.210537 IP 10.48.0.40.3956  > 10.48.0.64.50000: UDP, length 256      ← DISCOVERY_ACK
```

The cameras answer unicast straight back to pylon's own socket — pylon needs no
modification and immediately lists every camera.

Properties worth knowing:

* **Loop-free by construction.** A repeated frame is captured on the interface that owns
  its source IP, so `owner == capture interface` and it is never repeated again. No TTL
  tricks, no state.
* **All interfaces at once.** Unlike route workarounds (below), cameras on several NICs
  are discovered simultaneously; hot-plugged adapters are picked up within 10 s.
* **Zero impact on streaming.** The filter runs in the kernel (compiled via
  `tcpdump -ddd`); GVSP image traffic never reaches the daemon.
* **No dependencies.** Python 3 standard library only; uses `/dev/bpf*` directly.

## Install (macOS)

```
git clone https://github.com/thhart/gvcp-repeater.git
cd gvcp-repeater/macos
sudo ./install.sh
```

This installs `/usr/local/bin/gvcp-repeater.py` plus a LaunchDaemon
(`com.itth.gvcp-repeater`, starts at boot, restarts on failure) and starts it. Logs go
to `/var/log/gvcp-repeater.log`:

```
$ sudo tail /var/log/gvcp-repeater.log
2026-07-08 12:04:54 gvcp-repeater starting (filter: ip and udp dst port 3956 and ip dst host 255.255.255.255, 13 insns)
2026-07-08 12:04:54 tapping: en0(192.0.0.2), en5(10.48.0.64)
2026-07-08 12:04:12 repeated GVCP discovery: src 10.48.0.64 captured on en0 -> re-sent on en5 (#1)
```

Uninstall: `sudo ./uninstall.sh`.

Run in the foreground for a quick try-out (no install): `sudo ./gvcp-repeater.py`.

## Diagnostic tools

Two self-contained probes (also dependency-free) to establish ground truth on the wire,
independent of any vendor SDK — useful to separate camera-side from client-side trouble:

* [`tools/gvcp-discover.py`](tools/gvcp-discover.py) — sends GVCP discovery broadcasts
  (subnet-directed *and* limited) from a given local IP and pretty-prints every
  `DISCOVERY_ACK` (model, MAC, IP config, firmware, serial).
* [`tools/gvcp-sweep.py`](tools/gvcp-sweep.py) — unicast discovery sweep across a whole
  IPv4 prefix: finds every camera that answers by-IP discovery even when broadcast
  enumeration is broken.

## Alternatives considered (and why they fall short)

| Workaround | Problem |
|---|---|
| `sudo route add -host 255.255.255.255 -interface en5` | Works instantly, but serves **one** interface only, hijacks limited broadcast for the whole system, and dies on reboot/route churn. |
| Basler `AnnounceRemoteDevice()` / open by IP in your own code | Fine for your own applications, doesn't help the vendor GUI tools (Viewer, IP Configurator) you need for commissioning. |
| Making the camera NIC the primary interface | Breaks your actual network setup; not viable on machines that need internet + camera LAN. |
| Fixing it in pylon (bind discovery sockets with `IP_BOUND_IF`) | The correct fix — but it's in Basler's hands. If you're a Basler engineer reading this: `setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, if_nametoindex(ifname))` on the enumeration sockets makes this whole repository obsolete. Please. |

## Linux

The same failure class exists but manifests differently — Linux routes
`255.255.255.255` via the default route too unless the client uses `SO_BINDTODEVICE`,
and on the receive side `rp_filter` can silently drop discovery ACKs from
misconfigured cameras. Most vendor SDKs on Linux get at least one of these wrong.
A port of this repeater is straightforward (`AF_PACKET` + `SO_ATTACH_FILTER` instead of
BPF devices): see **[docs/linux.md](docs/linux.md)** for the full analysis and a
concrete implementation proposal.

## Windows

Windows' strong-host model sends limited broadcasts out the interface the socket is
bound to, so this particular mis-routing bug generally does **not** occur; broken
discovery on Windows is almost always the Windows Firewall dropping the unicast
`DISCOVERY_ACK` arriving at an ephemeral port. If a repeater is ever needed there, it
requires Npcap for injection: see **[docs/windows.md](docs/windows.md)** for the
analysis and a service proposal.

## FAQ

**Is this safe to leave running?** It runs as root (BPF requires it), reads only packets
matching an in-kernel filter for UDP port 3956 to 255.255.255.255, and writes only
byte-identical copies of those frames to a sibling interface. It never modifies payload,
never touches routing, never opens a listening port.

**Does it work for non-Basler cameras/SDKs?** Yes — the mechanism is protocol-level
(GigE Vision GVCP), not vendor-specific. Any SDK whose discovery uses limited broadcast
benefits.

**Why does discovery sometimes work without it?** If your camera NIC happens to be the
primary interface (e.g. Wi-Fi off), the broadcast route points at the right wire by
luck. Plug-in order and VPN clients can shuffle this — which is why the symptom feels
so erratic.

**GigE Vision "beacons"?** There are none. Cameras only ever answer requests. If your
tooling shows nothing, the request didn't reach the camera — start with
`tools/gvcp-discover.py` and `tcpdump -i <camera-if> -n udp port 3956`.

## License

MIT — Copyright 2026 ITTH GmbH & Co. KG
