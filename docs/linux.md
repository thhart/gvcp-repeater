# Linux: analysis and port proposal

## Does the macOS bug exist on Linux?

Partially — the same *class* of failure exists, with two distinct mechanisms:

**1. Transmit side — limited broadcast follows the route table.**
Like macOS, Linux routes a datagram to `255.255.255.255` by route lookup. The main
table normally has no host route for it, so the packet follows the **default route** —
i.e. out the internet-facing interface, not the camera NIC. Binding the socket to a
local *address* does not pin the egress device; only `SO_BINDTODEVICE` (or a
`255.255.255.255` route in a per-interface table) does. Whether a vendor SDK is
affected therefore depends on whether it uses `SO_BINDTODEVICE` — which requires
`CAP_NET_RAW` on older kernels, so several SDKs deliberately avoid it and are exposed
to exactly the macOS-style mis-route. Subnet-directed broadcasts (`10.48.0.255`) are
unaffected: they match the on-link route.

**2. Receive side — `rp_filter` drops the ACK (Linux-specific).**
With strict reverse-path filtering (`net.ipv4.conf.*.rp_filter=1`, the default on many
distributions), the kernel silently drops the `DISCOVERY_ACK` of a camera whose source
IP does not fit the receiving interface's routes — the classic case being a factory-new
camera answering from a Link-Local `169.254.x.x` address while your NIC has a static
address. The camera *answered*; Linux threw the answer away. Basler's own Linux notes
and the Aravis project both document this. Diagnosis: the ACK is visible in
`tcpdump -i ethX` but the application never sees it.

```
# confirm cause 2
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.ethX.rp_filter
# fix (loose mode)
sudo sysctl -w net.ipv4.conf.all.rp_filter=2 -w net.ipv4.conf.ethX.rp_filter=2
```

Also check `firewalld`/`ufw`/`nftables`: the ACK arrives as unsolicited UDP at an
ephemeral port (conntrack usually classifies it RELATED/ESTABLISHED, but strict rulesets
break this).

## Port proposal: `AF_PACKET` repeater

The repeater algorithm ports 1:1; Linux even makes it cleaner than macOS because
`AF_PACKET` replaces the `/dev/bpf*` devices:

* **Capture**: one `AF_PACKET`/`SOCK_RAW` socket per interface (or a single socket with
  `sll_ifindex` demultiplexing), with the *same classic BPF filter* attached via
  `SO_ATTACH_FILTER` — the 13-instruction program for
  `ip and udp dst port 3956 and ip dst host 255.255.255.255` is byte-identical; generate
  it with `tcpdump -ddd` or embed it. Outgoing packets are delivered with
  `sll_pkttype == PACKET_OUTGOING`, which is exactly the mis-routed-transmit case we
  need to see.
* **Owner lookup**: map packet source IP → owning interface via `getifaddrs(3)` (or
  netlink `RTM_GETADDR`), refreshed periodically — same as the macOS implementation.
* **Inject**: `sendto()` on the `AF_PACKET` socket of the owning interface with a
  rebuilt Ethernet header (broadcast destination, owner's MAC as source). Requires
  `CAP_NET_RAW` only.
* **Loop safety**: identical invariant — a repeated frame is captured on the interface
  owning its source IP and is never repeated again. Additionally skip
  `PACKET_OUTGOING` frames whose ingress interface already owns the source IP.

Deployment: a ~150-line Python (or C) daemon under systemd with
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, `DynamicUser=yes`,
`Restart=always` — no root needed, unlike macOS.

An eBPF/TC variant (clone the packet to the right egress with a `tc` classifier) would
avoid the userspace hop entirely, but is distro-kernel-dependent overkill for a handful
of 8-byte packets per scan.

## Status

Proposal only — not implemented, because the transmit-side bug needs a confirmed
affected SDK/setup to test against (contributions and packet captures welcome; open an
issue). The `rp_filter` receive-side fix above needs no new code.
