# Windows: analysis and port proposal

## Does the macOS bug exist on Windows?

Generally **no** — for the transmit side. Since Vista, Windows uses the strong-host
model: a UDP socket bound to a specific local address sends its limited broadcast
(`255.255.255.255`) out the interface owning that address. A per-interface enumerator
like pylon's therefore reaches every wire without needing a device bind. (An *unbound*
socket's limited broadcast goes out one interface chosen by metric — SDKs that
enumerate through a single unbound socket can still miss secondary NICs, but the major
GigE Vision SDKs bind per interface on Windows.)

The dominant Windows failure for "enumeration fails, open-by-IP works" is the
**receive side**:

1. **Windows Defender Firewall** dropping the unicast `DISCOVERY_ACK` — it arrives as
   unsolicited inbound UDP at an ephemeral port. Vendor installers add allow-rules for
   *their* tools; anything else (your own application, Python scripts) gets silently
   filtered, typically only on networks classified as "Public".
   Fix: allow the application, or a rule for inbound UDP with **remote** port 3956:
   ```
   netsh advfirewall firewall add rule name="GigE Vision discovery" dir=in
         action=allow protocol=UDP remoteport=3956
   ```
2. **VPN clients** (their lightweight filter drivers filter even with the tunnel down)
   and third-party endpoint security intercepting broadcast traffic.
3. **Camera/NIC subnet mismatch** — same as everywhere: the camera answers from
   `169.254.x.x` (LLA fallback) and the reply is discarded; use the vendor's "force IP"
   / this repo's `tools/gvcp-sweep.py` reasoning to locate it.

So on Windows: fix the firewall rule first; a repeater is rarely the answer.

## Port proposal (if a repeater is ever warranted)

Raw-frame capture/injection has no in-box user-mode API on Windows, so the port rides on
**Npcap** (the WinPcap successor, actively maintained, BSD-style licensed for
non-commercial redistribution — commercial bundling needs an Npcap OEM license):

* **Capture**: one `pcap` handle per adapter (`pcap_open_live`), same filter expression
  compiled with `pcap_compile`: `ip and udp dst port 3956 and ip dst host
  255.255.255.255`. Npcap delivers locally-sent frames when opened with
  `PCAP_OPENFLAG_NOCAPTURE_LOCAL` cleared — the mis-routed-transmit visibility needed.
* **Owner lookup**: source IP → adapter via `GetAdaptersAddresses()`.
* **Inject**: `pcap_sendpacket()` on the owning adapter with the rewritten Ethernet
  header. Same loop-free invariant as the macOS/Linux versions.
* **Packaging**: a Windows service (C# with SharpPcap, or Go/Rust) plus the Npcap
  runtime installer; needs Administrator only at install time.

## Status

Proposal only — not implemented. No confirmed Windows setup exhibiting the
transmit-side mis-route has been reported; the firewall rule above resolves the common
cases. If you hit a genuine Windows mis-route (prove it with Wireshark on both
adapters while the vendor tool scans), please open an issue with the capture.
