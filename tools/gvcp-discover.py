#!/usr/bin/env python3
# GVCP broadcast discovery probe: sends GigE Vision DISCOVERY_CMD broadcasts from a
# given local IP and pretty-prints every DISCOVERY_ACK. Vendor-SDK-independent ground
# truth for "which cameras answer discovery on this wire".
#
# Usage:  gvcp-discover.py <local-ip> [--broadcast 10.48.0.255] [--seconds 5]
#         (sends to 255.255.255.255 always; add --broadcast for the subnet-directed one)
#
# Copyright 2026 ITTH GmbH & Co. KG
import argparse, socket, struct, sys, time

GVCP_PORT = 3956

def parse_ack(data, addr):
    status, answer, length, ack_id = struct.unpack(">HHHH", data[:8])
    if answer != 0x0003:  # not a DISCOVERY_ACK
        return f"  [from {addr[0]}] non-discovery answer 0x{answer:04x}"
    p = data[8:]
    def ip(off): return ".".join(str(b) for b in p[off:off + 4])
    def s(off, n): return p[off:off + n].split(b"\0")[0].decode("ascii", "replace")
    mac = ":".join(f"{b:02x}" for b in p[10:16])
    return "\n".join([
        f"  DISCOVERY_ACK from {addr[0]}:",
        f"    spec {struct.unpack('>HH', p[0:4])}  mac {mac}",
        f"    ip_options 0x{struct.unpack('>I', p[16:20])[0]:08x}  ip_current 0x{struct.unpack('>I', p[20:24])[0]:08x}",
        f"    current_ip {ip(0x24)}  subnet {ip(0x34)}  gateway {ip(0x44)}",
        f"    manufacturer '{s(0x48, 32)}'  model '{s(0x68, 32)}'",
        f"    version '{s(0x88, 32)}'  serial '{s(0xd8, 16)}'  username '{s(0xe8, 16)}'",
    ])

def main():
    ap = argparse.ArgumentParser(description="GigE Vision (GVCP) broadcast discovery probe")
    ap.add_argument("local_ip", help="local IP of the interface to probe from")
    ap.add_argument("--broadcast", action="append", default=[],
                    help="additional (subnet-directed) broadcast address, repeatable")
    ap.add_argument("--seconds", type=float, default=5.0, help="listen duration (default 5)")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((args.local_ip, 0))
    sock.settimeout(0.5)
    print(f"bound to {sock.getsockname()}")

    # flags 0x11 = ack-required + allow-broadcast-ack, 0x01 = ack-required only
    for flags in (0x11, 0x01):
        pkt = struct.pack(">BBHHH", 0x42, flags, 0x0002, 0x0000, 0xFFFF)
        for dst in args.broadcast + ["255.255.255.255"]:
            try:
                sock.sendto(pkt, (dst, GVCP_PORT))
                print(f"sent DISCOVERY_CMD flags=0x{flags:02x} -> {dst}:{GVCP_PORT}")
            except OSError as e:
                print(f"send to {dst} FAILED: {e}")

    seen = {}
    end = time.time() + args.seconds
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        key = (addr[0], data[:8])
        if key in seen:
            continue
        seen[key] = True
        try:
            print(parse_ack(data, addr))
        except Exception as e:
            print(f"  [from {addr[0]}] unparseable ({e}): {data[:64].hex()}")

    print(f"done: {len(seen)} unique response(s)")
    return 0 if seen else 1

if __name__ == "__main__":
    sys.exit(main())
