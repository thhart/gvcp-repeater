#!/usr/bin/env python3
# GVCP unicast discovery sweep: sends a GigE Vision DISCOVERY_CMD to every host of an
# IPv4 prefix. Finds every camera that answers by-IP discovery, even when broadcast
# enumeration is broken — the wire-level equivalent of "add camera by IP".
#
# Usage:  gvcp-sweep.py <local-ip> <cidr>        e.g.  gvcp-sweep.py 10.48.0.64 10.48.0.0/24
#
# Copyright 2026 ITTH GmbH & Co. KG
import argparse, ipaddress, socket, struct, sys, time

GVCP_PORT = 3956

def parse_ack(data, addr):
    status, answer, length, ack_id = struct.unpack(">HHHH", data[:8])
    if answer != 0x0003:
        return f"{addr[0]}: non-discovery answer 0x{answer:04x}"
    p = data[8:]
    def ip(off): return ".".join(str(b) for b in p[off:off + 4])
    def s(off, n): return p[off:off + n].split(b"\0")[0].decode("ascii", "replace")
    mac = ":".join(f"{b:02x}" for b in p[10:16])
    return (f"{addr[0]}: mac {mac}  ip {ip(0x24)}/{ip(0x34)} gw {ip(0x44)}  "
            f"[{s(0x48, 32)} {s(0x68, 32)}]  fw '{s(0x88, 32)}'  serial '{s(0xd8, 16)}'  "
            f"name '{s(0xe8, 16)}'  ipcfg 0x{struct.unpack('>I', p[0x14:0x18])[0]:08x}")

def main():
    ap = argparse.ArgumentParser(description="GigE Vision (GVCP) unicast discovery sweep")
    ap.add_argument("local_ip", help="local IP of the interface to probe from")
    ap.add_argument("cidr", help="IPv4 prefix to sweep, e.g. 10.48.0.0/24")
    ap.add_argument("--seconds", type=float, default=3.0, help="final listen window (default 3)")
    args = ap.parse_args()

    net = ipaddress.ip_network(args.cidr, strict=False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.local_ip, 0))
    sock.setblocking(False)
    pkt = struct.pack(">BBHHH", 0x42, 0x01, 0x0002, 0x0000, 0x1234)

    seen = {}
    def drain():
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except BlockingIOError:
                return
            if addr[0] not in seen:
                try:
                    seen[addr[0]] = parse_ack(data, addr)
                except Exception as e:
                    seen[addr[0]] = f"{addr[0]}: unparseable ({e}) {data[:32].hex()}"

    for i, host in enumerate(net.hosts()):
        dst = str(host)
        if dst == args.local_ip:
            continue
        try:
            sock.sendto(pkt, (dst, GVCP_PORT))
        except OSError:
            pass
        if i % 16 == 15:
            time.sleep(0.02)
            drain()

    end = time.time() + args.seconds
    while time.time() < end:
        drain()
        time.sleep(0.1)

    for k in sorted(seen, key=lambda x: tuple(int(o) for o in x.split("."))):
        print(seen[k])
    print(f"total: {len(seen)} GVCP responder(s) in {net}")
    return 0 if seen else 1

if __name__ == "__main__":
    sys.exit(main())
