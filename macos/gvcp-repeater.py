#!/usr/bin/python3
# gvcp-repeater — repairs GigE Vision (GVCP) discovery on macOS multi-NIC hosts.
#
# Basler pylon (and other GigE Vision clients) send discovery as UDP to
# 255.255.255.255:3956 from one socket per interface IP, without IP_BOUND_IF.
# macOS routes ALL limited-broadcast packets via the single unscoped
# 255.255.255.255/32 route (the primary interface), so discovery for every
# other NIC leaves the wrong wire and cameras never see it.
#
# This daemon BPF-captures UDP packets to 255.255.255.255:3956 on all active
# Ethernet-like interfaces, maps each packet's source IP to the interface that
# owns it, and re-injects the frame on that interface when it was captured
# elsewhere. Loop-free by construction: a repeated frame is captured on the
# interface that owns its source IP and is therefore never repeated again.
#
# Copyright 2026 ITTH GmbH & Co. KG
import ctypes, fcntl, os, re, select, signal, struct, subprocess, sys, time

GVCP_PORT = 3956
REFRESH_S = 10          # interface rescan interval
FILTER_EXPR = "ip and udp dst port %d and ip dst host 255.255.255.255" % GVCP_PORT

# macOS BPF ioctls (64-bit)
BIOCSETIF     = 0x8020426c  # _IOW('B',108, struct ifreq)
BIOCSETF      = 0x80104267  # _IOW('B',103, struct bpf_program)
BIOCIMMEDIATE = 0x80044270  # _IOW('B',112, u_int)
BIOCSHDRCMPLT = 0x80044275  # _IOW('B',117, u_int)
BIOCSSEESENT  = 0x80044277  # _IOW('B',119, u_int)
BIOCGBLEN     = 0x40044266  # _IOR('B',102, u_int)

def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)

def compile_filter(ifname):
    """Use tcpdump -ddd to compile the kernel BPF filter program (EN10MB).
    Needs a real interface: without -i, macOS tcpdump picks PKTAP and refuses."""
    out = subprocess.run(["/usr/sbin/tcpdump", "-i", ifname, "-ddd", FILTER_EXPR],
                         capture_output=True, text=True, check=True).stdout.split()
    n = int(out[0])
    words = [int(x) for x in out[1:]]
    insns = (ctypes.c_char * (8 * n))()
    for i in range(n):
        code, jt, jf, k = words[4*i:4*i+4]
        struct.pack_into("=HBBI", insns, 8*i, code, jt, jf, k)
    return n, insns

FILTER_N, FILTER_INSNS = None, None

def active_interfaces():
    """Return {ifname: {'mac': bytes, 'ips': set()}} for up Ethernet-like interfaces."""
    names = subprocess.run(["/sbin/ifconfig", "-l", "-u", "inet"],
                           capture_output=True, text=True).stdout.split()
    result = {}
    for name in names:
        if re.match(r"^(lo|utun|awdl|llw|gif|stf|pktap|bridge|ap)\d", name):
            continue
        cfg = subprocess.run(["/sbin/ifconfig", name], capture_output=True, text=True).stdout
        mac = re.search(r"ether ([0-9a-f:]{17})", cfg)
        ips = set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", cfg))
        if mac and ips and "status: active" in cfg:
            result[name] = {"mac": bytes.fromhex(mac.group(1).replace(":", "")), "ips": ips}
    return result

def open_bpf(ifname):
    fd = None
    for i in range(256):
        try:
            fd = os.open("/dev/bpf%d" % i, os.O_RDWR)
            break
        except OSError:
            continue
    if fd is None:
        raise RuntimeError("no free /dev/bpf device")
    fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", ifname.encode()))
    fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
    fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack("I", 1))   # we supply full Ethernet headers on writes
    fcntl.ioctl(fd, BIOCSSEESENT, struct.pack("I", 1))    # we must see locally-sent (mis-routed) packets
    fcntl.ioctl(fd, BIOCSETF, struct.pack("@IP", FILTER_N, ctypes.addressof(FILTER_INSNS)))
    blen = struct.unpack("I", fcntl.ioctl(fd, BIOCGBLEN, struct.pack("I", 0)))[0]
    os.set_blocking(fd, False)
    return fd, blen

def bpf_frames(buf):
    """Yield captured frames from a BPF read buffer."""
    off = 0
    while off + 18 <= len(buf):
        caplen, datalen, hdrlen = struct.unpack_from("=IIH", buf, off + 8)
        if hdrlen < 18 or caplen == 0 or off + hdrlen + caplen > len(buf):
            return
        yield buf[off + hdrlen: off + hdrlen + caplen]
        off += (hdrlen + caplen + 3) & ~3  # BPF_WORDALIGN

def main():
    global FILTER_N, FILTER_INSNS
    while FILTER_N is None:
        ifs = active_interfaces()
        if ifs:
            FILTER_N, FILTER_INSNS = compile_filter(next(iter(ifs)))
        else:
            time.sleep(REFRESH_S)
    log("gvcp-repeater starting (filter: %s, %d insns)" % (FILTER_EXPR, FILTER_N))

    taps = {}        # ifname -> (fd, blen)
    ip_owner = {}    # ip -> ifname
    macs = {}        # ifname -> mac bytes
    signature = None
    last_refresh = 0.0
    repeated = 0

    running = [True]
    signal.signal(signal.SIGTERM, lambda *_: running.__setitem__(0, False))
    signal.signal(signal.SIGINT, lambda *_: running.__setitem__(0, False))

    while running[0]:
        now = time.time()
        if now - last_refresh >= REFRESH_S:
            last_refresh = now
            ifs = active_interfaces()
            sig = sorted((n, tuple(sorted(d["ips"]))) for n, d in ifs.items())
            if sig != signature:
                signature = sig
                for fd, _ in taps.values():
                    os.close(fd)
                taps, ip_owner, macs = {}, {}, {}
                for name, d in ifs.items():
                    try:
                        taps[name] = open_bpf(name)
                    except OSError as e:
                        log("WARN: cannot tap %s: %s" % (name, e))
                        continue
                    macs[name] = d["mac"]
                    for ip in d["ips"]:
                        ip_owner[ip] = name
                log("tapping: " + ", ".join("%s(%s)" % (n, "/".join(sorted(ifs[n]["ips"])))
                                            for n in taps) if taps else "tapping: (none)")

        if not taps:
            time.sleep(REFRESH_S)
            continue

        fd_if = {fd: name for name, (fd, _) in taps.items()}
        ready, _, _ = select.select(list(fd_if), [], [], 2.0)
        for fd in ready:
            cap_if = fd_if[fd]
            try:
                buf = os.read(fd, taps[cap_if][1])
            except (BlockingIOError, OSError):
                continue
            for frame in bpf_frames(buf):
                if len(frame) < 34 or frame[12:14] != b"\x08\x00":
                    continue
                src_ip = ".".join(str(b) for b in frame[26:30])
                owner = ip_owner.get(src_ip)
                if owner is None or owner == cap_if or owner not in taps:
                    continue
                out = b"\xff\xff\xff\xff\xff\xff" + macs[owner] + frame[12:]
                try:
                    os.write(taps[owner][0], out)
                    repeated += 1
                    log("repeated GVCP discovery: src %s captured on %s -> re-sent on %s (#%d)"
                        % (src_ip, cap_if, owner, repeated))
                except OSError as e:
                    log("WARN: inject on %s failed: %s" % (owner, e))

    for fd, _ in taps.values():
        os.close(fd)
    log("gvcp-repeater stopped (%d packets repeated)" % repeated)

if __name__ == "__main__":
    main()
