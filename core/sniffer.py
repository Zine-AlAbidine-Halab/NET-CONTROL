"""
sniffer.py — the capture engine and threat detectors.

Runs scapy's sniff() on a background thread. Each captured packet is:
  1. counted into live traffic statistics, and
  2. passed through two detectors:
       * ARP spoofing  — an IP whose MAC suddenly changes, which is
         the signature of an ARP cache poisoning / MITM attack.
       * Traffic flood — one source IP exceeding a packet-rate
         threshold inside a sliding time window (DoS-style).

Whitelisted hosts (see access_control) are trusted and skipped by the
detectors to reduce false positives.

scapy needs root and a real interface, so this runs on the Kali VM.
"""

import json
import os
import threading
import time
from collections import defaultdict, deque

from .alerts import log_event
from .access_control import is_whitelisted

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")

# scapy is imported lazily so the rest of the panel can be inspected
# (and the README demo'd) even on a machine without scapy installed.
try:
    from scapy.all import sniff, ARP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TrafficMonitor:
    """Holds live state shared between the sniffer thread and Flask."""

    def __init__(self, config):
        self.config = config
        self._lock = threading.Lock()

        # ARP table: IP -> MAC last seen.
        self.arp_table = {}

        # Per-IP packet timestamps for flood detection (sliding window).
        self.packet_times = defaultdict(lambda: deque())

        # Live counters for the dashboard.
        self.total_packets = 0
        self.packets_per_ip = defaultdict(int)
        self.protocol_counts = defaultdict(int)

        self.running = False
        self._thread = None

    # ---- detectors -----------------------------------------------------

    def _check_arp(self, pkt):
        """Detect a MAC address change for a known IP (ARP spoofing)."""
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        # op == 2 is an ARP reply, the packet type used in poisoning.
        if arp.op != 2:
            return

        ip, mac = arp.psrc, arp.hwsrc.lower()
        if is_whitelisted(ip):
            self.arp_table[ip] = mac
            return

        known = self.arp_table.get(ip)
        if known and known != mac:
            log_event(
                "ARP",
                f"ARP spoofing suspected: {ip} moved from {known} to {mac}",
                "critical",
            )
        self.arp_table[ip] = mac

    def _check_flood(self, src_ip):
        """Detect one IP sending too many packets in the time window."""
        det = self.config["detection"]
        window = det["flood_window_seconds"]
        threshold = det["flood_packet_threshold"]

        if is_whitelisted(src_ip):
            return

        now = time.time()
        times = self.packet_times[src_ip]
        times.append(now)
        # Drop timestamps older than the window.
        while times and now - times[0] > window:
            times.popleft()

        if len(times) == threshold:
            # Fires once when the threshold is first crossed.
            log_event(
                "FLOOD",
                f"Traffic flood from {src_ip}: "
                f"{len(times)} packets in {window}s",
                "critical",
            )

    # ---- packet handler ------------------------------------------------

    def _handle(self, pkt):
        with self._lock:
            self.total_packets += 1

            if self.config["detection"]["arp_check_enabled"]:
                self._check_arp(pkt)

            if pkt.haslayer(IP):
                src = pkt[IP].src
                self.packets_per_ip[src] += 1
                proto = pkt.sprintf("%IP.proto%")
                self.protocol_counts[proto] += 1
                self._check_flood(src)

    # ---- lifecycle -----------------------------------------------------

    def _run(self):
        iface = self.config.get("interface")
        # store=False keeps memory flat during long captures.
        sniff(iface=iface, prn=self._handle, store=False,
              stop_filter=lambda _: not self.running)

    def start(self):
        if not SCAPY_AVAILABLE:
            log_event("SYSTEM", "scapy not installed — capture disabled", "warning")
            return False
        if self.running:
            return False
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log_event("SYSTEM", f"Capture started on {self.config.get('interface')}", "info")
        return True

    def stop(self):
        self.running = False
        log_event("SYSTEM", "Capture stopped", "info")

    def snapshot(self):
        """Thread-safe copy of current stats for the dashboard."""
        with self._lock:
            top_talkers = sorted(
                self.packets_per_ip.items(), key=lambda kv: kv[1], reverse=True
            )[:10]
            return {
                "running": self.running,
                "scapy_available": SCAPY_AVAILABLE,
                "total_packets": self.total_packets,
                "unique_ips": len(self.packets_per_ip),
                "top_talkers": top_talkers,
                "protocols": dict(self.protocol_counts),
                "arp_entries": len(self.arp_table),
            }


def load_config():
    if not os.path.isfile(CONFIG_PATH):
        raise RuntimeError(
            "Missing config.json. Copy config.example.json to config.json "
            "and set your local interface/subnet."
        )
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)
