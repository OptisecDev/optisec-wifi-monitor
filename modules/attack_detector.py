"""Module 2 - Attack Detector: Deauth flood, Evil Twin, ARP poisoning detection."""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

try:
    from scapy.all import (
        sniff, Dot11, Dot11Deauth, Dot11Beacon, ARP, Ether,
        RadioTap, Dot11Elt
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class AttackDetector:
    def __init__(self, db, config, alert_mgr, monitor_iface: str):
        self.db = db
        self.config = config
        self.alert_mgr = alert_mgr
        self.monitor_iface = monitor_iface
        self._running = False

        # Deauth flood tracking: {src_mac: deque of timestamps}
        self._deauth_log: dict = defaultdict(lambda: deque())
        self._deauth_lock = threading.Lock()

        # Known BSSIDs and their SSIDs for Evil Twin detection
        self._known_networks: dict = {}  # ssid -> set of bssids
        self._ap_lock = threading.Lock()

        # ARP table for poisoning detection: {ip -> set of macs seen}
        self._arp_table: dict = defaultdict(set)
        self._arp_lock = threading.Lock()

    def start(self):
        self._running = True
        if not SCAPY_AVAILABLE:
            self.alert_mgr.low("SYSTEM", "Scapy not available - attack detection limited")
            self._poll_fallback()
            return

        try:
            sniff(
                iface=self.monitor_iface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"Attack detector sniff error: {e}")
            self._poll_fallback()

    def stop(self):
        self._running = False

    def _poll_fallback(self):
        """Minimal fallback when scapy unavailable."""
        while self._running:
            time.sleep(10)

    def _packet_handler(self, pkt):
        try:
            if pkt.haslayer(Dot11Deauth):
                self._handle_deauth(pkt)
            if pkt.haslayer(Dot11Beacon):
                self._handle_beacon(pkt)
            if pkt.haslayer(ARP):
                self._handle_arp(pkt)
        except Exception:
            pass

    # --- Deauth Flood ---
    def _handle_deauth(self, pkt):
        src = pkt[Dot11].addr2 or "unknown"
        dst = pkt[Dot11].addr1 or "broadcast"
        now = datetime.now()

        thresholds = self.config.alert_thresholds
        flood_count = thresholds.get("deauth_flood_count", 10)
        flood_window = thresholds.get("deauth_flood_window", 60)
        window = timedelta(seconds=flood_window)

        with self._deauth_lock:
            log = self._deauth_log[src]
            log.append(now)
            # Prune old entries
            while log and (now - log[0]) > window:
                log.popleft()
            count = len(log)

        if count >= flood_count:
            # Severity escalates with count
            if count >= flood_count * 3:
                severity = "CRITICAL"
            elif count >= flood_count * 2:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            msg = f"Deauth flood detected from {src} ({count} frames/{flood_window}s)"
            details = f"Target: {dst} | Frames: {count} in {flood_window}s"

            self.alert_mgr.add("DEAUTH_FLOOD", severity, msg, details)
            self.db.add_attack(
                "DEAUTH_FLOOD", severity,
                source_mac=src, target_mac=dst,
                details=details
            )

    # --- Evil Twin Detection ---
    def _handle_beacon(self, pkt):
        bssid = pkt[Dot11].addr3
        ssid = None

        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0:  # SSID
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    except Exception:
                        ssid = str(elt.info)
                    break
                elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None

        if not ssid or not bssid:
            return

        with self._ap_lock:
            if ssid not in self._known_networks:
                self._known_networks[ssid] = set()

            known_bssids = self._known_networks[ssid]

            if bssid not in known_bssids:
                if len(known_bssids) >= 1:
                    # Multiple BSSIDs for same SSID = possible Evil Twin
                    existing = list(known_bssids)
                    msg = f"Possible Evil Twin: SSID '{ssid}' seen from multiple BSSIDs"
                    details = (
                        f"Known BSSID(s): {', '.join(existing)} | "
                        f"New BSSID: {bssid}"
                    )
                    self.alert_mgr.add("EVIL_TWIN", "HIGH", msg, details)
                    self.db.add_attack(
                        "EVIL_TWIN", "HIGH",
                        bssid=bssid, ssid=ssid,
                        details=details
                    )
                known_bssids.add(bssid)

    # --- ARP Poisoning ---
    def _handle_arp(self, pkt):
        if pkt[ARP].op != 2:  # ARP reply only
            return

        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if not ip or not mac or mac == "00:00:00:00:00:00":
            return

        with self._arp_lock:
            known_macs = self._arp_table[ip]
            if known_macs and mac not in known_macs:
                old_macs = list(known_macs)
                msg = f"ARP poisoning detected: IP {ip} changed MAC"
                details = (
                    f"IP: {ip} | Previous MAC(s): {', '.join(old_macs)} | "
                    f"New MAC: {mac}"
                )
                self.alert_mgr.add("ARP_POISONING", "CRITICAL", msg, details)
                self.db.add_attack(
                    "ARP_POISONING", "CRITICAL",
                    source_mac=mac, target_mac=None,
                    details=details
                )
            known_macs.add(mac)

    def get_stats(self) -> dict:
        with self._deauth_lock:
            active_deauth_sources = len(self._deauth_log)
        with self._ap_lock:
            monitored_ssids = len(self._known_networks)
        with self._arp_lock:
            tracked_ips = len(self._arp_table)

        return {
            "active_deauth_sources": active_deauth_sources,
            "monitored_ssids": monitored_ssids,
            "tracked_ips": tracked_ips,
            "scapy_available": SCAPY_AVAILABLE,
        }
