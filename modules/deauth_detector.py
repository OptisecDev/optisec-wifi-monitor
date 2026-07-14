"""Module 5 - Deauth Detector: passive 802.11 deauth/disassoc burst detection."""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


DEFAULT_DEAUTH_CONFIG = {
    "enabled": True,
    "burst_count": 15,
    "burst_window": 10,
}


class DeauthDetector:
    """Passive deauthentication/disassociation attack detector.

    Tracks deauth/disassoc frames per transmitter (addr2) in a sliding
    window and flags abnormal burst frequency consistent with an active
    deauth attack (e.g. aireplay-ng, mdk4), independent of the Evil
    Twin/ARP checks in AttackDetector. Findings use the same alert/attack
    schema as AttackDetector so they flow into the existing Groq AI
    analysis and PDF reporting pipeline unchanged.
    """

    def __init__(self, db, config, alert_mgr, monitor_iface: str):
        self.db = db
        self.config = config
        self.alert_mgr = alert_mgr
        self.monitor_iface = monitor_iface
        self._running = False

        # Burst tracking: {attacker_mac: deque of (timestamp, target_mac)}
        self._frame_log: dict = defaultdict(lambda: deque())
        self._lock = threading.Lock()

        # Cumulative count of burst alerts fired this session (for TUI/status display).
        self._bursts_detected = 0

    @property
    def settings(self) -> dict:
        cfg = self.config.get("deauth_detection", {}) or {}
        merged = DEFAULT_DEAUTH_CONFIG.copy()
        merged.update(cfg)
        return merged

    def is_enabled(self) -> bool:
        return bool(self.settings.get("enabled", True))

    def start(self):
        self._running = True

        if not self.is_enabled():
            self.alert_mgr.info("SYSTEM", "Deauth detector disabled via config - not starting")
            return

        if not SCAPY_AVAILABLE:
            self.alert_mgr.low("SYSTEM", "Scapy not available - deauth detection limited")
            self._poll_fallback()
            return

        # Retry with backoff instead of giving up permanently on the first
        # sniff() failure - the monitor interface can disappear (unplugged
        # adapter, rfkill, airmon-ng restart) and come back mid-run.
        retry_delay = 5
        while self._running:
            try:
                sniff(
                    iface=self.monitor_iface,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
                retry_delay = 5
            except Exception as e:
                self.alert_mgr.low(
                    "SYSTEM",
                    f"Deauth detector sniff error on {self.monitor_iface}: {e} - "
                    f"retrying in {retry_delay}s"
                )
            if not self._running:
                return
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)

    def stop(self):
        self._running = False

    def _poll_fallback(self):
        """Minimal fallback when scapy is unavailable (permanent condition)."""
        while self._running:
            time.sleep(10)

    def _packet_handler(self, pkt):
        try:
            if pkt.haslayer(Dot11Deauth):
                self._handle_frame(pkt, "deauth")
            elif pkt.haslayer(Dot11Disas):
                self._handle_frame(pkt, "disassoc")
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"DeauthDetector packet parse error ({type(e).__name__})")

    def _handle_frame(self, pkt, frame_type: str):
        if not self.is_enabled():
            return

        dot11 = pkt[Dot11]
        # addr2 is the frame transmitter - the likely attacker source, even
        # when it spoofs the AP's BSSID to make the frame look legitimate.
        attacker = dot11.addr2 or "unknown"
        target = dot11.addr1 or "broadcast"
        bssid = dot11.addr3 or None
        now = datetime.now()

        settings = self.settings
        burst_count = settings.get("burst_count", 15)
        burst_window = settings.get("burst_window", 10)
        window = timedelta(seconds=burst_window)

        with self._lock:
            log = self._frame_log[attacker]
            log.append((now, target))
            while log and (now - log[0][0]) > window:
                log.popleft()
            count = len(log)
            distinct_targets = len({t for _, t in log})

        if count >= burst_count:
            # Broader target spread = broadcast-style flood = more severe.
            if count >= burst_count * 3 or distinct_targets >= 5:
                severity = "CRITICAL"
            elif count >= burst_count * 2 or distinct_targets >= 3:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            scope = (
                f"broadcast across {distinct_targets} clients"
                if distinct_targets > 1 else f"targeted at {target}"
            )
            msg = f"Deauth attack detected from {attacker} ({count} frames/{burst_window}s, {scope})"
            details = (
                f"Attacker MAC: {attacker} | BSSID: {bssid or 'unknown'} | "
                f"Frame type: {frame_type} | Frames: {count} in {burst_window}s | "
                f"Distinct targets: {distinct_targets}"
            )

            with self._lock:
                self._bursts_detected += 1

            self.alert_mgr.add("DEAUTH_ATTACK", severity, msg, details)
            self.db.add_attack(
                "DEAUTH_ATTACK", severity,
                source_mac=attacker, target_mac=target, bssid=bssid,
                details=details
            )

    def get_stats(self) -> dict:
        with self._lock:
            active_sources = len(self._frame_log)
            bursts_detected = self._bursts_detected
        return {
            "active_deauth_sources": active_sources,
            "bursts_detected": bursts_detected,
            "scapy_available": SCAPY_AVAILABLE,
            "enabled": self.is_enabled(),
        }
