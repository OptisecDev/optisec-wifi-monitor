"""Module 6 - Rogue AP Detector: broader rogue access point detection.

Distinct from the Evil Twin check in AttackDetector (which only flags a
second BSSID appearing for an SSID *within the current run*), this module
maintains a persistent, cross-restart BSSID baseline in the database and
flags:

  * A brand-new BSSID appearing for an SSID that already has an established,
    trusted history (either in this module's own persistent baseline, or in
    AttackDetector's live in-run view - reused via
    AttackDetector.get_known_bssids() rather than re-implemented).
  * A previously-trusted BSSID whose signal strength suddenly deviates far
    from its historical average, consistent with a spoofed/relayed AP
    operating from a different physical location.

Findings use the same alert/attack schema as AttackDetector and
DeauthDetector so they flow into the existing AI analysis and PDF reporting
pipeline unchanged.
"""

import threading
import time
from datetime import datetime, timedelta

from core.oui_lookup import get_vendor_with_fallback

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


DEFAULT_ROGUE_AP_CONFIG = {
    "enabled": True,
    "min_trusted_sightings": 3,
    "min_trusted_age_minutes": 30,
    "signal_deviation_db": 20,
    "eval_throttle_seconds": 5,
}


class RogueAPDetector:
    """Passive rogue access point detector with persistent BSSID trust baseline."""

    def __init__(self, db, config, alert_mgr, monitor_iface: str, attack_detector=None):
        self.db = db
        self.config = config
        self.alert_mgr = alert_mgr
        self.monitor_iface = monitor_iface
        self.attack_detector = attack_detector
        self._running = False

        # Per-BSSID evaluation throttle to avoid a DB round-trip per beacon.
        self._last_eval: dict = {}
        self._eval_lock = threading.Lock()

    @property
    def settings(self) -> dict:
        cfg = self.config.get("rogue_ap_detection", {}) or {}
        merged = DEFAULT_ROGUE_AP_CONFIG.copy()
        merged.update(cfg)
        return merged

    def is_enabled(self) -> bool:
        return bool(self.settings.get("enabled", True))

    def start(self):
        self._running = True

        if not self.is_enabled():
            self.alert_mgr.info("SYSTEM", "Rogue AP detector disabled via config - not starting")
            return

        if not SCAPY_AVAILABLE:
            self.alert_mgr.low("SYSTEM", "Scapy not available - rogue AP detection limited")
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
                    lfilter=lambda p: p.haslayer(Dot11Beacon),
                    stop_filter=lambda _: not self._running,
                )
                retry_delay = 5
            except Exception as e:
                self.alert_mgr.low(
                    "SYSTEM",
                    f"Rogue AP detector sniff error on {self.monitor_iface}: {e} - "
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
            if pkt.haslayer(Dot11Beacon):
                self._handle_beacon(pkt)
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"RogueAPDetector packet parse error ({type(e).__name__})")

    def _handle_beacon(self, pkt):
        if not self.is_enabled():
            return

        bssid = pkt[Dot11].addr3
        if not bssid:
            return

        if not self._should_evaluate(bssid):
            return

        ssid, channel = self._parse_ssid_and_channel(pkt)
        if not ssid:
            return

        signal = self._parse_signal(pkt)
        vendor = get_vendor_with_fallback(bssid)

        self._evaluate_ap(bssid, ssid, vendor, channel, signal)

    def _should_evaluate(self, bssid: str) -> bool:
        throttle = timedelta(seconds=self.settings.get("eval_throttle_seconds", 5))
        now = datetime.now()
        with self._eval_lock:
            last = self._last_eval.get(bssid)
            if last and (now - last) < throttle:
                return False
            self._last_eval[bssid] = now
        return True

    @staticmethod
    def _parse_ssid_and_channel(pkt):
        ssid = None
        channel = None
        elt = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            if elt.ID == 0 and ssid is None:
                try:
                    decoded = elt.info.decode('utf-8', errors='ignore')
                    ssid = decoded if decoded else None
                except Exception:
                    ssid = None
            elif elt.ID == 3 and channel is None:
                try:
                    channel = elt.info[0]
                except Exception:
                    channel = None
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
        return ssid, channel

    @staticmethod
    def _parse_signal(pkt):
        if not pkt.haslayer(RadioTap):
            return None
        try:
            if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                return -(256 - pkt[RadioTap].dBm_AntSignal)
        except Exception:
            pass
        return None

    # --- Rogue AP evaluation ---
    def _evaluate_ap(self, bssid, ssid, vendor, channel, signal):
        settings = self.settings
        prior = self.db.get_bssid_baseline(bssid)

        if prior is None:
            self._check_new_untrusted_ap(bssid, ssid, vendor, channel, settings)
        elif signal is not None and prior.get('avg_signal') is not None and self._meets_trust(prior, settings):
            self._check_signal_anomaly(bssid, ssid, prior, signal, settings)

        self.db.upsert_bssid_baseline(bssid, ssid, vendor, channel, signal)

    def _meets_trust(self, row: dict, settings: dict) -> bool:
        min_sightings = settings.get("min_trusted_sightings", 3)
        min_age = settings.get("min_trusted_age_minutes", 30)

        if (row.get('seen_count') or 0) < min_sightings:
            return False

        first_seen = row.get('first_seen')
        if not first_seen:
            return False
        if isinstance(first_seen, str):
            try:
                first_seen = datetime.fromisoformat(first_seen)
            except ValueError:
                return False

        return (datetime.now() - first_seen) >= timedelta(minutes=min_age)

    def _check_new_untrusted_ap(self, bssid, ssid, vendor, channel, settings):
        related = self.db.get_baseline_for_ssid(ssid)
        trusted_related = [r for r in related if self._meets_trust(r, settings)]

        known_live = set()
        if self.attack_detector is not None:
            known_live = self.attack_detector.get_known_bssids(ssid)

        # An SSID with no established trust anywhere is just a new network,
        # not a rogue one - nothing to compare the new BSSID against yet.
        if not trusted_related and not known_live:
            return

        known_desc = ', '.join(r['bssid'] for r in trusted_related) or ', '.join(known_live) or 'none'

        msg = f"Rogue AP suspected: new BSSID '{bssid}' for known SSID '{ssid}'"
        details = (
            f"SSID: {ssid} | New BSSID: {bssid} | Vendor: {vendor or 'Unknown'} | "
            f"Channel: {channel if channel is not None else 'unknown'} | "
            f"Known trusted BSSID(s): {known_desc}"
        )
        self.alert_mgr.add("ROGUE_AP", "HIGH", msg, details)
        self.db.add_attack("ROGUE_AP", "HIGH", bssid=bssid, ssid=ssid, details=details)

    def _check_signal_anomaly(self, bssid, ssid, prior, signal, settings):
        threshold = settings.get("signal_deviation_db", 20)
        baseline_avg = prior['avg_signal']
        deviation = abs(signal - baseline_avg)

        if deviation < threshold:
            return

        severity = "CRITICAL" if deviation >= threshold * 1.5 else "HIGH"
        msg = f"Rogue AP suspected: abnormal signal shift for trusted BSSID {bssid} ('{ssid}')"
        details = (
            f"SSID: {ssid} | BSSID: {bssid} | Baseline avg signal: {baseline_avg:.1f} dBm | "
            f"Current signal: {signal} dBm | Deviation: {deviation:.1f} dB"
        )
        self.alert_mgr.add("ROGUE_AP", severity, msg, details)
        self.db.add_attack("ROGUE_AP", severity, bssid=bssid, ssid=ssid, details=details)

    def get_stats(self) -> dict:
        with self._eval_lock:
            tracked = len(self._last_eval)
        return {
            "tracked_bssids": tracked,
            "scapy_available": SCAPY_AVAILABLE,
            "enabled": self.is_enabled(),
        }
