"""Module 7 - WPS Detector: passive WiFi Protected Setup vulnerability scanning.

Detection and reporting ONLY. This module never sends WPS registrar or
enrollee protocol frames (M1-M8) and never attempts PIN brute-force or
Pixie Dust key recovery - it only parses the WPS vendor-specific
information element that vulnerable/misconfigured APs already broadcast
in their own beacon and probe-response frames.

Findings use the same alert/attack schema as AttackDetector, DeauthDetector
and RogueAPDetector so they flow into the existing AI analysis and PDF
reporting pipeline unchanged.
"""

import threading
import time
from datetime import datetime, timedelta

from core.oui_lookup import get_vendor_with_fallback

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


DEFAULT_WPS_CONFIG = {
    "enabled": True,
    "eval_throttle_seconds": 300,
}

# Microsoft OUI (00:50:F2) vendor-specific IE, WPS vendor type 0x04.
WPS_OUI_PREFIX = b"\x00\x50\xf2\x04"

# WPS attribute type IDs (Wi-Fi Simple Config spec / wps_defs.h).
ATTR_CONFIG_METHODS = 0x1008
ATTR_DEV_PASSWORD_ID = 0x1012
ATTR_MANUFACTURER = 0x1021
ATTR_MODEL_NAME = 0x1023
ATTR_WPS_STATE = 0x1044
ATTR_AP_SETUP_LOCKED = 0x1057

# WPS Config Methods bitmask values.
WPS_CONFIG_LABEL = 0x0004
WPS_CONFIG_DISPLAY = 0x0008
WPS_CONFIG_KEYPAD = 0x0100
WPS_CONFIG_PUSHBUTTON = 0x0080

# Label/Display/Keypad all drive the standard M1-M8 online PIN exchange
# that Reaver/Pixie-Dust style attacks target. NFC/USB/Ethernet are
# out-of-band methods that don't use that exchange, so they're excluded.
PIN_METHOD_BITS = WPS_CONFIG_LABEL | WPS_CONFIG_DISPLAY | WPS_CONFIG_KEYPAD

# Chipset/vendor names publicly associated with weak WPS E-S1/E-S2 nonce
# generation in the original Pixie Dust research and follow-up chipset
# surveys (e.g. the pixiewps project's known-vulnerable list). This is a
# heuristic on the vendor/model string only - it is NOT a confirmed
# finding, since real confirmation requires capturing the WPS handshake
# nonces, which this passive-only module does not do.
PIXIE_DUST_VENDOR_HINTS = (
    "ralink", "mediatek", "broadcom", "realtek",
)


class WPSDetector:
    """Passive WPS vulnerability scanner.

    Parses the WPS vendor-specific information element from beacon and
    probe-response frames to flag APs with WPS enabled, distinguishing
    PIN-capable configurations (vulnerable to online PIN brute-force and,
    depending on chipset, offline Pixie Dust attacks) from push-button-only
    configurations (lower risk, requires physical proximity/timing).
    """

    def __init__(self, db, config, alert_mgr, monitor_iface: str):
        self.db = db
        self.config = config
        self.alert_mgr = alert_mgr
        self.monitor_iface = monitor_iface
        self._running = False

        # Per-BSSID evaluation throttle to avoid re-parsing/re-alerting on
        # every single beacon from the same AP.
        self._last_eval: dict = {}
        self._eval_lock = threading.Lock()

        # Distinct BSSIDs found with WPS enabled this session, and the subset
        # that are PIN-capable (the actually vulnerable ones), for TUI/status display.
        self._wps_enabled_bssids: set = set()
        self._vulnerable_bssids: set = set()

    @property
    def settings(self) -> dict:
        cfg = self.config.get("wps_detection", {}) or {}
        merged = DEFAULT_WPS_CONFIG.copy()
        merged.update(cfg)
        return merged

    def is_enabled(self) -> bool:
        return bool(self.settings.get("enabled", True))

    def start(self):
        self._running = True

        if not self.is_enabled():
            self.alert_mgr.info("SYSTEM", "WPS detector disabled via config - not starting")
            return

        if not SCAPY_AVAILABLE:
            self.alert_mgr.low("SYSTEM", "Scapy not available - WPS detection limited")
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
                    lfilter=lambda p: p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp),
                    stop_filter=lambda _: not self._running,
                )
                retry_delay = 5
            except Exception as e:
                self.alert_mgr.low(
                    "SYSTEM",
                    f"WPS detector sniff error on {self.monitor_iface}: {e} - "
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
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                self._handle_frame(pkt)
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"WPSDetector packet parse error ({type(e).__name__})")

    def _handle_frame(self, pkt):
        if not self.is_enabled():
            return

        bssid = pkt[Dot11].addr3
        if not bssid:
            return

        if not self._should_evaluate(bssid):
            return

        ssid = self._parse_ssid(pkt)
        wps_ie = self._find_wps_ie(pkt)
        if wps_ie is None:
            return

        attrs = self._parse_wps_attributes(wps_ie)
        vendor = get_vendor_with_fallback(bssid)

        self._evaluate_wps_ap(bssid, ssid, vendor, attrs)

    def _should_evaluate(self, bssid: str) -> bool:
        throttle = timedelta(seconds=self.settings.get("eval_throttle_seconds", 300))
        now = datetime.now()
        with self._eval_lock:
            last = self._last_eval.get(bssid)
            if last and (now - last) < throttle:
                return False
            self._last_eval[bssid] = now
        return True

    @staticmethod
    def _parse_ssid(pkt):
        elt = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            if elt.ID == 0:
                try:
                    decoded = elt.info.decode('utf-8', errors='ignore')
                    return decoded if decoded else None
                except Exception:
                    return None
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
        return None

    @staticmethod
    def _find_wps_ie(pkt):
        """Return the raw bytes of the WPS vendor-specific IE, if present."""
        elt = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            if elt.ID == 221 and bytes(elt.info).startswith(WPS_OUI_PREFIX):
                return bytes(elt.info)[len(WPS_OUI_PREFIX):]
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
        return None

    @staticmethod
    def _parse_wps_attributes(data: bytes) -> dict:
        """Parse WPS TLV attributes (2-byte type, 2-byte length, value)."""
        attrs = {}
        offset = 0
        length = len(data)
        while offset + 4 <= length:
            attr_type = int.from_bytes(data[offset:offset + 2], "big")
            attr_len = int.from_bytes(data[offset + 2:offset + 4], "big")
            value = data[offset + 4:offset + 4 + attr_len]
            if len(value) < attr_len:
                break
            attrs[attr_type] = value
            offset += 4 + attr_len
        return attrs

    @staticmethod
    def _decode_str(value: bytes):
        if not value:
            return None
        try:
            decoded = value.decode('utf-8', errors='ignore').strip('\x00').strip()
            return decoded or None
        except Exception:
            return None

    # --- WPS evaluation ---
    def _evaluate_wps_ap(self, bssid, ssid, vendor, attrs: dict):
        config_methods = None
        if ATTR_CONFIG_METHODS in attrs and len(attrs[ATTR_CONFIG_METHODS]) >= 2:
            config_methods = int.from_bytes(attrs[ATTR_CONFIG_METHODS][:2], "big")

        # No advertised config methods at all is unusual for a real WPS IE;
        # without evidence of PIN support, default to the lower-severity
        # (push-button-only) classification rather than the higher one -
        # this module reports what it observed, not a worst-case assumption.
        pin_capable = bool(config_methods is not None and (config_methods & PIN_METHOD_BITS))

        manufacturer = self._decode_str(attrs.get(ATTR_MANUFACTURER))
        model_name = self._decode_str(attrs.get(ATTR_MODEL_NAME))

        ap_setup_locked = None
        if ATTR_AP_SETUP_LOCKED in attrs and attrs[ATTR_AP_SETUP_LOCKED]:
            ap_setup_locked = bool(attrs[ATTR_AP_SETUP_LOCKED][0])

        wps_state = None
        if ATTR_WPS_STATE in attrs and attrs[ATTR_WPS_STATE]:
            state_val = attrs[ATTR_WPS_STATE][0]
            wps_state = {1: "Unconfigured", 2: "Configured"}.get(state_val, f"unknown({state_val})")

        severity = "HIGH" if pin_capable else "LOW"
        mode = "PIN-capable (Label/Display/Keypad)" if pin_capable else "push-button-only"

        msg = f"WPS enabled on '{ssid or bssid}' ({bssid}) - {mode}"
        details_parts = [
            f"SSID: {ssid or 'unknown'}",
            f"BSSID: {bssid}",
            f"Vendor: {vendor or 'Unknown'}",
            f"WPS mode: {mode}",
            f"Config methods bitmask: {hex(config_methods) if config_methods is not None else 'not advertised'}",
        ]
        if wps_state:
            details_parts.append(f"WPS state: {wps_state}")
        if ap_setup_locked is not None:
            details_parts.append(f"AP setup locked: {'yes' if ap_setup_locked else 'no'}")
        if manufacturer:
            details_parts.append(f"Manufacturer: {manufacturer}")
        if model_name:
            details_parts.append(f"Model: {model_name}")

        pixie_hint = self._pixie_dust_hint(vendor, manufacturer, model_name)
        if pixie_hint:
            details_parts.append(
                f"Pixie Dust indicator (unconfirmed, heuristic only - no handshake "
                f"captured): {pixie_hint} historically associated with weak WPS "
                f"nonce generation"
            )

        details = " | ".join(details_parts)

        with self._eval_lock:
            self._wps_enabled_bssids.add(bssid)
            if pin_capable:
                self._vulnerable_bssids.add(bssid)

        self.alert_mgr.add("WPS_VULNERABLE", severity, msg, details)
        self.db.add_attack("WPS_VULNERABLE", severity, bssid=bssid, ssid=ssid, details=details)

    @staticmethod
    def _pixie_dust_hint(vendor, manufacturer, model_name):
        haystack = " ".join(s for s in (vendor, manufacturer, model_name) if s).lower()
        if not haystack:
            return None
        for hint in PIXIE_DUST_VENDOR_HINTS:
            if hint in haystack:
                return hint
        return None

    def get_stats(self) -> dict:
        with self._eval_lock:
            tracked = len(self._last_eval)
            wps_enabled_aps = len(self._wps_enabled_bssids)
            wps_vulnerable_aps = len(self._vulnerable_bssids)
        return {
            "tracked_bssids": tracked,
            "wps_enabled_aps": wps_enabled_aps,
            "wps_vulnerable_aps": wps_vulnerable_aps,
            "scapy_available": SCAPY_AVAILABLE,
            "enabled": self.is_enabled(),
        }
