"""Unit tests for modules/wps_detector.py (WPSDetector)."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.wps_detector import (
    WPSDetector, DEFAULT_WPS_CONFIG,
    WPS_OUI_PREFIX, ATTR_CONFIG_METHODS, ATTR_MANUFACTURER, ATTR_MODEL_NAME,
    WPS_CONFIG_PUSHBUTTON, WPS_CONFIG_DISPLAY, WPS_CONFIG_KEYPAD,
)

from scapy.all import Dot11, Dot11Beacon, Dot11Elt


def _tlv(attr_type: int, value: bytes) -> bytes:
    return attr_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _wps_ie_bytes(config_methods: int = None, manufacturer: str = None, model_name: str = None) -> bytes:
    body = b""
    if config_methods is not None:
        body += _tlv(ATTR_CONFIG_METHODS, config_methods.to_bytes(2, "big"))
    if manufacturer is not None:
        body += _tlv(ATTR_MANUFACTURER, manufacturer.encode("utf-8"))
    if model_name is not None:
        body += _tlv(ATTR_MODEL_NAME, model_name.encode("utf-8"))
    return WPS_OUI_PREFIX + body


def make_beacon(bssid: str, ssid: str = "TestNet", wps_ie: bytes = None):
    pkt = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Beacon()
    pkt = pkt / Dot11Elt(ID=0, info=ssid.encode("utf-8"))
    if wps_ie is not None:
        pkt = pkt / Dot11Elt(ID=221, info=wps_ie)
    return pkt


class FakeConfig:
    """Minimal config stand-in exposing the same .get() interface as ConfigManager."""

    def __init__(self, wps_detection: dict = None):
        self._data = {
            "wps_detection": wps_detection if wps_detection is not None
            else dict(DEFAULT_WPS_CONFIG)
        }

    def get(self, key, default=None):
        return self._data.get(key, default)


def make_detector(wps_detection: dict = None):
    db = MagicMock()
    alert_mgr = MagicMock()
    config = FakeConfig(wps_detection)
    detector = WPSDetector(db, config, alert_mgr, monitor_iface="wlan1mon")
    return detector, db, alert_mgr


class TestWPSDetectorNoWPS(unittest.TestCase):
    """An AP with no WPS IE at all must not be flagged."""

    def test_beacon_without_wps_ie_does_not_alert(self):
        detector, db, alert_mgr = make_detector()
        pkt = make_beacon("AA:BB:CC:DD:EE:01", ssid="OpenNet", wps_ie=None)

        detector._handle_frame(pkt)

        alert_mgr.add.assert_not_called()
        db.add_attack.assert_not_called()


class TestWPSDetectorPinMode(unittest.TestCase):
    """WPS enabled with a PIN-capable method (Label/Display/Keypad) is a
    higher-severity finding."""

    def test_display_method_is_flagged_high_severity(self):
        detector, db, alert_mgr = make_detector()
        bssid = "AA:BB:CC:DD:EE:02"
        wps_ie = _wps_ie_bytes(config_methods=WPS_CONFIG_DISPLAY | WPS_CONFIG_PUSHBUTTON)
        pkt = make_beacon(bssid, ssid="PinNet", wps_ie=wps_ie)

        detector._handle_frame(pkt)

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[0], "WPS_VULNERABLE")
        self.assertEqual(args[1], "HIGH")
        self.assertIn(bssid, args[2])

        db.add_attack.assert_called_once()
        call_args, call_kwargs = db.add_attack.call_args
        self.assertEqual(call_args[0], "WPS_VULNERABLE")
        self.assertEqual(call_args[1], "HIGH")
        self.assertEqual(call_kwargs["bssid"], bssid)

    def test_keypad_only_method_is_flagged_high_severity(self):
        detector, db, alert_mgr = make_detector()
        bssid = "AA:BB:CC:DD:EE:03"
        wps_ie = _wps_ie_bytes(config_methods=WPS_CONFIG_KEYPAD)
        pkt = make_beacon(bssid, ssid="KeypadNet", wps_ie=wps_ie)

        detector._handle_frame(pkt)

        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[1], "HIGH")

    def test_pixie_dust_vendor_hint_is_noted_but_does_not_change_severity(self):
        detector, db, alert_mgr = make_detector()
        bssid = "AA:BB:CC:DD:EE:04"
        wps_ie = _wps_ie_bytes(
            config_methods=WPS_CONFIG_DISPLAY, manufacturer="Ralink Technology Corp."
        )
        pkt = make_beacon(bssid, ssid="RalinkAP", wps_ie=wps_ie)

        detector._handle_frame(pkt)

        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[1], "HIGH")
        self.assertIn("Pixie Dust indicator", args[3])
        self.assertIn("unconfirmed", args[3])


class TestWPSDetectorPushButtonOnly(unittest.TestCase):
    """WPS enabled with only push-button configured is a lower-severity finding."""

    def test_pushbutton_only_is_flagged_low_severity(self):
        detector, db, alert_mgr = make_detector()
        bssid = "AA:BB:CC:DD:EE:05"
        wps_ie = _wps_ie_bytes(config_methods=WPS_CONFIG_PUSHBUTTON)
        pkt = make_beacon(bssid, ssid="PbcNet", wps_ie=wps_ie)

        detector._handle_frame(pkt)

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[0], "WPS_VULNERABLE")
        self.assertEqual(args[1], "LOW")

        db.add_attack.assert_called_once()
        call_args, _ = db.add_attack.call_args
        self.assertEqual(call_args[1], "LOW")


class TestWPSDetectorDisabled(unittest.TestCase):
    """Detector disabled via config must be a complete no-op."""

    def test_disabled_detector_does_not_sniff(self):
        detector, db, alert_mgr = make_detector({"enabled": False})

        with patch("modules.wps_detector.sniff") as sniff_mock:
            detector.start()
            sniff_mock.assert_not_called()

        alert_mgr.info.assert_called_once()

    def test_disabled_detector_ignores_frames_reaching_handler(self):
        detector, db, alert_mgr = make_detector({"enabled": False})
        bssid = "AA:BB:CC:DD:EE:06"
        wps_ie = _wps_ie_bytes(config_methods=WPS_CONFIG_DISPLAY)
        pkt = make_beacon(bssid, ssid="StillOff", wps_ie=wps_ie)

        detector._handle_frame(pkt)

        alert_mgr.add.assert_not_called()
        db.add_attack.assert_not_called()

    def test_get_stats_reports_enabled_flag(self):
        detector, _, _ = make_detector({"enabled": False})
        self.assertFalse(detector.get_stats()["enabled"])

        detector2, _, _ = make_detector({"enabled": True})
        self.assertTrue(detector2.get_stats()["enabled"])


class TestWPSDetectorInterfaceUnavailable(unittest.TestCase):
    """If the monitor-mode interface can't be sniffed, start() must fail gracefully."""

    def test_sniff_exception_retries_then_stops_when_told(self):
        """start() must retry sniff() with backoff (interface can reappear
        mid-run) rather than giving up permanently, but must still not
        raise and must stop once _running is cleared."""
        detector, db, alert_mgr = make_detector({"enabled": True})

        call_count = {"n": 0}

        def fake_sniff(**kwargs):
            call_count["n"] += 1
            raise OSError("No such device")

        def fake_sleep(seconds):
            if call_count["n"] >= 2:
                detector._running = False

        with patch("modules.wps_detector.sniff", side_effect=fake_sniff):
            with patch("modules.wps_detector.time.sleep", side_effect=fake_sleep):
                detector.start()

        self.assertGreaterEqual(call_count["n"], 2)
        alert_mgr.low.assert_called()
        self.assertIn("wlan1mon", alert_mgr.low.call_args[0][1])


if __name__ == "__main__":
    unittest.main()
