"""Unit tests for modules/deauth_detector.py (DeauthDetector)."""

import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.deauth_detector import DeauthDetector, DEFAULT_DEAUTH_CONFIG

from scapy.all import Dot11, Dot11Deauth, Dot11Disas


def make_deauth(attacker: str, target: str = "ff:ff:ff:ff:ff:ff", bssid: str = None):
    return Dot11(addr1=target, addr2=attacker, addr3=bssid or attacker) / Dot11Deauth()


def make_disassoc(attacker: str, target: str = "ff:ff:ff:ff:ff:ff", bssid: str = None):
    return Dot11(addr1=target, addr2=attacker, addr3=bssid or attacker) / Dot11Disas()


class FakeConfig:
    """Minimal config stand-in exposing the same .get() interface as ConfigManager."""

    def __init__(self, deauth_detection: dict = None):
        self._data = {"deauth_detection": deauth_detection if deauth_detection is not None
                      else dict(DEFAULT_DEAUTH_CONFIG)}

    def get(self, key, default=None):
        return self._data.get(key, default)


def make_detector(deauth_detection: dict = None):
    db = MagicMock()
    alert_mgr = MagicMock()
    config = FakeConfig(deauth_detection)
    detector = DeauthDetector(db, config, alert_mgr, monitor_iface="wlan1mon")
    return detector, db, alert_mgr


class TestDeauthDetectorNormalTraffic(unittest.TestCase):
    """A few scattered deauth frames below the burst threshold must not alert."""

    def test_low_volume_traffic_does_not_trigger_alert(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "burst_count": 15, "burst_window": 10}
        )
        attacker = "AA:BB:CC:DD:EE:01"

        for _ in range(5):  # well under burst_count=15
            detector._packet_handler(make_deauth(attacker))

        alert_mgr.add.assert_not_called()
        db.add_attack.assert_not_called()

    def test_frames_outside_window_are_pruned(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "burst_count": 5, "burst_window": 1}
        )
        attacker = "AA:BB:CC:DD:EE:02"

        for _ in range(4):
            detector._packet_handler(make_deauth(attacker))
        # Let the 1s window fully expire before sending more.
        time.sleep(1.1)
        detector._packet_handler(make_deauth(attacker))

        alert_mgr.add.assert_not_called()
        db.add_attack.assert_not_called()


class TestDeauthDetectorBurstDetection(unittest.TestCase):
    """A rapid burst of deauth/disassoc frames must be flagged as an attack."""

    def test_deauth_burst_from_single_source_is_detected(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "burst_count": 10, "burst_window": 10}
        )
        attacker = "DE:AD:BE:EF:00:01"
        target = "11:22:33:44:55:66"

        for _ in range(12):  # exceeds burst_count=10
            detector._packet_handler(make_deauth(attacker, target=target))

        alert_mgr.add.assert_called()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[0], "DEAUTH_ATTACK")
        self.assertIn(attacker, args[2])

        db.add_attack.assert_called()
        _, kwargs = db.add_attack.call_args
        self.assertEqual(db.add_attack.call_args[0][0], "DEAUTH_ATTACK")
        self.assertEqual(kwargs["source_mac"], attacker)

    def test_disassoc_burst_is_also_detected(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "burst_count": 8, "burst_window": 10}
        )
        attacker = "DE:AD:BE:EF:00:02"

        for _ in range(9):
            detector._packet_handler(make_disassoc(attacker))

        alert_mgr.add.assert_called()
        db.add_attack.assert_called()

    def test_broadcast_style_burst_escalates_severity(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "burst_count": 5, "burst_window": 10}
        )
        attacker = "DE:AD:BE:EF:00:03"

        # 6 distinct targets => distinct_targets >= 5 => CRITICAL per module logic.
        for i in range(6):
            detector._packet_handler(
                make_deauth(attacker, target=f"00:00:00:00:00:0{i}")
            )

        alert_mgr.add.assert_called()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[1], "CRITICAL")


class TestDeauthDetectorInterfaceUnavailable(unittest.TestCase):
    """If the monitor-mode interface can't be sniffed, start() must fail gracefully."""

    def test_sniff_exception_falls_back_without_crashing(self):
        detector, db, alert_mgr = make_detector({"enabled": True})

        with patch("modules.deauth_detector.sniff", side_effect=OSError("No such device")):
            with patch.object(detector, "_poll_fallback") as fallback:
                detector.start()  # must not raise
                fallback.assert_called_once()

        alert_mgr.low.assert_called()
        self.assertIn("wlan1mon", alert_mgr.low.call_args[0][1])

    def test_scapy_unavailable_falls_back_without_crashing(self):
        detector, db, alert_mgr = make_detector({"enabled": True})

        with patch("modules.deauth_detector.SCAPY_AVAILABLE", False):
            with patch.object(detector, "_poll_fallback") as fallback:
                detector.start()
                fallback.assert_called_once()

        alert_mgr.low.assert_called()

    def test_poll_fallback_stops_when_running_cleared(self):
        detector, _, _ = make_detector({"enabled": True})
        detector._running = True

        t = threading.Thread(target=detector._poll_fallback, daemon=True)
        with patch("modules.deauth_detector.time.sleep", return_value=None):
            t.start()
            detector.stop()
            t.join(timeout=2)

        self.assertFalse(t.is_alive())


class TestDeauthDetectorDisabled(unittest.TestCase):
    """Detector disabled via config must be a complete no-op."""

    def test_disabled_detector_does_not_sniff(self):
        detector, db, alert_mgr = make_detector({"enabled": False})

        with patch("modules.deauth_detector.sniff") as sniff_mock:
            detector.start()
            sniff_mock.assert_not_called()

        alert_mgr.info.assert_called_once()

    def test_disabled_detector_ignores_frames_reaching_handler(self):
        detector, db, alert_mgr = make_detector({"enabled": False})
        attacker = "DE:AD:BE:EF:00:04"

        for _ in range(50):
            detector._packet_handler(make_deauth(attacker))

        alert_mgr.add.assert_not_called()
        db.add_attack.assert_not_called()

    def test_get_stats_reports_enabled_flag(self):
        detector, _, _ = make_detector({"enabled": False})
        self.assertFalse(detector.get_stats()["enabled"])

        detector2, _, _ = make_detector({"enabled": True})
        self.assertTrue(detector2.get_stats()["enabled"])


if __name__ == "__main__":
    unittest.main()
