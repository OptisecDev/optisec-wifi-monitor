"""Unit tests for modules/rogue_ap_detector.py (RogueAPDetector)."""

import os
import sys
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database
from modules.rogue_ap_detector import RogueAPDetector, DEFAULT_ROGUE_AP_CONFIG


class FakeConfig:
    """Minimal config stand-in exposing the same .get() interface as ConfigManager."""

    def __init__(self, rogue_ap_detection: dict = None):
        self._data = {
            "rogue_ap_detection": rogue_ap_detection if rogue_ap_detection is not None
            else dict(DEFAULT_ROGUE_AP_CONFIG)
        }

    def get(self, key, default=None):
        return self._data.get(key, default)


def make_detector(rogue_ap_detection: dict = None, db=None, attack_detector=None):
    db = db if db is not None else _temp_db()
    alert_mgr = MagicMock()
    config = FakeConfig(rogue_ap_detection)
    detector = RogueAPDetector(db, config, alert_mgr, monitor_iface="wlan1mon",
                               attack_detector=attack_detector)
    return detector, db, alert_mgr


def _temp_db():
    """Real SQLite-backed Database in a throwaway file - the baseline logic
    relies on real upsert/read-back semantics, not just mock call assertions.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return Database(db_path=path)


def establish_trust(detector, bssid, ssid, vendor="TP-Link", channel=6, signal=-50,
                    sightings=3, age_minutes=31):
    """Directly seed a trusted baseline row, bypassing packet parsing/throttle."""
    for _ in range(sightings):
        detector.db.upsert_bssid_baseline(bssid, ssid, vendor, channel, signal)
    # Backdate first_seen so the age requirement is satisfied.
    old_first_seen = datetime.now() - timedelta(minutes=age_minutes)
    detector.db.execute(
        "UPDATE bssid_baseline SET first_seen=? WHERE bssid=?",
        (old_first_seen, bssid)
    )


class TestRogueAPDetectorKnownAP(unittest.TestCase):
    """A BSSID already part of the trusted baseline must not be flagged."""

    def test_repeated_sighting_of_trusted_bssid_does_not_alert(self):
        detector, db, alert_mgr = make_detector()
        bssid = "AA:BB:CC:DD:EE:01"
        ssid = "HomeNet"
        establish_trust(detector, bssid, ssid, signal=-50)

        # Same BSSID seen again with a normal signal reading - no anomaly.
        detector._evaluate_ap(bssid, ssid, "TP-Link", 6, -52)

        alert_mgr.add.assert_not_called()

    def test_first_ever_sighting_of_new_ssid_does_not_alert(self):
        """A brand-new SSID/BSSID pair with no prior history anywhere is just
        a new network, not a rogue one."""
        detector, db, alert_mgr = make_detector()

        detector._evaluate_ap("11:22:33:44:55:66", "NeverSeenBefore", "Intel", 11, -60)

        alert_mgr.add.assert_not_called()


class TestRogueAPDetectorNewUntrustedAP(unittest.TestCase):
    """A brand-new BSSID for an SSID with established trust must be flagged."""

    def test_new_bssid_on_trusted_ssid_is_flagged(self):
        detector, db, alert_mgr = make_detector()
        ssid = "CorpWiFi"
        establish_trust(detector, "AA:BB:CC:DD:EE:02", ssid)

        rogue_bssid = "DE:AD:BE:EF:00:99"
        detector._evaluate_ap(rogue_bssid, ssid, "Unknown", 6, -40)

        alert_mgr.add.assert_called()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[0], "ROGUE_AP")
        self.assertIn(rogue_bssid, args[2])

        db_attacks = db.get_attacks(limit=10)
        self.assertTrue(any(a["attack_type"] == "ROGUE_AP" and a["bssid"] == rogue_bssid
                            for a in db_attacks))

    def test_new_bssid_reuses_attack_detector_known_set_not_just_own_baseline(self):
        """Even with no persistent baseline yet, a BSSID absent from
        AttackDetector's live known-BSSID set (reused, not duplicated) for an
        SSID it has already seen is still flagged."""
        fake_attack_detector = MagicMock()
        fake_attack_detector.get_known_bssids.return_value = {"AA:BB:CC:DD:EE:03"}

        detector, db, alert_mgr = make_detector(attack_detector=fake_attack_detector)
        ssid = "CafeWiFi"

        detector._evaluate_ap("FF:FF:FF:FF:FF:01", ssid, "Unknown", 1, -70)

        alert_mgr.add.assert_called()
        fake_attack_detector.get_known_bssids.assert_called_with(ssid)


class TestRogueAPDetectorSignalAnomaly(unittest.TestCase):
    """A trusted BSSID whose signal suddenly shifts far from baseline is flagged."""

    def test_large_signal_deviation_on_trusted_bssid_is_flagged(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "signal_deviation_db": 20, "min_trusted_sightings": 3,
             "min_trusted_age_minutes": 30}
        )
        bssid = "AA:BB:CC:DD:EE:04"
        ssid = "OfficeNet"
        establish_trust(detector, bssid, ssid, signal=-45)

        # Baseline ~-45 dBm, now suddenly -85 dBm (or a spoofed close-range
        # clone reading -20 dBm) - either direction is a location anomaly.
        detector._evaluate_ap(bssid, ssid, "TP-Link", 6, -85)

        alert_mgr.add.assert_called()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[0], "ROGUE_AP")
        self.assertIn(bssid, args[2])

    def test_small_signal_fluctuation_on_trusted_bssid_does_not_alert(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "signal_deviation_db": 20, "min_trusted_sightings": 3,
             "min_trusted_age_minutes": 30}
        )
        bssid = "AA:BB:CC:DD:EE:05"
        ssid = "OfficeNet2"
        establish_trust(detector, bssid, ssid, signal=-50)

        detector._evaluate_ap(bssid, ssid, "TP-Link", 6, -55)  # within threshold

        alert_mgr.add.assert_not_called()

    def test_untrusted_bssid_signal_swing_does_not_alert(self):
        """Signal-anomaly check only applies once a BSSID has met the trust
        bar - a freshly-seen BSSID swinging in signal isn't evidence of
        anything on its own."""
        detector, db, alert_mgr = make_detector()
        bssid = "AA:BB:CC:DD:EE:06"
        ssid = "NewNet"

        detector._evaluate_ap(bssid, ssid, "Unknown", 1, -40)
        detector._evaluate_ap(bssid, ssid, "Unknown", 1, -90)  # only 2 sightings, not trusted yet

        alert_mgr.add.assert_not_called()


class TestRogueAPDetectorDisabled(unittest.TestCase):
    """Detector disabled via config must be a complete no-op."""

    def test_disabled_detector_does_not_sniff(self):
        detector, db, alert_mgr = make_detector({"enabled": False})

        with patch("modules.rogue_ap_detector.sniff") as sniff_mock:
            detector.start()
            sniff_mock.assert_not_called()

        alert_mgr.info.assert_called_once()

    def test_disabled_detector_ignores_beacons_reaching_handler(self):
        detector, db, alert_mgr = make_detector({"enabled": False})

        detector._handle_beacon(MagicMock())

        alert_mgr.add.assert_not_called()

    def test_get_stats_reports_enabled_flag(self):
        detector, db, alert_mgr = make_detector({"enabled": False})
        self.assertFalse(detector.get_stats()["enabled"])

        detector2, db2, alert_mgr2 = make_detector({"enabled": True})
        self.assertTrue(detector2.get_stats()["enabled"])


class TestRogueAPDetectorInterfaceUnavailable(unittest.TestCase):
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

        with patch("modules.rogue_ap_detector.sniff", side_effect=fake_sniff):
            with patch("modules.rogue_ap_detector.time.sleep", side_effect=fake_sleep):
                detector.start()

        self.assertGreaterEqual(call_count["n"], 2)
        alert_mgr.low.assert_called()
        self.assertIn("wlan1mon", alert_mgr.low.call_args[0][1])


if __name__ == "__main__":
    unittest.main()
