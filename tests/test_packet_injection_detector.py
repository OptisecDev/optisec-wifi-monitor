"""Unit tests for modules/packet_injection_detector.py (PacketInjectionDetector)."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.packet_injection_detector import (
    PacketInjectionDetector, DEFAULT_PACKET_INJECTION_CONFIG,
)

from scapy.all import Dot11, Dot11Beacon, Dot11Elt


def make_data_frame(addr2: str, seq: int, retry: bool = False, addr1: str = "ff:ff:ff:ff:ff:ff",
                    payload: bytes = b"AAAA"):
    fc = 0x08 if retry else 0x00
    pkt = Dot11(addr1=addr1, addr2=addr2, addr3="AA:BB:CC:DD:EE:FF",
                SC=(seq << 4), FCfield=fc, type=2, subtype=0) / payload
    return pkt


def make_malformed_ds_frame(addr2: str, seq: int = 1):
    """Management frame with an invalid to-DS bit set - management frames
    never carry DS routing."""
    pkt = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=addr2, addr3="AA:BB:CC:DD:EE:FF",
                SC=(seq << 4), FCfield=0x01, type=0, subtype=8) / Dot11Beacon()
    return pkt


def make_truncated_elt_frame(addr2: str, seq: int = 1):
    """A beacon whose Dot11Elt chain is truncated mid-element on the wire,
    simulating a corrupt/hand-crafted information element."""
    pkt = (Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=addr2, addr3="AA:BB:CC:DD:EE:FF",
                SC=(seq << 4), FCfield=0x00, type=0, subtype=8)
           / Dot11Beacon()
           / Dot11Elt(ID=0, info=b"TestSSID"))
    raw = bytes(pkt)
    truncated = raw[:-4]  # cut off the tail of the SSID element's declared data
    return Dot11(truncated)


class FakeConfig:
    """Minimal config stand-in exposing the same .get() interface as ConfigManager."""

    def __init__(self, packet_injection_detection: dict = None):
        self._data = {
            "packet_injection_detection": (
                packet_injection_detection if packet_injection_detection is not None
                else dict(DEFAULT_PACKET_INJECTION_CONFIG)
            )
        }

    def get(self, key, default=None):
        return self._data.get(key, default)


def make_detector(packet_injection_detection: dict = None):
    db = MagicMock()
    alert_mgr = MagicMock()
    config = FakeConfig(packet_injection_detection)
    detector = PacketInjectionDetector(db, config, alert_mgr, monitor_iface="wlan1mon")
    return detector, db, alert_mgr


class TestPacketInjectionDetectorNormalTraffic(unittest.TestCase):
    """Ordinary, monotonically-increasing sequence numbers from one source
    must never be flagged."""

    def test_sequential_frames_do_not_alert(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:01"

        for seq in range(1, 30):
            detector._handle_frame(make_data_frame(source, seq))

        alert_mgr.add.assert_not_called()
        db.add_attack.assert_not_called()

    def test_normal_retry_of_same_frame_does_not_alert(self):
        """A single genuine link-layer retransmission (same seq, retry flag
        set) is normal 802.11 behavior, not a replay indicator."""
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:02"

        detector._handle_frame(make_data_frame(source, 10, retry=False))
        detector._handle_frame(make_data_frame(source, 10, retry=True))
        detector._handle_frame(make_data_frame(source, 11, retry=False))

        alert_mgr.add.assert_not_called()


class TestPacketInjectionDetectorSequenceAnomaly(unittest.TestCase):
    """Duplicate/out-of-order/impossibly-jumped sequence numbers from the
    same source must be flagged."""

    def test_duplicate_sequence_without_retry_flag_is_flagged(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:03"

        detector._handle_frame(make_data_frame(source, 50, retry=False))
        detector._handle_frame(make_data_frame(source, 50, retry=False))

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[0], "PACKET_INJECTION")
        self.assertIn(source, args[3])
        self.assertIn("duplicate_seq", args[3])

        db.add_attack.assert_called_once()
        call_args, call_kwargs = db.add_attack.call_args
        self.assertEqual(call_args[0], "PACKET_INJECTION")
        self.assertEqual(call_kwargs["source_mac"], source)

    def test_impossible_sequence_jump_is_flagged(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:04"

        detector._handle_frame(make_data_frame(source, 5))
        detector._handle_frame(make_data_frame(source, 4000))  # far beyond seq_jump_threshold

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertIn("seq_jump", args[3])

    def test_out_of_order_replayed_sequence_is_flagged(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:05"

        for seq in range(1, 6):
            detector._handle_frame(make_data_frame(source, seq))
        # Replays an already-seen, older sequence number out of order.
        detector._handle_frame(make_data_frame(source, 2, retry=False))

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertIn("out_of_order_seq", args[3])

    def test_anomaly_counted_by_type_in_get_stats(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:11"

        detector._handle_frame(make_data_frame(source, 50, retry=False))
        detector._handle_frame(make_data_frame(source, 50, retry=False))  # duplicate_seq

        stats = detector.get_stats()
        self.assertEqual(stats["anomaly_counts"].get("duplicate_seq"), 1)
        self.assertEqual(stats["total_anomalies"], 1)


class TestPacketInjectionDetectorMalformedFrame(unittest.TestCase):
    """Malformed/impossible frame-control combinations and corrupt element
    chains must be flagged."""

    def test_management_frame_with_invalid_ds_bits_is_flagged(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:06"

        detector._handle_frame(make_malformed_ds_frame(source))

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertEqual(args[0], "PACKET_INJECTION")
        self.assertIn("malformed_frame", args[3])
        self.assertIn("invalid DS bits", args[3])

    def test_reserved_frame_type_is_flagged(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:07"
        pkt = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=source, addr3="AA:BB:CC:DD:EE:FF",
                    SC=(1 << 4), FCfield=0x00, type=3, subtype=0)

        detector._handle_frame(pkt)

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertIn("reserved frame-control type", args[3])

    def test_truncated_information_element_is_flagged(self):
        detector, db, alert_mgr = make_detector()
        source = "AA:BB:CC:DD:EE:08"

        detector._handle_frame(make_truncated_elt_frame(source))

        alert_mgr.add.assert_called_once()
        args, _ = alert_mgr.add.call_args
        self.assertIn("Dot11Elt", args[3])


class TestPacketInjectionDetectorReplayPattern(unittest.TestCase):
    """Identical frame content repeated far more than normal retransmission
    behavior would produce must be flagged as a replay pattern."""

    def test_repeated_identical_payload_without_retry_flag_is_flagged(self):
        detector, db, alert_mgr = make_detector(
            {"enabled": True, "replay_count_threshold": 3, "replay_window_seconds": 10,
             "seq_jump_threshold": 1000, "seq_history_size": 20,
             "anomaly_window_seconds": 60, "eval_throttle_seconds": 0}
        )
        source = "AA:BB:CC:DD:EE:09"

        # Same seq + same payload repeated with no retry flag - not
        # explainable as a genuine link-layer retransmission.
        for _ in range(4):
            detector._handle_frame(make_data_frame(source, 99, retry=False, payload=b"REPLAYED"))

        alert_mgr.add.assert_called()
        found = any("replay_pattern" in call.args[3] for call in alert_mgr.add.call_args_list)
        self.assertTrue(found)


class TestPacketInjectionDetectorDisabled(unittest.TestCase):
    """Detector disabled via config must be a complete no-op."""

    def test_disabled_detector_does_not_sniff(self):
        detector, db, alert_mgr = make_detector({"enabled": False})

        with patch("modules.packet_injection_detector.sniff") as sniff_mock:
            detector.start()
            sniff_mock.assert_not_called()

        alert_mgr.info.assert_called_once()

    def test_disabled_detector_ignores_frames_reaching_handler(self):
        detector, db, alert_mgr = make_detector({"enabled": False})
        source = "AA:BB:CC:DD:EE:10"

        detector._handle_frame(make_data_frame(source, 1))
        detector._handle_frame(make_data_frame(source, 1))  # would otherwise dup-flag

        alert_mgr.add.assert_not_called()
        db.add_attack.assert_not_called()

    def test_get_stats_reports_enabled_flag(self):
        detector, _, _ = make_detector({"enabled": False})
        self.assertFalse(detector.get_stats()["enabled"])

        detector2, _, _ = make_detector({"enabled": True})
        self.assertTrue(detector2.get_stats()["enabled"])


class TestPacketInjectionDetectorInterfaceUnavailable(unittest.TestCase):
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

        with patch("modules.packet_injection_detector.sniff", side_effect=fake_sniff):
            with patch("modules.packet_injection_detector.time.sleep", side_effect=fake_sleep):
                detector.start()

        self.assertGreaterEqual(call_count["n"], 2)
        alert_mgr.low.assert_called()
        self.assertIn("wlan1mon", alert_mgr.low.call_args[0][1])


if __name__ == "__main__":
    unittest.main()
