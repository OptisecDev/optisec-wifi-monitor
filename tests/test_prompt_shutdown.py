"""stop() must wake a component's sleeping loop at once, so stop_all_components
can join every thread promptly instead of waiting out each sleep."""

import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import (
    ai_engine, attack_detector, deauth_detector, device_monitor, encryption_auditor,
    packet_injection_detector, rogue_ap_detector, telegram_notifier, wps_detector,
)

STOP_BUDGET = 0.5   # seconds a stopped thread may take to exit
LONG = 3600         # configured interval, far longer than STOP_BUDGET
SETTLE = 0.05       # lets the thread get from its entry hook into the wait


class FakeConfig:
    """config.get() with fixed values; on_get fires on every lookup."""

    alert_thresholds: dict = {}
    whitelist: list = []

    def __init__(self, values=None, on_get=None):
        self.values = values or {}
        self.on_get = on_get

    def get(self, key, default=None):
        if self.on_get:
            self.on_get()
        return self.values.get(key, default)


class PromptStopTestCase(unittest.TestCase):

    def record_waits(self, comp):
        """Record the timeout of every wait on comp's stop event, still waiting for real."""
        timeouts = []
        real_wait = comp._stop_event.wait

        def wait(timeout=None):
            timeouts.append(timeout)
            return real_wait(timeout)

        comp._stop_event.wait = wait
        return timeouts

    def assert_stops_promptly(self, comp, entered, thread=None, target=None):
        if thread is None:
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
        self.assertTrue(entered.wait(5), "loop never reached its sleep")
        time.sleep(SETTLE)

        t0 = time.monotonic()
        comp.stop()
        thread.join(STOP_BUDGET)
        elapsed = time.monotonic() - t0

        self.assertFalse(thread.is_alive(), f"thread still running {elapsed:.2f}s after stop()")
        self.assertLess(elapsed, STOP_BUDGET)

    def failing_sniff(self, entered):
        def sniff(**kwargs):
            entered.set()
            raise OSError("No such device")
        return sniff


class TestSniffDetectorsStopPromptly(PromptStopTestCase):
    """The five sniff-based detectors share the same retry and fallback loops."""

    DETECTORS = [
        (attack_detector, lambda cfg, am: attack_detector.AttackDetector(MagicMock(), cfg, am, "wlan1mon")),
        (deauth_detector, lambda cfg, am: deauth_detector.DeauthDetector(MagicMock(), cfg, am, "wlan1mon")),
        (rogue_ap_detector, lambda cfg, am: rogue_ap_detector.RogueAPDetector(MagicMock(), cfg, am, "wlan1mon")),
        (wps_detector, lambda cfg, am: wps_detector.WPSDetector(MagicMock(), cfg, am, "wlan1mon")),
        (packet_injection_detector,
         lambda cfg, am: packet_injection_detector.PacketInjectionDetector(MagicMock(), cfg, am, "wlan1mon")),
    ]

    def test_sniff_retry_backoff_wakes_on_stop(self):
        for module, make in self.DETECTORS:
            with self.subTest(module.__name__):
                entered = threading.Event()
                det = make(FakeConfig(), MagicMock())
                waits = self.record_waits(det)
                with patch.object(module, "SCAPY_AVAILABLE", True), \
                        patch.object(module, "sniff", side_effect=self.failing_sniff(entered), create=True):
                    self.assert_stops_promptly(det, entered, target=det.start)
                self.assertEqual(waits, [5])

    def test_scapy_unavailable_fallback_wakes_on_stop(self):
        for module, make in self.DETECTORS:
            with self.subTest(module.__name__):
                entered = threading.Event()
                alert_mgr = MagicMock()
                alert_mgr.low.side_effect = lambda *a: entered.set()
                det = make(FakeConfig(), alert_mgr)
                waits = self.record_waits(det)
                with patch.object(module, "SCAPY_AVAILABLE", False):
                    self.assert_stops_promptly(det, entered, target=det.start)
                self.assertEqual(waits, [10])


class TestDeviceMonitorStopsPromptly(PromptStopTestCase):

    def make(self, on_get=None, alert_mgr=None):
        db = MagicMock()
        db.get_all_devices.return_value = []
        cfg = FakeConfig({"scan_interval": LONG}, on_get=on_get)
        return device_monitor.DeviceMonitor(db, cfg, alert_mgr or MagicMock(), "wlan1mon", "wlan0")

    def test_scan_interval_wait_wakes_on_stop(self):
        entered = threading.Event()
        mon = self.make(on_get=entered.set)
        waits = self.record_waits(mon)
        with patch.object(device_monitor, "SCAPY_AVAILABLE", False), \
                patch.object(mon, "_active_nmap_scan"):
            self.assert_stops_promptly(mon, entered, target=mon.start)
        self.assertEqual(waits, [LONG])

    def test_passive_scan_retry_wakes_on_stop(self):
        entered = threading.Event()
        mon = self.make()
        waits = self.record_waits(mon)
        mon._running = True
        with patch.object(device_monitor, "sniff", side_effect=self.failing_sniff(entered), create=True):
            self.assert_stops_promptly(mon, entered, target=mon._passive_scan)
        self.assertEqual(waits, [5])


class TestEncryptionAuditorStopsPromptly(PromptStopTestCase):

    def test_iwlist_interval_wait_wakes_on_stop(self):
        entered = threading.Event()
        aud = encryption_auditor.EncryptionAuditor(MagicMock(), MagicMock(), "wlan1mon")
        waits = self.record_waits(aud)
        with patch.object(encryption_auditor, "SCAPY_AVAILABLE", False), \
                patch.object(aud, "_iwlist_scan", side_effect=entered.set):
            self.assert_stops_promptly(aud, entered, target=aud.start)
        self.assertEqual(waits, [60])

    def test_beacon_sniff_retry_wakes_on_stop(self):
        entered = threading.Event()
        aud = encryption_auditor.EncryptionAuditor(MagicMock(), MagicMock(), "wlan1mon")
        waits = self.record_waits(aud)
        aud._running = True
        with patch.object(encryption_auditor, "sniff", side_effect=self.failing_sniff(entered), create=True):
            self.assert_stops_promptly(aud, entered, target=aud._sniff_beacons)
        self.assertEqual(waits, [5])


class TestAIEngineStopsPromptly(PromptStopTestCase):

    def test_report_interval_wait_wakes_on_stop_without_reporting(self):
        entered = threading.Event()
        engine = ai_engine.AIEngine(MagicMock(), FakeConfig({"ai_report_interval": LONG}, on_get=entered.set))
        waits = self.record_waits(engine)
        with patch.object(engine, "generate_periodic_report") as report:
            self.assert_stops_promptly(engine, entered, target=engine.start)
        report.assert_not_called()
        self.assertEqual(waits, [LONG])


class TestTelegramNotifierStopsPromptly(PromptStopTestCase):

    def test_batch_interval_wait_wakes_on_stop_without_sending(self):
        entered = threading.Event()
        cfg = FakeConfig({"telegram_bot_token": "t", "telegram_chat_id": "1"})
        notifier = telegram_notifier.TelegramNotifier(cfg)
        waits = self.record_waits(notifier)
        with patch.object(notifier, "_send") as send:
            notifier.start()
            notifier.notify({"severity": "MEDIUM", "alert_type": "NEW_DEVICE", "message": "m"})
            entered.set()  # start() has launched the loop thread
            self.assert_stops_promptly(notifier, entered, thread=notifier.threads[0])
        send.assert_not_called()
        self.assertEqual(waits, [telegram_notifier._BATCH_INTERVAL])


if __name__ == "__main__":
    unittest.main()
