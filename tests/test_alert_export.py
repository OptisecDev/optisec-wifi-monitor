"""Unit tests for AlertManager.export_alerts_to_csv and the `export` CLI command."""

import csv
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from click.testing import CliRunner

from core.alert_manager import AlertManager
from core.database import Database

HEADER = ['timestamp', 'alert_type', 'severity', 'message', 'details']


def read_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.reader(f))


class ExportTestCase(unittest.TestCase):
    """Real SQLite-backed Database in a throwaway directory."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = Database(db_path=os.path.join(self.tmpdir, "alerts.db"))
        self.alert_mgr = AlertManager(self.db)
        self.csv_path = os.path.join(self.tmpdir, "alerts.csv")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestExportAlertsToCsv(ExportTestCase):

    def test_empty_log_writes_header_only_and_returns_zero(self):
        count = self.alert_mgr.export_alerts_to_csv(self.csv_path)

        self.assertEqual(count, 0)
        self.assertEqual(read_csv(self.csv_path), [HEADER])

    def test_header_row(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")
        self.alert_mgr.export_alerts_to_csv(self.csv_path)

        self.assertEqual(read_csv(self.csv_path)[0], HEADER)

    def test_one_row_per_alert_with_correct_values(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst", "src=AA:BB:CC:DD:EE:01")
        self.db.add_alert("ROGUE_AP", "CRITICAL", "Evil twin", "ssid=HomeNet")
        self.db.add_alert("NEW_DEVICE", "INFO", "New device", None)

        count = self.alert_mgr.export_alerts_to_csv(self.csv_path)

        rows = read_csv(self.csv_path)[1:]
        self.assertEqual(count, 3)
        self.assertEqual(len(rows), 3)
        expected = [
            [a['timestamp'], a['alert_type'], a['severity'], a['message'], a['details'] or '']
            for a in self.db.get_alerts(limit=-1)
        ]
        self.assertEqual(sorted(rows), sorted(expected))
        self.assertIn(['NEW_DEVICE', 'INFO', 'New device', ''], [r[1:] for r in rows])

    def test_alerts_added_via_manager_are_exported(self):
        self.alert_mgr.add("WPS", "MEDIUM", "WPS enabled", "bssid=x", print_to_console=False)

        self.assertEqual(self.alert_mgr.export_alerts_to_csv(self.csv_path), 1)
        self.assertEqual(read_csv(self.csv_path)[1][1:], ['WPS', 'MEDIUM', 'WPS enabled', 'bssid=x'])

    def test_commas_quotes_and_newlines_round_trip(self):
        message = 'Deauth from "attacker", target=all'
        details = 'line one, with comma\nline two "quoted"\r\nline three'
        self.db.add_alert("DEAUTH", "HIGH", message, details)

        self.alert_mgr.export_alerts_to_csv(self.csv_path)

        rows = read_csv(self.csv_path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][3], message)
        self.assertEqual(rows[1][4], details)

    def test_non_ascii_text_round_trips_as_utf8(self):
        message = "نقطة وصول مزيفة 🚨"
        details = "SSID=Café-Wi‑Fi"
        self.db.add_alert("ROGUE_AP", "CRITICAL", message, details)

        self.alert_mgr.export_alerts_to_csv(self.csv_path)

        with open(self.csv_path, 'rb') as f:
            raw = f.read()
        self.assertIn(message.encode('utf-8'), raw)
        rows = read_csv(self.csv_path)
        self.assertEqual(rows[1][3], message)
        self.assertEqual(rows[1][4], details)

    def test_export_is_not_truncated_at_old_10000_limit(self):
        self.db._get_conn().executemany(
            "INSERT INTO alerts (alert_type, severity, message) VALUES (?,?,?)",
            [("BULK", "LOW", f"alert {i}") for i in range(10005)],
        )
        self.db._get_conn().commit()

        self.assertEqual(self.alert_mgr.export_alerts_to_csv(self.csv_path), 10005)
        self.assertEqual(len(read_csv(self.csv_path)), 10006)


class TestExportCli(ExportTestCase):
    """`main.py export PATH` - license and authorization gates are mocked at the
    main.py boundary so no license server or interactive prompt is involved."""

    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.runner = CliRunner()

    def _invoke(self, path, license_valid=True, authorized=True):
        lic = MagicMock(is_valid=license_valid)
        with patch.object(self.main, "init_license", return_value=lic), \
             patch.object(self.main, "require_authorization", return_value=authorized), \
             patch.object(self.main, "Database", return_value=self.db):
            return self.runner.invoke(self.main.cli, ["export", path])

    def test_export_command_writes_csv_and_reports_count(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")
        self.db.add_alert("WPS", "MEDIUM", "WPS enabled")

        result = self._invoke(self.csv_path)

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Exported 2 alert(s)", result.output)
        self.assertIn("alerts.csv", result.output)
        self.assertEqual(len(read_csv(self.csv_path)), 3)

    def test_invalid_license_blocks_export(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")

        result = self._invoke(self.csv_path, license_valid=False)

        self.assertEqual(result.exit_code, 1)
        self.assertFalse(os.path.exists(self.csv_path))

    def test_declined_authorization_blocks_export(self):
        result = self._invoke(self.csv_path, authorized=False)

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Authorization not confirmed", result.output)
        self.assertFalse(os.path.exists(self.csv_path))

    def test_write_error_exits_non_zero(self):
        bad_path = os.path.join(self.tmpdir, "missing-dir", "alerts.csv")

        result = self._invoke(bad_path)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Failed to write CSV", result.output)


if __name__ == "__main__":
    unittest.main()
