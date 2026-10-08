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
        self.db.close()
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

    def _insert_at(self, timestamp, message):
        self.db._get_conn().execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", message, timestamp),
        )
        self.db._get_conn().commit()

    def test_rows_are_written_oldest_first(self):
        # Inserted out of chronological order, so neither insertion (id) order
        # nor the database's newest-first order matches the expected output.
        self._insert_at("2026-03-02 10:00:00", "middle")
        self._insert_at("2026-03-03 09:00:00", "newest")
        self._insert_at("2026-03-01 23:59:59", "oldest")

        self.assertEqual(self.alert_mgr.export_alerts_to_csv(self.csv_path), 3)

        rows = read_csv(self.csv_path)[1:]
        self.assertEqual([r[3] for r in rows], ["oldest", "middle", "newest"])
        self.assertEqual([r[0] for r in rows], sorted(r[0] for r in rows))

    def test_equal_timestamps_are_ordered_by_id(self):
        self._insert_at("2026-03-02 10:00:00", "later, same second, first id")
        self._insert_at("2026-03-01 08:00:00", "earliest")
        self._insert_at("2026-03-02 10:00:00", "later, same second, second id")

        self.alert_mgr.export_alerts_to_csv(self.csv_path)

        self.assertEqual(
            [r[3] for r in read_csv(self.csv_path)[1:]],
            ["earliest", "later, same second, first id", "later, same second, second id"],
        )

    def test_export_does_not_change_get_alerts_order(self):
        self._insert_at("2026-03-01 00:00:00", "old")
        self._insert_at("2026-03-02 00:00:00", "new")

        self.alert_mgr.export_alerts_to_csv(self.csv_path)

        self.assertEqual([a['message'] for a in self.db.get_alerts()], ["new", "old"])

    def test_export_is_not_truncated_at_old_10000_limit(self):
        self.db._get_conn().executemany(
            "INSERT INTO alerts (alert_type, severity, message) VALUES (?,?,?)",
            [("BULK", "LOW", f"alert {i}") for i in range(10005)],
        )
        self.db._get_conn().commit()

        self.assertEqual(self.alert_mgr.export_alerts_to_csv(self.csv_path), 10005)
        self.assertEqual(len(read_csv(self.csv_path)), 10006)

    def test_filter_by_alert_type(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")
        self.db.add_alert("WPS", "MEDIUM", "WPS enabled")
        self.db.add_alert("ROGUE_AP", "CRITICAL", "Evil twin")

        count = self.alert_mgr.export_alerts_to_csv(self.csv_path, alert_type="DEAUTH")
        rows = read_csv(self.csv_path)[1:]
        self.assertEqual(count, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "DEAUTH")

    def test_filter_by_since(self):
        conn = self.db._get_conn()
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "old", "2026-01-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "recent", "2026-03-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "future", "2026-05-01 10:00:00"),
        )
        conn.commit()

        count = self.alert_mgr.export_alerts_to_csv(self.csv_path, since="2026-02-01")
        rows = read_csv(self.csv_path)[1:]
        self.assertEqual(count, 2)
        messages = [r[3] for r in rows]
        self.assertIn("recent", messages)
        self.assertIn("future", messages)
        self.assertNotIn("old", messages)

    def test_filter_by_type_and_since(self):
        conn = self.db._get_conn()
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "DEAUTH old", "2026-01-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "DEAUTH recent", "2026-03-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("WPS", "MEDIUM", "WPS recent", "2026-04-01 10:00:00"),
        )
        conn.commit()

        count = self.alert_mgr.export_alerts_to_csv(self.csv_path, alert_type="DEAUTH", since="2026-02-01")
        rows = read_csv(self.csv_path)[1:]
        self.assertEqual(count, 1)
        self.assertEqual(rows[0][1], "DEAUTH")
        self.assertEqual(rows[0][3], "DEAUTH recent")

    def test_invalid_since_raises_valueerror(self):
        with self.assertRaises(ValueError):
            self.alert_mgr.export_alerts_to_csv(self.csv_path, since="not-a-date")

    def test_default_filters_unchanged(self):
        # When both alert_type and since are None, all alerts are exported.
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")
        self.db.add_alert("WPS", "MEDIUM", "WPS enabled")
        count = self.alert_mgr.export_alerts_to_csv(self.csv_path, alert_type=None, since=None)
        self.assertEqual(count, 2)


class TestExportCli(ExportTestCase):
    """`main.py export PATH` - the license gate is mocked at the main.py boundary
    so no license server is involved. require_authorization is deliberately NOT
    stubbed: export must not prompt, and with no stdin any prompt would fail."""

    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.runner = CliRunner()

    def _invoke(self, path, license_valid=True):
        lic = MagicMock(is_valid=license_valid)
        with patch.object(self.main, "init_license", return_value=lic), \
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

    def test_export_runs_without_any_interactive_input(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")
        lic = MagicMock(is_valid=True)
        with patch.object(self.main, "init_license", return_value=lic), \
             patch.object(self.main, "Database", return_value=self.db), \
             patch.object(self.main, "require_authorization",
                          wraps=self.main.require_authorization) as auth:
            result = self.runner.invoke(self.main.cli, ["export", self.csv_path])

        self.assertEqual(result.exit_code, 0, result.output)
        auth.assert_not_called()
        self.assertNotIn("authorization to monitor", result.output)
        self.assertIn("Exported 1 alert(s)", result.output)
        self.assertEqual(len(read_csv(self.csv_path)), 2)

    def test_invalid_license_blocks_export(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")

        result = self._invoke(self.csv_path, license_valid=False)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("LICENSE INVALID", result.output)
        self.assertFalse(os.path.exists(self.csv_path))

    def test_monitoring_commands_still_require_authorization(self):
        # Proves the export change is scoped: `tui` still prompts, and a "no"
        # stops it before any monitoring component is created.
        lic = MagicMock(is_valid=True)
        with patch.object(self.main, "init_license", return_value=lic), \
             patch.object(self.main, "require_authorization", return_value=False) as auth, \
             patch.object(self.main, "init_components") as init_components:
            result = self.runner.invoke(self.main.cli, ["tui"])

        auth.assert_called_once_with()
        init_components.assert_not_called()
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Authorization not confirmed", result.output)

    def test_write_error_exits_non_zero(self):
        bad_path = os.path.join(self.tmpdir, "missing-dir", "alerts.csv")

        result = self._invoke(bad_path)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Failed to write CSV", result.output)

    def test_export_with_type_filter(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")
        self.db.add_alert("WPS", "MEDIUM", "WPS enabled")

        lic = MagicMock(is_valid=True)
        with patch.object(self.main, "init_license", return_value=lic), \
             patch.object(self.main, "Database", return_value=self.db):
            result = self.runner.invoke(self.main.cli, ["export", "--type", "DEAUTH", self.csv_path])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Exported 1 alert(s)", result.output)
        rows = read_csv(self.csv_path)[1:]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "DEAUTH")

    def test_export_with_since_filter(self):
        conn = self.db._get_conn()
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "old", "2026-01-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "recent", "2026-03-01 10:00:00"),
        )
        conn.commit()

        lic = MagicMock(is_valid=True)
        with patch.object(self.main, "init_license", return_value=lic), \
             patch.object(self.main, "Database", return_value=self.db):
            result = self.runner.invoke(self.main.cli, ["export", "--since", "2026-02-01", self.csv_path])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Exported 1 alert(s)", result.output)
        rows = read_csv(self.csv_path)[1:]
        self.assertEqual(rows[0][3], "recent")

    def test_export_with_both_filters(self):
        conn = self.db._get_conn()
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "DEAUTH old", "2026-01-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("DEAUTH", "HIGH", "DEAUTH recent", "2026-03-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            ("WPS", "MEDIUM", "WPS recent", "2026-04-01 10:00:00"),
        )
        conn.commit()

        lic = MagicMock(is_valid=True)
        with patch.object(self.main, "init_license", return_value=lic), \
             patch.object(self.main, "Database", return_value=self.db):
            result = self.runner.invoke(
                self.main.cli,
                ["export", "--type", "DEAUTH", "--since", "2026-02-01", self.csv_path],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Exported 1 alert(s)", result.output)
        rows = read_csv(self.csv_path)[1:]
        self.assertEqual(rows[0][1], "DEAUTH")
        self.assertEqual(rows[0][3], "DEAUTH recent")

    def test_invalid_since_exits_nonzero(self):
        self.db.add_alert("DEAUTH", "HIGH", "Deauth burst")

        lic = MagicMock(is_valid=True)
        with patch.object(self.main, "init_license", return_value=lic), \
             patch.object(self.main, "Database", return_value=self.db):
            result = self.runner.invoke(self.main.cli, ["export", "--since", "not-a-date", self.csv_path])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid --since date", result.output)
        self.assertFalse(os.path.exists(self.csv_path))


if __name__ == "__main__":
    unittest.main()
