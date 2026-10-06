"""Timestamp storage in core/database.py.

Timestamps are written as explicit ISO-8601 strings instead of relying on
sqlite3's default datetime adapter (deprecated in Python 3.12). Databases
written by the previous release must still read back with the same values
and ordering, including the oldest-first CSV export.
"""

import csv
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
import warnings
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alert_manager import AlertManager
from core.database import Database, _now_ts

# What the previous release stored: datetime.now() through the default
# adapter (isoformat(" "), with microseconds) for explicit writes, and
# SQLite's CURRENT_TIMESTAMP ("YYYY-MM-DD HH:MM:SS") for column defaults.
OLD_ALERTS = [
    # (timestamp, alert_type) inserted deliberately out of chronological order
    ("2025-03-01 10:00:00",        "C"),
    ("2025-01-15 08:30:00.250000", "A"),
    ("2025-02-20 23:59:59",        "B"),
]


class TimestampTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "optisec.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestOldFormatDatabaseCompatibility(TimestampTestCase):

    def _create_old_format_db(self):
        Database(db_path=self.db_path)  # schema is unchanged between versions
        conn = sqlite3.connect(self.db_path)
        conn.executemany(
            "INSERT INTO alerts (alert_type, severity, message, timestamp) VALUES (?,?,?,?)",
            [(t, "HIGH", f"msg {t}", ts) for ts, t in OLD_ALERTS],
        )
        conn.execute(
            "INSERT INTO devices (mac, first_seen, last_seen) VALUES (?,?,?)",
            ("AA:AA:AA:AA:AA:01", "2025-01-01 00:00:00", "2025-01-02 12:00:00.500000"),
        )
        conn.execute(
            "INSERT INTO devices (mac, first_seen, last_seen) VALUES (?,?,?)",
            ("AA:AA:AA:AA:AA:02", "2025-01-01 00:00:00", "2025-01-03 09:00:00"),
        )
        conn.execute(
            "INSERT INTO bssid_baseline (bssid, ssid, first_seen, last_seen) VALUES (?,?,?,?)",
            ("11:22:33:44:55:66", "HomeNet", "2025-01-01 07:00:00.123456", "2025-01-01 07:00:00"),
        )
        conn.commit()
        conn.close()

    def test_old_timestamps_read_back_unchanged_and_ordered(self):
        self._create_old_format_db()
        db = Database(db_path=self.db_path)

        alerts = db.get_alerts(limit=-1)
        self.assertEqual([a["alert_type"] for a in alerts], ["C", "B", "A"])
        self.assertEqual(
            sorted(a["timestamp"] for a in alerts), sorted(ts for ts, _ in OLD_ALERTS)
        )

        row = db.get_bssid_baseline("11:22:33:44:55:66")
        self.assertEqual(row["first_seen"], "2025-01-01 07:00:00.123456")
        self.assertEqual(datetime.fromisoformat(row["first_seen"]),
                         datetime(2025, 1, 1, 7, 0, 0, 123456))

    def test_csv_export_of_old_db_is_oldest_first(self):
        self._create_old_format_db()
        db = Database(db_path=self.db_path)
        csv_path = os.path.join(self.tmpdir, "alerts.csv")

        AlertManager(db).export_alerts_to_csv(csv_path)

        with open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))[1:]
        self.assertEqual([r[0] for r in rows], [
            "2025-01-15 08:30:00.250000", "2025-02-20 23:59:59", "2025-03-01 10:00:00",
        ])

    def test_new_writes_sort_correctly_against_old_rows(self):
        self._create_old_format_db()
        db = Database(db_path=self.db_path)

        db.upsert_device("AA:AA:AA:AA:AA:01")   # existing row -> last_seen = now
        db.upsert_bssid_baseline("11:22:33:44:55:66", ssid="HomeNet")

        devices = db.get_all_devices()
        self.assertEqual(devices[0]["mac"], "AA:AA:AA:AA:AA:01")
        self.assertEqual(devices[1]["last_seen"], "2025-01-03 09:00:00")
        baseline = db.get_bssid_baseline("11:22:33:44:55:66")
        self.assertEqual(baseline["first_seen"], "2025-01-01 07:00:00.123456")
        self.assertGreater(baseline["last_seen"], "2025-01-01 07:00:00")


class TestExplicitTimestampFormat(TimestampTestCase):

    def test_written_value_is_iso_string_parseable_as_local_now(self):
        db = Database(db_path=self.db_path)
        db.upsert_device("AA:AA:AA:AA:AA:01")
        db.upsert_device("AA:AA:AA:AA:AA:01")

        raw = sqlite3.connect(self.db_path).execute(
            "SELECT last_seen, typeof(last_seen) FROM devices").fetchone()
        self.assertEqual(raw[1], "text")
        self.assertLess(abs(datetime.fromisoformat(raw[0]) - datetime.now()), timedelta(minutes=1))
        self.assertRegex(raw[0], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{6})?$")

    def test_writes_do_not_use_deprecated_default_adapter(self):
        db = Database(db_path=self.db_path)
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            db.upsert_device("AA:AA:AA:AA:AA:01")
            db.upsert_device("AA:AA:AA:AA:AA:01")
            db.upsert_bssid_baseline("11:22:33:44:55:66", ssid="HomeNet")
            db.upsert_bssid_baseline("11:22:33:44:55:66", ssid="HomeNet")
            db.upsert_audit("11:22:33:44:55:66", "HomeNet", "WPA2", False, True, 80)
            db.upsert_audit("11:22:33:44:55:66", "HomeNet", "WPA2", False, True, 80)

    def test_format_matches_previous_default_adapter(self):
        """The explicit format is exactly what the old default adapter
        stored, so old and new rows are interchangeable."""
        dt = datetime(2025, 6, 7, 8, 9, 10, 111213)
        conn = sqlite3.connect(":memory:")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                adapted = conn.execute("SELECT ?", (dt,)).fetchone()[0]
            except sqlite3.ProgrammingError:
                self.skipTest("default datetime adapter removed in this Python")
        self.assertEqual(adapted, dt.isoformat(" "))
        self.assertRegex(_now_ts(), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{6})?$")


if __name__ == "__main__":
    unittest.main()
