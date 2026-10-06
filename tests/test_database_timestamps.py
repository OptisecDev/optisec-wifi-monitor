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
import time
import unittest
import warnings
from datetime import datetime, timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alert_manager import AlertManager
from core.database import Database, _now_ts

TS_FORMAT = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{6})?$"

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
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.db_path = os.path.join(self.tmpdir, "optisec.db")

    def open_db(self, db_path=None):
        """Database closed at test end (cleanups run LIFO, so before rmtree)."""
        db = Database(db_path=db_path or self.db_path)
        self.addCleanup(db.close)
        return db


class TestOldFormatDatabaseCompatibility(TimestampTestCase):

    def _create_old_format_db(self):
        Database(db_path=self.db_path).close()  # schema is unchanged between versions
        conn = sqlite3.connect(self.db_path)
        self.addCleanup(conn.close)  # also covers a failed insert; closing twice is a no-op
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
        db = self.open_db()

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
        db = self.open_db()
        csv_path = os.path.join(self.tmpdir, "alerts.csv")

        AlertManager(db).export_alerts_to_csv(csv_path)

        with open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))[1:]
        self.assertEqual([r[0] for r in rows], [
            "2025-01-15 08:30:00.250000", "2025-02-20 23:59:59", "2025-03-01 10:00:00",
        ])

    def test_new_writes_sort_correctly_against_old_rows(self):
        self._create_old_format_db()
        db = self.open_db()

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
        db = self.open_db()
        db.upsert_device("AA:AA:AA:AA:AA:01")
        db.upsert_device("AA:AA:AA:AA:AA:01")

        conn = sqlite3.connect(self.db_path)
        try:
            raw = conn.execute("SELECT last_seen, typeof(last_seen) FROM devices").fetchone()
        finally:
            conn.close()
        self.assertEqual(raw[1], "text")
        self.assertLess(abs(datetime.fromisoformat(raw[0]) - datetime.now()), timedelta(minutes=1))
        self.assertRegex(raw[0], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{6})?$")

    def test_writes_do_not_use_deprecated_default_adapter(self):
        db = self.open_db()
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
        self.addCleanup(conn.close)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                adapted = conn.execute("SELECT ?", (dt,)).fetchone()[0]
            except sqlite3.ProgrammingError:
                self.skipTest("default datetime adapter removed in this Python")
        self.assertEqual(adapted, dt.isoformat(" "))
        self.assertRegex(_now_ts(), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{6})?$")


class FakeClock:
    """Stand-in for core.database._now_ts: a fixed start that advances one
    second per call, formatted exactly like the real helper."""

    def __init__(self, start=datetime(2026, 2, 3, 4, 5, 6, 123456)):
        self.now = start
        self.issued = []

    def __call__(self):
        self.now += timedelta(seconds=1)
        ts = self.now.isoformat(" ")
        self.issued.append(ts)
        return ts


class TestInsertsUseExplicitLocalTime(TimestampTestCase):
    """INSERTs into columns with DEFAULT CURRENT_TIMESTAMP must store
    _now_ts() (local time) rather than the UTC default.

    Runs in a fixed UTC+3 zone so a UTC value is 3 hours away from local
    time and cannot pass by coincidence on a UTC machine."""

    def setUp(self):
        super().setUp()
        if not hasattr(time, "tzset"):
            self.skipTest("time.tzset() not available on this platform")
        self._old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "UTC-3"  # POSIX sign convention: 3 hours ahead of UTC
        time.tzset()
        self.addCleanup(self._restore_tz)

    def _restore_tz(self):
        if self._old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self._old_tz
        time.tzset()

    # Every insert path that used to rely on the column default:
    # (label, writer, SQL returning the timestamp column(s) of the new row)
    INSERT_PATHS = [
        ("add_alert", lambda db: db.add_alert("DEAUTH", "HIGH", "msg"),
         "SELECT timestamp FROM alerts"),
        ("add_attack", lambda db: db.add_attack("DEAUTH", "HIGH", source_mac="AA:AA:AA:AA:AA:01"),
         "SELECT timestamp FROM attacks"),
        ("add_report", lambda db: db.add_report("PERIODIC", "report"),
         "SELECT timestamp FROM ai_reports"),
        ("upsert_device (new)", lambda db: db.upsert_device("AA:AA:AA:AA:AA:01"),
         "SELECT first_seen, last_seen FROM devices"),
        ("upsert_bssid_baseline (new)", lambda db: db.upsert_bssid_baseline("11:22:33:44:55:66", "HomeNet"),
         "SELECT first_seen, last_seen FROM bssid_baseline"),
        ("upsert_audit (new)", lambda db: db.upsert_audit("11:22:33:44:55:66", "HomeNet", "WPA2", False, True, 80),
         "SELECT timestamp FROM encryption_audits"),
    ]

    def _raw(self, db_path, sql):
        conn = sqlite3.connect(db_path)
        try:
            return conn.execute(sql).fetchone()
        finally:
            conn.close()

    def test_each_insert_path_stores_value_from_now_ts(self):
        for i, (label, write, sql) in enumerate(self.INSERT_PATHS):
            with self.subTest(path=label):
                db_path = os.path.join(self.tmpdir, f"path{i}.db")
                db = self.open_db(db_path)
                clock = FakeClock()
                with patch("core.database._now_ts", clock):
                    write(db)
                self.assertEqual(len(clock.issued), 1)
                for value in self._raw(db_path, sql):
                    self.assertEqual(value, clock.issued[0])

    def test_each_insert_path_stores_local_time_not_utc(self):
        for i, (label, write, sql) in enumerate(self.INSERT_PATHS):
            with self.subTest(path=label):
                db_path = os.path.join(self.tmpdir, f"path{i}.db")
                db = self.open_db(db_path)
                write(db)
                for value in self._raw(db_path, sql):
                    self.assertRegex(value, TS_FORMAT)
                    self.assertLess(abs(datetime.fromisoformat(value) - datetime.now()),
                                    timedelta(minutes=1),
                                    f"{label} stored {value!r}, local now is {datetime.now()}")

    def test_mixed_insert_and_update_paths_sort_chronologically(self):
        db = self.open_db()
        with patch("core.database._now_ts", FakeClock()):
            db.upsert_device("AA:AA:AA:AA:AA:01")             # insert
            db.upsert_device("AA:AA:AA:AA:AA:01")             # update (always explicit)
            db.upsert_device("AA:AA:AA:AA:AA:02")             # insert, newest
            db.upsert_audit("11:11:11:11:11:11", "A", "WPA2", False, True, 80)   # insert
            db.upsert_audit("11:11:11:11:11:11", "A", "WPA2", False, True, 80)   # update
            db.upsert_audit("22:22:22:22:22:22", "B", "WPA3", False, True, 95)   # insert, newest
            db.upsert_bssid_baseline("33:33:33:33:33:33", "C")                   # insert
            db.upsert_bssid_baseline("33:33:33:33:33:33", "C")                   # update
            db.upsert_bssid_baseline("44:44:44:44:44:44", "D")                   # insert, newest

        self.assertEqual([d["mac"] for d in db.get_all_devices()],
                         ["AA:AA:AA:AA:AA:02", "AA:AA:AA:AA:AA:01"])
        self.assertEqual([a["bssid"] for a in db.get_audits()],
                         ["22:22:22:22:22:22", "11:11:11:11:11:11"])
        first = db.get_bssid_baseline("33:33:33:33:33:33")
        newest = db.get_bssid_baseline("44:44:44:44:44:44")
        self.assertLess(first["first_seen"], first["last_seen"])
        self.assertLess(first["last_seen"], newest["first_seen"])

    def test_mixed_alert_paths_export_in_true_chronological_order(self):
        db = self.open_db()
        mgr = AlertManager(db)
        clock = FakeClock()
        with patch("core.database._now_ts", clock):
            db.add_alert("DEAUTH", "HIGH", "first")
            mgr.add("WPS", "MEDIUM", "second", print_to_console=False)
            db.add_alert("ROGUE_AP", "CRITICAL", "third")
            mgr.add("NEW_DEVICE", "INFO", "fourth", print_to_console=False)
            db.add_attack("DEAUTH", "HIGH")
            db.add_alert("DEAUTH", "HIGH", "fifth")
        csv_path = os.path.join(self.tmpdir, "alerts.csv")

        mgr.export_alerts_to_csv(csv_path)

        with open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))[1:]
        self.assertEqual([r[3] for r in rows], ["first", "second", "third", "fourth", "fifth"])
        alert_ts = [ts for i, ts in enumerate(clock.issued) if i != 4]  # 5th tick went to attacks
        self.assertEqual([r[0] for r in rows], alert_ts)
        self.assertEqual([a["message"] for a in db.get_alerts()],
                         ["fifth", "fourth", "third", "second", "first"])


class TestTimeWindowsUseLocalTime(TimestampTestCase):
    """Time-window queries must compare against local time, matching the
    local-time rows written by _now_ts().

    Runs in a fixed UTC+3 zone. The clock is frozen at the real local time
    (captured once) so that a UTC cutoff - SQLite's datetime('now', ...) -
    would land 27 hours back and wrongly include the 25-hour-old alert on
    any machine, including a UTC one."""

    def setUp(self):
        super().setUp()
        if not hasattr(time, "tzset"):
            self.skipTest("time.tzset() not available on this platform")
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "UTC-3"  # POSIX sign convention: 3 hours ahead of UTC
        time.tzset()
        self.addCleanup(self._restore_tz, old_tz)
        self.frozen = datetime.now()

    @staticmethod
    def _restore_tz(old_tz):
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        time.tzset()

    def _clock(self, at):
        return patch("core.database._local_now", return_value=at)

    def _db_with_alerts(self, *hours_ago):
        db = self.open_db()
        for h in hours_ago:
            with self._clock(self.frozen - timedelta(hours=h)):
                db.add_alert("DEAUTH", "HIGH", f"{h}h ago")
        return db

    def test_get_alerts_by_hour_includes_1h_and_excludes_25h_old_alert(self):
        db = self._db_with_alerts(1, 25)

        with self._clock(self.frozen):
            rows = db.get_alerts_by_hour(24)

        self.assertEqual(sum(r["count"] for r in rows), 1, rows)
        self.assertEqual(rows, [{"hour": (self.frozen - timedelta(hours=1)).strftime("%H"),
                                 "count": 1}])

    def test_get_alerts_by_hour_honours_the_hours_argument(self):
        db = self._db_with_alerts(1, 25)

        with self._clock(self.frozen):
            self.assertEqual(sum(r["count"] for r in db.get_alerts_by_hour(26)), 2)
            self.assertEqual(db.get_alerts_by_hour(0), [])


if __name__ == "__main__":
    unittest.main()
