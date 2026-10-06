"""Every sqlite connection is closed deterministically: Database.close() and
the main.py code paths that own a Database."""

import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from click.testing import CliRunner

from core.database import Database


class DbTestCase(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.db = Database(db_path=os.path.join(self.tmpdir, "optisec.db"))
        self.addCleanup(self.db.close)

    def assertClosed(self, conn):
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


class TestDatabaseClose(DbTestCase):

    def test_close_closes_the_calling_threads_connection(self):
        self.db.add_alert("DEAUTH", "HIGH", "msg")
        conn = self.db._get_conn()

        self.db.close()

        self.assertClosed(conn)

    def test_close_closes_connections_opened_by_other_threads(self):
        conns = []

        def worker():
            self.db.add_attack("DEAUTH", "HIGH")
            conns.append(self.db._get_conn())

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len({id(c) for c in conns}), 3)

        self.db.close()

        for conn in conns:
            self.assertClosed(conn)

    def test_close_is_idempotent_and_later_use_raises(self):
        self.db.add_alert("DEAUTH", "HIGH", "msg")
        self.db.close()
        self.db.close()

        with self.assertRaises(sqlite3.ProgrammingError):
            self.db.get_alerts()

    def test_use_after_close_does_not_open_a_new_connection_in_a_new_thread(self):
        self.db.close()
        errors = []

        def worker():
            try:
                self.db.get_alerts()
            except sqlite3.ProgrammingError as exc:
                errors.append(exc)

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        self.assertEqual(len(errors), 1)
        self.assertEqual(self.db._conns, [])

    def test_context_manager_closes_even_on_exception(self):
        path = os.path.join(self.tmpdir, "ctx.db")
        with self.assertRaises(RuntimeError):
            with Database(db_path=path) as db:
                db.add_alert("DEAUTH", "HIGH", "msg")
                conn = db._get_conn()
                raise RuntimeError("boom")

        self.assertClosed(conn)

    def test_init_db_closes_its_connection_when_schema_setup_fails(self):
        opened = []
        real_connect = sqlite3.connect

        def tracking_connect(*args, **kwargs):
            conn = real_connect(*args, **kwargs)
            opened.append(conn)
            return conn

        with patch("core.database.sqlite3.connect", tracking_connect), \
             patch.object(Database, "_create_schema", side_effect=sqlite3.OperationalError("disk I/O")):
            with self.assertRaises(sqlite3.OperationalError):
                Database(db_path=os.path.join(self.tmpdir, "broken.db"))

        self.assertEqual(len(opened), 1)
        self.assertClosed(opened[0])


class TestMainClosesDatabase(DbTestCase):
    """The license gate is mocked at the main.py boundary; nothing here
    touches ~/.optisec or a license server."""

    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.runner = CliRunner()
        self.lic = MagicMock(is_valid=True)

    def test_export_closes_database_on_success(self):
        self.db.add_alert("DEAUTH", "HIGH", "msg")
        conn = self.db._get_conn()
        with patch.object(self.main, "init_license", return_value=self.lic), \
             patch.object(self.main, "Database", return_value=self.db):
            result = self.runner.invoke(
                self.main.cli, ["export", os.path.join(self.tmpdir, "out.csv")])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertClosed(conn)

    def test_export_closes_database_when_write_fails(self):
        conn = self.db._get_conn()
        with patch.object(self.main, "init_license", return_value=self.lic), \
             patch.object(self.main, "Database", return_value=self.db):
            result = self.runner.invoke(
                self.main.cli, ["export", os.path.join(self.tmpdir, "missing", "out.csv")])

        self.assertEqual(result.exit_code, 1)
        self.assertClosed(conn)

    def test_stop_all_components_closes_database_after_stopping_components(self):
        conn = self.db._get_conn()
        db_open_during_stop = []
        monitor = MagicMock()
        monitor.stop.side_effect = lambda: db_open_during_stop.append(
            conn.execute("SELECT 1").fetchone()[0] == 1)
        components = {"db": self.db, "device_monitor": monitor}

        self.main.stop_all_components(components)

        self.assertEqual(db_open_during_stop, [True])
        self.assertClosed(conn)
        self.main.stop_all_components(components)  # safe to call again
        self.assertEqual(monitor.stop.call_count, 2)

    def test_init_components_closes_database_if_setup_fails(self):
        conn = self.db._get_conn()
        with patch.object(self.main, "Database", return_value=self.db), \
             patch.object(self.main, "ConfigManager", side_effect=RuntimeError("bad config")):
            with self.assertRaises(RuntimeError):
                self.main.init_components("wlan1", "wlan0", "en")

        self.assertClosed(conn)

    def test_monitoring_command_closes_database_if_startup_fails(self):
        conn = self.db._get_conn()
        for command in ("tui", "web", "both"):
            with self.subTest(command=command), \
                 patch.object(self.main, "init_license", return_value=self.lic), \
                 patch.object(self.main, "require_authorization", return_value=True), \
                 patch.object(self.main, "init_components", return_value={"db": self.db}), \
                 patch.object(self.main, "start_monitoring_threads",
                              side_effect=RuntimeError("no interface")):
                result = self.runner.invoke(self.main.cli, [command])

                self.assertIsInstance(result.exception, RuntimeError)
                self.assertClosed(conn)


if __name__ == "__main__":
    unittest.main()
