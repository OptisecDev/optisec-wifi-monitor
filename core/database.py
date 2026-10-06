"""SQLite database manager for Optisec WiFi Monitor."""

import functools
import logging
import sqlite3
import os
import threading
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


DEFAULT_DB_PATH = os.path.expanduser("~/.optisec/optisec.db")


def _local_now() -> datetime:
    """The one clock behind stored timestamps and time-window cutoffs."""
    return datetime.now()


def _now_ts() -> str:
    """Current local time as an ISO-8601 string for TIMESTAMP columns.

    Identical to what sqlite3's default datetime adapter (deprecated since
    Python 3.12) used to store - datetime.isoformat(" ") - so rows written
    by older versions and by this one compare, sort and parse the same.

    Every write passes this explicitly, including INSERTs into columns that
    have DEFAULT CURRENT_TIMESTAMP. That default is UTC, not local time, so
    rows written by older versions through the default (alerts, attacks,
    ai_reports, and first-insert device/baseline/audit rows) may be in UTC.
    The schema and those existing rows are deliberately left unchanged.
    """
    return _local_now().isoformat(" ")


def _write(default=None):
    """Mark a write method whose late call after close(drop_late_writes=True)
    is logged and dropped (returning `default`) instead of raising.

    Reads keep raising: a component acting on empty results during shutdown
    could fire false alerts (e.g. Telegram) instead of simply aborting.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            try:
                return fn(self, *args, **kwargs)
            except sqlite3.ProgrammingError:
                if not (self._closed and self._drop_late_writes):
                    raise
                logger.debug("Database closed for shutdown; dropped late %s()", fn.__name__)
                return default
        return wrapper
    return decorator


class Database:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._local = threading.local()
        # Every per-thread connection, so close() can close them all - not just
        # the calling thread's.
        self._conns = []
        self._conns_lock = threading.Lock()
        self._closed = False
        self._drop_late_writes = False
        self._init_db()

    def _get_conn(self):
        conn = getattr(self._local, 'conn', None)
        if conn is not None:
            return conn
        with self._conns_lock:
            if self._closed:
                raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
            try:
                conn.row_factory = sqlite3.Row
                # busy_timeout is per-connection (unlike journal_mode) - must be set
                # on every new connection, not just the one that first opens the file.
                conn.execute("PRAGMA busy_timeout=30000")
            except BaseException:
                conn.close()
                raise
            self._conns.append(conn)
        self._local.conn = conn
        return conn

    def close(self, drop_late_writes: bool = False):
        """Close every connection this instance opened, in any thread.

        Safe to call more than once. Any later query raises
        sqlite3.ProgrammingError, like a closed sqlite3.Connection - except
        that with drop_late_writes=True (process shutdown only), a write from
        a straggling daemon thread is logged at debug level and dropped.
        """
        with self._conns_lock:
            self._closed = True
            if drop_late_writes:
                self._drop_late_writes = True
            conns, self._conns = self._conns, []
        for conn in conns:
            conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            self._create_schema(conn)
        finally:
            conn.close()

    @staticmethod
    def _create_schema(conn):
        # WAL lets readers and writers proceed concurrently instead of the
        # default rollback-journal mode, where a single writer blocks every
        # other reader/writer - critical now that 8+ threads share this file.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT UNIQUE NOT NULL,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_whitelisted INTEGER DEFAULT 0,
                is_suspicious INTEGER DEFAULT 0,
                signal_strength INTEGER
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_mac TEXT,
                target_mac TEXT,
                bssid TEXT,
                ssid TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                network TEXT,
                devices_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS encryption_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                ssid TEXT,
                encryption_type TEXT,
                wps_enabled INTEGER DEFAULT 0,
                pmf_enabled INTEGER DEFAULT 0,
                security_score INTEGER DEFAULT 0,
                channel INTEGER,
                signal_strength INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS ai_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                content TEXT NOT NULL,
                language TEXT DEFAULT 'en',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS bssid_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT UNIQUE NOT NULL,
                ssid TEXT,
                vendor TEXT,
                channel INTEGER,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                seen_count INTEGER DEFAULT 1,
                avg_signal REAL,
                is_trusted INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);
            CREATE INDEX IF NOT EXISTS idx_bssid_baseline_bssid ON bssid_baseline(bssid);
            CREATE INDEX IF NOT EXISTS idx_bssid_baseline_ssid ON bssid_baseline(ssid);
        """)
        conn.commit()

    def execute(self, query: str, params: tuple = ()):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor

    def fetchall(self, query: str, params: tuple = ()):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def fetchone(self, query: str, params: tuple = ()):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None

    # --- Devices ---
    @_write(False)
    def upsert_device(self, mac: str, ip: str = None, hostname: str = None,
                      vendor: str = None, signal: int = None):
        # INSERT OR IGNORE + rowcount replaces a separate SELECT-then-INSERT/UPDATE:
        # that pattern let two threads (e.g. DeviceMonitor's passive-scan thread and
        # its own active-nmap loop) both see "no existing row" for the same brand-new
        # MAC and both try to INSERT, raising UNIQUE constraint IntegrityError. SQLite
        # serializes the INSERT OR IGNORE itself, so only one thread's insert can win.
        now = _now_ts()
        cursor = self.execute(
            "INSERT OR IGNORE INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, "
            "signal_strength) VALUES (?,?,?,?,?,?,?)",
            (mac, ip, hostname, vendor, now, now, signal)
        )
        is_new = cursor.rowcount == 1
        if not is_new:
            self.execute(
                "UPDATE devices SET ip=?, hostname=?, vendor=?, last_seen=?, signal_strength=? WHERE mac=?",
                (ip, hostname, vendor, now, signal, mac)
            )
        return is_new

    def get_all_devices(self):
        return self.fetchall("SELECT * FROM devices ORDER BY last_seen DESC")

    def get_device_count(self):
        row = self.fetchone("SELECT COUNT(*) as cnt FROM devices")
        return row['cnt'] if row else 0

    @_write()
    def set_whitelist(self, mac: str, whitelisted: bool):
        self.execute("UPDATE devices SET is_whitelisted=? WHERE mac=?", (int(whitelisted), mac))

    def get_whitelist(self):
        rows = self.fetchall("SELECT mac FROM devices WHERE is_whitelisted=1")
        return [r['mac'] for r in rows]

    # --- Alerts ---
    @_write()
    def add_alert(self, alert_type: str, severity: str, message: str, details: str = None):
        self.execute(
            "INSERT INTO alerts (alert_type, severity, message, details, timestamp) VALUES (?,?,?,?,?)",
            (alert_type, severity, message, details, _now_ts())
        )

    def get_alerts(self, limit: int = 50, unresolved_only: bool = False):
        if unresolved_only:
            return self.fetchall(
                "SELECT * FROM alerts WHERE resolved=0 ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        return self.fetchall("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))

    def get_alert_count(self):
        row = self.fetchone("SELECT COUNT(*) as cnt FROM alerts WHERE resolved=0")
        return row['cnt'] if row else 0

    @_write()
    def resolve_alert(self, alert_id: int):
        self.execute("UPDATE alerts SET resolved=1 WHERE id=?", (alert_id,))

    # --- Attacks ---
    @_write()
    def add_attack(self, attack_type: str, severity: str, source_mac: str = None,
                   target_mac: str = None, bssid: str = None, ssid: str = None, details: str = None):
        self.execute(
            "INSERT INTO attacks (attack_type, severity, source_mac, target_mac, bssid, ssid, details, "
            "timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (attack_type, severity, source_mac, target_mac, bssid, ssid, details, _now_ts())
        )

    def get_attacks(self, limit: int = 50):
        return self.fetchall("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,))

    def get_attack_count(self):
        row = self.fetchone("SELECT COUNT(*) as cnt FROM attacks")
        return row['cnt'] if row else 0

    # --- BSSID Baseline (persistent historical trust, used by RogueAPDetector) ---
    def get_bssid_baseline(self, bssid: str):
        return self.fetchone("SELECT * FROM bssid_baseline WHERE bssid=?", (bssid,))

    def get_baseline_for_ssid(self, ssid: str):
        return self.fetchall("SELECT * FROM bssid_baseline WHERE ssid=?", (ssid,))

    @_write()
    def upsert_bssid_baseline(self, bssid: str, ssid: str = None, vendor: str = None,
                              channel: int = None, signal: int = None):
        existing = self.get_bssid_baseline(bssid)
        if existing:
            seen_count = existing['seen_count'] + 1
            if signal is not None and existing['avg_signal'] is not None:
                avg_signal = existing['avg_signal'] + (signal - existing['avg_signal']) / seen_count
            elif signal is not None:
                avg_signal = float(signal)
            else:
                avg_signal = existing['avg_signal']
            self.execute(
                "UPDATE bssid_baseline SET ssid=?, vendor=?, channel=?, last_seen=?, "
                "seen_count=?, avg_signal=? WHERE bssid=?",
                (ssid or existing['ssid'], vendor or existing['vendor'],
                 channel if channel is not None else existing['channel'],
                 _now_ts(), seen_count, avg_signal, bssid)
            )
        else:
            now = _now_ts()
            self.execute(
                "INSERT INTO bssid_baseline (bssid, ssid, vendor, channel, first_seen, last_seen, "
                "seen_count, avg_signal) VALUES (?,?,?,?,?,?,1,?)",
                (bssid, ssid, vendor, channel, now, now,
                 float(signal) if signal is not None else None)
            )
        return self.get_bssid_baseline(bssid)

    # --- Encryption Audits ---
    @_write()
    def upsert_audit(self, bssid: str, ssid: str, encryption_type: str,
                     wps_enabled: bool, pmf_enabled: bool, security_score: int,
                     channel: int = None, signal: int = None):
        existing = self.fetchone("SELECT id FROM encryption_audits WHERE bssid=?", (bssid,))
        if existing:
            self.execute(
                "UPDATE encryption_audits SET ssid=?, encryption_type=?, wps_enabled=?, "
                "pmf_enabled=?, security_score=?, channel=?, signal_strength=?, timestamp=? WHERE bssid=?",
                (ssid, encryption_type, int(wps_enabled), int(pmf_enabled),
                 security_score, channel, signal, _now_ts(), bssid)
            )
        else:
            self.execute(
                "INSERT INTO encryption_audits (bssid, ssid, encryption_type, wps_enabled, "
                "pmf_enabled, security_score, channel, signal_strength, timestamp) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (bssid, ssid, encryption_type, int(wps_enabled), int(pmf_enabled),
                 security_score, channel, signal, _now_ts())
            )

    def get_audits(self, limit: int = 50):
        return self.fetchall("SELECT * FROM encryption_audits ORDER BY timestamp DESC LIMIT ?", (limit,))

    # --- AI Reports ---
    @_write()
    def add_report(self, report_type: str, content: str, language: str = 'en'):
        self.execute(
            "INSERT INTO ai_reports (report_type, content, language, timestamp) VALUES (?,?,?,?)",
            (report_type, content, language, _now_ts())
        )

    def get_reports(self, limit: int = 10):
        return self.fetchall("SELECT * FROM ai_reports ORDER BY timestamp DESC LIMIT ?", (limit,))

    # --- Stats ---
    def get_stats(self):
        return {
            'total_devices': self.get_device_count(),
            'active_alerts': self.get_alert_count(),
            'total_attacks': self.get_attack_count(),
            'audits': len(self.get_audits(limit=1000)),
        }

    def get_alerts_by_hour(self, hours: int = 24):
        # Rows are stored in local time (_now_ts), so the cutoff must be local
        # too - SQLite's datetime('now', ...) is UTC. Computed from the same
        # clock as the writes; equivalent to datetime('now', 'localtime', ...).
        # Rows written before the upgrade through the UTC column default can
        # appear off by the UTC offset; that only affects time windows during
        # the first day after upgrading, and those rows are left unchanged.
        cutoff = (_local_now() - timedelta(hours=hours)).isoformat(" ")
        return self.fetchall(
            "SELECT strftime('%H', timestamp) as hour, COUNT(*) as count "
            "FROM alerts WHERE timestamp >= ? "
            "GROUP BY hour ORDER BY hour",
            (cutoff,)
        )

    def get_attacks_by_type(self):
        return self.fetchall(
            "SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type"
        )
