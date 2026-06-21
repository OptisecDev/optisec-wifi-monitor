"""SQLite database manager for Optisec WiFi Monitor."""

import sqlite3
import os
import threading
from datetime import datetime


DEFAULT_DB_PATH = os.path.expanduser("~/.optisec/optisec.db")


class Database:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
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

            CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);
        """)
        conn.commit()
        conn.close()

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
    def upsert_device(self, mac: str, ip: str = None, hostname: str = None,
                      vendor: str = None, signal: int = None):
        existing = self.fetchone("SELECT id, is_whitelisted FROM devices WHERE mac = ?", (mac,))
        if existing:
            self.execute(
                "UPDATE devices SET ip=?, hostname=?, vendor=?, last_seen=?, signal_strength=? WHERE mac=?",
                (ip, hostname, vendor, datetime.now(), signal, mac)
            )
            return False  # not new
        else:
            self.execute(
                "INSERT INTO devices (mac, ip, hostname, vendor, signal_strength) VALUES (?,?,?,?,?)",
                (mac, ip, hostname, vendor, signal)
            )
            return True  # new device

    def get_all_devices(self):
        return self.fetchall("SELECT * FROM devices ORDER BY last_seen DESC")

    def get_device_count(self):
        row = self.fetchone("SELECT COUNT(*) as cnt FROM devices")
        return row['cnt'] if row else 0

    def set_whitelist(self, mac: str, whitelisted: bool):
        self.execute("UPDATE devices SET is_whitelisted=? WHERE mac=?", (int(whitelisted), mac))

    def get_whitelist(self):
        rows = self.fetchall("SELECT mac FROM devices WHERE is_whitelisted=1")
        return [r['mac'] for r in rows]

    # --- Alerts ---
    def add_alert(self, alert_type: str, severity: str, message: str, details: str = None):
        self.execute(
            "INSERT INTO alerts (alert_type, severity, message, details) VALUES (?,?,?,?)",
            (alert_type, severity, message, details)
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

    def resolve_alert(self, alert_id: int):
        self.execute("UPDATE alerts SET resolved=1 WHERE id=?", (alert_id,))

    # --- Attacks ---
    def add_attack(self, attack_type: str, severity: str, source_mac: str = None,
                   target_mac: str = None, bssid: str = None, ssid: str = None, details: str = None):
        self.execute(
            "INSERT INTO attacks (attack_type, severity, source_mac, target_mac, bssid, ssid, details) "
            "VALUES (?,?,?,?,?,?,?)",
            (attack_type, severity, source_mac, target_mac, bssid, ssid, details)
        )

    def get_attacks(self, limit: int = 50):
        return self.fetchall("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,))

    def get_attack_count(self):
        row = self.fetchone("SELECT COUNT(*) as cnt FROM attacks")
        return row['cnt'] if row else 0

    # --- Encryption Audits ---
    def upsert_audit(self, bssid: str, ssid: str, encryption_type: str,
                     wps_enabled: bool, pmf_enabled: bool, security_score: int,
                     channel: int = None, signal: int = None):
        existing = self.fetchone("SELECT id FROM encryption_audits WHERE bssid=?", (bssid,))
        if existing:
            self.execute(
                "UPDATE encryption_audits SET ssid=?, encryption_type=?, wps_enabled=?, "
                "pmf_enabled=?, security_score=?, channel=?, signal_strength=?, timestamp=? WHERE bssid=?",
                (ssid, encryption_type, int(wps_enabled), int(pmf_enabled),
                 security_score, channel, signal, datetime.now(), bssid)
            )
        else:
            self.execute(
                "INSERT INTO encryption_audits (bssid, ssid, encryption_type, wps_enabled, "
                "pmf_enabled, security_score, channel, signal_strength) VALUES (?,?,?,?,?,?,?,?)",
                (bssid, ssid, encryption_type, int(wps_enabled), int(pmf_enabled),
                 security_score, channel, signal)
            )

    def get_audits(self, limit: int = 50):
        return self.fetchall("SELECT * FROM encryption_audits ORDER BY timestamp DESC LIMIT ?", (limit,))

    # --- AI Reports ---
    def add_report(self, report_type: str, content: str, language: str = 'en'):
        self.execute(
            "INSERT INTO ai_reports (report_type, content, language) VALUES (?,?,?)",
            (report_type, content, language)
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
        return self.fetchall(
            "SELECT strftime('%H', timestamp) as hour, COUNT(*) as count "
            "FROM alerts WHERE timestamp >= datetime('now', ?) "
            "GROUP BY hour ORDER BY hour",
            (f'-{hours} hours',)
        )

    def get_attacks_by_type(self):
        return self.fetchall(
            "SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type"
        )
