"""Alert manager - handles alert creation, deduplication, and notification."""

import threading
import csv
from datetime import datetime, timedelta
from collections import deque
from rich.console import Console

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}

SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH": "⛔",
    "MEDIUM": "⚠",
    "LOW": "ℹ",
    "INFO": "•",
}

CSV_EXPORT_FIELDS = ['timestamp', 'alert_type', 'severity', 'message', 'details']


class AlertManager:
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._recent = deque(maxlen=200)
        self._dedup_window = timedelta(seconds=30)
        self._callbacks = []

    def register_callback(self, fn):
        """Register a callback called on every new alert: fn(alert_dict)."""
        self._callbacks.append(fn)

    def add(self, alert_type: str, severity: str, message: str, details: str = None,
            print_to_console: bool = True):
        with self._lock:
            # Deduplication: skip if exact same alert in last 30s
            now = datetime.now()
            key = (alert_type, message)
            for entry in self._recent:
                if entry['key'] == key and (now - entry['time']) < self._dedup_window:
                    return

            self._recent.append({'key': key, 'time': now})

        self.db.add_alert(alert_type, severity, message, details)

        alert = {
            'alert_type': alert_type,
            'severity': severity,
            'message': message,
            'details': details,
            'timestamp': now.isoformat(),
        }

        if print_to_console:
            icon = SEVERITY_ICONS.get(severity, "•")
            color = SEVERITY_COLORS.get(severity, "white")
            ts = now.strftime("%H:%M:%S")
            console.print(
                f"[dim]{ts}[/dim] [{color}]{icon} [{severity}] {message}[/{color}]"
            )

        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

        return alert

    def critical(self, alert_type: str, message: str, details: str = None):
        return self.add(alert_type, "CRITICAL", message, details)

    def high(self, alert_type: str, message: str, details: str = None):
        return self.add(alert_type, "HIGH", message, details)

    def medium(self, alert_type: str, message: str, details: str = None):
        return self.add(alert_type, "MEDIUM", message, details)

    def low(self, alert_type: str, message: str, details: str = None):
        return self.add(alert_type, "LOW", message, details)

    def info(self, alert_type: str, message: str, details: str = None):
        return self.add(alert_type, "INFO", message, details)

    def export_alerts_to_csv(self, filepath: str) -> int:
        """Export the full alert log from the database to a CSV file.

        Rows are written oldest first (by timestamp, then id). An empty log
        produces a file containing only the header row.

        Args:
            filepath: Path to the CSV file to create/replace.

        Returns:
            Number of alert rows written (excluding the header).
        """
        # SQLite treats a negative LIMIT as "no limit" - export the whole log
        # rather than silently truncating it.
        alerts = self.db.get_alerts(limit=-1)
        # get_alerts() returns newest first for the dashboards; sort here rather
        # than relying on (or changing) that order. id breaks timestamp ties,
        # since CURRENT_TIMESTAMP only has one-second resolution.
        alerts.sort(key=lambda a: (a.get('timestamp') or '', a.get('id') or 0))

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_EXPORT_FIELDS, extrasaction='ignore')
            writer.writeheader()
            for alert in alerts:
                writer.writerow(alert)

        return len(alerts)
