"""Alert manager - handles alert creation, deduplication, and notification."""

import threading
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
