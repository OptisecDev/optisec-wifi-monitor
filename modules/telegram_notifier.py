"""Telegram alert notifier — immediate for CRITICAL/HIGH, batched for MEDIUM."""

import re
import threading
import time
import requests
from collections import deque
from datetime import datetime

_TELEGRAM_URL = "https://api.telegram.org/bot{token}/sendMessage"
_MAC_RE = re.compile(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')

_SEV_EMOJI = {
    "CRITICAL": "🚨", "HIGH": "⛔", "MEDIUM": "⚠️", "LOW": "ℹ️", "INFO": "✅",
}
_ATK_EMOJI = {
    "DEAUTH_FLOOD": "💥", "EVIL_TWIN": "👥", "ARP_SPOOFING": "🎭",
    "ROGUE_AP": "📡", "PMKID_ATTACK": "🔓", "NEW_DEVICE": "📲",
}
_BATCH_INTERVAL = 300  # 5 minutes


class TelegramNotifier:
    def __init__(self, config):
        self.config = config
        self._medium_queue: deque = deque()
        self._lock = threading.Lock()
        self._running = False

    @property
    def _token(self) -> str:
        return self.config.get("telegram_bot_token", "")

    @property
    def _chat_id(self) -> str:
        return str(self.config.get("telegram_chat_id", ""))

    def is_configured(self) -> bool:
        return bool(self._token and self._chat_id)

    def start(self):
        if not self.is_configured():
            return
        self._running = True
        threading.Thread(target=self._batch_loop, daemon=True).start()

    def stop(self):
        self._running = False

    # ── Public API ────────────────────────────────────────────────────────

    def notify(self, alert: dict):
        """Called by AlertManager for every new alert."""
        if not self.is_configured():
            return
        sev = alert.get('severity', 'INFO')
        if sev in ('CRITICAL', 'HIGH'):
            threading.Thread(
                target=self._send,
                args=(self._format_alert(alert),),
                daemon=True,
            ).start()
        elif sev == 'MEDIUM':
            with self._lock:
                self._medium_queue.append(alert)

    def test_connection(self) -> bool:
        return self._send(
            "🔐 <b>Optisec WiFi Monitor</b>\n"
            "✅ Telegram alerts connected successfully.\n"
            f"🕐 <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
        )

    # ── Internal ──────────────────────────────────────────────────────────

    def _send(self, text: str) -> bool:
        try:
            resp = requests.post(
                _TELEGRAM_URL.format(token=self._token),
                json={"chat_id": self._chat_id, "text": text, "parse_mode": "HTML"},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def _format_alert(self, alert: dict) -> str:
        sev    = alert.get('severity', 'INFO')
        atype  = alert.get('alert_type', 'UNKNOWN')
        msg    = str(alert.get('message', ''))
        details = str(alert.get('details') or '')
        ts     = str(alert.get('timestamp', datetime.now().isoformat()))[:19]

        emoji  = _SEV_EMOJI.get(sev, "•")
        atk_e  = _ATK_EMOJI.get(atype, "")
        m      = _MAC_RE.search(msg)
        mac    = m.group(1) if m else 'N/A'

        lines = [
            f"{emoji}{atk_e} <b>[{sev}] {atype}</b>",
            f"🕐 <code>{ts}</code>",
            f"📟 MAC: <code>{mac}</code>",
            f"📋 {msg}",
        ]
        if details:
            lines.append(f"ℹ️ {details}")
        return "\n".join(lines)

    def _batch_loop(self):
        while self._running:
            time.sleep(_BATCH_INTERVAL)
            with self._lock:
                if not self._medium_queue:
                    continue
                batch = list(self._medium_queue)
                self._medium_queue.clear()

            header = (
                f"⚠️ <b>Optisec — {len(batch)} medium alert(s)</b>\n"
                f"{'─' * 28}\n"
            )
            body = "\n\n".join(self._format_alert(a) for a in batch[:10])
            self._send(header + body)
