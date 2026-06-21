"""Configuration manager for Optisec WiFi Monitor."""

import json
import os
from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()

DEFAULT_CONFIG_PATHS = [
    "/etc/optisec/config.json",
    os.path.expanduser("~/.optisec/config.json"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"),
]

DEFAULT_CONFIG = {
    "monitor_interface": "wlan1",
    "internet_interface": "wlan0",
    "groq_api_key": "",
    "openrouter_api_key": "",
    "openrouter_model": "meta-llama/llama-3.2-3b-instruct:free",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "language": "en",
    "whitelist": [],
    "alert_thresholds": {
        "deauth_flood_count": 10,
        "deauth_flood_window": 60,
        "arp_rate_limit": 50,
        "new_device_alert": True,
    },
    "web_port": 5000,
    "db_path": os.path.expanduser("~/.optisec/optisec.db"),
    "scan_interval": 30,
    "ai_report_interval": 300,
}


class ConfigManager:
    def __init__(self):
        self.config_path = self._find_or_create_config()
        self.config = self._load()

    def _find_or_create_config(self) -> str:
        for path in DEFAULT_CONFIG_PATHS:
            if os.path.exists(path):
                return path
        # Create in home dir
        path = os.path.expanduser("~/.optisec/config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return path

    def _load(self) -> dict:
        try:
            with open(self.config_path) as f:
                cfg = json.load(f)
            # Merge with defaults for missing keys
            merged = DEFAULT_CONFIG.copy()
            merged.update(cfg)
            return merged
        except (json.JSONDecodeError, IOError):
            return DEFAULT_CONFIG.copy()

    def save(self):
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def set(self, key: str, value):
        self.config[key] = value
        self.save()

    @property
    def monitor_interface(self) -> str:
        return self.config.get("monitor_interface", "wlan1")

    @property
    def internet_interface(self) -> str:
        return self.config.get("internet_interface", "wlan0")

    @property
    def groq_api_key(self) -> str:
        return self.config.get("groq_api_key", "")

    @property
    def openrouter_api_key(self) -> str:
        return self.config.get("openrouter_api_key", "")

    @property
    def openrouter_model(self) -> str:
        return self.config.get("openrouter_model", "meta-llama/llama-3.2-3b-instruct:free")

    @property
    def telegram_bot_token(self) -> str:
        return self.config.get("telegram_bot_token", "")

    @property
    def telegram_chat_id(self) -> str:
        return str(self.config.get("telegram_chat_id", ""))

    @property
    def language(self) -> str:
        return self.config.get("language", "en")

    @property
    def whitelist(self) -> list:
        return self.config.get("whitelist", [])

    @property
    def alert_thresholds(self) -> dict:
        return self.config.get("alert_thresholds", DEFAULT_CONFIG["alert_thresholds"])

    @property
    def db_path(self) -> str:
        return self.config.get("db_path", DEFAULT_CONFIG["db_path"])

    def add_to_whitelist(self, mac: str):
        wl = self.whitelist
        mac = mac.upper()
        if mac not in wl:
            wl.append(mac)
            self.config["whitelist"] = wl
            self.save()

    def remove_from_whitelist(self, mac: str):
        wl = self.whitelist
        mac = mac.upper()
        if mac in wl:
            wl.remove(mac)
            self.config["whitelist"] = wl
            self.save()

    def interactive_setup(self):
        console.print("\n[bold cyan]Optisec WiFi Monitor - Configuration[/bold cyan]\n")

        self.config["monitor_interface"] = Prompt.ask(
            "Monitor interface (Alpha adapter)", default=self.monitor_interface
        )
        self.config["internet_interface"] = Prompt.ask(
            "Internet interface", default=self.internet_interface
        )

        console.print("\n[bold cyan]── AI Configuration ─────────────────────[/bold cyan]")
        self.config["groq_api_key"] = Prompt.ask(
            "Groq API key (llama-3.3-70b)", default=self.groq_api_key, password=True
        )
        self.config["openrouter_api_key"] = Prompt.ask(
            "OpenRouter API key (fallback, optional)", default=self.openrouter_api_key, password=True
        )

        console.print("\n[bold cyan]── Telegram Alerts ──────────────────────[/bold cyan]")
        if Confirm.ask("Configure Telegram alerts?", default=bool(self.telegram_bot_token)):
            self.config["telegram_bot_token"] = Prompt.ask(
                "Telegram bot token", default=self.telegram_bot_token, password=True
            )
            self.config["telegram_chat_id"] = Prompt.ask(
                "Telegram chat ID", default=self.telegram_chat_id
            )
            # Test the connection
            from modules.telegram_notifier import TelegramNotifier
            notifier = TelegramNotifier(self)
            if Confirm.ask("Send a test message now?", default=True):
                ok = notifier.test_connection()
                if ok:
                    console.print("[green]✓ Test message sent successfully[/green]")
                else:
                    console.print("[red]✗ Failed — check token and chat ID[/red]")

        console.print("\n[bold cyan]── General ───────────────────────────────[/bold cyan]")
        lang = Prompt.ask("Language", choices=["en", "ar"], default=self.language)
        self.config["language"] = lang

        port = Prompt.ask("Web dashboard port", default=str(self.config.get("web_port", 5000)))
        self.config["web_port"] = int(port)

        self.save()
        console.print(f"\n[green]✓ Configuration saved to {self.config_path}[/green]")
