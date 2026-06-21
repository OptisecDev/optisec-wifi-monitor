"""Rich TUI dashboard for Optisec WiFi Monitor."""

import re
import threading
import time
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.prompt import Prompt
from rich import box
from rich.align import Align
from rich.style import Style


SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "green",
}

_MAC_RE = re.compile(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')

SEVERITY_ICON = {
    "CRITICAL": "🚨",
    "HIGH": "⛔",
    "MEDIUM": "⚠",
    "LOW": "ℹ",
    "INFO": "•",
}

SCORE_COLOR = {
    range(0, 30): "bold red",
    range(30, 60): "yellow",
    range(60, 80): "cyan",
    range(80, 101): "bold green",
}


def score_color(score: int) -> str:
    for r, color in SCORE_COLOR.items():
        if score in r:
            return color
    return "white"


class TUIDashboard:
    def __init__(self, components: dict):
        self.db = components['db']
        self.config = components['config']
        self.alert_mgr = components['alert_mgr']
        self.device_monitor = components.get('device_monitor')
        self.attack_detector = components.get('attack_detector')
        self.enc_auditor = components.get('enc_auditor')
        self.ai_engine = components.get('ai_engine')
        self.console = Console()
        self._running = True
        self._last_ai_report = None
        self._ai_lock = threading.Lock()

        # Register alert callback for live feed
        self._alert_feed = []
        self.alert_mgr.register_callback(self._on_alert)

    def _on_alert(self, alert: dict):
        self._alert_feed.insert(0, alert)
        if len(self._alert_feed) > 50:
            self._alert_feed.pop()

    def _make_header(self) -> Panel:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        monitor_iface = self.config.monitor_interface
        internet_iface = self.config.internet_interface

        header_text = Text()
        header_text.append("  OPTISEC WiFi MONITOR  ", style="bold cyan on dark_blue")
        header_text.append(f"  v1.0  ", style="bold white")
        header_text.append(f"  {now}  ", style="dim")
        header_text.append(f"  Monitor: {monitor_iface}  ", style="green")
        header_text.append(f"  Internet: {internet_iface}  ", style="blue")

        return Panel(Align.center(header_text), style="bold blue", height=3)

    def _make_stats_panel(self) -> Panel:
        stats = self.db.get_stats()

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Label", style="dim")
        table.add_column("Value", style="bold")

        table.add_row("Devices Detected", f"[cyan]{stats['total_devices']}[/cyan]")
        table.add_row("Active Alerts", f"[red]{stats['active_alerts']}[/red]")
        table.add_row("Attacks Logged", f"[yellow]{stats['total_attacks']}[/yellow]")
        table.add_row("Networks Audited", f"[green]{stats['audits']}[/green]")

        return Panel(table, title="[bold]Stats[/bold]", border_style="blue")

    def _make_devices_panel(self, max_rows: int = 12) -> Panel:
        devices = self.db.get_all_devices()[:max_rows]
        whitelist = set(m.upper() for m in self.config.whitelist)

        # Build set of MACs that have recent alerts
        alerted_macs: set = set()
        feed = self._alert_feed or self.db.get_alerts(limit=50)
        for a in feed:
            m = _MAC_RE.search(str(a.get('message', '')))
            if m:
                alerted_macs.add(m.group(1).upper())

        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=box.SIMPLE,
            expand=True,
        )
        table.add_column("MAC Address", style="cyan", min_width=18)
        table.add_column("IP", style="green", min_width=15)
        table.add_column("Vendor", style="white", min_width=15)
        table.add_column("Status", min_width=12)
        table.add_column("Last Seen", style="dim", min_width=8)

        for d in devices:
            mac = d.get('mac', '')
            ip = d.get('ip', 'N/A') or 'N/A'
            vendor = (d.get('vendor', 'Unknown') or 'Unknown')[:15]
            wl = mac.upper() in whitelist
            has_alert = mac.upper() in alerted_macs

            if has_alert:
                status = "[red]⚠ Alert[/red]"
            elif wl:
                status = "[green]✓ OK[/green]"
            else:
                status = "[yellow]? Unknown[/yellow]"

            last = d.get('last_seen', '')
            if last:
                try:
                    last = last[11:16]  # HH:MM
                except Exception:
                    pass

            table.add_row(mac, ip, vendor, status, last)

        return Panel(
            table,
            title=f"[bold]Devices ({len(devices)})[/bold]",
            border_style="cyan",
        )

    def _make_alerts_panel(self, max_rows: int = 10) -> Panel:
        alerts = self._alert_feed[:max_rows] or self.db.get_alerts(limit=max_rows)

        table = Table(
            show_header=True,
            header_style="bold red",
            box=box.SIMPLE,
            expand=True,
        )
        table.add_column("Time", style="dim", min_width=6)
        table.add_column("Type", style="cyan", min_width=14)
        table.add_column("MAC", style="white", min_width=18)
        table.add_column("Details")

        for a in alerts:
            sev = a.get('severity', 'INFO')
            style = SEVERITY_STYLE.get(sev, "white")
            ts = str(a.get('timestamp', ''))
            ts = ts[11:16] if len(ts) > 11 else ts[:5]
            atype = str(a.get('alert_type', ''))[:14]

            msg = str(a.get('message', ''))
            m = _MAC_RE.search(msg)
            mac_str = m.group(1) if m else "N/A"

            details = str(a.get('details') or msg)[:55]

            table.add_row(
                ts,
                f"[{style}]{atype}[/{style}]",
                f"[{style}]{mac_str}[/{style}]",
                f"[{style}]{details}[/{style}]",
            )

        return Panel(
            table,
            title="[bold red]Live Alerts[/bold red]",
            border_style="red",
        )

    def _make_attacks_panel(self, max_rows: int = 6) -> Panel:
        attacks = self.db.get_attacks(limit=max_rows)

        table = Table(
            show_header=True,
            header_style="bold yellow",
            box=box.SIMPLE,
            expand=True,
        )
        table.add_column("Time", style="dim", min_width=6)
        table.add_column("Type", style="yellow", min_width=14)
        table.add_column("Source MAC", style="red", min_width=18)
        table.add_column("Details")

        for atk in attacks:
            ts = str(atk.get('timestamp', ''))
            ts = ts[11:16] if len(ts) > 11 else ts[:5]
            atype = str(atk.get('attack_type', ''))
            src = str(atk.get('source_mac', 'N/A') or 'N/A')
            details = str(atk.get('details', ''))[:50]
            table.add_row(ts, atype, src, details)

        return Panel(
            table,
            title="[bold yellow]Attack Log[/bold yellow]",
            border_style="yellow",
        )

    def _make_encryption_panel(self, max_rows: int = 8) -> Panel:
        audits = self.db.get_audits(limit=max_rows)

        table = Table(
            show_header=True,
            header_style="bold green",
            box=box.SIMPLE,
            expand=True,
        )
        table.add_column("SSID", min_width=16)
        table.add_column("BSSID", style="dim", min_width=18)
        table.add_column("Encryption", min_width=10)
        table.add_column("WPS", min_width=5)
        table.add_column("Score", min_width=8)

        for a in audits:
            raw = str(a.get('ssid', '') or '')
            ssid = ('(binary)' if any(ord(c) < 32 or ord(c) > 126 for c in raw) else raw)[:16] or '(hidden)'
            bssid = str(a.get('bssid', ''))
            enc = str(a.get('encryption_type', 'UNKNOWN'))
            wps = "[red]YES[/red]" if a.get('wps_enabled') else "[green]No[/green]"
            score = int(a.get('security_score', 0))
            sc = score_color(score)
            enc_style = "green" if "WPA3" in enc else ("cyan" if "WPA2" in enc else "red")

            table.add_row(
                ssid,
                bssid,
                f"[{enc_style}]{enc}[/{enc_style}]",
                wps,
                f"[{sc}]{score}[/{sc}]",
            )

        return Panel(
            table,
            title="[bold green]Encryption Audit[/bold green]",
            border_style="green",
        )

    def _make_ai_panel(self) -> Panel:
        reports = self.db.get_reports(limit=1)
        if reports:
            content = reports[0].get('content', '')[:300] + "..."
            ts = reports[0].get('timestamp', '')
        else:
            content = "No AI reports yet. Reports generate every 5 minutes when API key is configured."
            ts = ""

        text = Text(content)
        footer = Text(f"\nLast report: {ts}", style="dim")

        return Panel(
            Text.assemble(text, footer),
            title="[bold magenta]AI Security Analysis[/bold magenta]",
            border_style="magenta",
        )

    def _make_footer(self) -> Panel:
        help_text = (
            "[dim]q[/dim] Quit  "
            "[dim]r[/dim] Generate AI Report  "
            "[dim]w[/dim] Whitelist Device  "
            "[dim]a[/dim] AI Ask  "
        )
        return Panel(help_text, height=3, border_style="dim")

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )
        layout["left"].split_column(
            Layout(name="stats", size=8),
            Layout(name="devices"),
        )
        layout["right"].split_column(
            Layout(name="alerts"),
            Layout(name="attacks", size=10),
            Layout(name="encryption", size=12),
            Layout(name="ai", size=10),
        )
        return layout

    def _refresh_layout(self, layout: Layout):
        layout["header"].update(self._make_header())
        layout["stats"].update(self._make_stats_panel())
        layout["devices"].update(self._make_devices_panel())
        layout["alerts"].update(self._make_alerts_panel())
        layout["attacks"].update(self._make_attacks_panel())
        layout["encryption"].update(self._make_encryption_panel())
        layout["ai"].update(self._make_ai_panel())
        layout["footer"].update(self._make_footer())

    def run(self):
        layout = self._build_layout()

        with Live(layout, refresh_per_second=1, screen=True) as live:
            while self._running:
                try:
                    self._refresh_layout(layout)
                    time.sleep(1)
                except KeyboardInterrupt:
                    self._running = False
                    break
                except Exception:
                    time.sleep(2)
