"""Rich TUI dashboard for Optisec WiFi Monitor."""

import re
import select
import sys
import termios
import threading
import time
import tty
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.align import Align


SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "green",
}

SEVERITY_ICON = {
    "CRITICAL": "🚨",
    "HIGH": "⛔",
    "MEDIUM": "⚠",
    "LOW": "ℹ",
    "INFO": "•",
}

SCORE_RANGES = [
    (range(0, 30),  "bold red"),
    (range(30, 60), "yellow"),
    (range(60, 80), "cyan"),
    (range(80, 101),"bold green"),
]

_MAC_RE    = re.compile(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')
_BINARY_PAT = re.compile(r'\\x[0-9a-fA-F]{2}')


def _sanitize_ssid(raw, max_len: int = 16) -> str:
    """Return printable SSID or '(hidden)' for empty/binary/iwlist-escaped SSIDs."""
    s = str(raw or '')
    if not s:
        return '(hidden)'
    if any(ord(c) < 32 or ord(c) > 126 for c in s):
        return '(hidden)'
    if _BINARY_PAT.search(s):
        return '(hidden)'
    return s[:max_len] or '(hidden)'


def score_color(score: int) -> str:
    for r, color in SCORE_RANGES:
        if score in r:
            return color
    return "white"


class TUIDashboard:
    def __init__(self, components: dict):
        self.db             = components['db']
        self.config         = components['config']
        self.alert_mgr      = components['alert_mgr']
        self.device_monitor = components.get('device_monitor')
        self.attack_detector= components.get('attack_detector')
        self.enc_auditor    = components.get('enc_auditor')
        self.ai_engine      = components.get('ai_engine')
        self.pdf_reporter   = components.get('pdf_reporter')
        self.console        = Console()

        self._running          = True
        self._alert_feed: list = []
        self._selected_net_idx = 0
        self._status_msg       = ""
        self._ai_lock          = threading.Lock()

        self.alert_mgr.register_callback(self._on_alert)

    # ── Alert feed ────────────────────────────────────────────────────────

    def _on_alert(self, alert: dict):
        self._alert_feed.insert(0, alert)
        if len(self._alert_feed) > 50:
            self._alert_feed.pop()

    # ── Key listener ──────────────────────────────────────────────────────

    def _start_key_listener(self):
        if not sys.stdin.isatty():
            return
        threading.Thread(target=self._key_loop, daemon=True).start()

    def _key_loop(self):
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while self._running:
                if select.select([sys.stdin], [], [], 0.2)[0]:
                    ch = sys.stdin.read(1)
                    if ch in ('q', '\x03', '\x1b'):
                        self._running = False
                    elif ch == 'r':
                        self._do_pdf()
                    elif ch in ('n', '\x1b[B'):   # n or down arrow
                        self._next_network()
                    elif ch in ('p', '\x1b[A'):   # p or up arrow
                        self._prev_network()
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception:
                pass

    def _do_pdf(self):
        if not self.pdf_reporter:
            self._status_msg = "PDF reporter not initialized"
            return

        def _gen():
            self._status_msg = "Generating PDF report..."
            path = self.pdf_reporter.generate()
            self._status_msg = (
                f"Report saved: {path}" if path
                else "PDF failed — install reportlab: pip install reportlab"
            )
        threading.Thread(target=_gen, daemon=True).start()

    def _next_network(self):
        audits = self.db.get_audits(limit=50)
        if audits:
            self._selected_net_idx = (self._selected_net_idx + 1) % len(audits)

    def _prev_network(self):
        audits = self.db.get_audits(limit=50)
        if audits:
            self._selected_net_idx = (self._selected_net_idx - 1) % len(audits)

    # ── Panels ────────────────────────────────────────────────────────────

    def _make_header(self) -> Panel:
        now            = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        monitor_iface  = self.config.monitor_interface
        internet_iface = self.config.internet_interface

        t = Text()
        t.append("  OPTISEC WiFi MONITOR  ", style="bold cyan on dark_blue")
        t.append("  v1.0  ",                 style="bold white")
        t.append(f"  {now}  ",               style="dim")
        t.append(f"  Mon:{monitor_iface}  ", style="green")
        t.append(f"  Net:{internet_iface}  ",style="blue")
        return Panel(Align.center(t), style="bold blue", height=3)

    def _make_stats_panel(self) -> Panel:
        stats = self.db.get_stats()
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Label", style="dim")
        table.add_column("Value", style="bold")
        table.add_row("Devices",  f"[cyan]{stats['total_devices']}[/cyan]")
        table.add_row("Alerts",   f"[red]{stats['active_alerts']}[/red]")
        table.add_row("Attacks",  f"[yellow]{stats['total_attacks']}[/yellow]")
        table.add_row("Networks", f"[green]{stats['audits']}[/green]")
        return Panel(table, title="[bold]Stats[/bold]", border_style="blue")

    def _make_devices_panel(self, max_rows: int = 10) -> Panel:
        devices   = self.db.get_all_devices()[:max_rows]
        whitelist = set(m.upper() for m in self.config.whitelist)

        alerted_macs: set = set()
        feed = self._alert_feed or self.db.get_alerts(limit=50)
        for a in feed:
            m = _MAC_RE.search(str(a.get('message', '')))
            if m:
                alerted_macs.add(m.group(1).upper())

        table = Table(show_header=True, header_style="bold cyan",
                      box=box.SIMPLE, expand=True)
        table.add_column("MAC",      style="cyan",  min_width=18)
        table.add_column("IP",       style="green", min_width=14)
        table.add_column("Vendor",   style="white", min_width=14)
        table.add_column("Status",                  min_width=12)
        table.add_column("Seen",     style="dim",   min_width=6)

        for d in devices:
            mac    = d.get('mac', '')
            ip     = d.get('ip', 'N/A') or 'N/A'
            vendor = (d.get('vendor', 'Unknown') or 'Unknown')[:14]
            wl     = mac.upper() in whitelist
            ha     = mac.upper() in alerted_macs

            if ha:
                status = "[red]⚠ Alert[/red]"
            elif wl:
                status = "[green]✓ OK[/green]"
            else:
                status = "[yellow]? Unknown[/yellow]"

            last = str(d.get('last_seen', ''))
            last = last[11:16] if len(last) > 11 else last[:5]
            table.add_row(mac, ip, vendor, status, last)

        return Panel(table, title=f"[bold]Devices ({len(devices)})[/bold]",
                     border_style="cyan")

    def _make_alerts_panel(self, max_rows: int = 10) -> Panel:
        alerts = self._alert_feed[:max_rows] or self.db.get_alerts(limit=max_rows)
        table  = Table(show_header=True, header_style="bold red",
                       box=box.SIMPLE, expand=True)
        table.add_column("Time",    style="dim",   min_width=6)
        table.add_column("Type",    style="cyan",  min_width=14)
        table.add_column("MAC",     style="white", min_width=18)
        table.add_column("Details")

        for a in alerts:
            sev   = a.get('severity', 'INFO')
            style = SEVERITY_STYLE.get(sev, "white")
            ts    = str(a.get('timestamp', ''))
            ts    = ts[11:16] if len(ts) > 11 else ts[:5]
            atype = str(a.get('alert_type', ''))[:14]
            msg   = str(a.get('message', ''))
            m     = _MAC_RE.search(msg)
            mac   = m.group(1) if m else "N/A"
            det   = str(a.get('details') or msg)[:50]

            table.add_row(
                ts,
                f"[{style}]{atype}[/{style}]",
                f"[{style}]{mac}[/{style}]",
                f"[{style}]{det}[/{style}]",
            )

        return Panel(table, title="[bold red]Live Alerts[/bold red]",
                     border_style="red")

    def _make_attacks_panel(self, max_rows: int = 6) -> Panel:
        attacks = self.db.get_attacks(limit=max_rows)
        table   = Table(show_header=True, header_style="bold yellow",
                        box=box.SIMPLE, expand=True)
        table.add_column("Time",   style="dim",    min_width=6)
        table.add_column("Type",   style="yellow", min_width=14)
        table.add_column("Source", style="red",    min_width=18)
        table.add_column("Details")

        for atk in attacks:
            ts   = str(atk.get('timestamp', ''))
            ts   = ts[11:16] if len(ts) > 11 else ts[:5]
            table.add_row(
                ts,
                str(atk.get('attack_type', '')),
                str(atk.get('source_mac', 'N/A') or 'N/A'),
                str(atk.get('details', ''))[:50],
            )

        return Panel(table, title="[bold yellow]Attack Log[/bold yellow]",
                     border_style="yellow")

    def _make_networks_panel(self, max_rows: int = 8) -> Panel:
        audits  = self.db.get_audits(limit=50)
        n       = len(audits)
        sel_idx = self._selected_net_idx % n if n else 0

        table = Table(show_header=True, header_style="bold blue",
                      box=box.SIMPLE, expand=True)
        table.add_column("",     min_width=2)   # selector
        table.add_column("SSID", min_width=14)
        table.add_column("Enc",  min_width=9)
        table.add_column("Sc",   min_width=4)
        table.add_column("WPS",  min_width=4)

        for i, a in enumerate(audits[:max_rows]):
            ssid  = _sanitize_ssid(a.get('ssid', ''), max_len=14)
            enc   = str(a.get('encryption_type', 'UNKNOWN'))
            score = int(a.get('security_score', 0))
            wps   = "[red]Y[/red]" if a.get('wps_enabled') else "[green]N[/green]"

            if score >= 70:
                row_c = "green"
            elif score >= 40:
                row_c = "yellow"
            else:
                row_c = "red"

            enc_c    = "green" if "WPA3" in enc else ("cyan" if "WPA2" in enc else "red")
            selector = "[bold cyan]▶[/bold cyan]" if i == sel_idx else " "

            table.add_row(
                selector,
                f"[{row_c}]{ssid}[/{row_c}]",
                f"[{enc_c}]{enc[:9]}[/{enc_c}]",
                f"[{row_c}]{score}[/{row_c}]",
                wps,
            )

        # Show selected network details in title
        title = "[bold blue]Networks[/bold blue]"
        if audits:
            ssid_sel = _sanitize_ssid(audits[sel_idx].get('ssid', ''), max_len=12)
            title = f"[bold blue]Networks[/bold blue] [dim]▶ {ssid_sel}[/dim]  [dim]n/p=select[/dim]"

        return Panel(table, title=title, border_style="blue")

    def _make_encryption_panel(self, max_rows: int = 6) -> Panel:
        audits = self.db.get_audits(limit=max_rows)
        table  = Table(show_header=True, header_style="bold green",
                       box=box.SIMPLE, expand=True)
        table.add_column("SSID",       min_width=14)
        table.add_column("BSSID",      style="dim", min_width=18)
        table.add_column("Encryption", min_width=10)
        table.add_column("WPS",        min_width=5)
        table.add_column("Score",      min_width=6)

        for a in audits:
            ssid  = _sanitize_ssid(a.get('ssid', ''), max_len=14)
            enc   = str(a.get('encryption_type', 'UNKNOWN'))
            wps   = "[red]YES[/red]" if a.get('wps_enabled') else "[green]No[/green]"
            score = int(a.get('security_score', 0))
            sc    = score_color(score)
            enc_c = "green" if "WPA3" in enc else ("cyan" if "WPA2" in enc else "red")

            table.add_row(ssid, str(a.get('bssid', '')),
                          f"[{enc_c}]{enc}[/{enc_c}]", wps,
                          f"[{sc}]{score}[/{sc}]")

        return Panel(table, title="[bold green]Encryption Audit[/bold green]",
                     border_style="green")

    def _make_ai_panel(self) -> Panel:
        """AI insights: rule-based risk scores + last Groq report summary."""
        lines: list[Text] = []

        # Rule-based device risk scores
        if self.ai_engine:
            insights = self.ai_engine.get_insights()
            avg = insights.get('avg_risk', 50)
            avg_c = score_color(int(avg))
            lines.append(Text.assemble(
                ("Network risk avg: ", "dim"),
                (f"{avg}/100", avg_c + " bold"),
            ))
            top_risk = insights.get('top_risk', [])
            if top_risk:
                lines.append(Text("Top risk devices:", style="dim"))
                for d, risk in top_risk:
                    rc  = score_color(risk)
                    mac = d.get('mac', 'N/A')
                    ven = (d.get('vendor', 'Unknown') or 'Unknown')[:12]
                    lines.append(Text.assemble(
                        (f"  {mac} ", "cyan"),
                        (f"({ven}) ", "white"),
                        (f"risk={risk}", rc + " bold"),
                    ))
            lines.append(Text(""))

        # Last Groq report
        reports = self.db.get_reports(limit=1)
        if reports:
            content = reports[0].get('content', '')[:280] + "…"
            ts      = str(reports[0].get('timestamp', ''))[:16]
            lines.append(Text(content, style="white"))
            lines.append(Text(f"\nLast report: {ts}", style="dim"))
        else:
            lines.append(Text(
                "No AI reports yet.\nReports generate every 5 min when Groq API key is set.",
                style="dim"
            ))

        content_block = Text("\n").join(lines)
        return Panel(content_block,
                     title="[bold magenta]AI Threat Analysis[/bold magenta]",
                     border_style="magenta")

    def _make_footer(self) -> Panel:
        status = f"  [yellow]{self._status_msg}[/yellow]" if self._status_msg else ""
        help_text = (
            "[dim]q[/dim] Quit  "
            "[dim]r[/dim] PDF Report  "
            "[dim]n/p[/dim] Network Select  "
            "[dim]w[/dim] Whitelist  "
            + status
        )
        return Panel(help_text, height=3, border_style="dim")

    # ── Layout ────────────────────────────────────────────────────────────

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
            Layout(name="stats",    size=8),
            Layout(name="devices"),
            Layout(name="networks", size=12),
        )
        layout["right"].split_column(
            Layout(name="alerts"),
            Layout(name="attacks",    size=9),
            Layout(name="encryption", size=10),
            Layout(name="ai",         size=10),
        )
        return layout

    def _refresh_layout(self, layout: Layout):
        layout["header"].update(self._make_header())
        layout["stats"].update(self._make_stats_panel())
        layout["devices"].update(self._make_devices_panel())
        layout["alerts"].update(self._make_alerts_panel())
        layout["attacks"].update(self._make_attacks_panel())
        layout["networks"].update(self._make_networks_panel())
        layout["encryption"].update(self._make_encryption_panel())
        layout["ai"].update(self._make_ai_panel())
        layout["footer"].update(self._make_footer())

    # ── Run ───────────────────────────────────────────────────────────────

    def run(self):
        layout = self._build_layout()
        self._start_key_listener()

        with Live(layout, refresh_per_second=1, screen=True):
            while self._running:
                try:
                    self._refresh_layout(layout)
                    time.sleep(1)
                except KeyboardInterrupt:
                    self._running = False
                    break
                except Exception:
                    time.sleep(2)
