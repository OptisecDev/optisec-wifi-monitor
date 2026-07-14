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
    # Fixed panel heights from _build_layout(), duplicated here (rather than
    # read back from the Layout at render time) so each panel builder can
    # compute how many data rows actually fit in its own box and report an
    # honest "shown/total" in its title instead of a count that overclaims.
    _ATTACKS_LAYOUT_SIZE    = 8
    _DETECTORS_LAYOUT_SIZE  = 8
    _ENCRYPTION_LAYOUT_SIZE = 9
    _NETWORKS_LAYOUT_SIZE   = 12
    _PANEL_ROW_OVERHEAD     = 5  # top border + top pad + header + rule + bottom border

    @classmethod
    def _rows_that_fit(cls, layout_size: int) -> int:
        return max(1, layout_size - cls._PANEL_ROW_OVERHEAD)

    @staticmethod
    def _count_label(shown: int, total: int) -> str:
        return f"{shown}/{total}" if shown < total else str(total)

    def __init__(self, components: dict):
        self.db             = components['db']
        self.config         = components['config']
        self.alert_mgr      = components['alert_mgr']
        self.device_monitor = components.get('device_monitor')
        self.attack_detector= components.get('attack_detector')
        self.deauth_detector= components.get('deauth_detector')
        self.rogue_ap_detector = components.get('rogue_ap_detector')
        self.wps_detector   = components.get('wps_detector')
        self.packet_injection_detector = components.get('packet_injection_detector')
        self.enc_auditor    = components.get('enc_auditor')
        self.ai_engine      = components.get('ai_engine')
        self.pdf_reporter   = components.get('pdf_reporter')
        self.console        = Console()

        self._running          = True
        self._alert_feed: list = []
        self._selected_net_idx = 0
        self._status_msg       = ""
        self._ai_lock          = threading.Lock()
        self._license_mgr      = components.get('license_mgr')

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
        if self._license_mgr and self._license_mgr.is_valid:
            t.append(f"  LICENSED TO: {self._license_mgr.name}  ", style="bold yellow")
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
        return Panel(table, title="[bold blue]Stats[/bold blue]", border_style="blue")

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

        return Panel(table, title=f"[bold cyan]Devices ({len(devices)})[/bold cyan]",
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
            icon  = SEVERITY_ICON.get(sev, "")
            ts    = str(a.get('timestamp', ''))
            ts    = ts[11:16] if len(ts) > 11 else ts[:5]
            atype = str(a.get('alert_type', ''))[:14]
            msg   = str(a.get('message', ''))
            m     = _MAC_RE.search(msg)
            mac   = m.group(1) if m else "N/A"
            det   = str(a.get('details') or msg)[:50]

            table.add_row(
                ts,
                f"[{style}]{icon} {atype}[/{style}]",
                f"[{style}]{mac}[/{style}]",
                f"[{style}]{det}[/{style}]",
            )

        return Panel(table, title=f"[bold red]Live Alerts ({len(alerts)})[/bold red]",
                     border_style="red")

    def _make_attacks_panel(self) -> Panel:
        row_budget = self._rows_that_fit(self._ATTACKS_LAYOUT_SIZE)
        attacks    = self.db.get_attacks(limit=50)
        total      = len(attacks)
        shown      = attacks[:row_budget]

        table   = Table(show_header=True, header_style="bold yellow",
                        box=box.SIMPLE, expand=True)
        table.add_column("Time",   style="dim", min_width=6)
        table.add_column("Type",   min_width=14)
        table.add_column("Source", min_width=18)
        table.add_column("Details")

        for atk in shown:
            sev     = atk.get('severity', 'INFO')
            style   = SEVERITY_STYLE.get(sev, "white")
            icon    = SEVERITY_ICON.get(sev, "")
            ts      = str(atk.get('timestamp', ''))
            ts      = ts[11:16] if len(ts) > 11 else ts[:5]
            source  = str(atk.get('source_mac', 'N/A') or 'N/A')
            details = str(atk.get('details', ''))[:50]

            table.add_row(
                ts,
                f"[{style}]{icon} {atk.get('attack_type', '')}[/{style}]",
                f"[{style}]{source}[/{style}]",
                f"[{style}]{details}[/{style}]",
            )

        label = self._count_label(len(shown), total)
        return Panel(table, title=f"[bold yellow]Attack Log ({label})[/bold yellow]",
                     border_style="yellow")

    @staticmethod
    def _detector_status_text(stats: dict) -> str:
        if not stats.get('enabled', True):
            return "[dim]○ Disabled[/dim]"
        if not stats.get('scapy_available', True):
            return "[yellow]● Limited[/yellow]"
        return "[green]● Active[/green]"

    @staticmethod
    def _finding_count_color(n: int) -> str:
        if n <= 0:
            return "green"
        elif n < 5:
            return "yellow"
        return "red"

    def _make_detectors_panel(self) -> Panel:
        """Live status/summary for the four passive attack detector modules
        (Deauth, Rogue AP, WPS, Packet Injection) - beyond their alerts already
        surfacing in the Live Alerts panel, this shows enabled/running state
        and a per-detector session summary in one place."""
        rows = []

        if self.deauth_detector:
            stats  = self.deauth_detector.get_stats()
            bursts = stats.get('bursts_detected', 0)
            c      = self._finding_count_color(bursts)
            rows.append((
                "Deauth",
                self._detector_status_text(stats),
                f"[{c}]{bursts} burst(s)[/{c}] "
                f"[dim]({stats.get('active_deauth_sources', 0)} active src)[/dim]",
            ))

        if self.rogue_ap_detector:
            stats   = self.rogue_ap_detector.get_stats()
            flagged = stats.get('rogue_aps_flagged', 0)
            c       = self._finding_count_color(flagged)
            rows.append((
                "Rogue AP",
                self._detector_status_text(stats),
                f"[{c}]{flagged} flagged[/{c}] "
                f"[dim]({stats.get('tracked_bssids', 0)} tracked)[/dim]",
            ))

        if self.wps_detector:
            stats = self.wps_detector.get_stats()
            vuln  = stats.get('wps_vulnerable_aps', 0)
            c     = self._finding_count_color(vuln)
            rows.append((
                "WPS",
                self._detector_status_text(stats),
                f"[{c}]{vuln} vulnerable[/{c}] "
                f"[dim]({stats.get('wps_enabled_aps', 0)} WPS APs)[/dim]",
            ))

        if self.packet_injection_detector:
            stats  = self.packet_injection_detector.get_stats()
            total  = stats.get('total_anomalies', 0)
            c      = self._finding_count_color(total)
            counts = stats.get('anomaly_counts', {}) or {}
            top    = sorted(counts.items(), key=lambda kv: -kv[1])[:2]
            breakdown = ' '.join(f"{k}:{v}" for k, v in top)
            findings = f"[{c}]{total} anomalies[/{c}]"
            if breakdown:
                findings += f" [dim]({breakdown})[/dim]"
            rows.append(("Pkt Inject", self._detector_status_text(stats), findings))

        row_budget = self._rows_that_fit(self._DETECTORS_LAYOUT_SIZE)
        shown      = rows[:row_budget]

        table = Table(show_header=True, header_style="bold white",
                      box=box.SIMPLE, expand=True)
        table.add_column("Detector", style="white", min_width=10)
        table.add_column("Status",   min_width=10)
        table.add_column("Findings")

        for row in shown:
            table.add_row(*row)

        if not rows:
            table.add_row("[dim]—[/dim]", "[dim]No detectors configured[/dim]", "")

        label = self._count_label(len(shown), len(rows)) if rows else ""
        title = f"[bold white]Detector Status ({label})[/bold white]" if label \
            else "[bold white]Detector Status[/bold white]"
        return Panel(table, title=title, border_style="white")

    def _make_networks_panel(self) -> Panel:
        audits  = self.db.get_audits(limit=50)
        n       = len(audits)
        sel_idx = self._selected_net_idx % n if n else 0

        row_budget = self._rows_that_fit(self._NETWORKS_LAYOUT_SIZE)
        shown      = audits[:row_budget]

        table = Table(show_header=True, header_style="bold blue",
                      box=box.SIMPLE, expand=True)
        table.add_column("",      min_width=2)   # selector
        table.add_column("SSID",  min_width=14)
        table.add_column("Enc",   min_width=9)
        table.add_column("Score", min_width=5)
        table.add_column("WPS",   min_width=4)

        for i, a in enumerate(shown):
            ssid  = _sanitize_ssid(a.get('ssid', ''), max_len=14)
            enc   = str(a.get('encryption_type', 'UNKNOWN'))
            score = int(a.get('security_score', 0))
            wps   = "[red]Y[/red]" if a.get('wps_enabled') else "[green]N[/green]"

            row_c    = score_color(score)
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
        label = self._count_label(len(shown), n) if n else "0"
        title = f"[bold blue]Networks ({label})[/bold blue]"
        if audits:
            ssid_sel = _sanitize_ssid(audits[sel_idx].get('ssid', ''), max_len=12)
            title = (f"[bold blue]Networks ({label})[/bold blue] "
                     f"[dim]▶ {ssid_sel}[/dim]  [dim]n/p=select[/dim]")

        return Panel(table, title=title, border_style="blue")

    def _make_encryption_panel(self) -> Panel:
        audits = self.db.get_audits(limit=50)
        has_issue = any(
            a.get('wps_enabled') or "WPA3" not in str(a.get('encryption_type', ''))
            for a in audits
        )
        panel_color = "red" if has_issue else "green"

        row_budget = self._rows_that_fit(self._ENCRYPTION_LAYOUT_SIZE)
        total      = len(audits)
        shown      = audits[:row_budget]

        table = Table(show_header=True, header_style=f"bold {panel_color}",
                      box=box.SIMPLE, expand=True)
        table.add_column("SSID",       min_width=14)
        table.add_column("BSSID",      style="dim", min_width=18)
        table.add_column("Encryption", min_width=10)
        table.add_column("WPS",        min_width=5)
        table.add_column("Score",      min_width=6)

        for a in shown:
            ssid  = _sanitize_ssid(a.get('ssid', ''), max_len=14)
            enc   = str(a.get('encryption_type', 'UNKNOWN'))
            wps   = "[red]Yes[/red]" if a.get('wps_enabled') else "[green]No[/green]"
            score = int(a.get('security_score', 0))
            sc    = score_color(score)
            enc_c = "green" if "WPA3" in enc else ("cyan" if "WPA2" in enc else "red")

            table.add_row(ssid, str(a.get('bssid', '')),
                          f"[{enc_c}]{enc}[/{enc_c}]", wps,
                          f"[{sc}]{score}[/{sc}]")

        label = self._count_label(len(shown), total)
        title = f"[bold {panel_color}]Encryption Audit ({label})[/bold {panel_color}]"
        return Panel(table, title=title, border_style=panel_color)

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
            Layout(name="networks", size=self._NETWORKS_LAYOUT_SIZE),
        )
        layout["right"].split_column(
            Layout(name="alerts", minimum_size=10),
            Layout(name="attacks",    size=self._ATTACKS_LAYOUT_SIZE),
            Layout(name="detectors",  size=self._DETECTORS_LAYOUT_SIZE),
            Layout(name="encryption", size=self._ENCRYPTION_LAYOUT_SIZE),
            Layout(name="ai",         size=8),
        )
        return layout

    def _refresh_layout(self, layout: Layout):
        layout["header"].update(self._make_header())
        layout["stats"].update(self._make_stats_panel())
        layout["devices"].update(self._make_devices_panel())
        layout["alerts"].update(self._make_alerts_panel())
        layout["attacks"].update(self._make_attacks_panel())
        layout["detectors"].update(self._make_detectors_panel())
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
