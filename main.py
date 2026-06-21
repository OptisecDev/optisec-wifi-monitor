#!/usr/bin/env python3
"""Optisec WiFi Monitor - Professional WiFi Defense Monitoring Tool for BlackArch Linux."""

import sys
import os
import threading
import signal
import time

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import Database
from core.config_manager import ConfigManager
from core.interface_manager import InterfaceManager
from core.alert_manager import AlertManager
from core.license_manager import LicenseManager
from modules.device_monitor import DeviceMonitor
from modules.attack_detector import AttackDetector
from modules.encryption_auditor import EncryptionAuditor
from modules.ai_engine import AIEngine
from modules.telegram_notifier import TelegramNotifier
from modules.pdf_reporter import PDFReporter

console = Console()

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        ██████╗ ██████╗ ████████╗██╗███████╗███████╗ ██████╗  ║
║       ██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔════╝██╔════╝  ║
║       ██║   ██║██████╔╝   ██║   ██║███████╗█████╗  ██║       ║
║       ██║   ██║██╔═══╝    ██║   ██║╚════██║██╔══╝  ██║       ║
║       ╚██████╔╝██║        ██║   ██║███████║███████╗╚██████╗  ║
║        ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚══════╝╚══════╝ ╚═════╝  ║
║                                                              ║
║              WiFi DEFENSE MONITOR  v1.0.0                   ║
║         Professional Network Security Tool                   ║
║                                                              ║
║    ⚠  AUTHORIZED DEFENSE USE ONLY  ⚠                        ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_banner():
    console.print(BANNER, style="bold cyan")


def require_authorization() -> bool:
    console.print(Panel.fit(
        "[bold yellow]AUTHORIZATION REQUIRED[/bold yellow]\n\n"
        "[white]Optisec WiFi Monitor is a defense-only tool.\n"
        "Unauthorized network monitoring may violate local laws\n"
        "and is strictly prohibited.[/white]",
        border_style="yellow",
    ))
    answer = console.input(
        "\n[bold cyan]Do you have authorization to monitor this network? (yes/no): [/bold cyan]"
    ).strip().lower()
    return answer in ('yes', 'y')


def init_license() -> LicenseManager:
    lic = LicenseManager()
    lic.load_or_create(
        name_prompt_fn=lambda: console.input(
            "\n[bold cyan]First run — enter your name for license: [/bold cyan]"
        ).strip() or "User"
    )
    if lic.is_valid:
        console.print(f"[green]✓  {lic.display}[/green]")
    return lic


def init_components(monitor_iface: str, internet_iface: str, lang: str,
                    license_mgr: LicenseManager = None) -> dict:
    db = Database()
    config = ConfigManager()
    config.config["monitor_interface"] = monitor_iface
    config.config["internet_interface"] = internet_iface
    if lang:
        config.config["language"] = lang

    alert_mgr = AlertManager(db)
    iface_mgr = InterfaceManager(monitor_iface, internet_iface)

    if not iface_mgr.check_interfaces():
        console.print(
            f"[yellow]⚠  Interface [bold]{monitor_iface}[/bold] not found — "
            f"passive sniffing may be limited.[/yellow]"
        )
    else:
        mode = iface_mgr.get_interface_mode(monitor_iface)
        if mode != 'monitor':
            console.print(
                f"[yellow]⚠  {monitor_iface} is in [bold]{mode}[/bold] mode, not monitor. "
                f"Run: [cyan]airmon-ng start {monitor_iface}[/cyan][/yellow]"
            )
        else:
            console.print(f"[green]✓  {monitor_iface} is in monitor mode[/green]")

    device_monitor  = DeviceMonitor(db, config, alert_mgr, monitor_iface, internet_iface)
    attack_detector = AttackDetector(db, config, alert_mgr, monitor_iface)
    enc_auditor     = EncryptionAuditor(db, alert_mgr, monitor_iface)
    ai_engine       = AIEngine(db, config, config.language)
    pdf_reporter    = PDFReporter(db, config)

    telegram = TelegramNotifier(config)
    alert_mgr.register_callback(telegram.notify)
    telegram.start()
    if telegram.is_configured():
        console.print("[green]✓  Telegram alerts enabled[/green]")

    return {
        'db': db,
        'config': config,
        'alert_mgr': alert_mgr,
        'iface_mgr': iface_mgr,
        'device_monitor':  device_monitor,
        'attack_detector': attack_detector,
        'enc_auditor':     enc_auditor,
        'ai_engine':       ai_engine,
        'pdf_reporter':    pdf_reporter,
        'telegram':        telegram,
        'license_mgr':     license_mgr,
    }


def start_monitoring_threads(components: dict) -> list:
    threads = []
    for name, fn in [
        ('DeviceMonitor', components['device_monitor'].start),
        ('AttackDetector', components['attack_detector'].start),
        ('EncryptionAuditor', components['enc_auditor'].start),
        ('AIEngine', components['ai_engine'].start),
    ]:
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        threads.append(t)
        console.print(f"[green]✓  {name} started[/green]")
    return threads


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[cyan]Usage:[/cyan]  python main.py [tui|web|both|config]\n")
        console.print("  [bold]tui[/bold]    Rich terminal dashboard")
        console.print("  [bold]web[/bold]    Flask web dashboard (port 5000)")
        console.print("  [bold]both[/bold]   TUI + web simultaneously")
        console.print("  [bold]config[/bold] Interactive configuration\n")


@cli.command()
@click.option('--monitor-iface', '-m', default='wlan1', show_default=True,
              help='Monitor mode interface (Alpha adapter)')
@click.option('--internet-iface', '-i', default='wlan0', show_default=True,
              help='Internet interface')
@click.option('--lang', '-l', default='en', type=click.Choice(['en', 'ar']),
              show_default=True, help='Report language')
def tui(monitor_iface, internet_iface, lang):
    """Launch the Rich TUI dashboard."""
    print_banner()
    lic = init_license()
    if not require_authorization():
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(0)

    components = init_components(monitor_iface, internet_iface, lang, lic)
    start_monitoring_threads(components)

    from tui.dashboard import TUIDashboard
    dash = TUIDashboard(components)
    console.print("\n[green]✓  Starting TUI dashboard... (Ctrl+C to exit)[/green]\n")
    time.sleep(0.5)
    dash.run()


@cli.command()
@click.option('--monitor-iface', '-m', default='wlan1', show_default=True)
@click.option('--internet-iface', '-i', default='wlan0', show_default=True)
@click.option('--port', '-p', default=5000, show_default=True, help='Web dashboard port')
@click.option('--lang', '-l', default='en', type=click.Choice(['en', 'ar']), show_default=True)
def web(monitor_iface, internet_iface, port, lang):
    """Launch the Flask web dashboard."""
    print_banner()
    lic = init_license()
    if not require_authorization():
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(0)

    components = init_components(monitor_iface, internet_iface, lang, lic)
    start_monitoring_threads(components)

    from web.app import create_app
    app = create_app(components)
    console.print(f"\n[green]✓  Web dashboard: [bold]http://0.0.0.0:{port}[/bold][/green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)


@cli.command()
@click.option('--monitor-iface', '-m', default='wlan1', show_default=True)
@click.option('--internet-iface', '-i', default='wlan0', show_default=True)
@click.option('--port', '-p', default=5000, show_default=True)
@click.option('--lang', '-l', default='en', type=click.Choice(['en', 'ar']), show_default=True)
def both(monitor_iface, internet_iface, port, lang):
    """Launch TUI + web dashboard simultaneously."""
    print_banner()
    lic = init_license()
    if not require_authorization():
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(0)

    components = init_components(monitor_iface, internet_iface, lang, lic)
    start_monitoring_threads(components)

    # Start web in background thread
    from web.app import create_app
    app = create_app(components)

    def run_web():
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

    web_thread = threading.Thread(target=run_web, name='WebServer', daemon=True)
    web_thread.start()
    console.print(f"[green]✓  Web dashboard: [bold]http://0.0.0.0:{port}[/bold][/green]")

    # TUI in foreground
    from tui.dashboard import TUIDashboard
    dash = TUIDashboard(components)
    time.sleep(0.5)
    dash.run()


@cli.command('config')
def configure():
    """Interactive configuration wizard."""
    print_banner()
    cfg = ConfigManager()
    cfg.interactive_setup()


if __name__ == '__main__':
    cli()
