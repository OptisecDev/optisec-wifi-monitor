#!/usr/bin/env python3
"""Optisec WiFi Monitor - Professional WiFi Defense Monitoring Tool for BlackArch Linux."""

import sys
import os
import csv
import logging
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
from core.license_manager import LicenseManager, LicenseActivationError
from modules.device_monitor import DeviceMonitor
from modules.attack_detector import AttackDetector
from modules.deauth_detector import DeauthDetector
from modules.rogue_ap_detector import RogueAPDetector
from modules.wps_detector import WPSDetector
from modules.packet_injection_detector import PacketInjectionDetector
from modules.encryption_auditor import EncryptionAuditor
from modules.ai_engine import AIEngine
from modules.telegram_notifier import TelegramNotifier
from modules.pdf_reporter import PDFReporter

console = Console()
logger = logging.getLogger(__name__)

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
    try:
        lic.load_or_create(
            key_prompt_fn=lambda: console.input(
                "\n[bold cyan]First run — enter your OPTISEC license key: [/bold cyan]"
            )
        )
    except LicenseActivationError as exc:
        console.print(Panel.fit(
            "[bold red]LICENSE ACTIVATION FAILED[/bold red]\n\n"
            f"[white]{exc}[/white]\n\n"
            "[white]Activation requires a real license key issued after purchase\n"
            "and a working internet connection the first time this runs.\n"
            "Check your key and connection, then try again.[/white]",
            border_style="red",
        ))
        sys.exit(1)
    if lic.is_valid:
        console.print(f"[green]✓  {lic.display}[/green]")
    threading.Thread(
        target=lic.refresh_license_status, name='LicenseRefresh', daemon=True
    ).start()
    return lic


def require_valid_license(lic: LicenseManager):
    """Block startup unless the license is activated against the real
    license server, unrevoked, bound to this machine, and still within its
    offline grace period. Without this, license status never affected
    anything the app did - is_valid was only read to decide whether to
    print a header string."""
    if lic.is_valid:
        return
    console.print(Panel.fit(
        "[bold red]LICENSE INVALID[/bold red]\n\n"
        "[white]No valid, currently-verified license was found for this machine.\n"
        f"Expected file: [cyan]{os.path.expanduser('~/.optisec/license.key')}[/cyan]\n\n"
        "This can happen if the license file is missing, was edited, was\n"
        "revoked, expired, was copied from a different machine (licenses\n"
        "are bound to one machine each), or hasn't been able to reach the\n"
        "license server in a while.[/white]",
        border_style="red",
    ))
    sys.exit(1)


def init_components(monitor_iface: str, internet_iface: str, lang: str,
                    license_mgr: LicenseManager = None) -> dict:
    db = Database()
    try:
        return _build_components(db, monitor_iface, internet_iface, lang, license_mgr)
    except BaseException:
        db.close()
        raise


def _build_components(db: Database, monitor_iface: str, internet_iface: str, lang: str,
                      license_mgr: LicenseManager = None) -> dict:
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
    deauth_detector = DeauthDetector(db, config, alert_mgr, monitor_iface)
    rogue_ap_detector = RogueAPDetector(db, config, alert_mgr, monitor_iface, attack_detector=attack_detector)
    wps_detector    = WPSDetector(db, config, alert_mgr, monitor_iface)
    packet_injection_detector = PacketInjectionDetector(db, config, alert_mgr, monitor_iface)
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
        'deauth_detector': deauth_detector,
        'rogue_ap_detector': rogue_ap_detector,
        'wps_detector':     wps_detector,
        'packet_injection_detector': packet_injection_detector,
        'enc_auditor':     enc_auditor,
        'ai_engine':       ai_engine,
        'pdf_reporter':    pdf_reporter,
        'telegram':        telegram,
        'license_mgr':     license_mgr,
    }


def start_monitoring_threads(components: dict) -> list:
    # Recorded in components as each starts, so stop_all_components can join
    # them even if a later one fails to start.
    threads = components.setdefault('threads', [])
    for name, fn in [
        ('DeviceMonitor', components['device_monitor'].start),
        ('AttackDetector', components['attack_detector'].start),
        ('DeauthDetector', components['deauth_detector'].start),
        ('RogueAPDetector', components['rogue_ap_detector'].start),
        ('WPSDetector', components['wps_detector'].start),
        ('PacketInjectionDetector', components['packet_injection_detector'].start),
        ('EncryptionAuditor', components['enc_auditor'].start),
        ('AIEngine', components['ai_engine'].start),
    ]:
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        threads.append(t)
        console.print(f"[green]✓  {name} started[/green]")
    return threads


_STOPPABLE_COMPONENTS = (
    'device_monitor', 'attack_detector', 'deauth_detector', 'rogue_ap_detector',
    'wps_detector', 'packet_injection_detector', 'enc_auditor', 'ai_engine', 'telegram',
)


def stop_all_components(components: dict, join_timeout: float = 2.0):
    """Stop every component, join its threads, then close the database.

    Threads are daemon=True so the process itself never hangs without this.
    Safe to call more than once (each .stop() just sets a flag).

    Joining shares one join_timeout deadline: a thread can be blocked in
    sniff() (until the next packet) or a long sleep, and must not hang
    shutdown. Writes from any such straggler after the close below are
    dropped with a debug log instead of raising.
    """
    for name in _STOPPABLE_COMPONENTS:
        comp = components.get(name)
        if comp is None:
            continue
        try:
            comp.stop()
        except Exception:
            pass

    threads = list(components.get('threads', ()))
    for name in _STOPPABLE_COMPONENTS:
        threads.extend(getattr(components.get(name), 'threads', ()))
    deadline = time.monotonic() + join_timeout
    for t in threads:
        if t is not threading.current_thread():
            t.join(max(0.0, deadline - time.monotonic()))
    alive = [t.name for t in threads if t.is_alive()]
    if alive:
        logger.debug("Threads still running at database close: %s", ", ".join(alive))

    db = components.get('db')
    if db is not None:
        db.close(drop_late_writes=True)


def _install_shutdown_handler(components: dict):
    """Ensure SIGTERM (e.g. from systemd or `kill`) also stops components.

    Python has no default handler for SIGTERM (unlike SIGINT, which it turns
    into KeyboardInterrupt), so without this a `kill`/service-stop would skip
    the try/finally cleanup in each CLI command entirely.
    """
    def _handler(signum, frame):
        console.print("\n[yellow]⚠  Received termination signal - shutting down...[/yellow]")
        stop_all_components(components)
        sys.exit(0)
    signal.signal(signal.SIGTERM, _handler)


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[cyan]Usage:[/cyan]  python main.py [tui|web|both|config|export]\n")
        console.print("  [bold]tui[/bold]    Rich terminal dashboard")
        console.print("  [bold]web[/bold]    Flask web dashboard (port 5000)")
        console.print("  [bold]both[/bold]   TUI + web simultaneously")
        console.print("  [bold]config[/bold] Interactive configuration")
        console.print("  [bold]export[/bold] Export alert log to CSV (export PATH)\n")


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
    require_valid_license(lic)
    if not require_authorization():
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(0)

    components = init_components(monitor_iface, internet_iface, lang, lic)
    try:
        start_monitoring_threads(components)
        _install_shutdown_handler(components)

        from tui.dashboard import TUIDashboard
        dash = TUIDashboard(components)
        console.print("\n[green]✓  Starting TUI dashboard... (Ctrl+C to exit)[/green]\n")
        time.sleep(0.5)
        dash.run()
    finally:
        stop_all_components(components)


@cli.command()
@click.option('--monitor-iface', '-m', default='wlan1', show_default=True)
@click.option('--internet-iface', '-i', default='wlan0', show_default=True)
@click.option('--port', '-p', default=5000, show_default=True, help='Web dashboard port')
@click.option('--lang', '-l', default='en', type=click.Choice(['en', 'ar']), show_default=True)
def web(monitor_iface, internet_iface, port, lang):
    """Launch the Flask web dashboard."""
    print_banner()
    lic = init_license()
    require_valid_license(lic)
    if not require_authorization():
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(0)

    components = init_components(monitor_iface, internet_iface, lang, lic)
    try:
        start_monitoring_threads(components)
        _install_shutdown_handler(components)

        from web.app import create_app
        app = create_app(components)
        console.print(f"\n[green]✓  Web dashboard: [bold]http://0.0.0.0:{port}[/bold][/green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    finally:
        stop_all_components(components)


@cli.command()
@click.option('--monitor-iface', '-m', default='wlan1', show_default=True)
@click.option('--internet-iface', '-i', default='wlan0', show_default=True)
@click.option('--port', '-p', default=5000, show_default=True)
@click.option('--lang', '-l', default='en', type=click.Choice(['en', 'ar']), show_default=True)
def both(monitor_iface, internet_iface, port, lang):
    """Launch TUI + web dashboard simultaneously."""
    print_banner()
    lic = init_license()
    require_valid_license(lic)
    if not require_authorization():
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(0)

    components = init_components(monitor_iface, internet_iface, lang, lic)
    try:
        start_monitoring_threads(components)
        _install_shutdown_handler(components)

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
    finally:
        stop_all_components(components)


@cli.command('config')
def configure():
    """Interactive configuration wizard."""
    print_banner()
    cfg = ConfigManager()
    cfg.interactive_setup()


@cli.command()
@click.argument('csv_path', type=click.Path(dir_okay=False))
def export(csv_path):
    """Export the alert log to a CSV file at CSV_PATH."""
    print_banner()
    lic = init_license()
    require_valid_license(lic)
    # No require_authorization() here: export only reads alerts already recorded
    # in the local database and never monitors a network, and the interactive
    # prompt would block scripted/scheduled exports. The license check above
    # still applies because export is a feature of the licensed product.

    with Database() as db:
        try:
            count = AlertManager(db).export_alerts_to_csv(csv_path)
        except (OSError, csv.Error) as exc:
            console.print(f"[red]✗  Failed to write CSV to {csv_path}: {exc}[/red]")
            sys.exit(1)

    console.print(f"[green]✓  Exported {count} alert(s) to [bold]{csv_path}[/bold][/green]")


if __name__ == '__main__':
    cli()
