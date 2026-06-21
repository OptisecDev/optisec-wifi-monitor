"""Wireless interface manager - monitor mode, channel hopping, status."""

import subprocess
import os
import re
from rich.console import Console

console = Console()


class InterfaceManager:
    def __init__(self, monitor_iface: str = "wlan1", internet_iface: str = "wlan0"):
        self.monitor_iface = monitor_iface
        self.internet_iface = internet_iface

    def _run(self, cmd: list) -> tuple[int, str, str]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode, result.stdout, result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return 1, "", str(e)

    def check_interfaces(self) -> bool:
        """Return True if monitor interface exists."""
        rc, out, _ = self._run(["ip", "link", "show", self.monitor_iface])
        return rc == 0

    def get_interface_mode(self, iface: str) -> str:
        """Return 'monitor', 'managed', or 'unknown'."""
        rc, out, _ = self._run(["iw", "dev", iface, "info"])
        if rc != 0:
            return "unknown"
        m = re.search(r'type (\w+)', out)
        return m.group(1) if m else "unknown"

    def enable_monitor_mode(self) -> bool:
        """Put monitor interface into monitor mode using airmon-ng."""
        console.print(f"[cyan]Enabling monitor mode on {self.monitor_iface}...[/cyan]")

        # Try airmon-ng first
        rc, out, _ = self._run(["airmon-ng", "start", self.monitor_iface])
        if rc == 0:
            # airmon-ng may rename to wlan1mon
            if "wlan1mon" in out:
                self.monitor_iface = "wlan1mon"
            console.print(f"[green]✓ Monitor mode enabled on {self.monitor_iface}[/green]")
            return True

        # Fallback: iw
        self._run(["ip", "link", "set", self.monitor_iface, "down"])
        self._run(["iw", "dev", self.monitor_iface, "set", "type", "monitor"])
        rc, _, _ = self._run(["ip", "link", "set", self.monitor_iface, "up"])
        if rc == 0:
            console.print(f"[green]✓ Monitor mode enabled (iw) on {self.monitor_iface}[/green]")
            return True

        console.print(f"[red]✗ Failed to enable monitor mode on {self.monitor_iface}[/red]")
        return False

    def disable_monitor_mode(self) -> bool:
        """Restore managed mode."""
        self._run(["airmon-ng", "stop", self.monitor_iface])
        self._run(["ip", "link", "set", self.monitor_iface, "down"])
        self._run(["iw", "dev", self.monitor_iface, "set", "type", "managed"])
        self._run(["ip", "link", "set", self.monitor_iface, "up"])
        return True

    def set_channel(self, channel: int) -> bool:
        rc, _, _ = self._run(["iw", "dev", self.monitor_iface, "set", "channel", str(channel)])
        return rc == 0

    def get_gateway_ip(self) -> str:
        rc, out, _ = self._run(["ip", "route", "show", "default"])
        m = re.search(r'default via (\S+)', out)
        return m.group(1) if m else ""

    def get_local_network(self) -> str:
        """Return local subnet like 192.168.1.0/24."""
        rc, out, _ = self._run(["ip", "-4", "addr", "show", self.internet_iface])
        m = re.search(r'inet (\d+\.\d+\.\d+)\.\d+/(\d+)', out)
        if m:
            return f"{m.group(1)}.0/{m.group(2)}"
        return "192.168.1.0/24"

    def list_interfaces(self) -> list:
        rc, out, _ = self._run(["iw", "dev"])
        ifaces = re.findall(r'Interface (\S+)', out)
        return ifaces

    def status(self) -> dict:
        return {
            "monitor_interface": self.monitor_iface,
            "internet_interface": self.internet_iface,
            "monitor_mode": self.get_interface_mode(self.monitor_iface),
            "internet_mode": self.get_interface_mode(self.internet_iface),
            "local_network": self.get_local_network(),
            "gateway": self.get_gateway_ip(),
            "available_interfaces": self.list_interfaces(),
        }
