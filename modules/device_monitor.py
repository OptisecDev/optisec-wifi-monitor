"""Module 1 - Device Monitor: passive scapy scan + active nmap, MAC whitelist, alerts."""

import threading
import time
import subprocess
import re
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, ARP, Ether, IP, Dot11, Dot11Beacon, Dot11ProbeResp,
        Dot11Elt, RadioTap, get_if_hwaddr, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import manuf
    MANUF_AVAILABLE = True
except ImportError:
    MANUF_AVAILABLE = False

from core.oui_lookup import get_vendor_with_fallback


class DeviceMonitor:
    def __init__(self, db, config, alert_mgr, monitor_iface: str, internet_iface: str):
        self.db = db
        self.config = config
        self.alert_mgr = alert_mgr
        self.monitor_iface = monitor_iface
        self.internet_iface = internet_iface
        self._running = False
        self._known_macs: set = set()
        self._lock = threading.Lock()

        if MANUF_AVAILABLE:
            try:
                self._manuf = manuf.MacParser()
            except Exception:
                self._manuf = None
        else:
            self._manuf = None

        # Load existing known MACs
        for dev in self.db.get_all_devices():
            self._known_macs.add(dev['mac'].upper())

    def start(self):
        self._running = True
        # Start passive scapy sniffer in background
        if SCAPY_AVAILABLE:
            t_passive = threading.Thread(target=self._passive_scan, daemon=True)
            t_passive.start()

        # Active nmap scan on interval
        while self._running:
            self._active_nmap_scan()
            interval = self.config.get("scan_interval", 30)
            time.sleep(interval)

    def stop(self):
        self._running = False

    def _get_vendor(self, mac: str) -> str:
        return get_vendor_with_fallback(mac, self._manuf)

    def _is_whitelisted(self, mac: str) -> bool:
        mac = mac.upper()
        whitelist = [m.upper() for m in self.config.whitelist]
        return mac in whitelist

    def _handle_new_device(self, mac: str, ip: str = None, hostname: str = None,
                           signal: int = None):
        mac = mac.upper()
        with self._lock:
            is_new = mac not in self._known_macs
            self._known_macs.add(mac)

        vendor = self._get_vendor(mac)
        self.db.upsert_device(mac, ip, hostname, vendor, signal)

        if is_new:
            whitelisted = self._is_whitelisted(mac)
            if self.config.alert_thresholds.get("new_device_alert", True):
                severity = "INFO" if whitelisted else "MEDIUM"
                status = "whitelisted" if whitelisted else "UNKNOWN - NOT whitelisted"
                self.alert_mgr.add(
                    "NEW_DEVICE",
                    severity,
                    f"New device detected: {mac} ({vendor})",
                    f"IP: {ip or 'N/A'} | Hostname: {hostname or 'N/A'} | Status: {status}",
                )

    def _passive_scan(self):
        """Passive ARP/Dot11 sniff to detect devices without sending packets."""
        def packet_handler(pkt):
            try:
                if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # ARP who-has
                    mac = pkt[ARP].hwsrc
                    ip = pkt[ARP].psrc
                    if mac and mac != "00:00:00:00:00:00":
                        self._handle_new_device(mac, ip)

                elif pkt.haslayer(Dot11) and pkt.haslayer(Dot11Beacon):
                    # Access point seen
                    bssid = pkt[Dot11].addr3
                    if bssid:
                        self._handle_new_device(bssid)

                elif pkt.haslayer(Dot11) and pkt.type == 2:  # Data frame
                    src = pkt[Dot11].addr2
                    if src and src != "ff:ff:ff:ff:ff:ff":
                        self._handle_new_device(src)

            except Exception:
                pass

        try:
            sniff(
                iface=self.monitor_iface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"Passive scan error: {e}")

    def _active_nmap_scan(self):
        """Active nmap host discovery on local network."""
        try:
            network = self._get_local_network()
            if not network:
                return

            if NMAP_AVAILABLE:
                nm = nmap.PortScanner()
                nm.scan(hosts=network, arguments='-sn --host-timeout 10s')
                for host in nm.all_hosts():
                    mac = ""
                    hostname = nm[host].hostname() or None
                    if 'mac' in nm[host].get('addresses', {}):
                        mac = nm[host]['addresses']['mac']
                    ip = nm[host]['addresses'].get('ipv4', host)
                    vendor = nm[host].get('vendor', {}).get(mac) or self._get_vendor(mac)
                    if mac:
                        self.db.upsert_device(mac.upper(), ip, hostname, vendor)
                        with self._lock:
                            if mac.upper() not in self._known_macs:
                                self._known_macs.add(mac.upper())
                                self._handle_new_device(mac, ip, hostname)
            else:
                # Fallback: arp-scan or arp table
                self._arp_table_scan()

        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"nmap scan error: {e}")

    def _arp_table_scan(self):
        """Read ARP table as fallback when nmap is unavailable."""
        try:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[2]
                    if re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                        self._handle_new_device(mac, ip)
        except Exception:
            pass

    def _get_local_network(self) -> str:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", self.internet_iface],
                capture_output=True, text=True
            )
            m = re.search(r'inet (\d+\.\d+\.\d+)\.\d+/(\d+)', result.stdout)
            if m:
                return f"{m.group(1)}.0/{m.group(2)}"
        except Exception:
            pass
        return ""

    def get_device_list(self) -> list:
        devices = self.db.get_all_devices()
        whitelist = set(m.upper() for m in self.config.whitelist)
        for d in devices:
            d['whitelisted'] = d['mac'].upper() in whitelist
        return devices


class PassiveMonitor:
    """Fingerprint every seen device passively, detect BSSID conflicts (Evil Twin),
    and fire immediate alerts — no packets are transmitted."""

    def __init__(self, db, alert_mgr, iface: str):
        self.db        = db
        self.alert_mgr = alert_mgr
        self.iface     = iface
        self._running  = False
        self._lock     = threading.Lock()
        # mac -> fingerprint dict
        self._fingerprints: dict = {}
        # ssid -> set of bssids (for conflict detection)
        self._ssid_bssids: dict = defaultdict(set)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        if SCAPY_AVAILABLE:
            t = threading.Thread(target=self._sniff, daemon=True)
            t.start()

    def stop(self):
        self._running = False

    # ── Sniffing ──────────────────────────────────────────────────────────

    def _sniff(self):
        try:
            sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"PassiveMonitor sniff error: {e}")

    def _handle_packet(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon):
                self._handle_beacon(pkt)
            elif pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
                self._handle_data_frame(pkt)
        except Exception:
            pass

    def _handle_beacon(self, pkt):
        bssid = (pkt[Dot11].addr3 or '').upper()
        if not bssid or bssid == 'FF:FF:FF:FF:FF:FF':
            return

        # Extract SSID and channel
        ssid    = ''
        channel = 0
        elt = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode('utf-8', errors='replace').strip('\x00')
                except Exception:
                    ssid = '(hidden)'
            elif elt.ID == 3 and elt.info:
                try:
                    channel = elt.info[0]
                except Exception:
                    pass
            elt = elt.payload if isinstance(getattr(elt, 'payload', None), Dot11Elt) else None

        signal = self._extract_signal(pkt)
        now    = datetime.now().isoformat()

        with self._lock:
            if bssid in self._fingerprints:
                fp = self._fingerprints[bssid]
                fp['last_seen']   = now
                fp['frame_count'] = fp.get('frame_count', 0) + 1
                if signal is not None:
                    fp['signal'] = signal
            else:
                self._fingerprints[bssid] = {
                    'mac':         bssid,
                    'type':        'AP',
                    'ssid':        ssid,
                    'channel':     channel,
                    'signal':      signal,
                    'first_seen':  now,
                    'last_seen':   now,
                    'frame_count': 1,
                }

            # ── BSSID conflict / Evil Twin detection ──────────────────────
            if ssid and ssid not in ('', '(hidden)'):
                existing_bssids = self._ssid_bssids[ssid].copy()
                if bssid not in existing_bssids:
                    self._ssid_bssids[ssid].add(bssid)
                    if existing_bssids:
                        others = ', '.join(sorted(existing_bssids))
                        self.alert_mgr.high(
                            "EVIL_TWIN",
                            f"Evil Twin detected! SSID '{ssid}' seen with multiple BSSIDs",
                            f"Known BSSID(s): {others} | New BSSID: {bssid}",
                        )

    def _handle_data_frame(self, pkt):
        src = (pkt[Dot11].addr2 or '').upper()
        if not src or src == 'FF:FF:FF:FF:FF:FF':
            return

        signal = self._extract_signal(pkt)
        now    = datetime.now().isoformat()

        with self._lock:
            if src in self._fingerprints:
                fp = self._fingerprints[src]
                fp['last_seen']   = now
                fp['frame_count'] = fp.get('frame_count', 0) + 1
                if signal is not None:
                    fp['signal'] = signal
            else:
                self._fingerprints[src] = {
                    'mac':         src,
                    'type':        'CLIENT',
                    'signal':      signal,
                    'first_seen':  now,
                    'last_seen':   now,
                    'frame_count': 1,
                }

    @staticmethod
    def _extract_signal(pkt) -> int | None:
        if SCAPY_AVAILABLE and pkt.haslayer(RadioTap):
            try:
                return int(pkt[RadioTap].dBm_AntSignal)
            except Exception:
                pass
        return None

    # ── Public API ────────────────────────────────────────────────────────

    def get_fingerprints(self) -> dict:
        with self._lock:
            return dict(self._fingerprints)

    def get_bssid_conflicts(self) -> dict:
        """Return {ssid: [bssid, ...]} for all SSIDs seen with more than one BSSID."""
        with self._lock:
            return {
                ssid: sorted(bssids)
                for ssid, bssids in self._ssid_bssids.items()
                if len(bssids) > 1
            }

    def get_stats(self) -> dict:
        with self._lock:
            aps     = sum(1 for f in self._fingerprints.values() if f.get('type') == 'AP')
            clients = sum(1 for f in self._fingerprints.values() if f.get('type') == 'CLIENT')
            return {
                'total_seen': len(self._fingerprints),
                'access_points': aps,
                'clients': clients,
                'bssid_conflicts': len([
                    s for s, b in self._ssid_bssids.items() if len(b) > 1
                ]),
            }
