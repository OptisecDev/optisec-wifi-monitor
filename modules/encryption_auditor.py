"""Module 3 - Encryption Auditor: WPA2/WPA3 check, WPS detection, security score."""

import threading
import time
import subprocess
import re

_BINARY_PAT = re.compile(r'\\x[0-9a-fA-F]{2}')


def _sanitize_ssid(raw) -> str:
    """Return printable SSID or '(hidden)' for empty/binary/escaped-byte SSIDs."""
    if not raw:
        return ''
    s = raw if isinstance(raw, str) else raw.decode('utf-8', errors='replace')
    if any(ord(c) < 32 or ord(c) > 126 for c in s):
        return '(hidden)'
    if _BINARY_PAT.search(s):
        return '(hidden)'
    return s

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# RSN Capabilities flags
RSN_PMF_REQUIRED = 0x0040
RSN_PMF_CAPABLE = 0x0080

# OUI for WPS
WPS_OUI = b'\x00\x50\xf2\x04'


class EncryptionAuditor:
    def __init__(self, db, alert_mgr, monitor_iface: str):
        self.db = db
        self.alert_mgr = alert_mgr
        self.monitor_iface = monitor_iface
        self._running = False
        self._seen: set = set()

    def start(self):
        self._running = True
        if SCAPY_AVAILABLE:
            t = threading.Thread(target=self._sniff_beacons, daemon=True)
            t.start()

        # Also use iwlist scan periodically as supplement
        while self._running:
            self._iwlist_scan()
            time.sleep(60)

    def stop(self):
        self._running = False

    def _sniff_beacons(self):
        try:
            sniff(
                iface=self.monitor_iface,
                prn=self._beacon_handler,
                store=False,
                lfilter=lambda p: p.haslayer(Dot11Beacon),
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"Encryption auditor sniff error: {e}")

    def _beacon_handler(self, pkt):
        try:
            bssid = pkt[Dot11].addr3
            if not bssid or bssid in self._seen:
                return
            self._seen.add(bssid)

            info = self._parse_beacon(pkt)
            if info:
                self._evaluate_and_store(info)
        except Exception:
            pass

    def _parse_beacon(self, pkt) -> dict:
        ssid = ""
        encryption = "OPEN"
        wps_enabled = False
        pmf_enabled = False
        channel = 0
        wpa3 = False
        wpa2 = False

        bssid = pkt[Dot11].addr3

        # Signal strength
        signal = None
        if pkt.haslayer(RadioTap):
            try:
                signal = -(256 - pkt[RadioTap].dBm_AntSignal) if hasattr(pkt[RadioTap], 'dBm_AntSignal') else None
            except Exception:
                signal = None

        # Parse Information Elements
        elt = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            eid = elt.ID
            info = elt.info

            if eid == 0:  # SSID
                try:
                    ssid = _sanitize_ssid(info)
                except Exception:
                    ssid = "(hidden)"

            elif eid == 3:  # DS Parameter (channel)
                try:
                    channel = info[0]
                except Exception:
                    pass

            elif eid == 48:  # RSN (WPA2/WPA3)
                wpa2 = True
                encryption = "WPA2"
                # Check PMF in RSN capabilities (last 2 bytes)
                if len(info) >= 10:
                    try:
                        caps_offset = self._rsn_caps_offset(info)
                        if caps_offset and caps_offset + 2 <= len(info):
                            caps = int.from_bytes(info[caps_offset:caps_offset+2], 'little')
                            if caps & (RSN_PMF_REQUIRED | RSN_PMF_CAPABLE):
                                pmf_enabled = True
                    except Exception:
                        pass
                # Check for SAE (WPA3)
                if b'\x00\x0f\xac\x08' in info:  # SAE AKM
                    wpa3 = True
                    encryption = "WPA3"
                elif b'\x00\x0f\xac\x02' in info:  # PSK AKM (WPA2-Personal)
                    encryption = "WPA2-PSK"
                elif b'\x00\x0f\xac\x01' in info:
                    encryption = "WPA2-EAP"

            elif eid == 221:  # Vendor Specific
                if WPS_OUI in info:
                    wps_enabled = True
                # WPA (old WPA1)
                if info[:4] == b'\x00\x50\xf2\x01':
                    if encryption == "OPEN":
                        encryption = "WPA"

            elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None

        return {
            'bssid': bssid,
            'ssid': ssid,
            'encryption': encryption,
            'wps_enabled': wps_enabled,
            'pmf_enabled': pmf_enabled,
            'channel': channel,
            'signal': signal,
            'wpa3': wpa3,
            'wpa2': wpa2,
        }

    def _rsn_caps_offset(self, rsn_info: bytes) -> int:
        """Calculate RSN capabilities field offset within RSN IE body."""
        try:
            offset = 2  # version (2 bytes)
            if offset + 4 > len(rsn_info):
                return None
            offset += 4  # group cipher suite
            if offset + 2 > len(rsn_info):
                return None
            pairwise_count = int.from_bytes(rsn_info[offset:offset+2], 'little')
            offset += 2 + pairwise_count * 4
            if offset + 2 > len(rsn_info):
                return None
            akm_count = int.from_bytes(rsn_info[offset:offset+2], 'little')
            offset += 2 + akm_count * 4
            return offset
        except Exception:
            return None

    def _calculate_score(self, info: dict) -> int:
        """Return security score 0-100."""
        score = 0

        enc = info.get('encryption', 'OPEN')
        if 'WPA3' in enc:
            score += 50
        elif 'WPA2' in enc:
            score += 35
        elif enc == 'WPA':
            score += 15
        else:  # OPEN
            score += 0

        if info.get('pmf_enabled'):
            score += 20

        if not info.get('wps_enabled'):
            score += 20
        else:
            score -= 10  # WPS is a vulnerability

        if 'PSK' in enc or enc == 'WPA3':
            score += 10  # personal use OK

        return max(0, min(100, score))

    def _evaluate_and_store(self, info: dict):
        score = self._calculate_score(info)
        bssid = info['bssid']
        ssid = info.get('ssid', '')
        enc = info.get('encryption', 'OPEN')

        self.db.upsert_audit(
            bssid=bssid,
            ssid=ssid,
            encryption_type=enc,
            wps_enabled=info.get('wps_enabled', False),
            pmf_enabled=info.get('pmf_enabled', False),
            security_score=score,
            channel=info.get('channel'),
            signal=info.get('signal'),
        )

        # Alert on weak security
        if enc == 'OPEN':
            self.alert_mgr.high(
                "WEAK_ENCRYPTION",
                f"Open network detected: '{ssid}' ({bssid})",
                f"Encryption: OPEN | Score: {score}/100"
            )
        elif enc == 'WPA':
            self.alert_mgr.medium(
                "WEAK_ENCRYPTION",
                f"Weak WPA network: '{ssid}' ({bssid})",
                f"Encryption: WPA (deprecated) | Score: {score}/100"
            )

        if info.get('wps_enabled'):
            self.alert_mgr.medium(
                "WPS_ENABLED",
                f"WPS enabled on '{ssid}' ({bssid}) - vulnerability risk",
                f"WPS can be brute-forced. Score: {score}/100"
            )

        if score < 40:
            self.alert_mgr.high(
                "LOW_SECURITY_SCORE",
                f"Low security score {score}/100 for '{ssid}' ({bssid})",
                f"Encryption: {enc} | WPS: {info.get('wps_enabled')} | PMF: {info.get('pmf_enabled')}"
            )

    def _iwlist_scan(self):
        """Supplementary scan using iwlist."""
        try:
            result = subprocess.run(
                ["iwlist", self.monitor_iface, "scan"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                return

            current = {}
            for line in result.stdout.splitlines():
                line = line.strip()

                bssid_m = re.search(r'Address:\s+([0-9A-Fa-f:]{17})', line)
                if bssid_m:
                    if current and current.get('bssid'):
                        self._process_iwlist_entry(current)
                    current = {'bssid': bssid_m.group(1)}

                ssid_m = re.search(r'ESSID:"([^"]*)"', line)
                if ssid_m:
                    current['ssid'] = ssid_m.group(1)

                chan_m = re.search(r'Channel[:=](\d+)', line)
                if chan_m:
                    current['channel'] = int(chan_m.group(1))

                sig_m = re.search(r'Signal level=(-?\d+)', line)
                if sig_m:
                    current['signal'] = int(sig_m.group(1))

                enc_m = re.search(r'Encryption key:(on|off)', line)
                if enc_m:
                    current['enc_on'] = enc_m.group(1) == 'on'

                if 'WPA2' in line:
                    current['wpa2'] = True
                if 'WPA3' in line or 'SAE' in line:
                    current['wpa3'] = True
                if 'WPA Version 1' in line and 'wpa2' not in current:
                    current['wpa'] = True
                if 'WPS' in line:
                    current['wps_enabled'] = True

            if current and current.get('bssid'):
                self._process_iwlist_entry(current)

        except Exception:
            pass

    def _process_iwlist_entry(self, entry: dict):
        bssid = entry.get('bssid', '')
        if not bssid or bssid in self._seen:
            return
        self._seen.add(bssid)

        if entry.get('wpa3'):
            enc = 'WPA3'
        elif entry.get('wpa2'):
            enc = 'WPA2'
        elif entry.get('wpa'):
            enc = 'WPA'
        elif entry.get('enc_on'):
            enc = 'WEP'
        else:
            enc = 'OPEN'

        ssid = _sanitize_ssid(entry.get('ssid', ''))
        info = {
            'bssid': bssid,
            'ssid': ssid,
            'encryption': enc,
            'wps_enabled': entry.get('wps_enabled', False),
            'pmf_enabled': False,
            'channel': entry.get('channel'),
            'signal': entry.get('signal'),
        }
        self._evaluate_and_store(info)

    def get_audit_summary(self) -> dict:
        audits = self.db.get_audits(limit=1000)
        total = len(audits)
        if not total:
            return {'total': 0}

        scores = [a['security_score'] for a in audits]
        enc_types = {}
        wps_count = 0
        for a in audits:
            et = a.get('encryption_type', 'UNKNOWN')
            enc_types[et] = enc_types.get(et, 0) + 1
            if a.get('wps_enabled'):
                wps_count += 1

        return {
            'total': total,
            'avg_score': round(sum(scores) / total, 1),
            'min_score': min(scores),
            'max_score': max(scores),
            'encryption_breakdown': enc_types,
            'wps_enabled_count': wps_count,
        }
