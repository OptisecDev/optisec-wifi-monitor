"""PDF session report generator using reportlab."""

import os
from datetime import datetime

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports'
)

try:
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, HRFlowable,
    )
    REPORTLAB_AVAILABLE = True

    C_BLUE   = rl_colors.HexColor("#0A1628")
    C_CYAN   = rl_colors.HexColor("#00D4FF")
    C_RED    = rl_colors.HexColor("#FF3B3B")
    C_ORANGE = rl_colors.HexColor("#FF8C00")
    C_YELLOW = rl_colors.HexColor("#FFB800")
    C_GREEN  = rl_colors.HexColor("#00C851")
    C_GRAY   = rl_colors.HexColor("#1E2D40")
    C_LGRAY  = rl_colors.HexColor("#F5F8FF")

except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFReporter:
    def __init__(self, db, config):
        self.db = db
        self.config = config

    def generate(self) -> str | None:
        if not REPORTLAB_AVAILABLE:
            return None

        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
        path = os.path.join(REPORTS_DIR, f"{ts}.pdf")

        doc = SimpleDocTemplate(
            path, pagesize=A4,
            leftMargin=1.5*cm, rightMargin=1.5*cm,
            topMargin=1.5*cm, bottomMargin=1.5*cm,
        )

        styles = getSampleStyleSheet()
        title_s = ParagraphStyle('T', parent=styles['Normal'],
            fontSize=22, textColor=C_CYAN, spaceAfter=4,
            fontName='Helvetica-Bold', alignment=TA_CENTER)
        sub_s = ParagraphStyle('S', parent=styles['Normal'],
            fontSize=11, textColor=rl_colors.gray, spaceAfter=4, alignment=TA_CENTER)
        sec_s = ParagraphStyle('SEC', parent=styles['Normal'],
            fontSize=12, textColor=C_CYAN, spaceBefore=10, spaceAfter=5,
            fontName='Helvetica-Bold')
        meta_s = ParagraphStyle('M', parent=styles['Normal'],
            fontSize=8, textColor=rl_colors.gray, alignment=TA_CENTER)
        foot_s = ParagraphStyle('F', parent=styles['Normal'],
            fontSize=7, textColor=rl_colors.gray, alignment=TA_CENTER)

        story = []

        # ── Header ──────────────────────────────────────────────────────
        story.append(Paragraph("OPTISEC WIFI MONITOR", title_s))
        story.append(Paragraph("Security Session Report", sub_s))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
            f"Monitor: {self.config.monitor_interface}  |  "
            f"Internet: {self.config.internet_interface}",
            meta_s))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN, spaceAfter=8))

        # ── Session Summary ──────────────────────────────────────────────
        stats = self.db.get_stats()
        threat_label, threat_color = self._threat_level(stats)

        story.append(Paragraph("SESSION SUMMARY", sec_s))
        sum_data = [
            ["Metric", "Value"],
            ["Total Devices Detected", str(stats.get('total_devices', 0))],
            ["Active Alerts", str(stats.get('active_alerts', 0))],
            ["Attacks Logged", str(stats.get('total_attacks', 0))],
            ["Networks Audited", str(stats.get('audits', 0))],
            ["Overall Threat Level", threat_label],
        ]
        sum_tbl = Table(sum_data, colWidths=[9*cm, 9*cm])
        sum_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), C_GRAY),
            ('TEXTCOLOR', (0, 0), (-1, 0), C_CYAN),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.4, rl_colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [rl_colors.white, C_LGRAY]),
            ('TEXTCOLOR', (1, 5), (1, 5), threat_color),
            ('FONTNAME', (1, 5), (1, 5), 'Helvetica-Bold'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(sum_tbl)
        story.append(Spacer(1, 0.3*cm))

        # ── Devices Table ────────────────────────────────────────────────
        devices = self.db.get_all_devices()[:40]
        if devices:
            story.append(Paragraph(f"DETECTED DEVICES ({len(devices)})", sec_s))
            dev_data = [["MAC Address", "IP", "Vendor", "Status", "Last Seen"]]
            whitelist = set(m.upper() for m in self.config.whitelist)
            for d in devices:
                mac = d.get('mac', '')
                wl = mac.upper() in whitelist
                status = "Whitelisted" if wl else ("Suspicious" if d.get('is_suspicious') else "Unknown")
                dev_data.append([
                    mac,
                    d.get('ip', 'N/A') or 'N/A',
                    (d.get('vendor', 'Unknown') or 'Unknown')[:22],
                    status,
                    str(d.get('last_seen', ''))[:16],
                ])
            dev_tbl = Table(dev_data, colWidths=[4.5*cm, 3.5*cm, 4.5*cm, 2.5*cm, 3*cm])
            dev_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), C_GRAY),
                ('TEXTCOLOR', (0, 0), (-1, 0), C_CYAN),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('GRID', (0, 0), (-1, -1), 0.3, rl_colors.lightgrey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [rl_colors.white, C_LGRAY]),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(dev_tbl)
            story.append(Spacer(1, 0.3*cm))

        # ── Alerts Log ───────────────────────────────────────────────────
        alerts = self.db.get_alerts(limit=40)
        if alerts:
            story.append(Paragraph(f"ALERTS LOG ({len(alerts)})", sec_s))
            sev_colors = {
                'CRITICAL': C_RED, 'HIGH': C_ORANGE,
                'MEDIUM': C_YELLOW, 'LOW': rl_colors.cyan, 'INFO': C_GREEN,
            }
            alert_data = [["Time", "Severity", "Type", "Message"]]
            row_styles = []
            for i, a in enumerate(alerts, 1):
                sev = a.get('severity', 'INFO')
                alert_data.append([
                    str(a.get('timestamp', ''))[:16],
                    sev,
                    str(a.get('alert_type', ''))[:18],
                    str(a.get('message', ''))[:55],
                ])
                c = sev_colors.get(sev, rl_colors.black)
                row_styles += [
                    ('TEXTCOLOR', (1, i), (1, i), c),
                    ('FONTNAME', (1, i), (1, i), 'Helvetica-Bold'),
                ]
            alert_tbl = Table(alert_data, colWidths=[3.5*cm, 2.5*cm, 3.5*cm, 8.5*cm])
            alert_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), C_GRAY),
                ('TEXTCOLOR', (0, 0), (-1, 0), C_CYAN),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('GRID', (0, 0), (-1, -1), 0.3, rl_colors.lightgrey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#FFF8F8")]),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ] + row_styles))
            story.append(alert_tbl)
            story.append(Spacer(1, 0.3*cm))

        # ── Encryption Audit ─────────────────────────────────────────────
        audits = self.db.get_audits(limit=30)
        if audits:
            story.append(Paragraph(f"ENCRYPTION AUDIT ({len(audits)} networks)", sec_s))
            enc_data = [["SSID", "BSSID", "Encryption", "WPS", "Score"]]
            enc_styles = []
            for i, a in enumerate(audits, 1):
                raw = str(a.get('ssid', '') or '')
                ssid = ('(binary)' if any(ord(c) < 32 or ord(c) > 126 for c in raw)
                        else raw[:18]) or '(hidden)'
                score = int(a.get('security_score', 0))
                wps = 'YES' if a.get('wps_enabled') else 'No'
                enc_data.append([ssid, str(a.get('bssid', '')),
                                  str(a.get('encryption_type', 'UNKNOWN')), wps, str(score)])
                sc = C_RED if score < 40 else (C_YELLOW if score < 70 else C_GREEN)
                enc_styles += [('TEXTCOLOR', (4, i), (4, i), sc),
                                ('FONTNAME', (4, i), (4, i), 'Helvetica-Bold')]
                if wps == 'YES':
                    enc_styles.append(('TEXTCOLOR', (3, i), (3, i), C_RED))
            enc_tbl = Table(enc_data, colWidths=[4*cm, 5*cm, 3.5*cm, 2*cm, 2.5*cm])
            enc_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), C_GRAY),
                ('TEXTCOLOR', (0, 0), (-1, 0), C_CYAN),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.3, rl_colors.lightgrey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#F5FFF8")]),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ] + enc_styles))
            story.append(enc_tbl)

        # ── Footer ───────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_CYAN))
        story.append(Paragraph(
            "Generated by Optisec WiFi Monitor v1.0  |  Authorized defense use only",
            foot_s))

        doc.build(story)
        return path

    def _threat_level(self, stats: dict) -> tuple:
        attacks = stats.get('total_attacks', 0)
        alerts  = stats.get('active_alerts', 0)
        if attacks > 5 or alerts > 20:
            return "CRITICAL", C_RED
        elif attacks > 2 or alerts > 5:
            return "HIGH",     C_ORANGE
        elif attacks > 0 or alerts > 0:
            return "MEDIUM",   C_YELLOW
        return "LOW", C_GREEN
