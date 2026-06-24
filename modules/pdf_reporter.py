"""PDF session report generator using reportlab."""

import os
import re
from datetime import datetime

_BINARY_PAT = re.compile(r'\\x[0-9a-fA-F]{2}')


def _sanitize_ssid(raw, max_len: int = 18) -> str:
    s = str(raw or '')
    if not s:
        return '(hidden)'
    if any(ord(c) < 32 or ord(c) > 126 for c in s):
        return '(hidden)'
    if _BINARY_PAT.search(s):
        return '(hidden)'
    return s[:max_len] or '(hidden)'

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
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True

    C_BLUE   = rl_colors.HexColor("#0A1628")
    C_CYAN   = rl_colors.HexColor("#00D4FF")
    C_RED    = rl_colors.HexColor("#FF3B3B")
    C_ORANGE = rl_colors.HexColor("#FF8C00")
    C_YELLOW = rl_colors.HexColor("#FFB800")
    C_GREEN  = rl_colors.HexColor("#00C851")
    C_GRAY   = rl_colors.HexColor("#1E2D40")
    C_LGRAY  = rl_colors.HexColor("#F5F8FF")

    _ENC_COLORS = {
        'WPA3':     rl_colors.HexColor("#00C851"),
        'WPA2-PSK': rl_colors.HexColor("#00AACC"),
        'WPA2-EAP': rl_colors.HexColor("#0066CC"),
        'WPA2':     rl_colors.HexColor("#0088FF"),
        'WPA':      rl_colors.HexColor("#FFB800"),
        'WEP':      rl_colors.HexColor("#FF8C00"),
        'OPEN':     rl_colors.HexColor("#FF3B3B"),
        'UNKNOWN':  rl_colors.HexColor("#888888"),
    }

except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFReporter:
    def __init__(self, db, config, license_key: str = ""):
        self.db          = db
        self.config      = config
        self.license_key = license_key or self._load_license_key()

    @staticmethod
    def _load_license_key() -> str:
        try:
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from core.license_manager import LicenseManager
            mgr = LicenseManager()
            mgr.load_or_create()
            return mgr.display
        except Exception:
            return "Optisec WiFi Monitor — Authorized Defense Use Only"

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
                ssid = _sanitize_ssid(a.get('ssid', ''))
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

        # ── Encryption Pie Chart ─────────────────────────────────────────
        enc_counts: dict = {}
        for a in audits:
            et = a.get('encryption_type', 'UNKNOWN')
            enc_counts[et] = enc_counts.get(et, 0) + 1
        if enc_counts:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("ENCRYPTION DISTRIBUTION", sec_s))
            pie_drawing = self._build_pie_chart(enc_counts)
            if pie_drawing:
                story.append(pie_drawing)
                story.append(Spacer(1, 0.3*cm))

        # ── High-Risk Devices Bar Chart ──────────────────────────────────
        risky = [d for d in devices if d.get('is_suspicious') or
                 not (d.get('vendor') or '').strip() or
                 (d.get('vendor') or '').strip() == 'Unknown']
        if risky:
            story.append(Paragraph(f"HIGH-RISK DEVICES ({len(risky)} flagged)", sec_s))
            bar_drawing = self._build_bar_chart(risky)
            if bar_drawing:
                story.append(bar_drawing)
                story.append(Spacer(1, 0.3*cm))

        # ── Footer ───────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_CYAN))
        story.append(Paragraph(
            f"Generated by Optisec WiFi Monitor v1.0  |  {self.license_key}",
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

    def _build_pie_chart(self, enc_counts: dict):
        """Pie chart showing encryption type distribution."""
        if not REPORTLAB_AVAILABLE or not enc_counts:
            return None
        labels = list(enc_counts.keys())
        data   = [enc_counts[k] for k in labels]
        total  = sum(data)

        d   = Drawing(400, 160)
        pie = Pie()
        pie.x      = 20
        pie.y      = 20
        pie.width  = 110
        pie.height = 110
        pie.data   = data

        for i, label in enumerate(labels):
            pie.slices[i].fillColor   = _ENC_COLORS.get(label, rl_colors.gray)
            pie.slices[i].strokeWidth = 0.5
            pct = round(data[i] * 100 / total) if total else 0
            pie.slices[i].label_text  = f"{label} ({pct}%)"

        pie.sideLabels       = 1
        pie.sideLabelsOffset = 0.08
        pie.simpleLabels     = 0

        d.add(pie)
        return d

    def _build_bar_chart(self, risky_devices: list):
        """Bar chart showing risk scores for the top 8 high-risk devices."""
        if not REPORTLAB_AVAILABLE or not risky_devices:
            return None

        top = risky_devices[:8]
        labels = [(d.get('mac') or 'Unknown')[-8:] for d in top]
        scores = []
        for d in top:
            if d.get('is_suspicious'):
                scores.append(85)
            elif not (d.get('vendor') or '').strip() or d.get('vendor') == 'Unknown':
                scores.append(65)
            else:
                scores.append(45)

        drawing = Drawing(400, 160)
        bc = VerticalBarChart()
        bc.x      = 40
        bc.y      = 30
        bc.height = 110
        bc.width  = 340
        bc.data   = [scores]

        bc.categoryAxis.categoryNames        = labels
        bc.categoryAxis.labels.angle         = 20
        bc.categoryAxis.labels.fontSize      = 6
        bc.categoryAxis.labels.dx            = -5
        bc.valueAxis.valueMin                = 0
        bc.valueAxis.valueMax                = 100
        bc.valueAxis.valueStep               = 20
        bc.valueAxis.labels.fontSize         = 7
        bc.bars[0].fillColor                 = C_RED
        bc.barWidth                          = 10

        drawing.add(bc)
        return drawing
