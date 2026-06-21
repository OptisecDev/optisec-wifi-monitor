"""AI Engine — Groq llama-3.3-70b-versatile, device risk scoring, Arabic/English reports."""

import re
import threading
import time
import json
import requests
from collections import defaultdict
from datetime import datetime

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

# OpenRouter fallback (kept for users who still have that key)
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_FREE_MODELS = [
    "meta-llama/llama-3.2-3b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
]

_MAC_RE = re.compile(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')


class AIEngine:
    def __init__(self, db, config, language: str = 'en'):
        self.db = db
        self.config = config
        self.language = language
        self._running = False
        self._latest_insights: dict = {}

    def start(self):
        self._running = True
        interval = self.config.get("ai_report_interval", 300)
        while self._running:
            time.sleep(interval)
            if self._running:
                self.generate_periodic_report()

    def stop(self):
        self._running = False

    # ── API dispatch ─────────────────────────────────────────────────────

    def _call_api(self, messages: list) -> str:
        groq_key = self.config.get("groq_api_key", "")
        if groq_key:
            result = self._call_groq(messages, groq_key)
            if result:
                return result

        openrouter_key = self.config.get("openrouter_api_key", "")
        if openrouter_key:
            result = self._call_openrouter(messages, openrouter_key)
            if result:
                return result

        return self._offline_analysis(messages)

    def _call_groq(self, messages: list, api_key: str) -> str:
        try:
            resp = requests.post(
                GROQ_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": GROQ_MODEL,
                    "messages": messages,
                    "max_tokens": 1024,
                    "temperature": 0.3,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content']
        except Exception:
            pass
        return ""

    def _call_openrouter(self, messages: list, api_key: str) -> str:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://optisec.local",
            "X-Title": "Optisec WiFi Monitor",
        }
        for model in OPENROUTER_FREE_MODELS:
            try:
                resp = requests.post(
                    OPENROUTER_URL,
                    headers=headers,
                    json={"model": model, "messages": messages,
                          "max_tokens": 1024, "temperature": 0.3},
                    timeout=30,
                )
                if resp.status_code == 200:
                    return resp.json()['choices'][0]['message']['content']
                elif resp.status_code == 429:
                    time.sleep(2)
            except Exception:
                continue
        return ""

    def _offline_analysis(self, messages: list) -> str:
        context = messages[-1]['content'] if messages else ""
        if self.language == 'ar':
            return (
                "⚠ تحليل غير متصل بالإنترنت\n\n"
                "لا يمكن الاتصال بـ Groq API أو OpenRouter.\n"
                "يرجى التحقق من مفتاح API والاتصال بالإنترنت.\n\n"
                "البيانات المجمعة:\n" + context[:500]
            )
        return (
            "⚠ Offline Analysis\n\n"
            "Could not reach Groq or OpenRouter API. Check API key and connection.\n\n"
            "Collected data summary:\n" + context[:500]
        )

    # ── Risk Scoring (rule-based, no API call) ───────────────────────────

    def score_device_risk(self, device: dict, device_alerts: list = None) -> int:
        """Return risk score 0–100: lower = more dangerous."""
        score = 60  # neutral baseline

        vendor = (device.get('vendor', '') or '').strip()
        if not vendor or vendor == 'Unknown':
            score -= 15

        if device.get('is_suspicious'):
            score -= 25

        if device.get('is_whitelisted'):
            score += 25

        n_alerts = len(device_alerts) if device_alerts else 0
        score -= min(35, n_alerts * 8)

        return max(0, min(100, score))

    def get_insights(self) -> dict:
        """Rule-based insights for TUI display — no API call."""
        devices = self.db.get_all_devices()
        alerts  = self.db.get_alerts(limit=50)
        attacks = self.db.get_attacks(limit=20)

        mac_alerts: dict = defaultdict(list)
        for a in alerts:
            m = _MAC_RE.search(str(a.get('message', '')))
            if m:
                mac_alerts[m.group(1).upper()].append(a)

        scored = []
        for d in devices:
            mac  = d.get('mac', '').upper()
            risk = self.score_device_risk(d, mac_alerts.get(mac, []))
            scored.append((d, risk))

        scored.sort(key=lambda x: x[1])  # lowest risk score first = highest threat

        self._latest_insights = {
            'total_devices': len(devices),
            'total_alerts':  len(alerts),
            'total_attacks': len(attacks),
            'top_risk':      scored[:3],
            'avg_risk':      round(sum(r for _, r in scored) / len(scored), 1) if scored else 50,
        }
        return self._latest_insights

    # ── Report generation ─────────────────────────────────────────────────

    def _build_context(self) -> dict:
        stats = self.db.get_stats()
        return {
            'stats':           stats,
            'recent_alerts':   self.db.get_alerts(limit=20),
            'recent_attacks':  self.db.get_attacks(limit=10),
            'audits':          self.db.get_audits(limit=10),
            'device_count':    stats.get('total_devices', 0),
            'timestamp':       datetime.now().isoformat(),
        }

    def _make_prompt(self, context: dict, report_type: str) -> str:
        ctx_str = json.dumps(context, indent=2, default=str, ensure_ascii=False)
        if self.language == 'ar':
            return (
                f"أنت محلل أمن شبكات خبير. قم بتحليل بيانات مراقبة WiFi وإنشاء تقرير أمني باللغة العربية.\n\n"
                f"نوع التقرير: {report_type}\nالبيانات:\n{ctx_str}\n\n"
                "أنشئ تقريرًا شاملاً يتضمن:\n"
                "1. ملخص الحالة الأمنية\n2. التهديدات المكتشفة وخطورتها\n"
                "3. الأجهزة المشبوهة\n4. نقاط الضعف في التشفير\n"
                "5. التوصيات الأمنية الفورية\n6. درجة المخاطرة الإجمالية (0-100)\n\n"
                "استخدم أسلوبًا احترافيًا وواضحًا."
            )
        return (
            f"You are an expert network security analyst. Analyze WiFi monitoring data "
            f"and generate a professional security report in English.\n\n"
            f"Report Type: {report_type}\nData:\n{ctx_str}\n\n"
            "Generate a comprehensive report including:\n"
            "1. Security Status Summary\n2. Detected Threats and Severity\n"
            "3. Suspicious Devices\n4. Encryption Vulnerabilities\n"
            "5. Immediate Security Recommendations\n6. Overall Risk Score (0-100)\n\n"
            "Use a professional, clear style with actionable insights."
        )

    def generate_periodic_report(self) -> dict:
        context = self._build_context()
        messages = [
            {"role": "system", "content": "You are a WiFi security monitoring AI assistant."},
            {"role": "user",   "content": self._make_prompt(context, "Periodic Security Report")},
        ]
        content = self._call_api(messages)
        self.db.add_report("PERIODIC", content, self.language)
        return {'type': 'PERIODIC', 'content': content, 'language': self.language}

    def analyze_anomaly(self, anomaly_data: dict) -> str:
        lang_hint = "in Arabic" if self.language == 'ar' else "in English"
        messages = [
            {"role": "system", "content": "You are a WiFi security expert. Be concise."},
            {"role": "user",   "content": (
                f"Analyze this WiFi anomaly and provide a brief security assessment {lang_hint}:\n"
                f"{json.dumps(anomaly_data, indent=2, default=str)}\n\n"
                "Provide: threat level, explanation, and immediate action."
            )},
        ]
        return self._call_api(messages)

    def generate_device_report(self, device: dict) -> str:
        lang_hint = "in Arabic" if self.language == 'ar' else "in English"
        messages = [
            {"role": "system", "content": "You are a network security analyst. Be concise."},
            {"role": "user",   "content": (
                f"Analyze this network device {lang_hint} and assess security risk:\n"
                f"{json.dumps(device, indent=2, default=str)}\n\n"
                "Provide: risk level (0-100), vendor context, and recommendations."
            )},
        ]
        result = self._call_api(messages)
        self.db.add_report("DEVICE_ANALYSIS", result, self.language)
        return result

    def generate_attack_report(self, attack: dict) -> str:
        lang_hint = "in Arabic" if self.language == 'ar' else "in English"
        messages = [
            {"role": "system", "content": "You are a cybersecurity incident responder."},
            {"role": "user",   "content": (
                f"Generate a security incident report {lang_hint} for this WiFi attack:\n"
                f"{json.dumps(attack, indent=2, default=str)}\n\n"
                "Include: attack description, impact, mitigation steps."
            )},
        ]
        result = self._call_api(messages)
        self.db.add_report("ATTACK_REPORT", result, self.language)
        return result

    def ask(self, question: str) -> str:
        context = self._build_context()
        ctx_summary = (
            f"Stats: {context['stats']} | "
            f"Alerts: {len(context['recent_alerts'])} | "
            f"Devices: {context['device_count']}"
        )
        messages = [
            {"role": "system", "content": (
                f"You are an expert WiFi security assistant for Optisec WiFi Monitor. "
                f"Network context: {ctx_summary}"
            )},
            {"role": "user", "content": question},
        ]
        return self._call_api(messages)
