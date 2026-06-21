"""Module 4 - AI Engine: OpenRouter API, anomaly detection, Arabic/English reports."""

import threading
import time
import json
import requests
from datetime import datetime

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

FREE_MODELS = [
    "meta-llama/llama-3.2-3b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
    "google/gemma-2-9b-it:free",
]


class AIEngine:
    def __init__(self, db, config, language: str = 'en'):
        self.db = db
        self.config = config
        self.language = language
        self._running = False

    def start(self):
        self._running = True
        interval = self.config.get("ai_report_interval", 300)
        while self._running:
            time.sleep(interval)
            if self._running:
                self.generate_periodic_report()

    def stop(self):
        self._running = False

    def _call_api(self, messages: list, model: str = None) -> str:
        api_key = self.config.openrouter_api_key
        if not api_key:
            return self._offline_analysis(messages)

        model = model or self.config.openrouter_model
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://optisec.local",
            "X-Title": "Optisec WiFi Monitor",
        }
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.3,
        }

        for attempt, mdl in enumerate([model] + FREE_MODELS):
            try:
                resp = requests.post(
                    OPENROUTER_URL,
                    headers=headers,
                    json={**payload, "model": mdl},
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data['choices'][0]['message']['content']
                elif resp.status_code == 429:
                    time.sleep(2)
                    continue
            except requests.RequestException:
                continue

        return self._offline_analysis(messages)

    def _offline_analysis(self, messages: list) -> str:
        """Rule-based fallback when API unavailable."""
        context = messages[-1]['content'] if messages else ""
        if self.language == 'ar':
            return (
                "⚠ تحليل غير متصل بالإنترنت\n\n"
                "لا يمكن الاتصال بواجهة برمجة تطبيقات OpenRouter.\n"
                "يرجى التحقق من مفتاح API والاتصال بالإنترنت.\n\n"
                "البيانات المجمعة:\n" + context[:500]
            )
        return (
            "⚠ Offline Analysis\n\n"
            "Could not reach OpenRouter API. Check API key and internet connection.\n\n"
            "Collected data summary:\n" + context[:500]
        )

    def _build_context(self) -> dict:
        stats = self.db.get_stats()
        recent_alerts = self.db.get_alerts(limit=20)
        recent_attacks = self.db.get_attacks(limit=10)
        audits = self.db.get_audits(limit=20)
        devices = self.db.get_all_devices()

        return {
            'stats': stats,
            'recent_alerts': recent_alerts,
            'recent_attacks': recent_attacks,
            'audits': audits[:10],
            'device_count': len(devices),
            'timestamp': datetime.now().isoformat(),
        }

    def _make_prompt(self, context: dict, report_type: str) -> str:
        ctx_str = json.dumps(context, indent=2, default=str, ensure_ascii=False)

        if self.language == 'ar':
            return f"""أنت محلل أمن شبكات خبير. قم بتحليل بيانات مراقبة WiFi التالية وإنشاء تقرير أمني احترافي باللغة العربية.

نوع التقرير: {report_type}
البيانات:
{ctx_str}

أنشئ تقريرًا شاملاً يتضمن:
1. ملخص الحالة الأمنية
2. التهديدات المكتشفة وخطورتها
3. الأجهزة المشبوهة
4. نقاط الضعف في التشفير
5. التوصيات الأمنية الفورية
6. خطة التحسين على المدى البعيد

استخدم أسلوبًا احترافيًا وواضحًا."""
        else:
            return f"""You are an expert network security analyst. Analyze the following WiFi monitoring data and generate a professional security report in English.

Report Type: {report_type}
Data:
{ctx_str}

Generate a comprehensive report including:
1. Security Status Summary
2. Detected Threats and Severity
3. Suspicious Devices
4. Encryption Vulnerabilities
5. Immediate Security Recommendations
6. Long-term Improvement Plan

Use a professional, clear style with actionable insights."""

    def generate_periodic_report(self) -> dict:
        context = self._build_context()
        prompt = self._make_prompt(context, "Periodic Security Report")

        messages = [
            {"role": "system", "content": "You are a WiFi security monitoring AI assistant."},
            {"role": "user", "content": prompt},
        ]

        content = self._call_api(messages)
        self.db.add_report("PERIODIC", content, self.language)
        return {'type': 'PERIODIC', 'content': content, 'language': self.language}

    def analyze_anomaly(self, anomaly_data: dict) -> str:
        lang_hint = "in Arabic" if self.language == 'ar' else "in English"
        prompt = (
            f"Analyze this WiFi network anomaly and provide a brief security assessment {lang_hint}:\n"
            f"{json.dumps(anomaly_data, indent=2, default=str)}\n\n"
            f"Provide: threat level, explanation, and immediate action."
        )
        messages = [
            {"role": "system", "content": "You are a WiFi security expert. Be concise."},
            {"role": "user", "content": prompt},
        ]
        return self._call_api(messages)

    def generate_device_report(self, device: dict) -> str:
        lang_hint = "in Arabic" if self.language == 'ar' else "in English"
        prompt = (
            f"Analyze this network device {lang_hint} and assess security risk:\n"
            f"{json.dumps(device, indent=2, default=str)}\n\n"
            f"Provide: risk level, vendor context, and recommendations."
        )
        messages = [
            {"role": "system", "content": "You are a network security analyst. Be concise."},
            {"role": "user", "content": prompt},
        ]
        result = self._call_api(messages)
        self.db.add_report("DEVICE_ANALYSIS", result, self.language)
        return result

    def generate_attack_report(self, attack: dict) -> str:
        lang_hint = "in Arabic" if self.language == 'ar' else "in English"
        prompt = (
            f"Generate a security incident report {lang_hint} for this WiFi attack:\n"
            f"{json.dumps(attack, indent=2, default=str)}\n\n"
            f"Include: attack description, impact, mitigation steps."
        )
        messages = [
            {"role": "system", "content": "You are a cybersecurity incident responder."},
            {"role": "user", "content": prompt},
        ]
        result = self._call_api(messages)
        self.db.add_report("ATTACK_REPORT", result, self.language)
        return result

    def ask(self, question: str) -> str:
        """Free-form security question answering."""
        context = self._build_context()
        ctx_summary = (
            f"Current stats: {context['stats']} | "
            f"Recent alerts: {len(context['recent_alerts'])} | "
            f"Devices: {context['device_count']}"
        )
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert WiFi security assistant for Optisec WiFi Monitor. "
                    f"Current network context: {ctx_summary}"
                )
            },
            {"role": "user", "content": question},
        ]
        return self._call_api(messages)
