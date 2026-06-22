<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║       ██████╗ ██████╗ ████████╗██╗███████╗███████╗ ██████╗  ║
║      ██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔════╝██╔════╝  ║
║      ██║   ██║██████╔╝   ██║   ██║███████╗█████╗  ██║       ║
║      ██║   ██║██╔═══╝    ██║   ██║╚════██║██╔══╝  ██║       ║
║      ╚██████╔╝██║        ██║   ██║███████║███████╗╚██████╗  ║
║       ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚══════╝╚══════╝ ╚═════╝  ║
║                  WiFi DEFENSE MONITOR  v1.0.0               ║
╚══════════════════════════════════════════════════════════════╝
```

**Professional WiFi Network Defense Tool for BlackArch Linux**

[![Python](https://img.shields.io/badge/Python-3.14-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-BlackArch_Linux-1793D1?style=for-the-badge&logo=arch-linux&logoColor=white)](https://blackarch.org)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-00ff88?style=for-the-badge)](https://github.com/ahssanali84syber-boop/optisec-wifi-monitor)
[![AI](https://img.shields.io/badge/AI-Groq_llama--3.3--70b-ff6b35?style=for-the-badge)](https://groq.com)
[![Price](https://img.shields.io/badge/License-$199_one--time-gold?style=for-the-badge)](https://ahssanali84syber-boop.github.io/optisec-wifi-monitor)

[🌐 Sales Page](https://ahssanali84syber-boop.github.io/optisec-wifi-monitor) · [📧 Support](mailto:ahssanali84.syber@gmail.com) · [🐛 Issues](https://github.com/ahssanali84syber-boop/optisec-wifi-monitor/issues)

</div>

---

## ⚠️ Authorization Notice | إشعار الترخيص

> **EN:** This tool is for **authorized network defense only**. Unauthorized monitoring of networks you do not own or have explicit permission to monitor may violate local laws.
>
> **AR:** هذه الأداة مخصصة **للدفاع الشبكي المرخص فقط**. مراقبة الشبكات التي لا تملكها أو ليس لديك إذن صريح بمراقبتها قد تنتهك القوانين المحلية.

---

## 📋 Table of Contents | جدول المحتويات

- [Features](#-features--المزايا)
- [Requirements](#-requirements--المتطلبات)
- [Installation](#-installation--التثبيت)
- [Usage](#-usage--الاستخدام)
- [Dashboard Preview](#-dashboard-preview)
- [Configuration](#-configuration--الإعداد)
- [Architecture](#-architecture--البنية)
- [License](#-license--الترخيص)

---

## ✨ Features | المزايا

| Feature | Description | الوصف |
|---------|-------------|-------|
| 📡 **Attack Detection** | Deauth flood, Evil Twin, ARP spoofing, PMKID, Rogue AP | كشف هجمات إلغاء المصادقة والنقاط المزيفة |
| 🔒 **Encryption Audit** | WPA2/WPA3, WPS detection, PMF check, score 0–100 | تدقيق تشفير الشبكات مع درجة أمان |
| 🤖 **AI Analysis** | Groq llama-3.3-70b threat summaries in AR/EN | تحليل التهديدات بالذكاء الاصطناعي |
| 🖥️ **Rich TUI** | 6-panel live terminal dashboard, 1s refresh | لوحة تحكم طرفية متقدمة |
| 🌐 **Web Dashboard** | Flask + SocketIO real-time web UI | واجهة ويب فورية |
| 📱 **Telegram Alerts** | Instant CRITICAL/HIGH, batched MEDIUM | تنبيهات تيليغرام فورية |
| 📄 **PDF Reports** | Auto-generated branded session reports | تقارير PDF احترافية تلقائية |
| 🗺️ **Multi-Network** | SSID selector, color-coded security scores | محدد شبكات متعددة |
| 🔑 **OUI Lookup** | Apple, Samsung, Huawei, Cisco, TP-Link, Alfa, Intel | معرّف بائع الأجهزة |
| 🪪 **License System** | Machine-bound key, generated on first run | نظام ترخيص مرتبط بالجهاز |

---

## 🛠 Requirements | المتطلبات

- **OS:** BlackArch Linux / Arch Linux
- **Python:** 3.10+
- **WiFi Adapter:** Monitor mode capable (e.g. Alfa AWUS036ACH)
- **Root access** for monitor mode and packet capture

```
scapy >= 2.5.0       # Packet capture
python-nmap >= 0.7.1 # Network scanning
rich >= 13.7.0       # TUI dashboard
flask >= 3.0.0       # Web dashboard
reportlab >= 4.0.0   # PDF reports
requests >= 2.31.0   # AI API calls
manuf >= 1.1.5       # MAC vendor lookup
```

---

## 🚀 Installation | التثبيت

### 1. Clone the repository

```bash
git clone https://github.com/ahssanali84syber-boop/optisec-wifi-monitor.git
cd optisec-wifi-monitor
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> **BlackArch users:** Most dependencies are available via `pacman`:
> ```bash
> sudo pacman -S python-scapy python-flask python-requests
> pip install rich reportlab manuf python-nmap flask-socketio
> ```

### 3. Set adapter to monitor mode

```bash
sudo airmon-ng start wlan1
# Your monitor interface is now wlan1mon
```

### 4. Run setup (optional — configures API keys)

```bash
sudo python main.py config
```

---

## 💻 Usage | الاستخدام

```
sudo python main.py [COMMAND] [OPTIONS]
```

| Command | Description | الوصف |
|---------|-------------|-------|
| `tui` | Rich terminal dashboard | لوحة تحكم الطرفية |
| `web` | Flask web dashboard (port 5000) | لوحة تحكم الويب |
| `both` | TUI + web simultaneously | كلاهما معاً |
| `config` | Interactive configuration wizard | معالج الإعداد |

### Quick start

```bash
# TUI dashboard on wlan1mon + wlan0
sudo python main.py tui -m wlan1mon -i wlan0

# Web dashboard on port 8080
sudo python main.py web -m wlan1mon -i wlan0 -p 8080

# Arabic language reports
sudo python main.py tui -m wlan1mon -i wlan0 -l ar
```

### TUI Key Bindings

| Key | Action |
|-----|--------|
| `r` | Generate PDF report |
| `n` | Next network in selector |
| `p` | Previous network |
| `q` | Quit |

---

## 📊 Dashboard Preview

```
┌─ OPTISEC WiFi MONITOR  v1.0 ─ 2026-06-22 14:32:01 ─ Mon:wlan1 ─ Net:wlan0 ─ LICENSED TO: Ehsan ─┐

┌─ Stats ──────┐  ┌─ Live Alerts ────────────────────────────────────────────────────┐
│ Devices   8  │  │ 14:32  DEAUTH_FLOOD   AA:BB:CC:11:22:33   847 frames/60s [CRIT] │
│ Alerts    3  │  │ 14:30  WPS_ENABLED    --                   MyNetwork vuln [MED]  │
│ Attacks   1  │  │ 14:28  NEW_DEVICE     EC:75:0C:95:A6:02   TP-Link detected [INF]│
│ Networks  5  │  └──────────────────────────────────────────────────────────────────┘
└──────────────┘
                   ┌─ Attack Log ─────────────────────────────────────────────────────┐
┌─ Devices (8) ┐   │ 14:32  DEAUTH_FLOOD  AA:BB:CC:11:22:33  847 pkts in 60s        │
│ EC:75:0C...  │   └──────────────────────────────────────────────────────────────────┘
│ ✓ OK TP-Link │
│ B8:27:EB...  │   ┌─ Encryption Audit ───────────────────────────────────────────────┐
│ ? Unknown    │   │ MyHome      WPA2-PSK  Score: 75  WPS: No                        │
│ AA:BB:CC...  │   │ Office_5G   WPA2      Score: 55  WPS: YES ⚠                     │
│ ⚠ Alert      │   │ SecureNet   WPA3      Score: 95  WPS: No                        │
└──────────────┘   └──────────────────────────────────────────────────────────────────┘

┌─ Networks ▶ MyHome ─ n/p=select ┐  ┌─ AI Threat Analysis (Groq) ─────────────────┐
│ ▶ MyHome     WPA2-PSK  75  N    │  │ Network risk avg: 43/100                    │
│   Office_5G  WPA2      55  Y    │  │ Top risk: AA:BB:CC (risk=15) Unknown vendor │
│   SecureNet  WPA3      95  N    │  │ Groq: Deauth flood indicates targeted DoS   │
│   (hidden)   OPEN      10  N    │  │ Recommend: Enable PMF on all clients        │
└─────────────────────────────────┘  └─────────────────────────────────────────────┘

[ q Quit  r PDF Report  n/p Network Select ]
```

---

## ⚙️ Configuration | الإعداد

Run the interactive wizard:

```bash
sudo python main.py config
```

Or edit `~/.optisec/config.json` directly:

```json
{
    "monitor_interface": "wlan1mon",
    "internet_interface": "wlan0",
    "groq_api_key": "gsk_...",
    "telegram_bot_token": "123456:ABC...",
    "telegram_chat_id": "123456789",
    "language": "en",
    "whitelist": ["EC:75:0C:95:A6:02"],
    "scan_interval": 30,
    "ai_report_interval": 300
}
```

### Getting a Groq API Key (free)

1. Sign up at [groq.com](https://groq.com)
2. Create an API key
3. Paste into `sudo python main.py config`

---

## 🏗 Architecture | البنية

```
optisec-wifi-monitor/
├── main.py                    # CLI entry point (click)
├── core/
│   ├── database.py            # SQLite persistence
│   ├── config_manager.py      # Config + wizard
│   ├── alert_manager.py       # Alert lifecycle + callbacks
│   ├── interface_manager.py   # WiFi interface detection
│   ├── license_manager.py     # License key gen + validation
│   └── oui_lookup.py          # Static OUI vendor table
├── modules/
│   ├── device_monitor.py      # Passive scapy + active nmap
│   ├── attack_detector.py     # Attack pattern detection
│   ├── encryption_auditor.py  # Beacon/iwlist encryption audit
│   ├── ai_engine.py           # Groq API + risk scoring
│   ├── telegram_notifier.py   # Instant + batched Telegram alerts
│   └── pdf_reporter.py        # reportlab PDF generation
├── tui/
│   └── dashboard.py           # Rich Live 6-panel TUI
├── web/
│   ├── app.py                 # Flask + SocketIO
│   └── templates/             # Jinja2 HTML templates
└── sales/
    └── index.html             # Bilingual landing page
```

**Data flow:**

```
WiFi Adapter (monitor mode)
    │
    ├─► DeviceMonitor  ──► SQLite DB ──► TUI / Web
    ├─► AttackDetector ──► AlertManager ──► Telegram / TUI
    ├─► EncryptionAuditor ──► DB ──► PDF / TUI
    └─► AIEngine (Groq) ──► DB ──► TUI panel
```

---

## 📜 License | الترخيص

**Proprietary — $199 one-time license**

This software is **not open source**. Purchase a license at:
👉 **[ahssanali84syber-boop.github.io/optisec-wifi-monitor](https://ahssanali84syber-boop.github.io/optisec-wifi-monitor)**

- ✅ One machine per license
- ✅ Lifetime updates (v1.x)
- ✅ 7-day money-back guarantee
- ❌ No redistribution
- ❌ No reverse engineering

---

<div align="center">

**Built for security professionals. Authorized defense use only.**

[![Buy License](https://img.shields.io/badge/Buy_License-$199_One--Time-00ff88?style=for-the-badge)](https://ahssanali84syber-boop.github.io/optisec-wifi-monitor)
[![Email Support](https://img.shields.io/badge/Email-Support-blue?style=for-the-badge&logo=gmail)](mailto:ahssanali84.syber@gmail.com)

</div>
