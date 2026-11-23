# Security Policy | سياسة الأمان

## Reporting a Vulnerability | الإبلاغ عن ثغرة

**EN:** Please report security vulnerabilities **privately** — do **not** open a
public GitHub issue, and do not disclose the issue publicly until it has been
resolved.

Use GitHub's private vulnerability reporting for this repository:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability** (GitHub Security Advisories).
3. Provide a clear description, affected version/commit, reproduction steps,
   and any proof-of-concept or logs.

**AR:** يُرجى الإبلاغ عن الثغرات الأمنية **بشكل خاص** — ولا تفتح مشكلة (issue)
عامة، ولا تكشف عن الثغرة علنًا حتى تتم معالجتها. استخدم ميزة الإبلاغ الخاص عن
الثغرات في GitHub عبر تبويب **Security** ثم **Report a vulnerability**، وأرفق
وصفًا واضحًا والإصدار المتأثر وخطوات إعادة الإنتاج.

## Response Targets | مدة الاستجابة المتوقعة

| Stage | Target |
|-------|--------|
| Acknowledgement of report | within 72 hours |
| Initial assessment / triage | within 7 days |
| Fix or mitigation plan for confirmed issues | within 30 days (severity-dependent) |

We will keep you informed of progress and let you know when the issue is
resolved. Coordinated disclosure is appreciated.

## Supported Versions | الإصدارات المدعومة

Only the latest released version (`v1.x`) receives security fixes.

## What Is NOT Considered a Vulnerability | ما لا يُعد ثغرة

The following are generally **out of scope**:

- Findings that require physical access to a user's machine, or an already
  root/administrator-compromised host.
- Issues that depend on running the tool against networks or devices you are
  **not authorized** to monitor (this tool is for authorized defense only).
- Missing security hardening that has no demonstrable, exploitable impact
  (e.g. "best practice" suggestions without a working attack).
- Reports produced solely by automated scanners without a verified,
  reproducible proof of concept.
- Vulnerabilities in third-party dependencies that are already publicly known
  and have no project-specific exploit path (report those upstream).
- Social engineering, phishing, or physical attacks against OPTISEC staff or
  users.
- Denial of service that requires unrealistic traffic volumes or privileged
  local access.

## Scope | النطاق

This policy covers the code in this repository. It does **not** authorize any
testing against production systems, third-party infrastructure, or networks you
do not own or have explicit written permission to test.
