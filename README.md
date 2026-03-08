# DefenceIQ 🛡️

**AI-powered fraud intelligence and financial crime prevention platform**

DefenceIQ is an open-source fraud intelligence platform built for financial services, fintechs, and compliance teams. It combines real-time threat intelligence, AML transaction monitoring, KYC workflows, and device fingerprinting into a single, self-hostable platform — without the enterprise price tag.

> Built by [Abdullateef Tunde Abdulsalam](https://fa3tech.io) · Fa3Tech Limited · UK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey.svg)](https://flask.palletsprojects.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-blue.svg)](https://postgresql.org)

---

## Why DefenceIQ?

Financial crime costs the UK economy over £190 billion annually. Most fraud intelligence platforms are either prohibitively expensive, US-focused, or closed-source black boxes. DefenceIQ was built to:

- Give compliance teams a **self-hostable, auditable** alternative to proprietary platforms
- Provide **real-time fraud intelligence** without per-query API costs
- Support **UK regulatory frameworks** — FCA, PRA, DORA, and the UK Money Laundering Regulations
- Be **open enough** to adapt to African, emerging market, and cross-border fraud patterns often missed by Western-centric tools

---

## Features

### 🔍 Threat Intelligence
| Feature | Description |
|---|---|
| **Dark Web Monitor** | Scan emails, IPs, URLs, and domains against 9 breach databases and threat feeds (HIBP, LeakCheck, EmailRep, AbuseIPDB, URLhaus, PhishTank, VirusTotal, OpenPhish, Tor exit nodes) |
| **IP Reputation** | Full IP analysis with geolocation, ASN, VPN/proxy/Tor detection, abuse score, and BGP ranking |
| **Phishing & Domain Alerts** | 7-source domain scanner with brand impersonation detection, typosquatting analysis, and certificate transparency monitoring via crt.sh |

### 🏦 Financial Crime Compliance
| Feature | Description |
|---|---|
| **AML Transaction Monitoring** | 12-rule screening engine covering structuring, velocity, round-trip patterns, high-risk jurisdictions, and suspicious narratives. SAR/STR filing workflow included |
| **Watchlist & Sanctions Screening** | Fuzzy-match screening against UN Security Council (1,002 entries) and UK HMT OFSI (8,048 entries) sanctions lists with alias support and 3 sensitivity levels |
| **KYC Workflow** | Customer due diligence with auto risk scoring, Standard/Enhanced DD classification, PEP and sanctions flags, document checklist lifecycle (required → uploaded → verified), and Approve/Reject workflow |

### 🧠 Behavioural & Device Intelligence
| Feature | Description |
|---|---|
| **Behavioural Risk Scoring** | 8-signal entity scoring engine using your own case history — frequency, severity, fraud type diversity, recency, financial exposure, velocity, and threat intel hits |
| **Device Fingerprinting** | Silent JavaScript fingerprint collector capturing screen, timezone, canvas hash, WebGL, fonts, plugins, and webdriver flag. Analyses 10 fraud signals including headless browsers, VPN ASNs, timezone mismatches, and anti-detect browsers |

### 📊 Case Management
- Fraud case creation and lifecycle tracking
- Indicator submission (email, IP, domain, URL, hash)
- Compliance report generation (PDF)
- Audit logging for all analyst actions
- Webhook support for real-time alerting

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.x |
| Database | PostgreSQL 14+ with SQLAlchemy |
| Auth | Flask-Login with CSRF protection |
| Email | Brevo (SMTP relay) |
| Frontend | Jinja2 templates, Syne + JetBrains Mono fonts |
| Deployment | Ubuntu 22.04 LTS, Gunicorn, Nginx |

---

## Getting Started

### Prerequisites

- Ubuntu 22.04+ (or any Debian-based Linux)
- Python 3.10+
- PostgreSQL 14+
- Nginx

### 1. Clone the Repository

```bash
git clone https://github.com/fa3tech/defenceiq.git
cd defenceiq
```

### 2. Set Up Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

Fill in your values:

```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:password@localhost/defenceiq

# Email (Brevo or any SMTP)
MAIL_SERVER=smtp-relay.brevo.com
MAIL_PORT=587
MAIL_USERNAME=your@email.com
MAIL_PASSWORD=your-smtp-key

# Threat Intelligence APIs (all free tiers supported)
ABUSEIPDB_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
ANTHROPIC_API_KEY=your-key   # Used for AI risk narrative generation
```

### 4. Initialise the Database

```bash
python3 -c "from app import app, db; app.app_context().push(); db.create_all(); print('Done')"
```

### 5. Run with Gunicorn

```bash
gunicorn -w 4 -b 127.0.0.1:5002 app:app
```

### 6. Configure Nginx

```nginx
server {
    server_name yourdomain.com;
    location / {
        proxy_pass http://127.0.0.1:5002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## API Keys (Free Tier)

All external integrations work on free API tiers:

| Service | Used For | Free Limit |
|---|---|---|
| [AbuseIPDB](https://abuseipdb.com) | IP reputation | 1,000 checks/day |
| [VirusTotal](https://virustotal.com) | Domain & URL scanning | 500 requests/day |
| [HaveIBeenPwned](https://haveibeenpwned.com/API/v3) | Breach detection | Passwords free, email needs key |
| [URLScan.io](https://urlscan.io) | Domain scanning | 100 scans/day |
| [Anthropic Claude](https://anthropic.com) | AI risk narratives | Pay-per-use |
| UN & HMT Sanctions Lists | Sanctions screening | Free, publicly available |

---

## Architecture

```
defenceiq/
├── app.py                    # Main Flask application & routes
├── darkweb_monitor.py        # Dark web & breach intelligence
├── ip_reputation.py          # IP threat analysis
├── phishing_checker.py       # Domain & phishing detection
├── sanctions_checker.py      # Fuzzy sanctions screening
├── behavioural_scorer.py     # Entity risk scoring
├── aml_engine.py             # AML transaction rules engine
├── kyc_engine.py             # KYC due diligence workflow
├── device_fingerprint.py     # Browser fingerprint analysis
├── templates/                # Jinja2 HTML templates
├── static/                   # CSS, JS assets
└── requirements.txt
```

---

## Screenshots

> _Screenshots coming soon — demo instance available at [defenceiq.io](https://defenceiq.io)_

---

## Sanctions Data Sources

- **UN Security Council Consolidated List** — Al-Qaida, Taliban, DPRK, ISIS, and associated individuals/entities. Updated from the UN XML feed.
- **UK HMT OFSI (Office of Financial Sanctions Implementation)** — Russia, Iran, Myanmar, Belarus, and global regimes. Updated from the HMT CSV feed.

Both lists are cached locally for 24 hours and refreshed automatically. The fuzzy matching engine handles name variations, aliases, transliterations, and common OCR errors.

---

## Roadmap

- [ ] Stripe billing integration (for hosted tier)
- [ ] OFAC SDN list integration
- [ ] EU Consolidated Sanctions List
- [ ] REST API for third-party integration
- [ ] Webhook event streaming
- [ ] Multi-tenant role-based access control
- [ ] DORA compliance reporting module
- [ ] Mobile-optimised dashboard

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for significant changes.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request

---

## Regulatory Context

DefenceIQ is designed with UK financial crime regulations in mind:

- **UK Money Laundering Regulations 2017** — KYC, CDD, and EDD workflows
- **FCA Handbook (SYSC)** — Systems and controls for financial crime prevention
- **DORA (Digital Operational Resilience Act)** — Threat intelligence and incident logging
- **Proceeds of Crime Act 2002** — SAR/STR filing workflow support

> ⚠️ DefenceIQ is a decision-support tool. It does not constitute legal or compliance advice. Always consult qualified compliance professionals for regulatory obligations.

---

## About the Author

DefenceIQ was built by **Abdullateef Tunde Abdulsalam**, a cybersecurity analyst and consultant specialising in financial services security, fraud intelligence, and regulatory compliance at a major UK bank.

- 🌐 [fa3tech.io](https://fa3tech.io)
- 💼 [LinkedIn](https://www.linkedin.com/in/aabdullateef/)
- 🔒 Also building [CertPulse](https://certpulse.tech) — SSL certificate monitoring & Autorenewal platform

---

## License

MIT License — see [LICENSE](LICENSE) for details.

You are free to use, modify, and distribute this software. Attribution appreciated but not required.
