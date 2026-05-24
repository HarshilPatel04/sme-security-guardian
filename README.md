# SME Security Guardian

**Real-time security alerts for non-expert SME operators — in plain English, on their phone.**

Most security tools are built for trained analysts. This one is built for the dental clinic owner, the shop manager, and the small business accountant who has never heard of a SIEM and should not have to.

SME Security Guardian sits on top of [Wazuh](https://wazuh.com) and does three things no existing tool does together:

- Translates technical alerts into plain-English crisis cards with step-by-step instructions
- Classifies every alert as 🔴 RED / 🟡 AMBER / 🟢 GREEN — no security knowledge required to act
- Pushes notifications directly to the business owner's phone via Telegram within seconds of detection

---

## The Problem It Solves

When Wazuh fires this alert:

```
Rule 2502 — Level 10 — MEDIUM
syslog: User missed the password more than one time
```

A trained analyst knows what to do. A dental receptionist does not.

When SME Security Guardian fires for the same attack:

```
🔴 RED ALERT — SME Security Guardian

WHAT HAPPENED:
Someone tried hundreds of passwords on your clinic computer
and one of them may have worked. An attacker may be inside
your system RIGHT NOW reading patient files.

DO THESE IN ORDER:
1. UNPLUG the internet cable from your computer NOW
2. Do NOT turn the computer off — leave it running
3. Take a photo of your screen with your phone
4. Call NHS Digital Cyber Helpline: 0300 303 5035
5. Tell all staff to stop using clinic computers

DO NOT:
❌ Turn the computer off — it destroys evidence
❌ Pay anyone who demands money
❌ Ignore this and go back to work

GDPR: Patient data may have been accessed.
You have 72 hours to report to the ICO.
⏰ Deadline: [calculated timestamp shown here]
```

Anyone can act on that. That is the point.

---

## Features

- **Traffic light system** — RED / AMBER / GREEN mapped to Wazuh severity levels, calibrated for non-experts not analysts
- **11 crisis cards** covering the most common SME attack techniques (MITRE ATT&CK aligned)
- **Sector-aware responses** — Healthcare SME gets GDPR guidance and NHS Digital helpline; Retail SME gets PCI-DSS guidance and payment processor notification steps
- **Telegram push notifications** — alert reaches the business owner's phone in seconds, wherever they are
- **Live web dashboard** — opens in any browser on the local network, no login complexity
- **Regulatory deadline calculation** — GDPR 72-hour and PCI-DSS 24-hour deadlines shown with actual timestamps
- **Zero licensing cost** — runs on Wazuh (free) and standard commodity hardware

---

## Architecture

```
Kali / attacker
      ↓  (attack)
Ubuntu / Windows victim
      ↓  (Wazuh agent)
Wazuh Server — alerts.json
      ↓
SME Security Guardian (Python / Flask)
      ↓                    ↓
Web Dashboard        Telegram Bot
(any browser)        (owner's phone)
```

---

## Sectors Covered

| Sector | Regulatory Guidance | Emergency Contact |
|--------|-------------------|-------------------|
| Healthcare SME | GDPR 72hr ICO report | NHS Digital Cyber Helpline: 0300 303 5035 |
| Retail SME | PCI-DSS 24hr processor notification | Action Fraud: 0300 123 2040 |

---

## MITRE ATT&CK Coverage

| Rule ID | Technique | Severity | Sector |
|---------|-----------|----------|--------|
| 100001 | T1078 — Brute Force | 🟡 AMBER | All |
| 100002 | T1078 — Credential Success | 🔴 RED | All |
| 100003 | T1003 — Credential Dumping | 🔴 RED | Healthcare |
| 100004 | T1003 — LSASS Access | 🔴 RED | All |
| 100005 | T1059 — Shell Execution | 🟡 AMBER | All |
| 100006 | T1059.001 — Obfuscated PowerShell | 🔴 RED | All |
| 100009 | T1486 — Ransomware Indicator | 🔴 RED | All |
| 100015 | T1136 — Backdoor User Created | 🟡 AMBER | Healthcare |
| 100016 | T1136 — Windows User Created | 🟡 AMBER | Retail |

---

## Requirements

- Wazuh v4.x (tested on v4.14.4 / Amazon Linux 2023)
- Python 3.8+
- Flask (`pip3 install flask`)
- Requests (`pip3 install requests`)
- A Telegram bot token (free — create via @BotFather in 2 minutes)

No GPU. No cloud subscription. Runs on a standard VM or low-cost mini PC.

---

## Quick Start

**1 — Clone and install dependencies**

```bash
git clone https://github.com/YOUR_USERNAME/sme-security-guardian
cd sme-security-guardian
pip3 install flask requests
```

**2 — Set up your Telegram bot**

- Open Telegram → search @BotFather → send `/newbot`
- Copy the token it gives you
- Message your new bot once, then visit:
  `https://api.telegram.org/botYOUR_TOKEN/getUpdates`
- Find your `chat_id` in the response

**3 — Configure**

Open `sme_guardian.py` and update lines 12–13:

```python
TELEGRAM_TOKEN   = "your_token_here"
TELEGRAM_CHAT_ID = "your_chat_id_here"
```

**4 — Run**

```bash
sudo python3 sme_guardian.py
```

**5 — Open dashboard**

Navigate to `http://YOUR_WAZUH_IP:5000` in any browser on your network.

**6 — Test**

Run a brute force from Kali against your victim VM:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt YOUR_VICTIM_IP ssh -t 4
```

Within 30 seconds: dashboard turns RED, Telegram message arrives on your phone.

---

## Project Background

This tool was developed as part of a BSc Cybersecurity dissertation at the University of Gloucestershire:

**"Design and Evaluation of a SIEM-Based Threat Detection Framework for Small and Medium Enterprises (SMEs)"**

The research identified a gap in the literature — no existing framework combines plain-language alert communication, sector-specific regulatory guidance, and low-cost deployment for non-expert SME operators. This tool is the practical artefact built to address that gap.

**Experimental results (7 attack simulations, 2,303 alerts captured):**
- Default Wazuh alert readability: 3/5
- SME Security Guardian readability: 5/5
- Custom rules fired: 99 across BASELINE and FRAMEWORK conditions
- CRITICAL chain detection (T1078 + T1136 correlation) achieved

---

## Limitations

- Tested on virtualised lab environment — not a production SME network
- Healthcare and Retail sectors only in current version
- Crisis card content is researcher-defined and should be reviewed by sector professionals before production deployment
- Windows-specific custom rules are limited in current version

---

## Roadmap

- [ ] Additional sectors: Legal, Accountancy, Construction
- [ ] Multi-jurisdiction support: EU (GDPR), US (HIPAA), Australia (Privacy Act)
- [ ] Sector plugin system — JSON-based community contributions
- [ ] One-command installer script
- [ ] Email notification channel alongside Telegram

---

## Responsible Use

This tool is designed for defensive use by owners of systems they are authorised to monitor. It does not facilitate offensive operations. Users are responsible for compliance with applicable laws in their jurisdiction.

---

## Author

**Harshil Patel**  
BSc Cybersecurity — University of Gloucestershire  
📍 Köln, Germany  
📧 pharshil2114@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/harshil-patel-878977308)

---

## License

MIT License — free to use, modify, and distribute with attribution.
