#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
# SME SECURITY GUARDIAN
# Dissertation Framework — Human-Centric SIEM for Non-Expert SMEs
#
# Architecture:
#   Wazuh alerts.json → This app → Traffic Light Classification →
#   Sector-Specific Crisis Cards → Web Dashboard + Telegram
#
# Run on Wazuh VM:    sudo python3 sme_guardian.py
# Dashboard:          http://192.168.56.4:5000
# ═══════════════════════════════════════════════════════════════════

import json
import time
import os
import threading
from datetime import datetime, timedelta
from flask import Flask, jsonify
import requests

# ═══════════════════════════════════════════════════════════════════
# CONFIG — REPLACE THESE TWO WITH YOUR TELEGRAM VALUES
# ═══════════════════════════════════════════════════════════════════
TELEGRAM_TOKEN   = "YOUR_TELEGRAM_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID_HERE"

ALERTS_LOG   = "/var/ossec/logs/alerts/alerts.json"
SECTOR_MAP   = {
    "001": "healthcare",
    "002": "retail",
    "000": "server"
}

app_state = {
    "current_status": "GREEN",
    "current_alert": None,
    "recent_alerts": [],
    "last_update": datetime.now().isoformat(),
    "total_red": 0, "total_amber": 0, "total_green": 0
}

# ═══════════════════════════════════════════════════════════════════
# TRAFFIC LIGHT CLASSIFIER
# ═══════════════════════════════════════════════════════════════════
def classify_severity(level, rule_id):
    l = int(level) if str(level).isdigit() else 0
    r = str(rule_id)
    if r.startswith("100"):
        if l >= 14: return "RED"
        if l >= 10: return "AMBER"
        return "AMBER"
    if l >= 12: return "RED"
    if l >= 8:  return "AMBER"
    if l >= 5:  return "AMBER"
    return "GREEN"

# ═══════════════════════════════════════════════════════════════════
# SECTOR-SPECIFIC CRISIS CARDS (written for Dr. Ahmed persona)
# ═══════════════════════════════════════════════════════════════════

CRISIS_CARDS = {

    # ─── HEALTHCARE ────────────────────────────────────────────────
    ("100001", "healthcare"): {
        "color": "AMBER",
        "title": "Someone is trying passwords on your computer",
        "what_happened": (
            "Someone outside your clinic is trying to guess your password "
            "by trying hundreds of passwords very quickly. This is like "
            "someone standing at your front door trying every key in a huge "
            "bunch. They have not got in yet, but they are actively trying."
        ),
        "do_in_order": [
            "Ask your staff: 'Did any of you forget your password and try to log in this morning?' If YES and it matches — this is fine, dismiss this alert.",
            "If NO staff was trying to log in — this is a real attack.",
            "Unplug the internet cable from your computer. It is the big blue cable (like a fat phone cable) at the back.",
            "Write the time right now on a piece of paper — you may need this for GDPR later.",
            "Call your IT person OR the NHS Digital Cyber Helpline on 0300 303 5035. Say: 'I have a red security alert on my clinic computer'."
        ],
        "do_not": [
            "Do NOT turn the computer off",
            "Do NOT keep using the computer normally",
            "Do NOT click any pop-up that appears",
            "Do NOT enter your password again"
        ],
        "regulatory": "GDPR NOTE: If patient records were accessed, you must report this to the ICO within 72 hours. Keep this alert as evidence.",
        "deadline_hours": 72,
        "emergency_contact": "NHS Digital Cyber Helpline: 0300 303 5035  |  ICO: ico.org.uk/report"
    },

    ("100002", "healthcare"): {
        "color": "RED",
        "title": "EMERGENCY — Someone may have broken into your computer",
        "what_happened": (
            "Someone tried many passwords on your clinic computer and one "
            "of them worked. An attacker may now be inside your computer "
            "RIGHT NOW. They may be reading patient files, copying records, "
            "or installing hidden programs. Every minute matters."
        ),
        "do_in_order": [
            "UNPLUG the internet cable from your computer in the next 2 minutes.",
            "Do NOT turn the computer off. Leave it running — police evidence.",
            "Take a photo of your computer screen with your phone NOW.",
            "Write down today's date and the exact time on paper.",
            "Call NHS Digital Cyber Helpline RIGHT NOW: 0300 303 5035. Say: 'Someone has broken into my clinic computer'.",
            "Tell all staff to stop using any clinic computer until help arrives.",
            "Lock your office door if patient files are stored there."
        ],
        "do_not": [
            "Do NOT turn the computer off — it destroys evidence",
            "Do NOT plug in any USB sticks or backup drives",
            "Do NOT open or close any programs",
            "Do NOT pay anyone who demands money",
            "Do NOT go back to work as normal"
        ],
        "regulatory": (
            "URGENT GDPR: Patient data may have been accessed. You MUST "
            "report to the ICO within 72 hours. Failing to report can cost "
            "up to £17.5 million in fines. The ICO needs: what happened, "
            "when it happened, what data was affected, what you did."
        ),
        "deadline_hours": 72,
        "emergency_contact": "NHS Digital Cyber Helpline: 0300 303 5035  |  Police cyber crime: 0300 123 2040  |  ICO: 0303 123 1113"
    },

    ("100003", "healthcare"): {
        "color": "RED",
        "title": "EMERGENCY — Your clinic password file was touched",
        "what_happened": (
            "The secret file that stores all the passwords on your clinic "
            "computer has been accessed. This file holds the login details "
            "for every user including yours. An attacker with this file can "
            "pretend to be you or your staff to access any system — NHS "
            "patient portals, banking, email, everything."
        ),
        "do_in_order": [
            "UNPLUG the internet cable right now.",
            "Do NOT turn the computer off.",
            "Take a photo of the screen with your phone.",
            "Write down the time and date on paper right now.",
            "Call NHS Digital Cyber Helpline: 0300 303 5035. Say: 'My clinic password file has been accessed'.",
            "Using YOUR PHONE (not the clinic computer): change your banking password, your personal email password, and any NHS portal passwords.",
            "Tell staff to do the same from their personal phones.",
            "Do NOT let anyone log into the clinic computer until cleared by IT."
        ],
        "do_not": [
            "Do NOT log back into the clinic computer",
            "Do NOT type ANY password into this computer",
            "Do NOT turn it off",
            "Do NOT let staff use the clinic computer"
        ],
        "regulatory": (
            "CRITICAL GDPR BREACH: Almost certainly reportable under Article 33. "
            "72-hour ICO notification clock starts NOW. You may also need to "
            "notify every patient whose data was on this system. Keep this "
            "alert, take screenshots, preserve ALL evidence."
        ),
        "deadline_hours": 72,
        "emergency_contact": "NHS Digital Cyber Helpline: 0300 303 5035  |  ICO Breach: ico.org.uk/for-organisations/report-a-breach"
    },

    ("100015", "healthcare"): {
        "color": "AMBER",
        "title": "A new user account was just created on your computer",
        "what_happened": (
            "Someone just created a new user account on your clinic computer. "
            "This is like someone making a new key to your front door. If "
            "you or your staff did not create this account, an attacker has "
            "made a hidden back-door to get into your system even after you "
            "change your passwords."
        ),
        "do_in_order": [
            "Ask your staff: 'Did any of you create a new computer account today?' If yes and it matches — dismiss.",
            "If NO ONE created it — this is an attacker's hidden account.",
            "Do NOT delete the account yourself — IT support needs to see it for evidence.",
            "Take a photo of your screen.",
            "Call NHS Digital Cyber Helpline: 0300 303 5035. Say: 'A new account appeared on my clinic computer that nobody created'.",
            "Change your own main password to the clinic computer using your phone — NOT the clinic computer."
        ],
        "do_not": [
            "Do NOT delete the new account (evidence needed)",
            "Do NOT log in AS the new account",
            "Do NOT ignore this if nobody admits creating it"
        ],
        "regulatory": "GDPR NOTE: If this account was used to access patient data, 72-hour ICO reporting clock starts now.",
        "deadline_hours": 72,
        "emergency_contact": "NHS Digital Cyber Helpline: 0300 303 5035"
    },

    ("100009", "healthcare"): {
        "color": "RED",
        "title": "EMERGENCY — RANSOMWARE — Your files are being locked",
        "what_happened": (
            "Your computer files are being encrypted by ransomware. This "
            "means all your patient records, appointment books, X-rays and "
            "documents are being locked RIGHT NOW so you cannot open them. "
            "The attackers will demand money to unlock them. Every second "
            "matters — the longer this runs the more files are destroyed."
        ),
        "do_in_order": [
            "UNPLUG the internet cable THIS SECOND.",
            "Also pull out any external hard drives or USB sticks — physically remove them.",
            "Do NOT turn the computer off.",
            "Take a photo of the screen — especially any ransom note that appears.",
            "Call Action Fraud: 0300 123 2040 AND NHS Digital Cyber Helpline: 0300 303 5035.",
            "Tell all staff to NOT touch any other computer in the clinic.",
            "Check if any other computers in the clinic show the same problem — if yes, unplug them too.",
            "DO NOT PAY THE RANSOM. Paying funds criminals and does not guarantee file recovery."
        ],
        "do_not": [
            "Do NOT pay the ransom under any circumstances without expert advice",
            "Do NOT turn the computer off",
            "Do NOT plug in any backups — they may get infected too",
            "Do NOT use any other clinic computer until told it is safe"
        ],
        "regulatory": (
            "MAJOR GDPR INCIDENT: Ransomware is always a reportable breach. "
            "ICO MUST be notified within 72 hours. Patients whose data may "
            "be affected may need to be individually notified. This is the "
            "most serious type of data breach possible."
        ),
        "deadline_hours": 72,
        "emergency_contact": "NHS Digital Cyber Helpline: 0300 303 5035  |  Action Fraud: 0300 123 2040  |  ICO: 0303 123 1113"
    },

    # ─── RETAIL ────────────────────────────────────────────────────
    ("100001", "retail"): {
        "color": "AMBER",
        "title": "Someone is trying passwords on your till",
        "what_happened": (
            "Someone is trying many passwords to log into your shop computer "
            "or till system. This could be someone trying to steal customer "
            "card details. Even if they have not got in yet, they are "
            "actively trying RIGHT NOW."
        ),
        "do_in_order": [
            "Ask staff: 'Did anyone forget their password?' If yes and matches — dismiss.",
            "If NOBODY was trying — this is a real attack.",
            "Unplug the internet cable from your till computer.",
            "Stop taking card payments — only cash until cleared. Tell customers: 'card machine issue, cash only please'.",
            "Call your card payment provider (Worldpay, SumUp, Square etc) and tell them about this alert.",
            "Call Action Fraud: 0300 123 2040.",
            "Write down the time and keep this alert as evidence."
        ],
        "do_not": [
            "Do NOT process card payments until cleared",
            "Do NOT turn the till computer off",
            "Do NOT ignore the alert"
        ],
        "regulatory": "PCI-DSS: If cardholder data was exposed, you must notify your card processor within 24 hours.",
        "deadline_hours": 24,
        "emergency_contact": "Your card payment provider  |  Action Fraud: 0300 123 2040"
    },

    ("100002", "retail"): {
        "color": "RED",
        "title": "EMERGENCY — Attacker broke into your till system",
        "what_happened": (
            "Someone guessed the password to your shop computer and is now "
            "logged in. They may be reading customer card details, copying "
            "transaction records, or installing card-skimming software. "
            "Your customers' card numbers could be leaving your shop right now."
        ),
        "do_in_order": [
            "UNPLUG the internet cable NOW.",
            "STOP taking card payments. Tell customers 'cash only today — system issue'.",
            "Do NOT turn the computer off.",
            "Take a photo of the screen.",
            "Call your card payment provider (Worldpay/SumUp/Square) RIGHT NOW. Say: 'My till has been compromised, I need emergency PCI-DSS support'.",
            "Call Action Fraud: 0300 123 2040.",
            "Keep ALL receipts from today — do not throw any away.",
            "Do not let staff use any shop computer until help arrives."
        ],
        "do_not": [
            "Do NOT process ANY card payments",
            "Do NOT turn the till off",
            "Do NOT throw away today's receipts",
            "Do NOT post about this on social media yet"
        ],
        "regulatory": (
            "PCI-DSS MAJOR INCIDENT: 24 hours to notify your card processor. "
            "You may need to notify affected customers. Card fraud traced "
            "to your till can lose you the ability to take card payments "
            "in future. This is as serious as it gets for a retail business."
        ),
        "deadline_hours": 24,
        "emergency_contact": "Your card payment provider  |  Action Fraud: 0300 123 2040  |  ICO: 0303 123 1113"
    },

    ("100004", "retail"): {
        "color": "RED",
        "title": "EMERGENCY — Password stealer active on your till",
        "what_happened": (
            "A program is trying to steal passwords and card details from "
            "your till computer's memory. This specific technique is used "
            "in almost every major shop card-data theft. If this is real, "
            "your customers' card numbers may be leaving your shop now."
        ),
        "do_in_order": [
            "UNPLUG the internet cable IMMEDIATELY.",
            "Stop card payments — cash only from this second.",
            "Do not turn the till off.",
            "Photo the screen with your phone.",
            "Call your payment processor NOW.",
            "Call Action Fraud: 0300 123 2040.",
            "Keep every receipt from today."
        ],
        "do_not": [
            "Do NOT take card payments",
            "Do NOT restart or shut down the till",
            "Do NOT delete any files"
        ],
        "regulatory": "PCI-DSS CRITICAL: 24-hour payment processor notification required.",
        "deadline_hours": 24,
        "emergency_contact": "Your card provider emergency line  |  Action Fraud: 0300 123 2040"
    },

    ("100008", "retail"): {
        "color": "RED",
        "title": "EMERGENCY — Attacker spreading between your shop computers",
        "what_happened": (
            "An attacker is trying to spread from one computer to another "
            "in your shop. If you have a till and a back-office computer "
            "both connected, both may now be compromised. This is how "
            "major retail chains have lost millions of card records."
        ),
        "do_in_order": [
            "Unplug ALL shop computers from the internet — every cable.",
            "Turn off the WiFi router (the flashing-lights box).",
            "Stop card payments immediately.",
            "Do NOT turn the computers off.",
            "Call your card payment provider: 'My shop network is compromised, emergency.'",
            "Call Action Fraud: 0300 123 2040.",
            "Keep all receipts from today."
        ],
        "do_not": [
            "Do NOT take card payments",
            "Do NOT turn computers off",
            "Do NOT reconnect to internet until cleared"
        ],
        "regulatory": "PCI-DSS MAJOR: Likely affects multiple systems. Processor notification in 24 hours.",
        "deadline_hours": 24,
        "emergency_contact": "Card payment provider emergency  |  Action Fraud: 0300 123 2040"
    },

    ("100013", "retail"): {
        "color": "AMBER",
        "title": "Someone may have opened a bad email attachment",
        "what_happened": (
            "A suspicious program just ran on your shop computer. This "
            "usually happens when someone opens an email attachment that "
            "looks like an invoice, delivery notice or supplier document "
            "but is actually a trick to install malware."
        ),
        "do_in_order": [
            "Ask staff: 'Did anyone just open an email attachment?'",
            "If YES — ask who it was from and if they expected it.",
            "If the email was NOT expected or looked strange — it was likely malicious.",
            "Unplug the affected computer from the internet.",
            "Do not open any more emails from that sender.",
            "Call your IT support for a virus scan."
        ],
        "do_not": [
            "Do NOT open more attachments until cleared",
            "Do NOT forward the suspicious email to anyone",
            "Do NOT reply to the sender"
        ],
        "regulatory": "PCI-DSS: If card systems are affected, notify your payment processor.",
        "deadline_hours": 24,
        "emergency_contact": "Your IT support  |  Action Fraud: 0300 123 2040"
    },

    ("100016", "retail"): {
        "color": "AMBER",
        "title": "New account created on your shop computer",
        "what_happened": (
            "A new user account was created on your shop computer using a "
            "command line (not the normal way). Attackers create hidden "
            "accounts to keep access even after you change passwords."
        ),
        "do_in_order": [
            "Ask staff: 'Did any of you create a new account today?'",
            "If YES and matches — dismiss this alert.",
            "If NO — this is an attacker's hidden backdoor.",
            "Do NOT delete the account — IT support needs evidence.",
            "Take a photo of the screen.",
            "Call your card payment provider AND your IT support.",
            "Change your own password using your phone, not the shop computer."
        ],
        "do_not": [
            "Do NOT delete the new account",
            "Do NOT log in AS the new account",
            "Do NOT ignore if staff do not recognise it"
        ],
        "regulatory": "PCI-DSS: Potentially serious. 24-hour notification if card systems affected.",
        "deadline_hours": 24,
        "emergency_contact": "Your IT support  |  Card payment provider  |  Action Fraud: 0300 123 2040"
    },
}

# ═══════════════════════════════════════════════════════════════════
# TELEGRAM NOTIFIER
# ═══════════════════════════════════════════════════════════════════
def send_telegram(card, sector, agent_name):
    if "YOUR_TELEGRAM" in TELEGRAM_TOKEN:
        print("[Telegram] Token not configured — skipping")
        return

    color = card['color']
    emoji = {"RED":"🔴","AMBER":"🟡","GREEN":"🟢"}.get(color,"⚪")

    lines = [
        f"{emoji} *{color} ALERT — SME Security Guardian*",
        "",
        f"*{card['title']}*",
        "",
        f"_Sector: {sector.upper()}_",
        f"_System: {agent_name}_",
        f"_Time: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}_",
        "",
        "*WHAT HAPPENED:*",
        card['what_happened'],
        ""
    ]

    if card.get('do_in_order'):
        lines.append("*DO THESE IN ORDER:*")
        for i, s in enumerate(card['do_in_order'], 1):
            lines.append(f"{i}. {s}")
        lines.append("")

    if card.get('do_not'):
        lines.append("*DO NOT:*")
        for s in card['do_not']:
            lines.append(f"❌ {s}")
        lines.append("")

    if card.get('regulatory'):
        lines.append(f"*REGULATORY:*\n{card['regulatory']}\n")

    if card.get('deadline_hours'):
        deadline = datetime.now() + timedelta(hours=card['deadline_hours'])
        lines.append(f"⏰ *Action deadline: {deadline.strftime('%H:%M on %d/%m/%Y')}*")
        lines.append("")

    if card.get('emergency_contact'):
        lines.append(f"📞 *Emergency: {card['emergency_contact']}*")

    message = "\n".join(lines)

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        r = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }, timeout=10)
        if r.status_code == 200:
            print(f"[Telegram] ✓ {color} sent")
        else:
            print(f"[Telegram] ✗ {r.status_code}: {r.text[:150]}")
    except Exception as e:
        print(f"[Telegram] Error: {e}")

# ═══════════════════════════════════════════════════════════════════
# ALERT PROCESSOR
# ═══════════════════════════════════════════════════════════════════
def process_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    rule_id = str(rule.get("id", ""))
    level = rule.get("level", 0)
    desc = rule.get("description", "")
    agent_id = str(agent.get("id", "000")).zfill(3)
    agent_name = agent.get("name", "unknown")

    sector = SECTOR_MAP.get(agent_id, "healthcare")
    color = classify_severity(level, rule_id)

    key = (rule_id, sector)
    if key in CRISIS_CARDS:
        card = CRISIS_CARDS[key].copy()
    else:
        if color == "GREEN":
            return None  # skip noise
        card = {
            "color": color,
            "title": desc[:80] if desc else f"Rule {rule_id}",
            "what_happened": f"Wazuh detected unusual activity: {desc}",
            "do_in_order": [
                "Ask your staff if anyone did anything unusual in the last few minutes",
                "If nobody recognises this — unplug the internet cable",
                "Call your IT support"
            ],
            "do_not": [
                "Do NOT turn the computer off",
                "Do NOT ignore if staff does not recognise the activity"
            ],
            "regulatory": "Regulatory notification may be required depending on what was affected",
            "deadline_hours": 72 if sector == "healthcare" else 24,
            "emergency_contact": "Your IT support or relevant regulator"
        }

    record = {
        "timestamp": datetime.now().isoformat(),
        "time_display": datetime.now().strftime("%H:%M:%S"),
        "color": card['color'],
        "title": card['title'],
        "agent_name": agent_name,
        "sector": sector,
        "rule_id": rule_id,
        "level": level,
        "card": card
    }

    app_state["recent_alerts"].insert(0, record)
    app_state["recent_alerts"] = app_state["recent_alerts"][:20]
    app_state["last_update"] = datetime.now().isoformat()

    if card['color'] == "RED":
        app_state["current_status"] = "RED"
        app_state["current_alert"] = record
        app_state["total_red"] += 1
        send_telegram(card, sector, agent_name)
    elif card['color'] == "AMBER":
        if app_state["current_status"] != "RED":
            app_state["current_status"] = "AMBER"
            app_state["current_alert"] = record
        app_state["total_amber"] += 1
        send_telegram(card, sector, agent_name)
    else:
        app_state["total_green"] += 1

    return record

# ═══════════════════════════════════════════════════════════════════
# MONITOR THREAD
# ═══════════════════════════════════════════════════════════════════
def monitor_alerts():
    print(f"[Monitor] Watching {ALERTS_LOG}")
    while not os.path.exists(ALERTS_LOG):
        print("[Monitor] Waiting for alerts.json ...")
        time.sleep(5)

    with open(ALERTS_LOG, "r") as f:
        f.seek(0, 2)
        print("[Monitor] Live monitoring active")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                alert = json.loads(line.strip())
                record = process_alert(alert)
                if record:
                    tag = {"RED":"🔴","AMBER":"🟡","GREEN":"🟢"}.get(record['color'],"⚪")
                    print(f"{tag} [{record['time_display']}] "
                          f"Rule {record['rule_id']} | "
                          f"{record['agent_name']} | "
                          f"{record['title'][:55]}")
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[Monitor] Error: {e}")

# ═══════════════════════════════════════════════════════════════════
# FLASK WEB DASHBOARD
# ═══════════════════════════════════════════════════════════════════
app = Flask(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SME Security Guardian</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, Arial, sans-serif; }
body { background:#0D1B2A; color:#E8F4FD; min-height:100vh; padding:20px; }
.container { max-width:1200px; margin:0 auto; }
.header { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; padding-bottom:16px; border-bottom:2px solid #00C6AE; }
.header h1 { color:#00C6AE; font-size:24px; }
.header .sub { color:#8BAFC8; font-size:14px; margin-top:4px; }
.header .time { color:#8BAFC8; font-size:13px; font-family:monospace; }
.status-banner { padding:40px; border-radius:16px; margin-bottom:24px; text-align:center; font-weight:900; transition:all .3s; }
.status-banner .label { font-size:13px; font-weight:400; opacity:0.85; letter-spacing:3px; margin-bottom:8px; }
.status-banner .text { font-size:44px; }
.status-RED { background: linear-gradient(135deg, #E63946, #B12330); color:#FFF; animation:pulse 1.5s infinite; }
.status-AMBER { background: linear-gradient(135deg, #F4A261, #D4842F); color:#1A1A2E; }
.status-GREEN { background: linear-gradient(135deg, #52B788, #2D8659); color:#FFF; }
@keyframes pulse { 0%,100% { transform:scale(1); box-shadow:0 0 40px rgba(230,57,70,.5);} 50% { transform:scale(1.02); box-shadow:0 0 60px rgba(230,57,70,.8);} }
.stats { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-bottom:24px; }
.stat { background:#1B2C3E; padding:20px; border-radius:12px; text-align:center; }
.stat .n { font-size:36px; font-weight:900; }
.stat .l { font-size:11px; color:#8BAFC8; letter-spacing:1px; margin-top:4px; }
.stat.red .n { color:#E63946; } .stat.amber .n { color:#F4A261; } .stat.green .n { color:#52B788; }
.section { background:#1B2C3E; border-radius:12px; padding:24px; margin-bottom:20px; }
.section h2 { color:#00C6AE; margin-bottom:16px; font-size:17px; padding-bottom:8px; border-bottom:1px solid #2D3A50; }
.crisis { background:#0F1F30; padding:24px; border-radius:12px; border-left:6px solid #00C6AE; }
.crisis.RED { border-left-color:#E63946; } .crisis.AMBER { border-left-color:#F4A261; } .crisis.GREEN { border-left-color:#52B788; }
.crisis h3 { font-size:20px; margin-bottom:12px; color:#FFF; }
.crisis .what { font-size:15px; line-height:1.6; margin-bottom:20px; padding:14px; background:rgba(0,0,0,.25); border-radius:8px; }
.block { margin-bottom:18px; }
.block h4 { font-size:12px; letter-spacing:1.5px; margin-bottom:10px; color:#00C6AE; }
.block.dont h4 { color:#E63946; }
.block ol { padding-left:24px; }
.block ol li { padding:8px 0; line-height:1.5; }
.block ul { list-style:none; }
.block ul li { padding:6px 0 6px 28px; position:relative; line-height:1.5; }
.block.dont ul li::before { content:"✕"; position:absolute; left:6px; color:#E63946; font-weight:900; }
.regulatory { padding:14px; background:rgba(244,162,97,.12); border-left:4px solid #F4A261; border-radius:6px; margin-bottom:10px; font-size:13px; line-height:1.5; }
.regulatory strong { color:#F4A261; display:block; margin-bottom:4px; }
.deadline { padding:14px; background:rgba(230,57,70,.12); border-left:4px solid #E63946; border-radius:6px; margin-bottom:10px; font-weight:700; color:#E63946; }
.contact { padding:14px; background:rgba(45,125,210,.12); border-left:4px solid #2D7DD2; border-radius:6px; font-size:13px; }
.contact strong { color:#2D7DD2; display:block; margin-bottom:4px; }
.recent-item { display:flex; gap:12px; padding:10px; background:rgba(0,0,0,.2); border-radius:8px; margin-bottom:8px; align-items:center; }
.dot { width:12px; height:12px; border-radius:50%; flex-shrink:0; }
.recent-item.RED .dot { background:#E63946; box-shadow:0 0 8px #E63946; }
.recent-item.AMBER .dot { background:#F4A261; }
.recent-item.GREEN .dot { background:#52B788; }
.recent-item .t { color:#8BAFC8; font-size:12px; font-family:monospace; min-width:70px; }
.recent-item .title { flex:1; font-size:13px; }
.recent-item .sec { font-size:10px; color:#8BAFC8; letter-spacing:1px; }
.empty { text-align:center; padding:40px; color:#8BAFC8; font-size:13px; }
@media(max-width:768px){ .stats{grid-template-columns:1fr;} .status-banner .text{font-size:32px;} }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>🛡️ SME Security Guardian</h1>
      <div class="sub">Human-Centric Alert System  |  Healthcare + Retail</div>
    </div>
    <div class="time" id="time">--:--:--</div>
  </div>
  <div class="status-banner status-GREEN" id="status">
    <div class="label">CURRENT STATUS</div>
    <div class="text" id="status-text">ALL CLEAR</div>
  </div>
  <div class="stats">
    <div class="stat red"><div class="n" id="s-red">0</div><div class="l">RED ALERTS</div></div>
    <div class="stat amber"><div class="n" id="s-amber">0</div><div class="l">AMBER ALERTS</div></div>
    <div class="stat green"><div class="n" id="s-green">0</div><div class="l">NORMAL</div></div>
  </div>
  <div class="section">
    <h2>⚠️ Current Crisis Card</h2>
    <div id="card"><div class="empty">No active alerts. System monitoring normally.</div></div>
  </div>
  <div class="section">
    <h2>📋 Recent Activity (last 20)</h2>
    <div id="recent"><div class="empty">No alerts yet. Monitoring...</div></div>
  </div>
</div>
<script>
function updateTime(){ document.getElementById('time').textContent = new Date().toLocaleTimeString(); }
setInterval(updateTime,1000); updateTime();
async function fetchState(){
  try {
    const r = await fetch('/api/state'); const d = await r.json();
    const sb = document.getElementById('status');
    sb.className = 'status-banner status-' + d.current_status;
    document.getElementById('status-text').textContent =
      d.current_status==='RED' ? '🚨 RED ALERT 🚨' :
      d.current_status==='AMBER' ? '⚠ ATTENTION NEEDED' : '✓ ALL CLEAR';
    document.getElementById('s-red').textContent = d.total_red;
    document.getElementById('s-amber').textContent = d.total_amber;
    document.getElementById('s-green').textContent = d.total_green;
    const cardEl = document.getElementById('card');
    if (d.current_alert && d.current_alert.card) {
      const c = d.current_alert.card;
      let h = '<div class="crisis '+c.color+'"><h3>'+c.title+'</h3><div class="what">'+c.what_happened+'</div>';
      if (c.do_in_order && c.do_in_order.length) { h+='<div class="block"><h4>DO THESE IN ORDER:</h4><ol>'; c.do_in_order.forEach(s=>h+='<li>'+s+'</li>'); h+='</ol></div>'; }
      if (c.do_not && c.do_not.length) { h+='<div class="block dont"><h4>DO NOT:</h4><ul>'; c.do_not.forEach(s=>h+='<li>'+s+'</li>'); h+='</ul></div>'; }
      if (c.regulatory) h+='<div class="regulatory"><strong>REGULATORY:</strong>'+c.regulatory+'</div>';
      if (c.deadline_hours) h+='<div class="deadline">⏰ Action deadline: '+c.deadline_hours+' hours</div>';
      if (c.emergency_contact) h+='<div class="contact"><strong>EMERGENCY CONTACT:</strong>'+c.emergency_contact+'</div>';
      h+='</div>';
      cardEl.innerHTML = h;
    }
    const rEl = document.getElementById('recent');
    if (d.recent_alerts && d.recent_alerts.length) {
      rEl.innerHTML = d.recent_alerts.map(a =>
        '<div class="recent-item '+a.color+'"><div class="dot"></div><div class="t">'+a.time_display+'</div><div class="title">'+a.title+'</div><div class="sec">'+a.sector.toUpperCase()+'</div></div>'
      ).join('');
    }
  } catch(e){ console.error(e); }
}
fetchState(); setInterval(fetchState, 2000);
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    return DASHBOARD_HTML

@app.route("/api/state")
def api_state():
    return jsonify(app_state)

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "="*68)
    print("  SME SECURITY GUARDIAN — Human-Centric SIEM for SMEs")
    print("  Sectors: Healthcare + Retail")
    print("="*68)
    print(f"  Dashboard : http://192.168.56.4:5000")
    print(f"  Alerts    : {ALERTS_LOG}")
    tgram = "Configured" if "YOUR_TELEGRAM" not in TELEGRAM_TOKEN else "NOT configured (edit TELEGRAM_TOKEN)"
    print(f"  Telegram  : {tgram}")
    print("="*68 + "\n")

    t = threading.Thread(target=monitor_alerts, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
