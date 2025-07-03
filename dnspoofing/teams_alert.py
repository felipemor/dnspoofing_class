import requests
import config  # Importa o TEAMS_WEBHOOK do seu config.py

def send_teams_alert(domain, fake_ip, real_ip):
    message = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "Alerta DNS Spoof",
        "themeColor": "EA4300",
        "title": "🔐 Spoof DNS Detectado",
        "sections": [{
            "activityTitle": f"Domínio Spoofado: **{domain}**",
            "facts": [
                {"name": "IP Falso:", "value": fake_ip},
                {"name": "Origem da Consulta (IP real):", "value": real_ip}
            ],
            "markdown": True
        }]
    }
    try:
        requests.post(config.TEAMS_WEBHOOK, json=message)
    except Exception as e:
        print(f"[!] Erro ao enviar alerta Teams: {e}")
