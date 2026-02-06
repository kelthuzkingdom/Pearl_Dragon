import threading
import socket
import time
import random
import json
import requests
from datetime import datetime
from cryptography.fernet import Fernet
import re
import os
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import ICMP
from scapy.layers.l2 import ARP

class AttackModule:
    def __init__(self, bnra_api_url="http://localhost:5000", target_ip="192.168.1.0/24"):
        self.api_url = bnra_api_url
        self.target_network = target_ip
        self.auth_token = None
        self.defense_module = BNRADefensiveIntel(bnra_api_url)
        self.running = False
        self.attack_signatures = {
            "mimikatz": r"mimikatz",
            "netscan": r"netscan",
            "sql_injection": r"UNION SELECT",
            "xss": r"<script>",
            "zero_day": r"buffer overflow"
        }

    def authenticate_attack(self):
        try:
            response = requests.post(
                f"{self.api_url}/api/auth/login",
                json={"username": "attacker", "password": "bnra2024"}
            )
            if response.status_code == 200:
                self.auth_token = response.json().get('token')
                return True
        except:
            return False

    def start_attack_operations(self):
        self.running = True
        print("[ATTACK] Starting offensive operations...")

        threads = [
            threading.Thread(target=self.port_scan, daemon=True),
            threading.Thread(target=self.dns_enumeration, daemon=True),
            threading.Thread(target=self.network_discovery, daemon=True),
            threading.Thread(target=self.exploit_simulation, daemon=True),
            threading.Thread(target=self.data_exfiltration, daemon=True),
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
            time
