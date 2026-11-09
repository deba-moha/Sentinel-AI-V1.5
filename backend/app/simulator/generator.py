"""
Sentinel AI - Synthetic Telemetry & Attack Generator
Generates realistic security events and simulated cyber-attacks for demonstration.
Note: All generation is purely synthetic within the local database. No actual network packets or flooding are produced.
"""
import random
from datetime import datetime, timezone
from typing import List
from backend.app.schemas.log import LogCreate


class LogGenerator:
    BENIGN_IPS = ["192.168.1.15", "192.168.1.28", "192.168.1.102", "10.0.0.45", "10.0.0.88"]
    ATTACKER_IPS = ["198.51.100.42", "203.0.113.19", "185.220.101.5", "45.155.205.12", "194.26.29.112"]
    BOTNET_IPS = ["198.51.100.11", "198.51.100.12", "198.51.100.13", "198.51.100.14", "198.51.100.15", "198.51.100.16"]
    COMMON_USERS = ["jdoe", "alice", "bob", "devops", "deployer"]
    TARGET_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]

    @classmethod
    def generate_brute_force(cls, count: int = 6, attacker_ip: str = None) -> List[LogCreate]:
        ip = attacker_ip or random.choice(cls.ATTACKER_IPS)
        logs = []
        target_user = random.choice(["alice", "bob", "service_account", "guest"])
        for i in range(count):
            logs.append(LogCreate(
                timestamp=datetime.now(timezone.utc),
                source_ip=ip,
                destination_ip="10.0.0.5",
                source_port=random.randint(40000, 65000),
                destination_port=22,
                protocol="TCP",
                event_type="AUTHENTICATION_FAILED",
                severity="MEDIUM",
                user=target_user,
                message=f"Failed SSH login attempt for '{target_user}' from {ip} (attempt {i + 1}/{count})",
                raw_data={"auth_method": "password", "attempt": i + 1}
            ))
        return logs

    @classmethod
    def generate_port_scan(cls, count: int = 8, attacker_ip: str = None) -> List[LogCreate]:
        ip = attacker_ip or random.choice(cls.ATTACKER_IPS)
        logs = []
        ports_to_scan = random.sample(cls.TARGET_PORTS, min(count, len(cls.TARGET_PORTS)))
        for port in ports_to_scan:
            logs.append(LogCreate(
                timestamp=datetime.now(timezone.utc),
                source_ip=ip,
                destination_ip="10.0.0.5",
                source_port=random.randint(40000, 65000),
                destination_port=port,
                protocol="TCP",
                event_type="PORT_SCAN_PROBE",
                severity="LOW",
                user=None,
                message=f"SYN probe to port {port} rejected by perimeter firewall",
                raw_data={"tcp_flags": "SYN", "action": "DROP", "port": port}
            ))
        return logs

    @classmethod
    def generate_root_login(cls, attacker_ip: str = None, success: bool = True) -> List[LogCreate]:
        ip = attacker_ip or random.choice(cls.ATTACKER_IPS)
        if success:
            return [
                LogCreate(
                    timestamp=datetime.now(timezone.utc),
                    source_ip=ip,
                    destination_ip="10.0.0.5",
                    source_port=random.randint(40000, 65000),
                    destination_port=22,
                    protocol="TCP",
                    event_type="AUTHENTICATION_SUCCESS",
                    severity="CRITICAL",
                    user="root",
                    message=f"Direct remote privileged root shell opened from external IP {ip}",
                    raw_data={"auth_method": "publickey_bypass", "user": "root"}
                )
            ]
        else:
            return [
                LogCreate(
                    timestamp=datetime.now(timezone.utc),
                    source_ip=ip,
                    destination_ip="10.0.0.5",
                    source_port=random.randint(40000, 65000),
                    destination_port=22,
                    protocol="TCP",
                    event_type="AUTHENTICATION_FAILED",
                    severity="LOW",
                    user="root",
                    message=f"Isolated failed password attempt for user 'root' from {ip}",
                    raw_data={"auth_method": "password", "user": "root"}
                )
            ]

    @classmethod
    def generate_ddos_aggregate(cls, count: int = 24, target_ip: str = "10.0.0.5") -> List[LogCreate]:
        """
        Generates synthetic multi-source traffic targeting a single destination host to demonstrate DDoS detection safely.
        """
        logs = []
        for i in range(count):
            bot_ip = cls.BOTNET_IPS[i % len(cls.BOTNET_IPS)]
            logs.append(LogCreate(
                timestamp=datetime.now(timezone.utc),
                source_ip=bot_ip,
                destination_ip=target_ip,
                source_port=random.randint(40000, 65000),
                destination_port=80,
                protocol="TCP",
                event_type="HTTP_FLOOD_PROBE",
                severity="MEDIUM",
                user=None,
                message=f"Synthetic HTTP GET request flood to {target_ip}:80 from {bot_ip}",
                raw_data={"bot_id": i % len(cls.BOTNET_IPS), "probe_index": i}
            ))
        return logs

    @classmethod
    def generate_anomalous_spike(cls, count: int = 25, attacker_ip: str = None) -> List[LogCreate]:
        ip = attacker_ip or random.choice(cls.ATTACKER_IPS)
        logs = []
        endpoints = ["/api/v1/login", "/api/v1/search", "/admin/config", "/wp-login.php", "/.env"]
        for i in range(count):
            logs.append(LogCreate(
                timestamp=datetime.now(timezone.utc),
                source_ip=ip,
                destination_ip="10.0.0.5",
                source_port=random.randint(40000, 65000),
                destination_port=443,
                protocol="TCP",
                event_type="HTTP_REQUEST",
                severity="LOW",
                user=None,
                message=f"High frequency HTTP GET {random.choice(endpoints)} from {ip}",
                raw_data={"http_status": 404, "user_agent": "python-requests/2.31"}
            ))
        return logs

    @classmethod
    def generate_normal_traffic(cls, count: int = 5) -> List[LogCreate]:
        logs = []
        for _ in range(count):
            ip = random.choice(cls.BENIGN_IPS)
            user = random.choice(cls.COMMON_USERS)
            event_type = random.choice(["HTTP_REQUEST", "AUTHENTICATION_SUCCESS", "DNS_QUERY"])
            if event_type == "HTTP_REQUEST":
                msg = f"HTTP 200 GET /dashboard for user '{user}'"
                port = 443
                sev = "INFO"
            elif event_type == "AUTHENTICATION_SUCCESS":
                msg = f"User '{user}' successfully logged in from internal IP {ip}"
                port = 443
                sev = "INFO"
            else:
                msg = "Standard internal DNS resolution for api.sentinel.internal"
                port = 53
                sev = "INFO"

            logs.append(LogCreate(
                timestamp=datetime.now(timezone.utc),
                source_ip=ip,
                destination_ip="10.0.0.5",
                source_port=random.randint(40000, 65000),
                destination_port=port,
                protocol="TCP" if port != 53 else "UDP",
                event_type=event_type,
                severity=sev,
                user=user,
                message=msg,
                raw_data={"status": "normal"}
            ))
        return logs
