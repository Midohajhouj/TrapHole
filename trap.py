#!/usr/bin/env python3
"""
CANARYTRAP Ultimate Pro - Advanced Honeypot Monitoring System
Author: Security Research Team
Version: 3.0
Features:
- Real-time monitoring of Proot honeypot activities
- Multi-service monitoring (SSH, HTTP, MySQL, Redis, FTP, Tomcat)
- Behavioral analysis and threat scoring
- Automated response capabilities
- Detailed logging and reporting
- Web-based dashboard
- Integration with threat intelligence feeds
"""

import os
import sys
import socket
import threading
import time
import json
import re
import subprocess
import pty
import select
import hashlib
import ipaddress
import platform
import sqlite3
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse
from collections import defaultdict
import geoip2.database
import requests
import smtplib
from email.mime.text import MIMEText

# ========================
# 🛠️ Configuration
# ========================
class Config:
    # Core settings
    PROOT_ROOT = os.path.expanduser("~/ubuntu_honeypot_ultimate")
    LOG_DIR = os.path.expanduser("~/ubuntu_honeypot_ultimate/logs")
    TRAP_DIR = os.path.expanduser("~/ubuntu_honeypot_ultimate/trap")
    DB_FILE = os.path.expanduser("~/ubuntu_honeypot_ultimate/honeypot.db")
    
    # Service ports
    PORTS = {
        "ssh": 22,
        "http": 80,
        "https": 443,
        "mysql": 3306,
        "redis": 6379,
        "ftp": 21,
        "telnet": 23,
        "snmp": 161,
        "tomcat": 8080,
        "apache": 80
    }
    
    # Monitoring intervals (seconds)
    MONITOR_INTERVALS = {
        "process_scan": 60,
        "file_integrity": 300,
        "log_analysis": 30,
        "network_scan": 120
    }
    
    # GeoIP database paths
    GEOIP_DB = {
        "city": "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "country": "/usr/share/GeoIP/GeoLite2-Country.mmdb"
    }
    
    # Threat intelligence feeds
    THREAT_FEEDS = {
        "abuseipdb": "https://api.abuseipdb.com/api/v2/check",
        "virustotal": "https://www.virustotal.com/api/v3/ip_addresses/",
        "greynoise": "https://api.greynoise.io/v3/community/"
    }
    
    # API keys (should be moved to environment variables in production)
    API_KEYS = {
        "abuseipdb": "YOUR_ABUSEIPDB_KEY",
        "virustotal": "YOUR_VIRUSTOTAL_KEY",
        "greynoise": "YOUR_GREYNOISE_KEY"
    }
    
    # Alert settings
    ALERT_SETTINGS = {
        "email": {
            "enabled": True,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "smtp_user": "alerts@example.com",
            "smtp_pass": "SecurePassword123!",
            "from_addr": "honeypot@example.com",
            "to_addr": "security@example.com"
        },
        "slack": {
            "enabled": False,
            "webhook_url": "https://hooks.slack.com/services/XXXXX"
        }
    }
    
    # Web dashboard settings
    WEB_DASHBOARD = {
        "enabled": True,
        "port": 8080,
        "auth": {
            "username": "admin",
            "password": "SecurePassword123!"  # Change this!
        }
    }

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ========================
# 📊 Database Setup
# ========================
class HoneypotDB:
    def __init__(self):
        self.conn = sqlite3.connect(Config.DB_FILE)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Events table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            service TEXT,
            source_ip TEXT,
            event_type TEXT,
            details TEXT,
            threat_score INTEGER,
            country TEXT,
            city TEXT,
            isp TEXT,
            is_tor INTEGER,
            is_known_attacker INTEGER,
            is_cloud_provider INTEGER
        )
        ''')
        
        # System monitoring table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            check_type TEXT,
            status TEXT,
            details TEXT
        )
        ''')
        
        # File integrity table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_integrity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            file_path TEXT,
            hash TEXT,
            status TEXT
        )
        ''')
        
        # Threat intelligence cache
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            last_checked DATETIME,
            abuse_score INTEGER,
            is_malicious INTEGER,
            reports INTEGER,
            is_tor INTEGER,
            is_cloud INTEGER,
            details TEXT
        )
        ''')
        
        # Attack patterns table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT,
            description TEXT,
            threat_score INTEGER
        )
        ''')
        
        # Insert common attack patterns
        cursor.executemany('''
        INSERT OR IGNORE INTO attack_patterns (pattern, description, threat_score)
        VALUES (?, ?, ?)
        ''', [
            (r'Failed password for', 'SSH brute force attempt', 30),
            (r'Invalid user', 'SSH invalid user attempt', 40),
            (r'union select', 'SQL injection attempt', 80),
            (r'\/etc\/passwd', 'Path traversal attempt', 70),
            (r'wget|curl', 'Potential malware download', 60),
            (r'\.\.\/', 'Path traversal attempt', 70),
            (r'phpinfo\(\)', 'PHP info disclosure attempt', 50),
            (r'<script>', 'XSS attempt', 60),
            (r'benchmark\(', 'SQL injection attempt', 80),
            (r'\/wp-admin', 'WordPress admin access', 40)
        ])
        
        self.conn.commit()
    
    def log_event(self, service, source_ip, event_type, details):
        """Log an event to the database with threat intelligence enrichment"""
        try:
            # Get geoip and threat info
            geo_info = self.get_geoip_info(source_ip)
            threat_info = self.check_threat_intelligence(source_ip)
            
            # Calculate threat score
            threat_score = self.calculate_threat_score(event_type, details, threat_info)
            
            cursor = self.conn.cursor()
            cursor.execute('''
            INSERT INTO events (
                timestamp, service, source_ip, event_type, details, 
                threat_score, country, city, isp, is_tor, is_known_attacker, is_cloud_provider
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                service,
                source_ip,
                event_type,
                json.dumps(details),
                threat_score,
                geo_info.get('country'),
                geo_info.get('city'),
                geo_info.get('isp'),
                threat_info.get('is_tor', 0),
                threat_info.get('is_malicious', 0),
                threat_info.get('is_cloud', 0)
            ))
            self.conn.commit()
            
            return threat_score
        except Exception as e:
            print(f"{Colors.RED}[!] Database error: {str(e)}{Colors.END}")
            return 0
    
    def get_geoip_info(self, ip_address):
        """Get geographic information for an IP address"""
        try:
            if not os.path.exists(Config.GEOIP_DB['city']):
                return {}
            
            with geoip2.database.Reader(Config.GEOIP_DB['city']) as reader:
                response = reader.city(ip_address)
                return {
                    'country': response.country.name,
                    'city': response.city.name,
                    'isp': response.traits.isp,
                    'asn': response.traits.autonomous_system_number
                }
        except:
            return {}
    
    def check_threat_intelligence(self, ip_address):
        """Check threat intelligence feeds for an IP address"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            SELECT * FROM threat_intel 
            WHERE ip_address = ? AND last_checked > datetime('now', '-1 day')
            ''', (ip_address,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'abuse_score': row[3],
                    'is_malicious': row[4],
                    'reports': row[5],
                    'is_tor': row[6],
                    'is_cloud': row[7]
                }
            
            # If not in cache or stale, query APIs
            result = {
                'abuse_score': 0,
                'is_malicious': 0,
                'reports': 0,
                'is_tor': 0,
                'is_cloud': 0
            }
            
            # Check AbuseIPDB
            if Config.API_KEYS['abuseipdb']:
                response = requests.get(
                    Config.THREAT_FEEDS['abuseipdb'],
                    params={'ipAddress': ip_address, 'maxAgeInDays': '90'},
                    headers={'Key': Config.API_KEYS['abuseipdb'], 'Accept': 'application/json'}
                )
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    result['abuse_score'] = data.get('abuseConfidenceScore', 0)
                    result['is_malicious'] = 1 if data.get('abuseConfidenceScore', 0) > 50 else 0
                    result['reports'] = data.get('totalReports', 0)
                    result['is_tor'] = 1 if data.get('isTor', False) else 0
            
            # Check VirusTotal
            if Config.API_KEYS['virustotal']:
                response = requests.get(
                    Config.THREAT_FEEDS['virustotal'] + ip_address,
                    headers={'x-apikey': Config.API_KEYS['virustotal']}
                )
                if response.status_code == 200:
                    data = response.json().get('data', {}).get('attributes', {})
                    if data.get('last_analysis_stats', {}).get('malicious', 0) > 0:
                        result['is_malicious'] = 1
            
            # Check GreyNoise
            if Config.API_KEYS['greynoise']:
                response = requests.get(
                    Config.THREAT_FEEDS['greynoise'] + ip_address,
                    headers={'key': Config.API_KEYS['greynoise']}
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('classification') == 'malicious':
                        result['is_malicious'] = 1
                    if data.get('metadata', {}).get('tor'):
                        result['is_tor'] = 1
                    if data.get('metadata', {}).get('cloud_provider'):
                        result['is_cloud'] = 1
            
            # Cache the results
            cursor.execute('''
            INSERT OR REPLACE INTO threat_intel (
                ip_address, last_checked, abuse_score, is_malicious, reports, is_tor, is_cloud, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip_address,
                datetime.now().isoformat(),
                result['abuse_score'],
                result['is_malicious'],
                result['reports'],
                result['is_tor'],
                result['is_cloud'],
                json.dumps(result)
            ))
            self.conn.commit()
            
            return result
        except Exception as e:
            print(f"{Colors.RED}[!] Threat intel error: {str(e)}{Colors.END}")
            return {}
    
    def calculate_threat_score(self, event_type, details, threat_info):
        """Calculate a threat score based on event details and threat intel"""
        score = 0
        
        # Base score based on event type
        if event_type == 'login_attempt':
            score = 20
        elif event_type == 'command_execution':
            score = 50
        elif event_type == 'exploit_attempt':
            score = 80
        elif event_type == 'file_modification':
            score = 60
        elif event_type == 'malware_download':
            score = 90
        
        # Add points for suspicious commands
        if 'command' in details:
            cmd = details['command'].lower()
            suspicious_commands = [
                'rm ', 'chmod', 'chown', 'wget', 'curl', 'nc ', 'netcat', 
                'ssh ', 'scp', 'cat /etc/passwd', 'cat /etc/shadow',
                'iptables', 'ufw', 'chattr', 'usermod', 'useradd'
            ]
            for sc in suspicious_commands:
                if sc in cmd:
                    score += 30
        
        # Add points for threat intelligence
        score += threat_info.get('abuse_score', 0) / 2
        if threat_info.get('is_malicious', 0):
            score += 30
        if threat_info.get('is_tor', 0):
            score += 20
        if threat_info.get('is_cloud', 0):
            score += 10
        
        # Cap at 100
        return min(100, score)
    
    def get_recent_events(self, limit=50):
        """Get recent events for dashboard"""
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT * FROM events 
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (limit,))
        return cursor.fetchall()
    
    def get_stats(self):
        """Get statistics for dashboard"""
        cursor = self.conn.cursor()
        
        stats = {
            'total_events': 0,
            'high_threat': 0,
            'countries': defaultdict(int),
            'services': defaultdict(int),
            'attack_types': defaultdict(int),
            'top_attackers': defaultdict(int)
        }
        
        # Total events
        cursor.execute('SELECT COUNT(*) FROM events')
        stats['total_events'] = cursor.fetchone()[0]
        
        # High threat events
        cursor.execute('SELECT COUNT(*) FROM events WHERE threat_score > 70')
        stats['high_threat'] = cursor.fetchone()[0]
        
        # Top countries
        cursor.execute('''
        SELECT country, COUNT(*) as count 
        FROM events 
        WHERE country IS NOT NULL 
        GROUP BY country 
        ORDER BY count DESC 
        LIMIT 5
        ''')
        for row in cursor.fetchall():
            stats['countries'][row[0]] = row[1]
        
        # Service distribution
        cursor.execute('''
        SELECT service, COUNT(*) as count 
        FROM events 
        GROUP BY service 
        ORDER BY count DESC
        ''')
        for row in cursor.fetchall():
            stats['services'][row[0]] = row[1]
        
        # Attack type distribution
        cursor.execute('''
        SELECT event_type, COUNT(*) as count 
        FROM events 
        GROUP BY event_type 
        ORDER BY count DESC
        ''')
        for row in cursor.fetchall():
            stats['attack_types'][row[0]] = row[1]
        
        # Top attackers
        cursor.execute('''
        SELECT source_ip, COUNT(*) as count 
        FROM events 
        WHERE source_ip != 'internal' 
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT 5
        ''')
        for row in cursor.fetchall():
            stats['top_attackers'][row[0]] = row[1]
        
        return stats

# ========================
# 📝 Logging System
# ========================
class EnhancedLogger:
    def __init__(self, db):
        self.db = db
        os.makedirs(Config.LOG_DIR, exist_ok=True)
    
    def log(self, service, source_ip, event_type, details):
        """Log an event with full details"""
        try:
            # Log to database with threat intelligence
            threat_score = self.db.log_event(service, source_ip, event_type, details)
            
            # Also log to file
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "service": service,
                "source_ip": source_ip,
                "event_type": event_type,
                "threat_score": threat_score,
                "details": details
            }
            
            log_file = os.path.join(Config.LOG_DIR, f"{service}_events.json")
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            
            # Color coding based on threat level
            if threat_score > 70:
                color = Colors.RED
            elif threat_score > 40:
                color = Colors.YELLOW
            else:
                color = Colors.GREEN
            
            print(f"{color}[{service.upper()}] {event_type.upper()} from {source_ip} (Threat: {threat_score}){Colors.END}")
            print(f"{color}Details: {json.dumps(details, indent=2)}{Colors.END}")
            
            # Trigger alerts for high threat events
            if threat_score > 70:
                self.trigger_alert(service, source_ip, event_type, details, threat_score)
        except Exception as e:
            print(f"{Colors.RED}[!] Logging error: {str(e)}{Colors.END}")
    
    def trigger_alert(self, service, source_ip, event_type, details, threat_score):
        """Trigger an alert for high-threat events"""
        alert_msg = f"""
        🚨 HIGH THREAT ALERT 🚨
        Service: {service}
        Source IP: {source_ip}
        Event Type: {event_type}
        Threat Score: {threat_score}
        
        Details:
        {json.dumps(details, indent=2)}
        """
        
        print(f"{Colors.RED}{alert_msg}{Colors.END}")
        
        # Log to dedicated alert file
        alert_file = os.path.join(Config.LOG_DIR, "alerts.log")
        with open(alert_file, "a") as f:
            f.write(alert_msg + "\n\n")
        
        # Send email alert
        if Config.ALERT_SETTINGS['email']['enabled']:
            self.send_email_alert(alert_msg)
        
        # Send Slack alert
        if Config.ALERT_SETTINGS['slack']['enabled']:
            self.send_slack_alert(alert_msg)
    
    def send_email_alert(self, message):
        """Send email alert"""
        try:
            msg = MIMEText(message)
            msg['Subject'] = '🚨 Honeypot High Threat Alert'
            msg['From'] = Config.ALERT_SETTINGS['email']['from_addr']
            msg['To'] = Config.ALERT_SETTINGS['email']['to_addr']
            
            with smtplib.SMTP(Config.ALERT_SETTINGS['email']['smtp_server'], 
                             Config.ALERT_SETTINGS['email']['smtp_port']) as server:
                server.starttls()
                server.login(Config.ALERT_SETTINGS['email']['smtp_user'],
                           Config.ALERT_SETTINGS['email']['smtp_pass'])
                server.send_message(msg)
        except Exception as e:
            print(f"{Colors.RED}[!] Email alert failed: {str(e)}{Colors.END}")
    
    def send_slack_alert(self, message):
        """Send Slack alert"""
        try:
            payload = {
                "text": message,
                "username": "Honeypot Alert",
                "icon_emoji": ":warning:"
            }
            requests.post(
                Config.ALERT_SETTINGS['slack']['webhook_url'],
                json=payload,
                timeout=10
            )
        except Exception as e:
            print(f"{Colors.RED}[!] Slack alert failed: {str(e)}{Colors.END}")

# ========================
# 🕵️‍♂️ Monitoring Components
# ========================
class ProotMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.baseline_files = {}
        self.baseline_processes = set()
        self.known_malicious_ips = set()
    
    def start_monitoring(self):
        """Start all monitoring threads"""
        # Initial baselines
        self.create_file_baseline()
        self.create_process_baseline()
        
        # Start monitoring threads
        threading.Thread(target=self.monitor_processes, daemon=True).start()
        threading.Thread(target=self.monitor_file_integrity, daemon=True).start()
        threading.Thread(target=self.monitor_logs, daemon=True).start()
        threading.Thread(target=self.monitor_network, daemon=True).start()
        threading.Thread(target=self.monitor_services, daemon=True).start()
        
        print(f"{Colors.GREEN}[+] Proot monitoring started{Colors.END}")
    
    def create_file_baseline(self):
        """Create baseline hashes for critical files"""
        critical_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/nginx/nginx.conf",
            "/var/www/html/index.php",
            "/var/www/html/wp-config.php",
            "/etc/mysql/my.cnf",
            "/etc/redis/redis.conf"
        ]
        
        for file_path in critical_files:
            full_path = os.path.join(Config.PROOT_ROOT, file_path.lstrip('/'))
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    self.baseline_files[file_path] = file_hash
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Could not hash {file_path}: {str(e)}{Colors.END}")
    
    def create_process_baseline(self):
        """Create baseline of expected processes"""
        self.baseline_processes = {
            "nginx", "mysql", "redis-server", 
            "sshd", "vsftpd", "snmpd", "telnetd",
            "apache2", "tomcat9"
        }
    
    def monitor_processes(self):
        """Monitor running processes in the Proot environment"""
        while True:
            try:
                # Get current processes
                result = subprocess.run(
                    ["proot", "-S", Config.PROOT_ROOT, "ps", "-aux"],
                    capture_output=True, text=True
                )
                
                current_processes = set()
                suspicious_processes = set()
                
                for line in result.stdout.splitlines():
                    if len(line.split()) > 10:
                        process = line.split()[10]
                        current_processes.add(process)
                        
                        # Check for suspicious processes
                        if process not in self.baseline_processes:
                            if not any(x in process for x in ['ps', 'grep', 'awk', 'sed']):
                                suspicious_processes.add(process)
                
                # Log any suspicious processes
                if suspicious_processes:
                    for process in suspicious_processes:
                        self.logger.log(
                            "system", 
                            "internal", 
                            "suspicious_process", 
                            {
                                "process": process,
                                "action": "detected",
                                "status": "investigate"
                            }
                        )
                
                time.sleep(Config.MONITOR_INTERVALS['process_scan'])
            except Exception as e:
                print(f"{Colors.RED}[!] Process monitor error: {str(e)}{Colors.END}")
                time.sleep(10)
    
    def monitor_file_integrity(self):
        """Monitor critical files for changes"""
        while True:
            try:
                for file_path, expected_hash in self.baseline_files.items():
                    full_path = os.path.join(Config.PROOT_ROOT, file_path.lstrip('/'))
                    
                    if os.path.exists(full_path):
                        with open(full_path, 'rb') as f:
                            current_hash = hashlib.sha256(f.read()).hexdigest()
                        
                        if current_hash != expected_hash:
                            self.logger.log(
                                "system", 
                                "internal", 
                                "file_modification", 
                                {
                                    "file": file_path,
                                    "old_hash": expected_hash,
                                    "new_hash": current_hash,
                                    "status": "changed"
                                }
                            )
                            # Update baseline
                            self.baseline_files[file_path] = current_hash
                    else:
                        self.logger.log(
                            "system", 
                            "internal", 
                            "file_modification", 
                            {
                                "file": file_path,
                                "status": "deleted"
                            }
                        )
                
                time.sleep(Config.MONITOR_INTERVALS['file_integrity'])
            except Exception as e:
                print(f"{Colors.RED}[!] File monitor error: {str(e)}{Colors.END}")
                time.sleep(30)
    
    def monitor_logs(self):
        """Monitor system logs for suspicious activity"""
        log_files = [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/mysql/error.log",
            "/var/log/tomcat9/catalina.out"
        ]
        
        # Track log positions
        log_positions = {}
        for log_file in log_files:
            full_path = os.path.join(Config.PROOT_ROOT, log_file.lstrip('/'))
            if os.path.exists(full_path):
                log_positions[log_file] = os.path.getsize(full_path)
        
        while True:
            try:
                for log_file in log_files:
                    full_path = os.path.join(Config.PROOT_ROOT, log_file.lstrip('/'))
                    
                    if not os.path.exists(full_path):
                        continue
                    
                    current_size = os.path.getsize(full_path)
                    if log_file not in log_positions or log_positions[log_file] > current_size:
                        # Log rotated or truncated
                        log_positions[log_file] = 0
                    
                    if current_size > log_positions[log_file]:
                        with open(full_path, 'r') as f:
                            f.seek(log_positions[log_file])
                            new_lines = f.read()
                            log_positions[log_file] = f.tell()
                            
                            # Analyze new lines
                            self.analyze_log_entries(log_file, new_lines)
                
                time.sleep(Config.MONITOR_INTERVALS['log_analysis'])
            except Exception as e:
                print(f"{Colors.RED}[!] Log monitor error: {str(e)}{Colors.END}")
                time.sleep(30)
    
    def analyze_log_entries(self, log_file, log_entries):
        """Analyze log entries for suspicious patterns"""
        suspicious_patterns = {
            "auth.log": [
                (r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)", "failed_login"),
                (r"Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)", "invalid_user"),
                (r"session opened for user (\w+) by", "session_opened"),
                (r"session closed for user (\w+)", "session_closed"),
                (r"sudo: (\w+) : command not allowed", "sudo_attempt")
            ],
            "nginx/access.log": [
                (r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] "(GET|POST|PUT|DELETE) (.*?) HTTP.*" (\d+)', "http_access"),
                (r'(\d+\.\d+\.\d+\.\d+).*"(?:\\"|[^"])*?(union select|sleep\(|benchmark|information_schema)', "sql_injection"),
                (r'(\d+\.\d+\.\d+\.\d+).*"(?:\\"|[^"])*?(\.\./|\.\.\\|etc/passwd)', "path_traversal"),
                (r'(\d+\.\d+\.\d+\.\d+).*"(?:\\"|[^"])*?(wp-admin|wp-login)', "wordpress_scan"),
                (r'(\d+\.\d+\.\d+\.\d+).*"(?:\\"|[^"])*?(\.php\?)', "php_exploit")
            ],
            "mysql/error.log": [
                (r"Access denied for user '(\w+)'@'(\d+\.\d+\.\d+\.\d+)'", "mysql_failed_login"),
                (r"Got an error reading communication packets", "mysql_conn_error")
            ],
            "tomcat9/catalina.out": [
                (r"(\d+\.\d+\.\d+\.\d+).*?manager/html", "tomcat_manager_access"),
                (r"(\d+\.\d+\.\d+\.\d+).*?\/\.\.\/", "tomcat_path_traversal")
            ]
        }
        
        log_name = log_file.split('/')[-1]
        
        for line in log_entries.splitlines():
            for pattern, event_type in suspicious_patterns.get(log_name, []):
                match = re.search(pattern, line)
                if match:
                    groups = match.groups()
                    source_ip = groups[1] if len(groups) > 1 else "unknown"
                    
                    details = {
                        "log_line": line,
                        "pattern": pattern,
                        "log_file": log_file
                    }
                    
                    if event_type == "failed_login":
                        details.update({
                            "username": groups[0],
                            "source_ip": groups[1]
                        })
                    
                    self.logger.log(
                        "log_monitor", 
                        source_ip, 
                        event_type, 
                        details
                    )
    
    def monitor_network(self):
        """Monitor network connections in the Proot environment"""
        while True:
            try:
                result = subprocess.run(
                    ["proot", "-S", Config.PROOT_ROOT, "netstat", "-tulnp"],
                    capture_output=True, text=True
                )
                
                suspicious_connections = []
                
                for line in result.stdout.splitlines():
                    if "ESTABLISHED" in line:
                        parts = line.split()
                        if len(parts) > 6:
                            local_addr, foreign_addr = parts[3], parts[4]
                            program = parts[6]
                            
                            # Check for suspicious foreign addresses
                            if not any(x in foreign_addr for x in ['127.0.0.1', '0.0.0.0', '::1']):
                                suspicious_connections.append({
                                    "local_address": local_addr,
                                    "foreign_address": foreign_addr,
                                    "program": program
                                })
                
                if suspicious_connections:
                    self.logger.log(
                        "network", 
                        "internal", 
                        "suspicious_connection", 
                        {
                            "connections": suspicious_connections,
                            "status": "investigate"
                        }
                    )
                
                time.sleep(Config.MONITOR_INTERVALS['network_scan'])
            except Exception as e:
                print(f"{Colors.RED}[!] Network monitor error: {str(e)}{Colors.END}")
                time.sleep(30)
    
    def monitor_services(self):
        """Monitor service status"""
        while True:
            try:
                services = ["nginx", "mysql", "redis-server", "apache2", "vsftpd", "tomcat9"]
                for service in services:
                    result = subprocess.run(
                        ["proot", "-S", Config.PROOT_ROOT, "service", service, "status"],
                        capture_output=True, text=True
                    )
                    
                    if "active (running)" not in result.stdout:
                        self.logger.log(
                            "system",
                            "internal",
                            "service_down",
                            {
                                "service": service,
                                "status": "down",
                                "output": result.stdout
                            }
                        )
                
                time.sleep(60)
            except Exception as e:
                print(f"{Colors.RED}[!] Service monitor error: {str(e)}{Colors.END}")
                time.sleep(30)

# ========================
# 🌐 Web Dashboard
# ========================
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread"""

class DashboardHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.db = kwargs.pop('db')
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        # Check authentication
        if not self.authenticate():
            self.send_auth_challenge()
            return
        
        # Route requests
        if self.path == '/':
            self.show_dashboard()
        elif self.path == '/events':
            self.show_events()
        elif self.path == '/stats':
            self.show_stats()
        elif self.path == '/attackers':
            self.show_attackers()
        else:
            self.send_error(404, "Not Found")
    
    def authenticate(self):
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Basic '):
            return False
        
        auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
        username, password = auth_decoded.split(':', 1)
        
        return (username == Config.WEB_DASHBOARD['auth']['username'] and 
                password == Config.WEB_DASHBOARD['auth']['password'])
    
    def send_auth_challenge(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Honeypot Dashboard"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Authentication required')
    
    def show_dashboard(self):
        stats = self.db.get_stats()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = f"""
        <html>
        <head>
            <title>Honeypot Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .card {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
                .stat {{ display: inline-block; margin-right: 20px; }}
                .high-threat {{ color: red; font-weight: bold; }}
                .chart-container {{ width: 100%; height: 300px; }}
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <h1>Honeypot Dashboard</h1>
            
            <div class="card">
                <h2>Overview</h2>
                <div class="stat">
                    <h3>Total Events</h3>
                    <p>{stats['total_events']}</p>
                </div>
                <div class="stat">
                    <h3>High Threat Events</h3>
                    <p class="high-threat">{stats['high_threat']}</p>
                </div>
            </div>
            
            <div class="card">
                <h2>Top Countries</h2>
                <div class="chart-container">
                    <canvas id="countriesChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h2>Service Distribution</h2>
                <div class="chart-container">
                    <canvas id="servicesChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h2>Recent Events</h2>
                <p><a href="/events">View all events</a></p>
            </div>
            
            <div class="card">
                <h2>Top Attackers</h2>
                <p><a href="/attackers">View attacker details</a></p>
            </div>
            
            <script>
                // Countries chart
                const countriesCtx = document.getElementById('countriesChart').getContext('2d');
                const countriesChart = new Chart(countriesCtx, {{
                    type: 'bar',
                    data: {{
                        labels: {json.dumps(list(stats['countries'].keys()))},
                        datasets: [{{
                            label: 'Events by Country',
                            data: {json.dumps(list(stats['countries'].values()))},
                            backgroundColor: 'rgba(54, 162, 235, 0.5)',
                            borderColor: 'rgba(54, 162, 235, 1)',
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        scales: {{
                            y: {{
                                beginAtZero: true
                            }}
                        }}
                    }}
                }});
                
                // Services chart
                const servicesCtx = document.getElementById('servicesChart').getContext('2d');
                const servicesChart = new Chart(servicesCtx, {{
                    type: 'pie',
                    data: {{
                        labels: {json.dumps(list(stats['services'].keys()))},
                        datasets: [{{
                            label: 'Events by Service',
                            data: {json.dumps(list(stats['services'].values()))},
                            backgroundColor: [
                                'rgba(255, 99, 132, 0.5)',
                                'rgba(54, 162, 235, 0.5)',
                                'rgba(255, 206, 86, 0.5)',
                                'rgba(75, 192, 192, 0.5)',
                                'rgba(153, 102, 255, 0.5)'
                            ],
                            borderColor: [
                                'rgba(255, 99, 132, 1)',
                                'rgba(54, 162, 235, 1)',
                                'rgba(255, 206, 86, 1)',
                                'rgba(75, 192, 192, 1)',
                                'rgba(153, 102, 255, 1)'
                            ],
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        responsive: true
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        self.wfile.write(html.encode())
    
    def show_events(self):
        events = self.db.get_recent_events(50)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
        <html>
        <head>
            <title>Recent Events</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .high-threat {{ background-color: #ffcccc; }}
            </style>
        </head>
        <body>
            <h1>Recent Events</h1>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Service</th>
                    <th>Source IP</th>
                    <th>Event Type</th>
                    <th>Threat Score</th>
                </tr>
        """
        
        for event in events:
            threat_class = "high-threat" if event[6] > 70 else ""
            html += f"""
                <tr class="{threat_class}">
                    <td>{event[1]}</td>
                    <td>{event[2]}</td>
                    <td>{event[3]}</td>
                    <td>{event[4]}</td>
                    <td>{event[6]}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        self.wfile.write(html.encode())
    
    def show_stats(self):
        stats = self.db.get_stats()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
        <html>
        <head>
            <title>Statistics</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .stat-section {{ margin-bottom: 30px; }}
                .stat-row {{ display: flex; margin-bottom: 10px; }}
                .stat-label {{ width: 200px; font-weight: bold; }}
                .stat-bar-container {{ width: 300px; background-color: #eee; }}
                .stat-bar {{ height: 20px; background-color: #4CAF50; }}
            </style>
        </head>
        <body>
            <h1>Honeypot Statistics</h1>
            
            <div class="stat-section">
                <h2>Service Distribution</h2>
        """
        
        max_service_count = max(stats['services'].values()) if stats['services'] else 1
        
        for service, count in stats['services'].items():
            width = (count / max_service_count) * 100
            html += f"""
                <div class="stat-row">
                    <div class="stat-label">{service}</div>
                    <div class="stat-bar-container">
                        <div class="stat-bar" style="width: {width}%"></div>
                    </div>
                    <div>{count}</div>
                </div>
            """
        
        html += """
            </div>
            
            <div class="stat-section">
                <h2>Attack Type Distribution</h2>
        """
        
        max_attack_count = max(stats['attack_types'].values()) if stats['attack_types'] else 1
        
        for attack_type, count in stats['attack_types'].items():
            width = (count / max_attack_count) * 100
            html += f"""
                <div class="stat-row">
                    <div class="stat-label">{attack_type}</div>
                    <div class="stat-bar-container">
                        <div class="stat-bar" style="width: {width}%"></div>
                    </div>
                    <div>{count}</div>
                </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        self.wfile.write(html.encode())
    
    def show_attackers(self):
        stats = self.db.get_stats()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
        <html>
        <head>
            <title>Top Attackers</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Top Attackers</h1>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Event Count</th>
                </tr>
        """
        
        for ip, count in stats['top_attackers'].items():
            html += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{count}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        self.wfile.write(html.encode())

# ========================
# 🚀 Main Execution
# ========================
def main():
    print(f"{Colors.BLUE}")
    print("""
   ___  _  _  ___  ___  _  _  ___  _____  ___  ___  ___ 
  / __|| \| || _ \| _ \| \| || _ \|_   _|| _ \| __|| _ \\
 | (__ | .` ||  _/|   /| .` ||  _/  | |  |   /| _| |   /
  \___||_|\_||_|  |_|_\|_|\_||_|    |_|  |_|_\|___||_|_\\
    """)
    print(f"{Colors.END}")
    print(f"{Colors.GREEN}🚀 Starting CANARYTRAP Ultimate Pro Honeypot Monitor{Colors.END}")
    
    # Initialize database and logger
    db = HoneypotDB()
    logger = EnhancedLogger(db)
    
    # Start monitoring
    monitor = ProotMonitor(logger)
    monitor.start_monitoring()
    
    # Start web dashboard if enabled
    if Config.WEB_DASHBOARD['enabled']:
        def run_dashboard():
            server = ThreadedHTTPServer(
                ('0.0.0.0', Config.WEB_DASHBOARD['port']),
                lambda *args: DashboardHandler(*args, db=db)
            print(f"{Colors.GREEN}[+] Web dashboard running on port {Config.WEB_DASHBOARD['port']}{Colors.END}")
            server.serve_forever()
        
        threading.Thread(target=run_dashboard, daemon=True).start()
    
    print(f"\n{Colors.GREEN}🎭 Monitoring services:{Colors.END}")
    for service, port in Config.PORTS.items():
        print(f"  - {port} ({service.upper()})")
    
    print(f"\n{Colors.YELLOW}💡 Monitoring all activities in the Proot environment...{Colors.END}")
    print(f"{Colors.YELLOW}🛑 Press Ctrl+C to stop\n{Colors.END}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}🛑 Shutting down CANARYTRAP monitor{Colors.END}")
        sys.exit(0)

if __name__ == "__main__":
    main()
