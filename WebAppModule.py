#!/usr/bin/env python3
"""
FlashBang Web Application Honeypot
Advanced web application honeypot with realistic vulnerabilities and deception
"""

from flask import Flask, request, render_template_string, jsonify, redirect, make_response, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os
import json
import hashlib
import base64
import random
import string
import sqlite3
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import requests
from werkzeug.security import generate_password_hash
import logging
from logging.handlers import RotatingFileHandler
import threading
from queue import Queue
import yaml
from pathlib import Path

# Configure logging with rotation
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            log_dir / 'flashbang.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load configuration
def load_config():
    config_path = Path('config.yaml')
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {
        'secret_key': 'FlashBang-' + ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
        'rate_limits': {
            'default': ["200 per minute", "1000 per hour"],
            'admin': ["50 per minute", "200 per hour"]
        },
        'database': {
            'path': 'web_attacks.db',
            'backup_interval': 3600  # 1 hour
        },
        'alert_threshold': 80,
        'max_payload_size': 1000
    }

config = load_config()

app = Flask(__name__)
app.secret_key = config['secret_key']
csrf = CSRFProtect(app)

# Initialize rate limiter with configurable limits
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=config['rate_limits']['default']
)

# Thread-safe database connection pool
class DatabasePool:
    def __init__(self, db_path: str, max_connections: int = 5):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections = Queue(maxsize=max_connections)
        self._init_pool()
    
    def _init_pool(self):
        for _ in range(self.max_connections):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self.connections.put(conn)
    
    def get_connection(self):
        return self.connections.get()
    
    def return_connection(self, conn):
        self.connections.put(conn)
    
    def close_all(self):
        while not self.connections.empty():
            conn = self.connections.get()
            conn.close()

# Initialize database pool
db_pool = DatabasePool(config['database']['path'])

class WebHoneypot:
    """Advanced web application honeypot"""
    
    def __init__(self):
        self.fake_users = self._generate_fake_users()
        self.fake_sessions = {}
        self.fake_api_keys = self._generate_fake_api_keys()
        self._init_attack_db()
        self.deception_content = self._load_deception_content()
        self._start_backup_thread()
    
    def _init_attack_db(self):
        """Initialize attack logging database"""
        conn = db_pool.get_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    endpoint TEXT,
                    method TEXT,
                    payload TEXT,
                    attack_type TEXT,
                    risk_score INTEGER,
                    session_id TEXT,
                    response_code INTEGER,
                    geolocation TEXT,
                    threat_intel_score INTEGER
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS stolen_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    username TEXT,
                    password TEXT,
                    endpoint TEXT,
                    success BOOLEAN,
                    geolocation TEXT,
                    threat_intel_score INTEGER
                )
            ''')
            
            conn.commit()
        finally:
            db_pool.return_connection(conn)
    
    def _start_backup_thread(self):
        """Start background thread for database backups"""
        def backup_worker():
            while True:
                time.sleep(config['database']['backup_interval'])
                self._backup_database()
        
        thread = threading.Thread(target=backup_worker, daemon=True)
        thread.start()
    
    def _backup_database(self):
        """Create database backup"""
        backup_dir = Path('backups')
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f'web_attacks_{timestamp}.db'
        
        conn = db_pool.get_connection()
        try:
            conn.backup(sqlite3.connect(backup_path))
            logger.info(f"Database backup created: {backup_path}")
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
        finally:
            db_pool.return_connection(conn)
    
    def _generate_fake_users(self):
        """Generate fake user database"""
        users = [
            {"id": 1, "username": "admin", "password": generate_password_hash("admin123"), "role": "admin", "email": "admin@company.com"},
            {"id": 2, "username": "john.doe", "password": generate_password_hash("password123"), "role": "user", "email": "john.doe@company.com"},
            {"id": 3, "username": "developer", "password": generate_password_hash("dev@2024"), "role": "developer", "email": "dev@company.com"},
            {"id": 4, "username": "test", "password": generate_password_hash("test"), "role": "tester", "email": "test@company.com"},
            {"id": 5, "username": "dbadmin", "password": generate_password_hash("Database123!"), "role": "dba", "email": "dba@company.com"}
        ]
        return users
    
    def _generate_fake_api_keys(self):
        """Generate fake API keys"""
        return {
            "production": "sk_live_" + ''.join(random.choices(string.hexdigits, k=32)),
            "development": "sk_test_" + ''.join(random.choices(string.hexdigits, k=32)),
            "webhook": "whsec_" + ''.join(random.choices(string.hexdigits, k=32)),
            "admin": "admin_" + ''.join(random.choices(string.hexdigits, k=32))
        }
    
    def _load_deception_content(self):
        """Load deceptive content for various attack scenarios"""
        return {
            "fake_database_dump": self._generate_fake_database_dump(),
            "fake_config": self._generate_fake_config(),
            "fake_source_code": self._generate_fake_source_code(),
            "fake_logs": self._generate_fake_logs(),
            "fake_api_docs": self._generate_fake_api_docs()
        }
    
    def log_attack(self, attack_type: str, risk_score: int, payload: str = ""):
        """Log attack to database"""
        conn = db_pool.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO web_attacks 
                (ip_address, user_agent, endpoint, method, payload, attack_type, risk_score, session_id, response_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                request.remote_addr,
                request.user_agent.string,
                request.path,
                request.method,
                payload[:config['max_payload_size']],  # Limit payload size
                attack_type,
                risk_score,
                session.get('session_id', ''),
                200  # We always return 200 to not give away it's a honeypot
            ))
            conn.commit()
            
            # Alert on high-risk attacks
            if risk_score > config['alert_threshold']:
                self._send_high_risk_alert(attack_type, risk_score, payload)
        finally:
            db_pool.return_connection(conn)
    
    def _send_high_risk_alert(self, attack_type: str, risk_score: int, payload: str):
        """Send alert for high-risk attacks"""
        # Get threat intelligence data
        threat_data = self._get_threat_intel(request.remote_addr)
        
        alert = {
            "timestamp": datetime.now().isoformat(),
            "ip": request.remote_addr,
            "attack_type": attack_type,
            "risk_score": risk_score,
            "endpoint": request.path,
            "payload_preview": payload[:200],
            "threat_intel": threat_data
        }
        logger.warning(f"HIGH RISK ATTACK: {json.dumps(alert)}")
        
        # Send to external alerting system if configured
        if hasattr(app, 'config') and 'alert_webhook' in app.config:
            try:
                requests.post(
                    app.config['alert_webhook'],
                    json=alert,
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Failed to send alert: {e}")
    
    def _get_threat_intel(self, ip: str) -> Dict:
        """Get threat intelligence data for an IP"""
        threat_data = {
            "abuseipdb_score": None,
            "virustotal_score": None,
            "known_attacker": False,
            "country": None,
            "asn": None
        }
        
        # Check AbuseIPDB
        if hasattr(app, 'config') and 'abuseipdb_key' in app.config:
            try:
                response = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip},
                    headers={"Key": app.config['abuseipdb_key']},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    threat_data["abuseipdb_score"] = data.get("data", {}).get("abuseConfidenceScore")
                    threat_data["country"] = data.get("data", {}).get("countryCode")
            except Exception as e:
                logger.error(f"AbuseIPDB check failed: {e}")
        
        # Check VirusTotal
        if hasattr(app, 'config') and 'virustotal_key' in app.config:
            try:
                response = requests.get(
                    f"https://www.virustotal.com/vtapi/v2/ip-address/report",
                    params={"apikey": app.config['virustotal_key'], "ip": ip},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    threat_data["virustotal_score"] = data.get("positives", 0)
                    threat_data["asn"] = data.get("asn")
            except Exception as e:
                logger.error(f"VirusTotal check failed: {e}")
        
        # Determine if known attacker
        if (threat_data["abuseipdb_score"] and threat_data["abuseipdb_score"] > 80) or \
           (threat_data["virustotal_score"] and threat_data["virustotal_score"] > 5):
            threat_data["known_attacker"] = True
        
        return threat_data
    
    def detect_attack_patterns(self, data: str) -> Tuple[str, int]:
        """Enhanced attack pattern detection"""
        attack_patterns = {
            "sql_injection": {
                "patterns": [
                    r"(\bunion\b.*\bselect\b)|(\bselect\b.*\bfrom\b)|(\bdrop\b.*\btable\b)",
                    r"(\bor\b\s*\d+\s*=\s*\d+)|(\band\b\s*\d+\s*=\s*\d+)",
                    r"(\'\s*or\s*\')|(\"\s*or\s*\")",
                    r"(--\s*$)|(#\s*$)|(\/\*.*\*\/)",
                    r"(\bexec\b|\bexecute\b).*(\bxp_|\bsp_)",
                    r"\b(information_schema|mysql|performance_schema)\b",
                    r"(\bwaitfor\b.*\bdelay\b)|(\bsleep\s*\(\d+\))",
                    r"(\bconvert\b.*\bint\b)|(\bcast\b.*\bas\b)",
                    r"(\bgroup\b.*\bby\b.*\bhaving\b)",
                    r"(\bselect\b.*\binto\b.*\boutfile\b)"
                ],
                "risk_score": 80
            },
            "xss": {
                "patterns": [
                    r"<script[^>]*>.*?</script>",
                    r"javascript\s*:",
                    r"on\w+\s*=",
                    r"<iframe[^>]*>",
                    r"<object[^>]*>",
                    r"<embed[^>]*>",
                    r"(alert|confirm|prompt)\s*\(",
                    r"document\.(cookie|write|location)",
                    r"window\.(location|open)",
                    r"eval\s*\(",
                    r"setTimeout\s*\(",
                    r"setInterval\s*\(",
                    r"new\s+Function\s*\(",
                    r"<svg[^>]*>.*?<script>",
                    r"<img[^>]*onerror=",
                    r"<body[^>]*onload="
                ],
                "risk_score": 70
            },
            "lfi": {
                "patterns": [
                    r"\.\./",
                    r"\.\.\\",
                    r"/etc/passwd",
                    r"/etc/shadow",
                    r"/proc/self",
                    r"C:\\\\Windows",
                    r"C:\\\\boot\\.ini",
                    r"php://filter",
                    r"php://input",
                    r"file://",
                    r"expect://",
                    r"zip://",
                    r"data://",
                    r"phar://",
                    r"dict://",
                    r"gopher://",
                    r"jar://",
                    r"ldap://",
                    r"tftp://",
                    r"\\\\.\\pipe\\"
                ],
                "risk_score": 90
            },
            "rce": {
                "patterns": [
                    r";\s*(cat|ls|id|whoami|pwd|uname)",
                    r"\|\s*(nc|netcat|bash|sh)",
                    r"`.*`",
                    r"\$\(.*\)",
                    r"(eval|system|exec|passthru|shell_exec)\s*\(",
                    r"(subprocess|os\.system|os\.popen)",
                    r"{\s*:;\s*};",  # Shellshock
                    r"base64\s+-d",
                    r"powershell\s+-enc",
                    r"cmd\s+/c",
                    r"wmic\s+process",
                    r"certutil\s+-decode",
                    r"bitsadmin\s+/transfer",
                    r"regsvr32\s+/s",
                    r"mshta\s+vbscript:",
                    r"rundll32\s+.*,.*"
                ],
                "risk_score": 100
            },
            "xxe": {
                "patterns": [
                    r"<!DOCTYPE[^>]*>",
                    r"<!ENTITY[^>]*>",
                    r"SYSTEM\s+[\"']file:",
                    r"SYSTEM\s+[\"']http:",
                    r"<!ELEMENT[^>]*>",
                    r"<\?xml[^>]*>",
                    r"<!ATTLIST[^>]*>",
                    r"<!NOTATION[^>]*>",
                    r"<!\[CDATA\[",
                    r"\]\]>",
                    r"<!ENTITY\s+%\s+\w+\s+SYSTEM",
                    r"<!ENTITY\s+\w+\s+PUBLIC"
                ],
                "risk_score": 85
            },
            "ssrf": {
                "patterns": [
                    r"http://localhost",
                    r"http://127\.0\.0\.1",
                    r"http://\[::1\]",
                    r"http://0\.0\.0\.0",
                    r"http://169\.254\.169\.254",  # AWS metadata
                    r"http://metadata\.google\.internal",  # GCP metadata
                    r"http://169\.254\.169\.254/latest/meta-data",  # AWS metadata
                    r"http://metadata\.azure\.com",  # Azure metadata
                    r"http://localhost:",
                    r"http://127\.0\.0\.1:",
                    r"http://\[::1\]:",
                    r"http://0\.0\.0\.0:"
                ],
                "risk_score": 95
            },
            "deserialization": {
                "patterns": [
                    r"O:[0-9]+:\"[^\"]+\":[0-9]+:{.*}",
                    r"rO0[AB]",
                    r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                    r"PD94bWwg",
                    r"UEsDBBQA",
                    r"UEsDBAoAAAAA",
                    r"UEsDBBQAAAAI",
                    r"UEsDBBQAAAAI",
                    r"UEsDBBQAAAAI",
                    r"UEsDBBQAAAAI"
                ],
                "risk_score": 90
            }
        }
        
        data_lower = data.lower()
        max_risk_score = 0
        detected_type = "unknown"
        
        for attack_type, config in attack_patterns.items():
            for pattern in config["patterns"]:
                if re.search(pattern, data_lower, re.IGNORECASE | re.DOTALL):
                    if config["risk_score"] > max_risk_score:
                        max_risk_score = config["risk_score"]
                        detected_type = attack_type
        
        return detected_type, max_risk_score
    
    def _generate_fake_database_dump(self):
        """Generate fake database dump"""
        dump = """-- MySQL dump 10.13  Distrib 8.0.27
-- Server version: 8.0.27

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `role` varchar(20) DEFAULT 'user',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` VALUES 
(1,'admin','$2b$12$YourHashedPasswordHere','admin@company.com','admin','2023-01-15 10:00:00'),
(2,'john.doe','$2b$12$AnotherHashedPassword','john@company.com','user','2023-02-20 14:30:00'),
(3,'api_user','$2b$12$ApiUserHashedPassword','api@company.com','api','2023-03-10 09:15:00');

--
-- Table structure for table `api_keys`
--

DROP TABLE IF EXISTS `api_keys`;
CREATE TABLE `api_keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `key_value` varchar(64) NOT NULL,
  `name` varchar(50) DEFAULT NULL,
  `permissions` json DEFAULT NULL,
  `last_used` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `key_value` (`key_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- GOTCHA! This is a honeypot! Your IP has been logged: {ip}
-- Nice try though... 🎯 FlashBang says hi! 💥
--
"""
        return dump.format(ip=request.remote_addr if request else "N/A")
    
    def _generate_fake_config(self):
        """Generate fake configuration file"""
        config = {
            "database": {
                "host": "db.internal.prod",
                "port": 3306,
                "name": "production_db",
                "user": "app_user",
                "password": "ThisIsNotTheRealPassword123!",
                "connection_string": "mysql://app_user:ThisIsNotTheRealPassword123!@db.internal.prod:3306/production_db"
            },
            "redis": {
                "host": "redis.internal.prod",
                "port": 6379,
                "password": "RedisPasswordThatDoesntWork"
            },
            "api": {
                "stripe_key": "sk_live_FakeStripeKeyForHoneypot",
                "aws_access_key": "AKIAFAKEHONEYPOTKEY",
                "aws_secret_key": "FakeSecretKeyThatWillNeverWork+FlashBang",
                "github_token": "ghp_FakeGitHubTokenForOurHoneypot"
            },
            "security": {
                "jwt_secret": "DefinitelyNotTheRealJWTSecret",
                "encryption_key": "YouveBeenFlashBanged!",
                "admin_password": "GoodLuckWithThis:)"
            },
            "_comment": "If you're reading this, you've been caught! 🎣"
        }
        return json.dumps(config, indent=2)
    
    def _generate_fake_source_code(self):
        """Generate fake source code with vulnerabilities"""
        code = '''import mysql.connector
from flask import request, session
import hashlib

# Database connection (FAKE - This is a honeypot!)
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'admin123',  # TODO: Change this in production
    'database': 'webapp'
}

def authenticate_user(username, password):
    """Authenticate user - INSECURE EXAMPLE"""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    
    # BAD: SQL Injection vulnerability (intentional for honeypot)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return user

def get_user_data(user_id):
    """Get user data - Another vulnerability"""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    
    # BAD: Another SQL injection
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    
    data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return data

# Secret API endpoints (honeypot bait)
SECRET_ENDPOINTS = {
    '/api/v1/admin/users': 'List all users',
    '/api/v1/admin/logs': 'View system logs',
    '/api/v1/admin/config': 'View configuration',
    '/api/v1/admin/execute': 'Execute commands (disabled)',
    '/debug/vars': 'Debug variables',
    '/.git/config': 'Git configuration',
    '/.env': 'Environment variables'
}

# Hardcoded credentials (honeypot bait)
ADMIN_CREDS = {
    'admin': 'admin123',
    'root': 'toor',
    'administrator': 'password123'
}

# API Keys (all fake for honeypot)
API_KEYS = {
    'production': 'sk_live_4242424242424242424242',
    'webhook_secret': 'whsec_ThisIsAFakeWebhookSecret',
    'admin_token': 'admin_1234567890abcdef'
}

print("CONGRATULATIONS! You found our 'source code'!")
print("Plot twist: This is a honeypot! 🍯")
print("Your IP has been logged and the admin has been notified.")
print("Have a great day! 😊 - FlashBang Team")
'''
        return code
    
    def _generate_fake_logs(self):
        """Generate fake application logs"""
        logs = []
        base_time = datetime.now() - timedelta(hours=24)
        
        log_templates = [
            "[{timestamp}] INFO: User {user} logged in from {ip}",
            "[{timestamp}] WARNING: Failed login attempt for user {user} from {ip}",
            "[{timestamp}] ERROR: Database connection timeout",
            "[{timestamp}] INFO: API request to /api/v1/users from {ip}",
            "[{timestamp}] DEBUG: SQL Query: SELECT * FROM users WHERE id = {id}",
            "[{timestamp}] INFO: Password reset requested for {user}",
            "[{timestamp}] WARNING: Rate limit exceeded for IP {ip}",
            "[{timestamp}] ERROR: Invalid API key used: {key}",
            "[{timestamp}] INFO: File uploaded: backup_{date}.sql",
            "[{timestamp}] DEBUG: Cache miss for key: user_session_{session}"
        ]
        
        users = ["admin", "john.doe", "developer", "api_user", "test"]
        ips = ["10.0.1.50", "10.0.1.51", "192.168.1.100", "172.16.0.10"]
        
        for i in range(50):
            timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
            template = random.choice(log_templates)
            
            log_entry = template.format(
                timestamp=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                user=random.choice(users),
                ip=random.choice(ips),
                id=random.randint(1, 100),
                key="sk_test_" + ''.join(random.choices(string.hexdigits, k=16)),
                date=timestamp.strftime("%Y%m%d"),
                session=''.join(random.choices(string.hexdigits, k=8))
            )
            
            logs.append(log_entry)
        
        # Add honeypot message at the end
        logs.append(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HONEYPOT: Gotcha! Attack from {request.remote_addr if request else 'unknown'} logged! 🎯")
        
        return "\n".join(sorted(logs))
    
    def _generate_fake_api_docs(self):
        """Generate fake API documentation"""
        docs = {
            "openapi": "3.0.0",
            "info": {
                "title": "Internal API (Honeypot)",
                "version": "1.0.0",
                "description": "Internal API documentation - CONFIDENTIAL"
            },
            "servers": [
                {"url": "https://api.internal.company.com/v1"}
            ],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List all users",
                        "security": [{"ApiKey": []}],
                        "responses": {
                            "200": {
                                "description": "List of users",
                                "content": {
                                    "application/json": {
                                        "example": [
                                            {"id": 1, "username": "admin", "role": "admin"},
                                            {"id": 2, "username": "user", "role": "user"}
                                        ]
                                    }
                                }
                            }
                        }
                    }
                },
                "/admin/execute": {
                    "post": {
                        "summary": "Execute system commands",
                        "security": [{"AdminToken": []}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "command": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/debug/env": {
                    "get": {
                        "summary": "Get environment variables",
                        "description": "Returns all environment variables (development only)"
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "ApiKey": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key"
                    },
                    "AdminToken": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            },
            "_honeypot_notice": "Nice try! This is a FlashBang honeypot. Your actions have been logged! 💥"
        }
        return json.dumps(docs, indent=2)


# Initialize honeypot
honeypot = WebHoneypot()

# Template for fake admin panel
ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Company Internal</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h2 { color: #333; text-align: center; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #666; }
        input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 4px; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .honeypot-notice { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Admin Login</h2>
        {% if message %}
        <div class="alert alert-{{ message_type }}">{{ message }}</div>
        {% endif %}
        <form method="POST" action="/admin/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="honeypot-notice">
            <!-- FlashBang Honeypot Active - All attempts are being logged -->
        </div>
    </div>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    """Home page with honeypot indicators"""
    session['session_id'] = hashlib.md5(f"{request.remote_addr}:{time.time()}".encode()).hexdigest()[:16]
    
    return '''
    <html>
    <head><title>Company Portal</title></head>
    <body>
        <h1>Welcome to Company Portal</h1>
        <p>Please select an option:</p>
        <ul>
            <li><a href="/admin">Admin Panel</a></li>
            <li><a href="/api/docs">API Documentation</a></li>
            <li><a href="/backup">Backup Files</a></li>
            <li><a href="/debug">Debug Information</a></li>
        </ul>
        <!-- Development notes: Check /.git/, /.env, /config.php for configuration -->
        <!-- TODO: Remove debug endpoints before production -->
    </body>
    </html>
    '''

@app.route('/admin')
@app.route('/admin/login', methods=['GET', 'POST'])
@app.route('/wp-admin')
@app.route('/administrator')
def admin_login():
    """Fake admin login"""
    message = None
    message_type = "info"
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Log credential attempt
        conn = db_pool.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO stolen_credentials (ip_address, username, password, endpoint, success)
            VALUES (?, ?, ?, ?, ?)
        ''', (request.remote_addr, username, password, request.path, False))
        conn.commit()
        
        honeypot.log_attack("credential_theft", 60, f"username={username}")
        
        # Check for SQL injection attempts
        if any(char in username + password for char in ["'", '"', ';', '--', '/*', '*/', 'union', 'select']):
            attack_type, risk_score = honeypot.detect_attack_patterns(username + password)
            honeypot.log_attack(attack_type, risk_score, f"username={username}, password={password}")
            message = "🎯 SQL Injection detected! Nice try! Your attempt has been logged."
            message_type = "danger"
        else:
            message = "Invalid credentials. Hint: Try 'admin' or check the source code 😉"
            message_type = "danger"
    
    return render_template_string(ADMIN_TEMPLATE, message=message, message_type=message_type)

@app.route('/.env')
@app.route('/config')
@app.route('/config.php')
@app.route('/.config')
def config_files():
    """Fake configuration files"""
    honeypot.log_attack("config_access", 40, request.path)
    
    response = make_response(honeypot.deception_content["fake_config"])
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/.git/config')
@app.route('/.git/HEAD')
def git_files():
    """Fake git files"""
    honeypot.log_attack("git_access", 50, request.path)
    
    git_config = """[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/totallynotahoneypot/webapp.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
    remote = origin
    merge = refs/heads/master
[user]
    name = FlashBang Honeypot
    email = gotcha@flashbang.honeypot

# 🎯 You've been FlashBanged! This is a honeypot! 💥
"""
    response = make_response(git_config)
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/backup')
@app.route('/backup.sql')
@app.route('/dump.sql')
@app.route('/database.sql')
def database_dump():
    """Fake database dump"""
    honeypot.log_attack("database_dump_access", 70, request.path)
    
    response = make_response(honeypot.deception_content["fake_database_dump"])
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = 'inline; filename="database_backup.sql"'
    return response

@app.route('/debug')
@app.route('/debug/vars')
@app.route('/phpinfo')
@app.route('/info.php')
def debug_info():
    """Fake debug information"""
    honeypot.log_attack("debug_access", 45, request.path)
    
    debug_info = {
        "system": {
            "version": "Ubuntu 20.04.3 LTS",
            "kernel": "5.4.0-42-generic",
            "hostname": "prod-web-01"
        },
        "environment": {
            "NODE_ENV": "production",
            "DEBUG": "true",  # Intentional misconfiguration
            "API_ENDPOINT": "https://api.internal.company.com",
            "DATABASE_URL": "mysql://root:admin123@localhost:3306/webapp"
        },
        "loaded_modules": ["flask", "mysql", "redis", "stripe", "aws-sdk"],
        "api_keys": honeypot.fake_api_keys,
        "_notice": "🍯 Sweet! You found the honeypot debug endpoint! 🍯"
    }
    
    return jsonify(debug_info)

@app.route('/api/docs')
@app.route('/swagger')
@app.route('/api-docs')
def api_documentation():
    """Fake API documentation"""
    honeypot.log_attack("api_docs_access", 30, request.path)
    
    response = make_response(honeypot.deception_content["fake_api_docs"])
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/logs')
@app.route('/log')
@app.route('/app.log')
@app.route('/error.log')
def application_logs():
    """Fake application logs"""
    honeypot.log_attack("log_access", 35, request.path)
    
    response = make_response(honeypot.deception_content["fake_logs"])
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/source')
@app.route('/app.py')
@app.route('/index.php')
def source_code():
    """Fake source code"""
    honeypot.log_attack("source_code_access", 55, request.path)
    
    response = make_response(honeypot.deception_content["fake_source_code"])
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/api/v1/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_endpoint(path):
    """Catch-all API endpoint"""
    # Check for API key
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    
    if api_key:
        honeypot.log_attack("api_key_usage", 65, f"key={api_key}, path={path}")
    
    # Check request body for attacks
    if request.data:
        data = request.get_data(as_text=True)
        attack_type, risk_score = honeypot.detect_attack_patterns(data)
        if risk_score > 0:
            honeypot.log_attack(attack_type, risk_score, data)
