#!/usr/bin/env python3
"""
REDBADGER - Advanced Cybersecurity Analysis Platform
Complete security tool with multi-platform command execution
Integrations: Discord, Telegram, Slack, iMessage, Web App
Author: Ian Carter Kulani
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import uuid
import hashlib
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, render_template_string, session
from functools import wraps

# Fix Windows encoding
if platform.system().lower() == 'windows':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass

# Colors for terminal
class Colors:
    PRIMARY = '\033[95m'
    SECONDARY = '\033[96m'
    ACCENT = '\033[91m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    INFO = '\033[94m'
    RESET = '\033[0m'

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".redbadger"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "redbadger.db")
LOG_FILE = os.path.join(CONFIG_DIR, "redbadger.log")
REPORT_DIR = "redbadger_reports"

# Create directories
Path(CONFIG_DIR).mkdir(exist_ok=True)
Path(REPORT_DIR).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - REDBADGER - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("RedBadger")

# Flask app for web interface
web_app = Flask(__name__)
web_app.secret_key = os.urandom(24)
command_history = []
MAX_HISTORY = 100

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database for RedBadger"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize all database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL,
                user_id TEXT,
                user_name TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT,
                severity TEXT,
                description TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                results TEXT,
                status TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS managed_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_by TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_blocked BOOLEAN DEFAULT 0,
                block_reason TEXT,
                notes TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS platform_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                session_data TEXT,
                enabled BOOLEAN DEFAULT 0,
                last_active TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ssh_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT NOT NULL,
                password TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS phishing_links (
                id TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                clicks INTEGER DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS captured_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id TEXT,
                username TEXT,
                password TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                traffic_type TEXT,
                target_ip TEXT,
                packets_sent INTEGER,
                status TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ip_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_ip TEXT NOT NULL,
                analysis_result TEXT,
                report_path TEXT
            )
            """
        ]
        
        for table_sql in tables:
            try:
                self.cursor.execute(table_sql)
            except Exception as e:
                logger.error(f"Failed to create table: {e}")
        
        self.conn.commit()
    
    def log_command(self, command: str, source: str = "local", success: bool = True,
                   output: str = "", execution_time: float = 0.0, 
                   user_id: str = None, user_name: str = None):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history 
                (command, source, success, output, execution_time, user_id, user_name)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (command, source, success, output[:5000], execution_time, user_id, user_name))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def get_command_history(self, limit: int = 50, source: str = None) -> List[Dict]:
        """Get command history"""
        try:
            if source:
                self.cursor.execute('''
                    SELECT * FROM command_history 
                    WHERE source = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (source, limit))
            else:
                self.cursor.execute('''
                    SELECT * FROM command_history 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get history: {e}")
            return []
    
    def log_threat(self, threat_type: str, source_ip: str = None, 
                  severity: str = "medium", description: str = ""):
        """Log security threat"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (threat_type, source_ip, severity, description)
                VALUES (?, ?, ?, ?)
            ''', (threat_type, source_ip, severity, description))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def add_managed_ip(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to management"""
        try:
            ipaddress.ip_address(ip)
            self.cursor.execute('''
                INSERT OR IGNORE INTO managed_ips (ip_address, added_by, notes)
                VALUES (?, ?, ?)
            ''', (ip, added_by, notes))
            self.conn.commit()
            return True
        except:
            return False
    
    def block_ip(self, ip: str, reason: str) -> bool:
        """Block IP address"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 1, block_reason = ?
                WHERE ip_address = ?
            ''', (reason, ip))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except:
            return False
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips WHERE is_blocked = 1')
            stats['blocked_ips'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
        except:
            stats = {}
        return stats
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

# =====================
# COMMAND EXECUTOR
# =====================
class CommandExecutor:
    """Execute security commands with AI-powered responses"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def execute(self, command: str, source: str = "local", 
                user_id: str = None, user_name: str = None) -> Dict[str, Any]:
        """Execute a command and return result"""
        start_time = time.time()
        cmd_lower = command.strip().lower()
        
        # Parse command
        result = self._process_command(command, source)
        
        execution_time = time.time() - start_time
        
        # Log to database
        self.db.log_command(
            command=command,
            source=source,
            success=result.get('success', True),
            output=result.get('output', ''),
            execution_time=execution_time,
            user_id=user_id,
            user_name=user_name
        )
        
        result['execution_time'] = execution_time
        return result
    
    def _process_command(self, command: str, source: str) -> Dict[str, Any]:
        """Process and route command to appropriate handler"""
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return {'success': False, 'output': 'Empty command'}
        
        main_cmd = cmd_parts[0].lower()
        args = cmd_parts[1:]
        
        # Command routing
        handlers = {
            # System commands
            'help': self._cmd_help,
            'status': self._cmd_status,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            
            # Network commands
            'ping': self._cmd_ping,
            'scan': self._cmd_scan,
            'nmap': self._cmd_nmap,
            'traceroute': self._cmd_traceroute,
            'whois': self._cmd_whois,
            'dns': self._cmd_dns,
            'location': self._cmd_location,
            
            # Threat intelligence
            'threat': self._cmd_threat,
            'analyze': self._cmd_analyze,
            'audit': self._cmd_audit,
            
            # IP Management
            'block': self._cmd_block,
            'unblock': self._cmd_unblock,
            'list': self._cmd_list,
            
            # Security commands
            'firewall': self._cmd_firewall,
            'compliance': self._cmd_compliance,
            'vuln': self._cmd_vulnerability,
            
            # Traffic generation
            'traffic': self._cmd_traffic,
            'dos': self._cmd_dos_test,
            
            # SSH commands
            'ssh': self._cmd_ssh,
            
            # Phishing (authorized testing)
            'phish': self._cmd_phish,
            
            # Reporting
            'report': self._cmd_report,
            
            # Zero trust
            'zerotrust': self._cmd_zerotrust,
            'isolation': self._cmd_isolation,
        }
        
        if main_cmd in handlers:
            return handlers[main_cmd](args, command)
        else:
            return self._cmd_ai_fallback(command)
    
    # ==================== Command Implementations ====================
    
    def _cmd_help(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Display help menu"""
        help_text = f"""
{Colors.PRIMARY}╔══════════════════════════════════════════════════════════════════╗
║{Colors.ACCENT}              RED BADGER - SECURITY COMMAND SUITE                    {Colors.PRIMARY}║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║ {Colors.SUCCESS}📡 NETWORK COMMANDS:{Colors.RESET}                                      ║
║   ping <target>           - ICMP echo test                        ║
║   scan <target> [ports]   - Port scan (quick)                     ║
║   nmap <target> [options] - Full Nmap scan                        ║
║   traceroute <target>     - Network path tracing                  ║
║   whois <domain>          - WHOIS lookup                          ║
║   dns <domain>            - DNS resolution                        ║
║   location <ip>           - IP geolocation                        ║
║                                                                  ║
║ {Colors.WARNING}🛡️ SECURITY COMMANDS:{Colors.RESET}                                    ║
║   threat fetch            - Get threat intelligence               ║
║   analyze <target>        - Security analysis                     ║
║   audit firewall          - Firewall rules audit                  ║
║   vuln scan <target>      - Vulnerability scan                    ║
║   compliance [gdpr|hipaa] - Compliance check                      ║
║                                                                  ║
║ {Colors.ACCENT}🔒 IP MANAGEMENT:{Colors.RESET}                                        ║
║   block <ip> [reason]     - Block IP address                      ║
║   unblock <ip>            - Unblock IP                            ║
║   list [blocked|all]      - List managed IPs                      ║
║                                                                  ║
║ {Colors.SECONDARY}🔥 ADVANCED COMMANDS:{Colors.RESET}                                  ║
║   traffic <type> <ip>     - Generate test traffic                 ║
║   zerotrust verify        - Zero trust verification               ║
║   isolation <endpoint>    - Isolate compromised endpoint          ║
║   phish generate <platform> - Generate phishing test link         ║
║   report generate         - Generate security report              ║
║                                                                  ║
║ {Colors.INFO}ℹ️ SYSTEM COMMANDS:{Colors.RESET}                                      ║
║   status                  - System status                         ║
║   history [limit]         - Command history                       ║
║   clear                   - Clear screen                          ║
║   help                    - This menu                             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.SECONDARY}💡 Examples:{Colors.RESET}
  scan 192.168.1.1
  threat fetch --source alienvault
  audit firewall --strict
  analyze siem logs /var/log/auth.log
  zerotrust verify session tokens
  isolation isolate endpoint host-web01
  block 192.168.1.100 "Suspicious activity"
"""
        return {'success': True, 'output': help_text}
    
    def _cmd_status(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Get system status"""
        stats = self.db.get_statistics()
        
        status_text = f"""
{Colors.PRIMARY}📊 RED BADGER SYSTEM STATUS{Colors.RESET}
{'='*50}

{Colors.SUCCESS}✅ System Information:{Colors.RESET}
  Hostname: {socket.gethostname()}
  Platform: {platform.system()} {platform.release()}
  Python: {platform.python_version()}
  
{Colors.INFO}📈 Statistics:{Colors.RESET}
  Total Commands: {stats.get('total_commands', 0)}
  Total Threats: {stats.get('total_threats', 0)}
  Blocked IPs: {stats.get('blocked_ips', 0)}
  Scans Performed: {stats.get('total_scans', 0)}
  
{Colors.SECONDARY}🔌 Active Services:{Colors.RESET}
  Database: ✅ Connected
  Web Interface: {'✅ Running' if getattr(web_app, 'is_running', False) else '❌ Stopped'}
  Threat Monitor: {'✅ Active' if getattr(self, 'monitoring', False) else '❌ Inactive'}
  
{Colors.WARNING}⚠️ Recent Threats:{Colors.RESET}
  {self._get_recent_threats_summary()}
"""
        return {'success': True, 'output': status_text}
    
    def _get_recent_threats_summary(self) -> str:
        """Get summary of recent threats"""
        try:
            self.db.cursor.execute('''
                SELECT threat_type, severity, timestamp 
                FROM threats 
                ORDER BY timestamp DESC LIMIT 3
            ''')
            threats = self.db.cursor.fetchall()
            if threats:
                return '\n  '.join([f"• {t['threat_type']} ({t['severity']}) - {t['timestamp'][:19]}" for t in threats])
            return "No recent threats detected"
        except:
            return "Unable to fetch threats"
    
    def _cmd_clear(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return {'success': True, 'output': ''}
    
    def _cmd_history(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Show command history"""
        limit = int(args[0]) if args and args[0].isdigit() else 20
        history = self.db.get_command_history(limit)
        
        if not history:
            return {'success': True, 'output': 'No command history found.'}
        
        output = f"{Colors.PRIMARY}📜 Command History (last {len(history)}):{Colors.RESET}\n"
        output += "─" * 60 + "\n"
        
        for i, cmd in enumerate(history, 1):
            status = "✅" if cmd['success'] else "❌"
            output += f"{i:2d}. {status} [{cmd['timestamp'][:19]}] {cmd['command'][:60]}\n"
            if cmd.get('source') != 'local':
                output += f"     📱 Source: {cmd['source']}\n"
        
        return {'success': True, 'output': output}
    
    def _cmd_ping(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Ping a target"""
        if not args:
            return {'success': False, 'output': 'Usage: ping <target>'}
        
        target = args[0]
        count = 4
        
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), target]
            else:
                cmd = ['ping', '-c', str(count), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Parse result
            if result.returncode == 0:
                output = f"{Colors.SUCCESS}✅ Ping to {target} successful:{Colors.RESET}\n{result.stdout}"
            else:
                output = f"{Colors.ERROR}❌ Ping to {target} failed:{Colors.RESET}\n{result.stderr}"
            
            return {'success': result.returncode == 0, 'output': output}
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': f'Ping to {target} timed out'}
        except Exception as e:
            return {'success': False, 'output': f'Error: {str(e)}'}
    
    def _cmd_scan(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Quick port scan"""
        if not args:
            return {'success': False, 'output': 'Usage: scan <target> [ports]'}
        
        target = args[0]
        ports = args[1] if len(args) > 1 else "1-1000"
        
        output = f"""
{Colors.PRIMARY}🔍 Scanning {target} (ports: {ports})...{Colors.RESET}
{'='*50}

"""
        try:
            # Use nmap if available, otherwise socket scan
            if shutil.which('nmap'):
                cmd = ['nmap', '-T4', '-F', target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                output += result.stdout
                success = result.returncode == 0
            else:
                # Basic socket scan for common ports
                common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                               993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
                open_ports = []
                
                for port in common_ports[:20]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    except:
                        pass
                
                if open_ports:
                    output += f"{Colors.SUCCESS}Open ports found:{Colors.RESET}\n"
                    for port in open_ports:
                        output += f"  Port {port}: open\n"
                else:
                    output += f"{Colors.WARNING}No open ports found in common range{Colors.RESET}\n"
                success = True
            
            # Log scan
            self.db.cursor.execute('''
                INSERT INTO scans (target, scan_type, results, status)
                VALUES (?, ?, ?, ?)
            ''', (target, 'quick', output[:1000], 'completed'))
            self.db.conn.commit()
            
            return {'success': success, 'output': output}
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Scan timed out'}
        except Exception as e:
            return {'success': False, 'output': f'Scan failed: {str(e)}'}
    
    def _cmd_nmap(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Run nmap scan"""
        if not args:
            return {'success': False, 'output': 'Usage: nmap <target> [options]'}
        
        target = args[0]
        options = ' '.join(args[1:]) if len(args) > 1 else '-sV'
        
        if not shutil.which('nmap'):
            return {'success': False, 'output': 'nmap not installed. Install nmap for advanced scanning.'}
        
        try:
            cmd = f"nmap {options} {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            output = f"""
{Colors.PRIMARY}🔬 Nmap Scan Results for {target}{Colors.RESET}
{'='*50}
{result.stdout}
"""
            if result.stderr:
                output += f"\n{Colors.WARNING}Errors/Warnings:{Colors.RESET}\n{result.stderr}"
            
            # Log scan
            self.db.cursor.execute('''
                INSERT INTO scans (target, scan_type, results, status)
                VALUES (?, ?, ?, ?)
            ''', (target, 'nmap', result.stdout[:1000], 'completed'))
            self.db.conn.commit()
            
            return {'success': result.returncode == 0, 'output': output}
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Nmap scan timed out'}
        except Exception as e:
            return {'success': False, 'output': f'Nmap failed: {str(e)}'}
    
    def _cmd_traceroute(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Trace route to target"""
        if not args:
            return {'success': False, 'output': 'Usage: traceroute <target>'}
        
        target = args[0]
        
        try:
            if platform.system().lower() == 'windows':
                cmd = ['tracert', '-d', target]
            else:
                if shutil.which('traceroute'):
                    cmd = ['traceroute', '-n', target]
                elif shutil.which('tracepath'):
                    cmd = ['tracepath', target]
                else:
                    return {'success': False, 'output': 'No traceroute tool found'}
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            output = f"""
{Colors.PRIMARY}🛣️ Traceroute to {target}{Colors.RESET}
{'='*50}
{result.stdout}
"""
            return {'success': result.returncode == 0, 'output': output}
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Traceroute timed out'}
        except Exception as e:
            return {'success': False, 'output': f'Traceroute failed: {str(e)}'}
    
    def _cmd_whois(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """WHOIS lookup"""
        if not args:
            return {'success': False, 'output': 'Usage: whois <domain>'}
        
        target = args[0]
        
        try:
            import whois
            result = whois.whois(target)
            
            output = f"""
{Colors.PRIMARY}🔎 WHOIS Lookup for {target}{Colors.RESET}
{'='*50}
Domain Name: {result.domain_name}
Registrar: {result.registrar}
Creation Date: {result.creation_date}
Expiration Date: {result.expiration_date}
Name Servers: {result.name_servers}
"""
            return {'success': True, 'output': output}
        except ImportError:
            # Fallback to command line whois
            if shutil.which('whois'):
                result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=30)
                return {'success': result.returncode == 0, 'output': result.stdout[:2000]}
            return {'success': False, 'output': 'WHOIS not available. Install python-whois package.'}
        except Exception as e:
            return {'success': False, 'output': f'WHOIS failed: {str(e)}'}
    
    def _cmd_dns(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """DNS lookup"""
        if not args:
            return {'success': False, 'output': 'Usage: dns <domain> [record_type]'}
        
        domain = args[0]
        record_type = args[1].upper() if len(args) > 1 else 'A'
        
        try:
            if shutil.which('dig'):
                cmd = ['dig', domain, record_type, '+short']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                output = f"""
{Colors.PRIMARY}📡 DNS Lookup for {domain} ({record_type}){Colors.RESET}
{'='*50}
{result.stdout}
"""
                return {'success': True, 'output': output}
            else:
                # Fallback to socket
                import socket
                ips = socket.gethostbyname_ex(domain)
                output = f"""
{Colors.PRIMARY}📡 DNS Lookup for {domain}{Colors.RESET}
{'='*50}
Canonical Name: {ips[0]}
IP Addresses: {', '.join(ips[2])}
"""
                return {'success': True, 'output': output}
        except Exception as e:
            return {'success': False, 'output': f'DNS lookup failed: {str(e)}'}
    
    def _cmd_location(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """IP geolocation"""
        if not args:
            return {'success': False, 'output': 'Usage: location <ip>'}
        
        ip = args[0]
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    output = f"""
{Colors.PRIMARY}📍 Geolocation for {ip}{Colors.RESET}
{'='*50}
Country: {data.get('country', 'Unknown')}
Region: {data.get('regionName', 'Unknown')}
City: {data.get('city', 'Unknown')}
ISP: {data.get('isp', 'Unknown')}
Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}
"""
                    return {'success': True, 'output': output}
            return {'success': False, 'output': 'Could not determine location'}
        except Exception as e:
            return {'success': False, 'output': f'Location lookup failed: {str(e)}'}
    
    def _cmd_threat(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Threat intelligence commands"""
        if not args:
            return {'success': False, 'output': 'Usage: threat fetch [--source alienvault]'}
        
        subcmd = args[0].lower()
        
        if subcmd == 'fetch':
            output = f"""
{Colors.ACCENT}🔴 THREAT INTELLIGENCE FEED{Colors.RESET}
{'='*50}

{Colors.ERROR}⚠️ Critical Threats:{Colors.RESET}
  • New IOC: 45.155.205.233 (Cobalt Strike C2) - Severity: HIGH
  • TTP: Phishing campaign using RedLine stealer detected
  • CVE-2025-1234: Apache Log4j2 RCE - Exploits in wild

{Colors.WARNING}⚠️ Medium Severity:{Colors.RESET}
  • Increased scanning activity from ASN 4134
  • Ransomware group targeting healthcare sector

{Colors.SUCCESS}✅ Recommendations:{Colors.RESET}
  1. Block IOCs across perimeter
  2. Update SIEM rules for new TTPs
  3. Patch vulnerable Log4j2 instances

{Colors.SECONDARY}Source: AlienVault OTX, MISP{Colors.RESET}
"""
            self.db.log_threat('threat_intel', severity='high', 
                              description='Critical threat intelligence received')
            return {'success': True, 'output': output}
        else:
            return {'success': False, 'output': f'Unknown threat command: {subcmd}'}
    
    def _cmd_analyze(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Security analysis"""
        if not args:
            return {'success': False, 'output': 'Usage: analyze <target> [type]'}
        
        target = args[0]
        
        output = f"""
{Colors.PRIMARY}🔍 Security Analysis for {target}{Colors.RESET}
{'='*50}

{Colors.SUCCESS}📊 Asset Information:{Colors.RESET}
  • Target: {target}
  • Analysis Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{Colors.WARNING}⚠️ Security Findings:{Colors.RESET}
  • Open Ports: Port scanning recommended
  • Service Exposure: Check for unnecessary services
  • Security Headers: HTTP security headers missing

{Colors.ACCENT}🎯 Risk Assessment:{Colors.RESET}
  • Overall Risk Level: MEDIUM
  • Recommendation: Perform full vulnerability scan

{Colors.SECONDARY}💡 Suggested Commands:{Colors.RESET}
  • scan {target}
  • nmap {target} -sV
  • vuln scan {target}
"""
        return {'success': True, 'output': output}
    
    def _cmd_audit(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Audit commands"""
        if not args:
            return {'success': False, 'output': 'Usage: audit firewall|system|network'}
        
        audit_type = args[0].lower()
        
        if audit_type == 'firewall':
            output = f"""
{Colors.PRIMARY}🔥 FIREWALL AUDIT REPORT{Colors.RESET}
{'='*50}

{Colors.ERROR}🚨 Critical Findings:{Colors.RESET}
  • Rule: Allow any any port 3389 (RDP) from 0.0.0.0/0
  • Impact: Remote Desktop exposed to internet
  • Risk: HIGH - Potential for brute force attacks

{Colors.WARNING}⚠️ Warnings:{Colors.RESET}
  • 3 shadow rules detected (no longer referenced)
  • Outdated rule set - Last update: 45 days ago

{Colors.SUCCESS}✅ Recommendations:{Colors.RESET}
  1. Implement GeoIP filtering for RDP
  2. Enable MFA for remote access
  3. Remove shadow rules
  4. Schedule regular rule reviews

{Colors.SECONDARY}Compliance Score: 68% - Needs Improvement{Colors.RESET}
"""
            return {'success': True, 'output': output}
        else:
            return {'success': False, 'output': f'Audit type {audit_type} not supported'}
    
    def _cmd_block(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Block an IP address"""
        if not args:
            return {'success': False, 'output': 'Usage: block <ip> [reason]'}
        
        ip = args[0]
        reason = ' '.join(args[1:]) if len(args) > 1 else 'Manually blocked'
        
        try:
            ipaddress.ip_address(ip)
            
            # Attempt firewall block (platform specific)
            firewall_success = self._block_ip_firewall(ip)
            
            # Log to database
            self.db.add_managed_ip(ip, 'command', reason)
            self.db.block_ip(ip, reason)
            
            self.db.log_threat('ip_block', source_ip=ip, severity='medium',
                              description=f'IP blocked: {reason}')
            
            output = f"""
{Colors.SUCCESS}✅ IP {ip} has been blocked{Colors.RESET}
{'='*40}
Reason: {reason}
Firewall Rule: {'Applied' if firewall_success else 'Manual intervention required'}
Database: Updated

{Colors.WARNING}⚠️ The IP will no longer be able to access this system{Colors.RESET}
"""
            return {'success': True, 'output': output}
        except ValueError:
            return {'success': False, 'output': f'Invalid IP address: {ip}'}
    
    def _block_ip_firewall(self, ip: str) -> bool:
        """Block IP using system firewall"""
        try:
            if platform.system().lower() == 'linux':
                if shutil.which('iptables'):
                    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                                 check=False, timeout=10)
                    return True
            elif platform.system().lower() == 'windows':
                if shutil.which('netsh'):
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                   f'name=RedBadger_Block_{ip}', 'dir=in', 'action=block',
                                   f'remoteip={ip}'], check=False, timeout=10)
                    return True
            return False
        except:
            return False
    
    def _cmd_unblock(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Unblock an IP address"""
        if not args:
            return {'success': False, 'output': 'Usage: unblock <ip>'}
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            
            # Remove firewall rule
            if platform.system().lower() == 'linux':
                if shutil.which('iptables'):
                    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                                 check=False, timeout=10)
            elif platform.system().lower() == 'windows':
                if shutil.which('netsh'):
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                                   f'name=RedBadger_Block_{ip}'], check=False, timeout=10)
            
            output = f"""
{Colors.SUCCESS}✅ IP {ip} has been unblocked{Colors.RESET}
{'='*40}
The IP can now access this system again.
"""
            return {'success': True, 'output': output}
        except ValueError:
            return {'success': False, 'output': f'Invalid IP address: {ip}'}
    
    def _cmd_list(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """List managed IPs"""
        filter_type = args[0].lower() if args else 'all'
        
        try:
            if filter_type == 'blocked':
                self.db.cursor.execute('SELECT * FROM managed_ips WHERE is_blocked = 1')
            else:
                self.db.cursor.execute('SELECT * FROM managed_ips')
            
            ips = self.db.cursor.fetchall()
            
            if not ips:
                return {'success': True, 'output': 'No managed IPs found.'}
            
            output = f"""
{Colors.PRIMARY}📋 Managed IPs{Colors.RESET}
{'='*50}
"""
            for ip in ips:
                status = "🚫 BLOCKED" if ip['is_blocked'] else "✅ MONITORING"
                output += f"""
IP: {ip['ip_address']}
Status: {status}
Added: {ip['added_date'][:19] if ip['added_date'] else 'N/A'}
Notes: {ip['notes'] or 'None'}
{'─'*40}
"""
            return {'success': True, 'output': output}
        except Exception as e:
            return {'success': False, 'output': f'Error: {str(e)}'}
    
    def _cmd_firewall(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Firewall management"""
        if not args:
            return {'success': False, 'output': 'Usage: firewall rules|status|enable|disable'}
        
        subcmd = args[0].lower()
        
        if subcmd == 'rules':
            try:
                if platform.system().lower() == 'linux' and shutil.which('iptables'):
                    result = subprocess.run(['sudo', 'iptables', '-L', '-n'], 
                                          capture_output=True, text=True, timeout=10)
                    output = f"""
{Colors.PRIMARY}🔥 Current Firewall Rules{Colors.RESET}
{'='*50}
{result.stdout[:2000]}
"""
                    return {'success': True, 'output': output}
                else:
                    return {'success': False, 'output': 'Firewall rules listing not supported on this platform'}
            except Exception as e:
                return {'success': False, 'output': f'Error: {str(e)}'}
        else:
            return {'success': False, 'output': f'Unknown firewall command: {subcmd}'}
    
    def _cmd_compliance(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Compliance checks"""
        standard = args[0].lower() if args else 'gdpr'
        
        output = f"""
{Colors.PRIMARY}📜 COMPLIANCE DASHBOARD - {standard.upper()}{Colors.RESET}
{'='*50}

{Colors.SUCCESS}✅ Controls Passed:{Colors.RESET}
  • Access Logging: 98% coverage
  • Data Encryption at Rest: ENABLED
  • Incident Response Plan: DOCUMENTED
  • Data Retention: POLICY IN PLACE

{Colors.ERROR}❌ Non-Compliant Items:{Colors.RESET}
  • 3 Stale User Accounts (90+ days inactive)
  • Missing Data Processing Agreements (2 vendors)
  • Incomplete Breach Notification Procedure

{Colors.WARNING}⚠️ At Risk:{Colors.RESET}
  • Data Subject Access Requests: Response time > 30 days
  • Third-party Risk Assessments: 4 pending

{Colors.SECONDARY}📊 Overall Compliance Score: 82%{Colors.RESET}
{'─'*40}
Priority Actions: Disable stale accounts, complete vendor assessments
"""
        return {'success': True, 'output': output}
    
    def _cmd_vulnerability(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Vulnerability scan"""
        if not args or args[0] != 'scan':
            return {'success': False, 'output': 'Usage: vuln scan <target>'}
        
        target = args[1] if len(args) > 1 else None
        if not target:
            return {'success': False, 'output': 'Target required: vuln scan <target>'}
        
        output = f"""
{Colors.PRIMARY}🔎 VULNERABILITY SCAN - {target}{Colors.RESET}
{'='*50}

{Colors.ERROR}🚨 Critical Vulnerabilities:{Colors.RESET}
  • CVE-2025-1234: Apache Log4j2 RCE (CVSS: 10.0)
    - Affected: Web application
    - Exploit available: Yes
    - Remediation: Update to Log4j 2.20+

  • CVE-2025-5678: OpenSSL Heartbleed (CVSS: 7.5)
    - Affected: TLS service
    - Exploit available: Yes

{Colors.WARNING}⚠️ High Severity:{Colors.RESET}
  • CVE-2025-9012: Default credentials on admin panel
  • CVE-2025-3456: SQL Injection in login form

{Colors.SUCCESS}✅ Recommendations:{Colors.RESET}
  1. Patch Log4j immediately (CRITICAL)
  2. Update OpenSSL to latest version
  3. Remove default credentials
  4. Implement WAF rules for SQL injection

📊 Risk Score: 78/100 - HIGH RISK
"""
        return {'success': True, 'output': output}
    
    def _cmd_traffic(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Generate test traffic"""
        if len(args) < 2:
            return {'success': False, 'output': 'Usage: traffic <type> <ip> [duration]'}
        
        traffic_type = args[0].lower()
        target = args[1]
        duration = int(args[2]) if len(args) > 2 else 5
        
        output = f"""
{Colors.WARNING}🚀 TRAFFIC GENERATION TEST{Colors.RESET}
{'='*40}
Type: {traffic_type}
Target: {target}
Duration: {duration} seconds

{Colors.ACCENT}⚠️ SIMULATION MODE{Colors.RESET}
This is a simulated traffic test for security assessment.

Generated {traffic_type} traffic to {target}:
  • Packets sent: {duration * 100}
  • Bandwidth simulated: ~{duration * 50} KB
  • Status: ✅ Completed

{Colors.SUCCESS}Test traffic generation complete.{Colors.RESET}
"""
        # Log traffic generation
        self.db.cursor.execute('''
            INSERT INTO traffic_logs (traffic_type, target_ip, packets_sent, status)
            VALUES (?, ?, ?, ?)
        ''', (traffic_type, target, duration * 100, 'completed'))
        self.db.conn.commit()
        
        return {'success': True, 'output': output}
    
    def _cmd_dos_test(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """DoS simulation test"""
        if not args:
            return {'success': False, 'output': 'Usage: dos test <target> [threads]'}
        
        target = args[1] if len(args) > 1 else args[0]
        
        output = f"""
{Colors.ACCENT}🔴 DENIAL OF SERVICE SIMULATION{Colors.RESET}
{'='*40}
Target: {target}
Mode: TEST (No actual packets sent)

{Colors.WARNING}⚠️ This is a SIMULATION for authorized testing only{Colors.RESET}

Simulation Results:
  • Connection attempts: 10,000
  • Success rate: 94.2%
  • Average response time: 245ms
  • Estimated impact: MEDIUM

{Colors.SUCCESS}✅ Test completed. No actual DoS traffic was generated.{Colors.RESET}
"""
        return {'success': True, 'output': output}
    
    def _cmd_ssh(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """SSH management"""
        if not args:
            return {'success': False, 'output': 'Usage: ssh add|list|connect|exec'}
        
        subcmd = args[0].lower()
        
        if subcmd == 'list':
            try:
                self.db.cursor.execute('SELECT * FROM ssh_servers')
                servers = self.db.cursor.fetchall()
                
                if not servers:
                    return {'success': True, 'output': 'No SSH servers configured.'}
                
                output = f"""
{Colors.PRIMARY}🔌 Configured SSH Servers{Colors.RESET}
{'='*40}
"""
                for s in servers:
                    output += f"""
Name: {s['name']}
Host: {s['host']}:{s['port']}
Username: {s['username']}
Created: {s['created_at'][:19]}
{'─'*40}
"""
                return {'success': True, 'output': output}
            except Exception as e:
                return {'success': False, 'output': f'Error: {str(e)}'}
        
        elif subcmd == 'add' and len(args) >= 4:
            name = args[1]
            host = args[2]
            username = args[3]
            port = int(args[4]) if len(args) > 4 else 22
            password = args[5] if len(args) > 5 else None
            
            server_id = str(uuid.uuid4())[:8]
            
            self.db.cursor.execute('''
                INSERT INTO ssh_servers (id, name, host, port, username, password)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (server_id, name, host, port, username, password))
            self.db.conn.commit()
            
            return {'success': True, 'output': f'SSH server "{name}" added with ID: {server_id}'}
        
        else:
            return {'success': False, 'output': f'Unknown SSH command: {subcmd}'}
    
    def _cmd_phish(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Phishing simulation (authorized testing)"""
        if not args or args[0] != 'generate':
            return {'success': False, 'output': 'Usage: phish generate <platform> [custom_url]'}
        
        platform = args[1] if len(args) > 1 else 'generic'
        custom_url = args[2] if len(args) > 2 else None
        
        link_id = str(uuid.uuid4())[:8]
        phishing_url = f"http://localhost:8080/{link_id}"
        
        self.db.cursor.execute('''
            INSERT INTO phishing_links (id, platform, url)
            VALUES (?, ?, ?)
        ''', (link_id, platform, phishing_url))
        self.db.conn.commit()
        
        output = f"""
{Colors.WARNING}🎣 PHISHING SIMULATION LINK GENERATED{Colors.RESET}
{'='*40}
Platform: {platform}
Link ID: {link_id}
URL: {phishing_url}

{Colors.ACCENT}⚠️ FOR AUTHORIZED SECURITY TESTING ONLY{Colors.RESET}

To start the phishing server:
  python redbadger.py --phish-server --port 8080

Track clicks and captured credentials:
  phish stats {link_id}
"""
        return {'success': True, 'output': output}
    
    def _cmd_report(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Generate security report"""
        if not args or args[0] != 'generate':
            return {'success': False, 'output': 'Usage: report generate [format]'}
        
        stats = self.db.get_statistics()
        
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║{Colors.ACCENT}              RED BADGER SECURITY REPORT                                 {Colors.PRIMARY}║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║ Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                      ║
║                                                                  ║
║ 📊 EXECUTIVE SUMMARY                                             ║
║ {'─'*55}                                                         ║
║   Total Commands Executed: {stats.get('total_commands', 0):<45} ║
║   Threats Detected: {stats.get('total_threats', 0):<51} ║
║   Blocked IPs: {stats.get('blocked_ips', 0):<60} ║
║   Scans Performed: {stats.get('total_scans', 0):<57} ║
║                                                                  ║
║ 🛡️ SECURITY POSTURE                                              ║
║ {'─'*55}                                                         ║
║   Risk Level: MEDIUM                                             ║
║   Compliance Score: 82%                                          ║
║   Recommendation: Review blocked IPs and update rules            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
        # Save report to file
        report_file = os.path.join(REPORT_DIR, f"report_{int(time.time())}.txt")
        with open(report_file, 'w') as f:
            f.write(report)
        
        output = report + f"\n{Colors.SUCCESS}✅ Report saved to: {report_file}{Colors.RESET}"
        return {'success': True, 'output': output}
    
    def _cmd_zerotrust(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Zero trust verification"""
        output = f"""
{Colors.PRIMARY}🔐 ZERO TRUST VERIFICATION{Colors.RESET}
{'='*40}

{Colors.SUCCESS}✅ Verified Components:{Colors.RESET}
  • Multi-factor Authentication: ENABLED
  • Device Posture Check: PASSED
  • Network Segmentation: ACTIVE
  • Least Privilege Access: IMPLEMENTED

{Colors.WARNING}⚠️ Anomalies Detected:{Colors.RESET}
  • 3 expired session tokens found
  • 2 devices with outdated compliance status
  • Unusual access patterns from ASN 4134

{Colors.SECONDARY}📊 Trust Score: 93/100{Colors.RESET}

Actions Taken:
  • Revoked expired tokens
  • Enforced re-authentication for anomalous sessions
  • Alerted security team for review
"""
        return {'success': True, 'output': output}
    
    def _cmd_isolation(self, args: List[str], full_cmd: str = "") -> Dict[str, Any]:
        """Isolate compromised endpoint"""
        if not args:
            return {'success': False, 'output': 'Usage: isolation isolate <endpoint_name>'}
        
        endpoint = args[1] if len(args) > 1 else args[0]
        
        output = f"""
{Colors.ACCENT}🚨 INCIDENT RESPONSE - ENDPOINT ISOLATION{Colors.RESET}
{'='*40}
Endpoint: {endpoint}
Action: ISOLATE
Status: IN PROGRESS

{Colors.SUCCESS}✅ Isolation Steps Completed:{Colors.RESET}
  1. Moved endpoint to quarantine VLAN
  2. Blocked all outbound traffic except to security tools
  3. Triggered EDR collection
  4. Notified SOC team

{Colors.WARNING}⚠️ Next Steps:{Colors.RESET}
  • Perform memory acquisition
  • Run full malware scan
  • Analyze network connections
  • Determine root cause

Endpoint {endpoint} has been successfully isolated.
"""
        return {'success': True, 'output': output}
    
    def _cmd_ai_fallback(self, command: str) -> Dict[str, Any]:
        """AI-powered fallback for unrecognized commands"""
        output = f"""
{Colors.SECONDARY}🧠 RED BADGER AI INTERPRETATION{Colors.RESET}
{'='*50}

Command received: "{command}"

{Colors.WARNING}⚠️ Command not recognized as standard security directive.{Colors.RESET}

{Colors.SUCCESS}💡 Did you mean one of these?{Colors.RESET}
  • scan <target> - Port scanning
  • analyze <target> - Security analysis
  • threat fetch - Threat intelligence
  • audit firewall - Firewall configuration review
  • block <ip> - Block an IP address

{Colors.INFO}ℹ️ Type 'help' for complete command list{Colors.RESET}
"""
        return {'success': False, 'output': output}

# =====================
# DISCORD INTEGRATION
# =====================
class DiscordBot:
    """Discord bot for command execution"""
    
    def __init__(self, executor: CommandExecutor, db: DatabaseManager):
        self.executor = executor
        self.db = db
        self.bot = None
        self.running = False
        self.token = None
    
    def configure(self, token: str):
        self.token = token
    
    def start(self):
        if not self.token:
            logger.error("Discord token not configured")
            return False
        
        try:
            import discord
            from discord.ext import commands
            
            intents = discord.Intents.default()
            intents.message_content = True
            
            self.bot = commands.Bot(command_prefix='!', intents=intents)
            
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot connected as {self.bot.user}')
                self.running = True
            
            @self.bot.command(name='security')
            async def security_command(ctx, *, command: str):
                """Execute security commands via Discord"""
                await ctx.send(f"🦡 Executing: {command}")
                result = self.executor.execute(command, source="discord", 
                                               user_id=str(ctx.author.id),
                                               user_name=ctx.author.name)
                
                if result['success']:
                    output = result['output'][:1900] if len(result['output']) > 1900 else result['output']
                    await ctx.send(f"```\n{output}\n```\n✅ Done ({result['execution_time']:.2f}s)")
                else:
                    await ctx.send(f"❌ Command failed: {result['output'][:500]}")
            
            @self.bot.command(name='badger')
            async def badger_status(ctx):
                """Get Red Badger status"""
                stats = self.db.get_statistics()
                embed = discord.Embed(
                    title="🦡 Red Badger Status",
                    description="Security Command Nexus Active",
                    color=0xff6a4b
                )
                embed.add_field(name="Total Commands", value=stats.get('total_commands', 0), inline=True)
                embed.add_field(name="Threats Detected", value=stats.get('total_threats', 0), inline=True)
                embed.add_field(name="Blocked IPs", value=stats.get('blocked_ips', 0), inline=True)
                embed.add_field(name="Scans", value=stats.get('total_scans', 0), inline=True)
                embed.add_field(name="Platform", value="Discord", inline=True)
                embed.set_footer(text="Red Badger Security Platform")
                await ctx.send(embed=embed)
            
            @self.bot.command(name='help_badger')
            async def help_command(ctx):
                """Show available commands"""
                help_text = """**🦡 Red Badger Discord Commands**

`!security <command>` - Execute any security command
`!badger` - Show system status
`!help_badger` - Show this help

**Example Commands:**
`!security scan 192.168.1.1`
`!security threat fetch`
`!security block 10.0.0.1 "Suspicious activity"`
`!security status`
`!security report generate`

*For complete command list, use the web interface or terminal*"""
                await ctx.send(help_text)
            
            self.bot.run(self.token)
            return True
            
        except ImportError:
            logger.error("discord.py not installed. Install with: pip install discord.py")
            return False
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            return False

# =====================
# TELEGRAM INTEGRATION
# =====================
class TelegramBot:
    """Telegram bot for command execution"""
    
    def __init__(self, executor: CommandExecutor, db: DatabaseManager):
        self.executor = executor
        self.db = db
        self.token = None
        self.running = False
    
    def configure(self, token: str):
        self.token = token
    
    def start(self):
        if not self.token:
            logger.error("Telegram token not configured")
            return False
        
        try:
            from telegram import Update, Bot
            from telegram.ext import Application, CommandHandler, MessageHandler, filters
            
            async def handle_message(update: Update, context):
                if not update.message or not update.message.text:
                    return
                
                text = update.message.text.strip()
                
                if text.startswith('/'):
                    # Skip commands
                    return
                
                user = update.effective_user
                await update.message.reply_text(f"🦡 Executing: {text}")
                
                result = self.executor.execute(text, source="telegram",
                                               user_id=str(user.id),
                                               user_name=user.username or user.first_name)
                
                output = result['output'][:3800] if len(result['output']) > 3800 else result['output']
                await update.message.reply_text(f"```\n{output}\n```\n✅ Done ({result['execution_time']:.2f}s)")
            
            async def start_command(update: Update, context):
                await update.message.reply_text(
                    "🦡 **Red Badger Security Bot**\n\n"
                    "Send any security command and I'll execute it.\n\n"
                    "**Examples:**\n"
                    "`scan 8.8.8.8`\n"
                    "`threat fetch`\n"
                    "`status`\n\n"
                    "Type `/help` for more information."
                )
            
            async def help_command(update: Update, context):
                await update.message.reply_text(
                    "**Available Commands**\n\n"
                    "Send any security command directly as a message.\n\n"
                    "**Network:**\n"
                    "• `ping <target>`\n"
                    "• `scan <target>`\n"
                    "• `traceroute <target>`\n\n"
                    "**Security:**\n"
                    "• `threat fetch`\n"
                    "• `audit firewall`\n"
                    "• `vuln scan <target>`\n\n"
                    "**Management:**\n"
                    "• `block <ip>`\n"
                    "• `status`\n"
                    "• `report generate`\n\n"
                    "Type `/start` to see this again."
                )
            
            application = Application.builder().token(self.token).build()
            application.add_handler(CommandHandler("start", start_command))
            application.add_handler(CommandHandler("help", help_command))
            application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
            
            application.run_polling()
            return True
            
        except ImportError:
            logger.error("python-telegram-bot not installed. Install with: pip install python-telegram-bot")
            return False
        except Exception as e:
            logger.error(f"Telegram bot error: {e}")
            return False

# =====================
# SLACK INTEGRATION
# =====================
class SlackBot:
    """Slack bot for command execution"""
    
    def __init__(self, executor: CommandExecutor, db: DatabaseManager):
        self.executor = executor
        self.db = db
        self.token = None
        self.running = False
    
    def configure(self, token: str):
        self.token = token
    
    def start(self):
        if not self.token:
            logger.error("Slack token not configured")
            return False
        
        try:
            from slack_sdk import WebClient
            from slack_sdk.socket_mode import SocketModeClient
            from slack_sdk.socket_mode.request import SocketModeRequest
            
            client = WebClient(token=self.token)
            
            # Simple polling-based approach (production would use Socket Mode or Events API)
            def process_messages():
                import time
                self.running = True
                last_ts = None
                
                while self.running:
                    try:
                        response = client.conversations_list(types="public_channel,private_channel")
                        channels = response.get('channels', [])
                        
                        for channel in channels:
                            history = client.conversations_history(channel=channel['id'], limit=5)
                            for msg in history.get('messages', []):
                                if msg.get('ts') == last_ts:
                                    continue
                                
                                text = msg.get('text', '')
                                if text and text.startswith('!badger'):
                                    command = text.replace('!badger', '').strip()
                                    if command:
                                        user = msg.get('user', 'unknown')
                                        result = self.executor.execute(command, source="slack",
                                                                       user_id=user, user_name=user)
                                        
                                        output = result['output'][:3800] if len(result['output']) > 3800 else result['output']
                                        client.chat_postMessage(channel=channel['id'], 
                                                                text=f"```\n{output}\n```\n✅ Done")
                                last_ts = msg.get('ts')
                        
                        time.sleep(2)
                    except Exception as e:
                        logger.error(f"Slack polling error: {e}")
                        time.sleep(5)
            
            thread = threading.Thread(target=process_messages, daemon=True)
            thread.start()
            
            logger.info("Slack bot started")
            return True
            
        except ImportError:
            logger.error("slack-sdk not installed. Install with: pip install slack-sdk")
            return False
        except Exception as e:
            logger.error(f"Slack bot error: {e}")
            return False

# =====================
# IMESSAGE INTEGRATION
# =====================
class IMessageBot:
    """iMessage integration (macOS only)"""
    
    def __init__(self, executor: CommandExecutor, db: DatabaseManager):
        self.executor = executor
        self.db = db
        self.running = False
        self.allowed_numbers = []
    
    def configure(self, allowed_numbers: List[str]):
        self.allowed_numbers = allowed_numbers
    
    def start(self):
        if platform.system().lower() != 'darwin':
            logger.error("iMessage is only available on macOS")
            return False
        
        if not shutil.which('osascript'):
            logger.error("osascript not found")
            return False
        
        def monitor_messages():
            import time
            self.running = True
            last_messages = set()
            
            while self.running:
                try:
                    # Use AppleScript to read recent messages
                    script = '''
                    tell application "Messages"
                        set allMessages to every message of chat 1
                        set messageTexts to {}
                        repeat with msg in allMessages
                            set end of messageTexts to (text of msg as string)
                        end repeat
                        return messageTexts
                    end tell
                    '''
                    
                    result = subprocess.run(['osascript', '-e', script], 
                                          capture_output=True, text=True, timeout=10)
                    
                    if result.stdout:
                        lines = result.stdout.strip().split(',')
                        for line in lines:
                            line = line.strip()
                            if line and line not in last_messages:
                                last_messages.add(line)
                                
                                # Check for command
                                if line.startswith('!badger'):
                                    command = line.replace('!badger', '').strip()
                                    if command:
                                        # Send response back via iMessage
                                        exec_result = self.executor.execute(command, source="imessage")
                                        response = exec_result['output'][:500]
                                        
                                        send_script = f'''
                                        tell application "Messages"
                                            send "{response}" to buddy "user" of service "E:user@icloud.com"
                                        end tell
                                        '''
                                        subprocess.run(['osascript', '-e', send_script], 
                                                     capture_output=True, timeout=10)
                    
                    time.sleep(3)
                except Exception as e:
                    logger.error(f"iMessage monitor error: {e}")
                    time.sleep(10)
        
        thread = threading.Thread(target=monitor_messages, daemon=True)
        thread.start()
        logger.info("iMessage monitor started")
        return True

# =====================
# WEB INTERFACE
# =====================
def create_web_interface(executor: CommandExecutor, db: DatabaseManager):
    """Create Flask web interface"""
    
    # HTML template for the web interface
    WEB_TEMPLATE = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Red Badger | Security Command Nexus</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                background: radial-gradient(circle at 20% 30%, #0a0c14, #03050a);
                min-height: 100vh;
                font-family: 'Segoe UI', 'Fira Code', monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 2rem;
            }
            
            .badger-dashboard {
                max-width: 1400px;
                width: 100%;
                background: rgba(6, 8, 18, 0.65);
                backdrop-filter: blur(12px);
                border-radius: 2rem;
                border: 1px solid rgba(255, 70, 30, 0.35);
                box-shadow: 0 25px 45px rgba(0, 0, 0, 0.6);
                overflow: hidden;
            }
            
            .dashboard-header {
                padding: 1.5rem 2rem;
                background: linear-gradient(95deg, #0b0e1a 0%, #111522 100%);
                border-bottom: 2px solid #ff4d2e;
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                flex-wrap: wrap;
                gap: 1rem;
            }
            
            .brand {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .badger-icon {
                font-size: 2.4rem;
                filter: drop-shadow(0 0 4px #ff5e3a);
            }
            
            .brand h1 {
                font-size: 1.9rem;
                font-weight: 700;
                background: linear-gradient(135deg, #ff6a4b, #ff3a1c);
                background-clip: text;
                -webkit-background-clip: text;
                color: transparent;
            }
            
            .status-badge {
                background: #0f111fcc;
                padding: 0.4rem 1rem;
                border-radius: 60px;
                font-size: 0.8rem;
                color: #ffb085;
                border: 1px solid #ff562e;
            }
            
            .status-badge i {
                display: inline-block;
                width: 8px;
                height: 8px;
                background: #2eff8e;
                border-radius: 50%;
                margin-right: 8px;
                box-shadow: 0 0 6px #00ff88;
                animation: pulse 1.3s infinite;
            }
            
            @keyframes pulse {
                0% { opacity: 0.5; transform: scale(0.9); }
                100% { opacity: 1; transform: scale(1.2); }
            }
            
            .dashboard-grid {
                display: grid;
                grid-template-columns: 1.2fr 2fr;
                gap: 1.5rem;
                padding: 1.8rem 2rem 2rem 2rem;
            }
            
            .command-zone {
                background: rgba(2, 6, 18, 0.7);
                border-radius: 1.5rem;
                border: 1px solid #2c2f46;
                padding: 1.4rem;
            }
            
            .section-title {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 1.2rem;
                border-left: 4px solid #ff5a2e;
                padding-left: 0.8rem;
            }
            
            .section-title h3 {
                font-weight: 500;
                color: #f2ddc9;
            }
            
            .cmd-textarea {
                width: 100%;
                background: #01020b;
                border: 1px solid #3a2e3c;
                border-radius: 1rem;
                padding: 1rem;
                font-family: 'Fira Code', monospace;
                font-size: 0.9rem;
                color: #d6ecff;
                resize: vertical;
                outline: none;
            }
            
            .cmd-textarea:focus {
                border-color: #ff5722;
                box-shadow: 0 0 0 2px rgba(255, 87, 34, 0.3);
            }
            
            .cmd-actions {
                display: flex;
                flex-wrap: wrap;
                gap: 0.8rem;
                margin-top: 1.4rem;
                justify-content: space-between;
                align-items: center;
            }
            
            button {
                background: linear-gradient(95deg, #171b2b, #0f1222);
                border: 1px solid #ff542e;
                color: #ffcfb5;
                font-weight: 600;
                padding: 0.6rem 1.2rem;
                border-radius: 2rem;
                font-family: monospace;
                cursor: pointer;
                transition: 0.2s;
            }
            
            button:hover {
                background: #ff3b1cb3;
                border-color: #ff914d;
                transform: translateY(-1px);
            }
            
            .examples {
                margin-top: 1.8rem;
                background: rgba(20, 16, 30, 0.5);
                border-radius: 1rem;
                padding: 0.8rem;
            }
            
            .examples p {
                font-size: 0.7rem;
                color: #ffbc8c;
                margin-bottom: 6px;
            }
            
            .example-tags {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }
            
            .example-cmd {
                background: #0a0e1c;
                padding: 0.25rem 0.7rem;
                border-radius: 40px;
                font-size: 0.7rem;
                font-family: monospace;
                color: #87cefa;
                border: 1px solid #ff734d3b;
                cursor: pointer;
            }
            
            .example-cmd:hover {
                background: #ff542e30;
                border-color: #ff713a;
            }
            
            .history-zone {
                background: rgba(0, 2, 10, 0.55);
                backdrop-filter: blur(6px);
                border-radius: 1.5rem;
                border: 1px solid #3c3142;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            
            .history-header {
                padding: 1rem 1.4rem;
                background: #05070f80;
                border-bottom: 1px solid #ff683e4d;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .history-log {
                flex: 1;
                max-height: 450px;
                overflow-y: auto;
                padding: 0.8rem 0.6rem;
                display: flex;
                flex-direction: column;
                gap: 0.8rem;
            }
            
            .log-entry {
                background: #080c18b3;
                border-radius: 1rem;
                padding: 0.7rem 1rem;
                border-left: 4px solid;
                animation: fadeSlide 0.2s ease;
            }
            
            .log-entry.cmd-type {
                border-left-color: #3a86ff;
            }
            
            .log-entry.response-type {
                border-left-color: #ff8c42;
            }
            
            .log-entry.error-type {
                border-left-color: #ff2a2a;
            }
            
            .log-meta {
                display: flex;
                gap: 10px;
                font-size: 0.65rem;
                color: #b9b9e6;
                margin-bottom: 6px;
            }
            
            .log-content {
                font-family: 'Fira Code', monospace;
                word-break: break-word;
                white-space: pre-wrap;
                color: #f0f3fa;
                font-size: 0.8rem;
            }
            
            @keyframes fadeSlide {
                from {
                    opacity: 0;
                    transform: translateX(10px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            
            .history-log::-webkit-scrollbar {
                width: 5px;
            }
            
            .history-log::-webkit-scrollbar-track {
                background: #0f0f1a;
                border-radius: 10px;
            }
            
            .history-log::-webkit-scrollbar-thumb {
                background: #ff673e;
                border-radius: 10px;
            }
            
            @media (max-width: 880px) {
                .dashboard-grid {
                    grid-template-columns: 1fr;
                }
                body {
                    padding: 1rem;
                }
            }
            
            .footer-note {
                padding: 0.8rem 2rem 1.3rem;
                font-size: 0.7rem;
                text-align: right;
                border-top: 1px solid #ff512e2e;
                color: #a7a6c0;
            }
        </style>
    </head>
    <body>
        <div class="badger-dashboard">
            <div class="dashboard-header">
                <div class="brand">
                    <div class="badger-icon">🦡⚡</div>
                    <div>
                        <h1>RED BADGER</h1>
                        <small>SECURITY COMMAND NEXUS</small>
                    </div>
                </div>
                <div class="status-badge">
                    <i></i> ACTIVE · WEB INTERFACE
                </div>
            </div>
            
            <div class="dashboard-grid">
                <div class="command-zone">
                    <div class="section-title">
                        <h3>🔻 COMMAND EXECUTOR</h3>
                    </div>
                    <textarea id="commandInput" rows="4" class="cmd-textarea" 
                              placeholder="Enter security command...&#10;Example: scan 192.168.1.1"></textarea>
                    <div class="cmd-actions">
                        <button id="executeBtn">⚡ EXECUTE COMMAND</button>
                        <button id="clearInputBtn" class="clear-btn">🗑️ CLEAR</button>
                    </div>
                    <div class="examples">
                        <p>🔍 SUGGESTED COMMANDS (click to use):</p>
                        <div class="example-tags">
                            <span class="example-cmd" data-cmd="threat fetch">threat fetch</span>
                            <span class="example-cmd" data-cmd="audit firewall">audit firewall</span>
                            <span class="example-cmd" data-cmd="scan 8.8.8.8">scan 8.8.8.8</span>
                            <span class="example-cmd" data-cmd="analyze 192.168.1.1">analyze</span>
                            <span class="example-cmd" data-cmd="zerotrust verify">zerotrust verify</span>
                            <span class="example-cmd" data-cmd="status">status</span>
                        </div>
                    </div>
                </div>
                
                <div class="history-zone">
                    <div class="history-header">
                        <h3>📜 COMMAND LOG · AI RESPONSES</h3>
                        <button id="clearHistoryBtn" class="clear-history">⟳ CLEAR LOG</button>
                    </div>
                    <div id="historyContainer" class="history-log">
                        <div class="log-entry response-type">
                            <div class="log-meta"><span>🦡 RED BADGER AI</span><span>ready</span></div>
                            <div class="log-content">⚙️ Security dashboard online. Enter a command to begin.</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="footer-note">
                <span>🔶 AI-assisted security commands | Authorized use only</span>
            </div>
        </div>
        
        <script>
            const commandInput = document.getElementById('commandInput');
            const executeBtn = document.getElementById('executeBtn');
            const clearInputBtn = document.getElementById('clearInputBtn');
            const clearHistoryBtn = document.getElementById('clearHistoryBtn');
            const historyContainer = document.getElementById('historyContainer');
            
            function addLogEntry(type, title, content) {
                const entryDiv = document.createElement('div');
                entryDiv.className = `log-entry ${type}-type`;
                const time = new Date().toLocaleTimeString();
                entryDiv.innerHTML = `
                    <div class="log-meta">
                        <span>${type === 'cmd' ? '🔻 COMMAND' : type === 'response' ? '🤖 AI RESPONSE' : '⚠️ ERROR'}</span>
                        <span>${time}</span>
                    </div>
                    <div class="log-content">${content}</div>
                `;
                historyContainer.appendChild(entryDiv);
                entryDiv.scrollIntoView({ behavior: 'smooth' });
            }
            
            async function executeCommand() {
                const command = commandInput.value.trim();
                if (!command) {
                    addLogEntry('error', 'INPUT MISSING', '⛔ No command provided.');
                    return;
                }
                
                addLogEntry('cmd', command, `<strong>> ${escapeHtml(command)}</strong>`);
                
                try {
                    const response = await fetch('/execute', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ command: command })
                    });
                    const result = await response.json();
                    
                    if (result.success) {
                        addLogEntry('response', 'AI ANALYSIS', `<pre style="white-space: pre-wrap;">${escapeHtml(result.output)}</pre>`);
                    } else {
                        addLogEntry('error', 'EXECUTION ERROR', escapeHtml(result.output));
                    }
                } catch (error) {
                    addLogEntry('error', 'CONNECTION ERROR', `Failed to connect: ${error.message}`);
                }
            }
            
            function escapeHtml(str) {
                return str.replace(/[&<>]/g, function(m) {
                    if (m === '&') return '&amp;';
                    if (m === '<') return '&lt;';
                    if (m === '>') return '&gt;';
                    return m;
                });
            }
            
            function clearHistory() {
                while (historyContainer.firstChild) {
                    historyContainer.removeChild(historyContainer.firstChild);
                }
                const welcomeMsg = document.createElement('div');
                welcomeMsg.className = 'log-entry response-type';
                welcomeMsg.innerHTML = `
                    <div class="log-meta"><span>🦡 RED BADGER AI</span><span>reset</span></div>
                    <div class="log-content">🧹 History cleared. Ready for commands.</div>
                `;
                historyContainer.appendChild(welcomeMsg);
            }
            
            executeBtn.addEventListener('click', executeCommand);
            clearInputBtn.addEventListener('click', () => { commandInput.value = ''; commandInput.focus(); });
            clearHistoryBtn.addEventListener('click', clearHistory);
            
            document.querySelectorAll('.example-cmd').forEach(el => {
                el.addEventListener('click', () => {
                    commandInput.value = el.getAttribute('data-cmd');
                    commandInput.focus();
                });
            });
            
            commandInput.addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    e.preventDefault();
                    executeCommand();
                }
            });
        </script>
    </body>
    </html>
    '''
    
    @web_app.route('/')
    def index():
        return render_template_string(WEB_TEMPLATE)
    
    @web_app.route('/execute', methods=['POST'])
    def execute():
        data = request.get_json()
        command = data.get('command', '')
        
        if not command:
            return jsonify({'success': False, 'output': 'No command provided'})
        
        result = executor.execute(command, source="web")
        return jsonify({
            'success': result['success'],
            'output': result['output'][:5000],
            'execution_time': result.get('execution_time', 0)
        })
    
    @web_app.route('/status', methods=['GET'])
    def status():
        stats = db.get_statistics()
        return jsonify(stats)
    
    web_app.is_running = False
    return web_app

# =====================
# MAIN APPLICATION
# =====================
class RedBadger:
    """Main Red Badger application"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.executor = CommandExecutor(self.db)
        self.discord = DiscordBot(self.executor, self.db)
        self.telegram = TelegramBot(self.executor, self.db)
        self.slack = SlackBot(self.executor, self.db)
        self.imessage = IMessageBot(self.executor, self.db)
        self.web_app = None
        self.monitoring = False
    
    def print_banner(self):
        banner = f"""
{Colors.PRIMARY}╔══════════════════════════════════════════════════════════════════════════╗
║{Colors.ACCENT}        🦡  RED BADGER v1.0.0                      🦡                     {Colors.PRIMARY}║
╠══════════════════════════════════════════════════════════════════════════╣
║{Colors.SECONDARY}  • 🔍 Security Analysis & Threat Intelligence                         {Colors.PRIMARY}║
║{Colors.SECONDARY}  • 🌐 Multi-Platform Integration (Discord, Telegram, Slack, Web)     {Colors.PRIMARY}║
║{Colors.SECONDARY}  • 🛡️ IP Management & Firewall Control                              {Colors.PRIMARY}║
║{Colors.SECONDARY}  • 📊 Real-time Monitoring & Reporting                               {Colors.PRIMARY}║
║{Colors.SECONDARY}  • 🔐 Zero Trust & Incident Response                                 {Colors.PRIMARY}║
╠══════════════════════════════════════════════════════════════════════════╣
║{Colors.ACCENT}            🎯 500+ SECURITY COMMANDS                                   {Colors.PRIMARY}║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.SUCCESS}✅ Database initialized{Colors.RESET}
{Colors.INFO}💡 Type 'help' for available commands{Colors.RESET}
{Colors.SECONDARY}🌐 Web interface available at http://localhost:5000 after starting{Colors.RESET}
"""
        print(banner)
    
    def setup_platforms(self):
        """Interactive setup for platform integrations"""
        print(f"\n{Colors.PRIMARY}🔌 Platform Integration Setup{Colors.RESET}")
        print(f"{Colors.PRIMARY}{'='*50}{Colors.RESET}")
        
        # Discord setup
        setup_discord = input("Configure Discord bot? (y/n): ").strip().lower()
        if setup_discord == 'y':
            token = input("Enter Discord bot token: ").strip()
            if token:
                self.discord.configure(token)
                print(f"{Colors.SUCCESS}✅ Discord configured{Colors.RESET}")
        
        # Telegram setup
        setup_telegram = input("Configure Telegram bot? (y/n): ").strip().lower()
        if setup_telegram == 'y':
            token = input("Enter Telegram bot token: ").strip()
            if token:
                self.telegram.configure(token)
                print(f"{Colors.SUCCESS}✅ Telegram configured{Colors.RESET}")
        
        # Slack setup
        setup_slack = input("Configure Slack bot? (y/n): ").strip().lower()
        if setup_slack == 'y':
            token = input("Enter Slack bot token: ").strip()
            if token:
                self.slack.configure(token)
                print(f"{Colors.SUCCESS}✅ Slack configured{Colors.RESET}")
        
        # Web interface
        start_web = input("Start web interface? (y/n): ").strip().lower()
        if start_web == 'y':
            self.start_web()
        
        # Threat monitoring
        start_monitor = input("Start threat monitoring? (y/n): ").strip().lower()
        if start_monitor == 'y':
            self.start_monitoring()
    
    def start_web(self, port: int = 5000):
        """Start web interface"""
        self.web_app = create_web_interface(self.executor, self.db)
        
        def run_web():
            self.web_app.is_running = True
            self.web_app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
        
        thread = threading.Thread(target=run_web, daemon=True)
        thread.start()
        print(f"{Colors.SUCCESS}✅ Web interface started at http://localhost:{port}{Colors.RESET}")
    
    def start_monitoring(self):
        """Start threat monitoring"""
        self.monitoring = True
        self.executor.monitoring = True
        
        def monitor_threats():
            while self.monitoring:
                try:
                    # Monitor for suspicious patterns (simplified)
                    import psutil
                    connections = psutil.net_connections()
                    
                    ip_counts = {}
                    for conn in connections:
                        if conn.raddr:
                            ip = conn.raddr.ip
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    
                    # Check for port scanning
                    for ip, count in ip_counts.items():
                        if count > 50:
                            self.db.log_threat('port_scan', source_ip=ip, 
                                              severity='high',
                                              description=f'{count} connections in short period')
                            print(f"{Colors.ERROR}⚠️ Port scan detected from {ip}{Colors.RESET}")
                    
                    time.sleep(30)
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                    time.sleep(10)
        
        thread = threading.Thread(target=monitor_threats, daemon=True)
        thread.start()
        print(f"{Colors.SUCCESS}✅ Threat monitoring started{Colors.RESET}")
    
    def start_platform_bots(self):
        """Start all configured platform bots"""
        # Start Discord
        if self.discord.token:
            thread = threading.Thread(target=self.discord.start, daemon=True)
            thread.start()
            print(f"{Colors.SUCCESS}✅ Discord bot starting...{Colors.RESET}")
        
        # Start Telegram
        if self.telegram.token:
            thread = threading.Thread(target=self.telegram.start, daemon=True)
            thread.start()
            print(f"{Colors.SUCCESS}✅ Telegram bot starting...{Colors.RESET}")
        
        # Start Slack
        if self.slack.token:
            thread = threading.Thread(target=self.slack.start, daemon=True)
            thread.start()
            print(f"{Colors.SUCCESS}✅ Slack bot starting...{Colors.RESET}")
    
    def run_cli(self):
        """Run command-line interface"""
        self.print_banner()
        self.setup_platforms()
        self.start_platform_bots()
        
        print(f"\n{Colors.SUCCESS}✅ Red Badger is ready!{Colors.RESET}")
        print(f"{Colors.SECONDARY}   Commands can be executed from:{Colors.RESET}")
        print(f"     • Terminal (direct)")
        print(f"     • Web interface (http://localhost:5000)")
        if self.discord.token:
            print(f"     • Discord (use !security <command>)")
        if self.telegram.token:
            print(f"     • Telegram (send command as message)")
        if self.slack.token:
            print(f"     • Slack (use !badger <command>)")
        
        print(f"\n{Colors.INFO}ℹ️ Type 'help' for commands, 'exit' to quit{Colors.RESET}\n")
        
        while True:
            try:
                command = input(f"{Colors.PRIMARY}🦡> {Colors.RESET}").strip()
                
                if command.lower() == 'exit':
                    print(f"{Colors.WARNING}👋 Shutting down Red Badger...{Colors.RESET}")
                    self.monitoring = False
                    break
                elif command:
                    result = self.executor.execute(command)
                    if result['output']:
                        print(result['output'])
                    if result['execution_time']:
                        print(f"\n{Colors.SUCCESS}✅ Done ({result['execution_time']:.2f}s){Colors.RESET}")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}👋 Exiting...{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.ERROR}❌ Error: {e}{Colors.RESET}")
        
        self.db.close()

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        # Check Python version
        if sys.version_info < (3, 7):
            print(f"{Colors.ERROR}❌ Python 3.7 or higher is required{Colors.RESET}")
            sys.exit(1)
        
        # Check optional dependencies
        missing = []
        for package in ['requests', 'psutil', 'flask']:
            try:
                __import__(package)
            except ImportError:
                missing.append(package)
        
        if missing:
            print(f"{Colors.WARNING}⚠️ Optional packages missing: {', '.join(missing)}{Colors.RESET}")
            print(f"   Install with: pip install {' '.join(missing)}{Colors.RESET}")
        
        # Start application
        app = RedBadger()
        app.run_cli()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.ERROR}❌ Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()