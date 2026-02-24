#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
MINI CYBER TOOLKIT v1.0 BY @x404ctl - MAliX
═══════════════════════════════════════════════════════════════════

A professional, lightweight cybersecurity toolkit.
All modules consolidated into a single file for easy deployment.

DEPENDENCIES:
    pip install psutil

USAGE:
    python mini_cyber_toolkit.py

MODULES:
    [1] Password Generator  - Secure password generation
    [2] Hash Generator      - Multi-algorithm hashing
    [3] Hash Checker        - Verify and compare hashes
    [4] IP Checker          - Network interface information
    [5] Port Scanner        - TCP port scanning
    [6] System Information  - CPU, Memory, Disk, Network stats

AUTHOR: @x404ctl - MAliX
LICENSE: MIT (Educational purposes)
═══════════════════════════════════════════════════════════════════
"""

import os
import sys
import re
import socket
import uuid
import ipaddress
import hashlib
import secrets
import string
import threading
import platform
import urllib.request
import urllib.error
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Try importing psutil, provide fallback if not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. System Info module will be limited.")
    print("    Install with: pip install psutil\n")


# ═══════════════════════════════════════════════════════════════════
# REPORT MANAGER - Handles saving reports for all modules
# ═══════════════════════════════════════════════════════════════════

class ReportManager:
    """Manages saving reports to files for all toolkit modules."""

    def __init__(self, module_name):
        self.module_name = module_name
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        self.report_data = {
            "module": module_name,
            "timestamp": datetime.now().isoformat(),
            "results": []
        }

    def add_entry(self, title, content):
        """Add an entry to the report."""
        self.report_data["results"].append({
            "title": title,
            "content": content,
            "time": datetime.now().strftime("%H:%M:%S")
        })

    def save_text_report(self, content_lines):
        """Save a formatted text report."""
        filename = self.report_dir / f"{self.module_name}_{self.timestamp}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write(f"MINI CYBER TOOLKIT - {self.module_name.upper()} REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Author: @x404ctl - MAliX\n")
            f.write("=" * 70 + "\n\n")
            for line in content_lines:
                f.write(line + "\n")
            f.write("\n" + "=" * 70 + "\n")
            f.write("End of Report\n")
        return filename

    def save_json_report(self):
        """Save report in JSON format."""
        filename = self.report_dir / f"{self.module_name}_{self.timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.report_data, f, indent=2)
        return filename

    def prompt_save(self, content_lines):
        """Prompt user to save report and save if requested."""
        save_choice = input("\n    Save report to file? [y/N]: ").strip().lower()
        if save_choice == 'y':
            txt_file = self.save_text_report(content_lines)
            json_file = self.save_json_report()
            print(f"\n    Reports saved:")
            print(f"      Text:  {txt_file}")
            print(f"      JSON:  {json_file}")


# ═══════════════════════════════════════════════════════════════════
# MODULE 1: PASSWORD GENERATOR
# ═══════════════════════════════════════════════════════════════════

class PasswordGenerator:
    """Secure password generation with strength analysis."""

    def __init__(self):
        self.report = ReportManager("password_generator")

    def generate(self, length=16, use_upper=True, use_lower=True, 
                 use_digits=True, use_special=True):
        """Generate a secure password with specified criteria."""
        chars = ""
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if not chars:
            return None

        password = []
        if use_upper:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_lower:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        if use_special:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

        for _ in range(length - len(password)):
            password.append(secrets.choice(chars))

        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def estimate_strength(self, password):
        """Estimate password strength (Weak, Medium, Strong)."""
        score = 0
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 1

        if score <= 2:
            return "Weak"
        elif score <= 4:
            return "Medium"
        else:
            return "Strong"

    def run(self):
        """Execute interactive password generation."""
        print("    ┌─────────────────────────────────────────────────────────┐")
        print("    │              PASSWORD GENERATOR                         │")
        print("    └─────────────────────────────────────────────────────────┘")

        try:
            length = int(input("    Enter password length (8-64) [16]: ") or "16")
            length = max(8, min(64, length))
        except ValueError:
            length = 16

        use_upper = input("    Include uppercase letters? [Y/n]: ").lower() != 'n'
        use_lower = input("    Include lowercase letters? [Y/n]: ").lower() != 'n'
        use_digits = input("    Include digits? [Y/n]: ").lower() != 'n'
        use_special = input("    Include special characters? [Y/n]: ").lower() != 'n'

        password = self.generate(length, use_upper, use_lower, use_digits, use_special)

        if password:
            strength = self.estimate_strength(password)

            # Prepare report content
            report_lines = [
                f"Password Length: {length}",
                f"Character Types: Upper={use_upper}, Lower={use_lower}, Digits={use_digits}, Special={use_special}",
                f"Generated Password: {password}",
                f"Strength Assessment: {strength}",
                f"Entropy: ~{len(password) * 6.6:.1f} bits (estimated)"
            ]

            print("\n    ┌─────────────────────────────────────────────────────────┐")
            print(f"    │  Generated Password: {password:<29} │")
            print(f"    │  Strength: {strength:<40} │")
            print(f"    │  Length: {len(password):<42} │")
            print("    └─────────────────────────────────────────────────────────┘")

            self.report.add_entry("Password Generated", password)
            self.report.add_entry("Strength", strength)
            self.report.prompt_save(report_lines)
        else:
            print("    Error: No character types selected!")


# ═══════════════════════════════════════════════════════════════════
# MODULE 2: HASH GENERATOR
# ═══════════════════════════════════════════════════════════════════

class HashGenerator:
    """Multi-algorithm hash generation tool."""

    ALGORITHMS = {
        '1': ('MD5', 'md5'),
        '2': ('SHA-1', 'sha1'),
        '3': ('SHA-256', 'sha256'),
        '4': ('SHA-512', 'sha512'),
        '5': ('BLAKE2b', 'blake2b')
    }

    def __init__(self):
        self.report = ReportManager("hash_generator")

    def hash_string(self, text, algorithm='sha256'):
        """Generate hash from string input."""
        try:
            if algorithm == 'blake2b':
                return hashlib.blake2b(text.encode()).hexdigest()
            else:
                hasher = hashlib.new(algorithm)
                hasher.update(text.encode())
                return hasher.hexdigest()
        except Exception as e:
            return f"Error: {e}"

    def hash_file(self, filepath, algorithm='sha256'):
        """Generate hash from file content."""
        try:
            if algorithm == 'blake2b':
                hasher = hashlib.blake2b()
            else:
                hasher = hashlib.new(algorithm)

            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return "Error: File not found"
        except Exception as e:
            return f"Error: {e}"

    def run(self):
        """Execute interactive hash generation."""
        print("    ┌─────────────────────────────────────────────────────────┐")
        print("    │              HASH GENERATOR                             │")
        print("    ├─────────────────────────────────────────────────────────┤")
        print("    │  Select Algorithm:                                      │")
        for key, (name, _) in self.ALGORITHMS.items():
            print(f"    │    [{key}] {name:<45} │")
        print("    └─────────────────────────────────────────────────────────┘")

        choice = input("    Select algorithm [1-5]: ").strip()

        if choice not in self.ALGORITHMS:
            print("    Invalid selection!")
            return

        algo_name, algo_func = self.ALGORITHMS[choice]

        print("\n    [1] Hash text string")
        print("    [2] Hash file")
        mode = input("    Select mode [1-2]: ").strip()

        report_lines = [f"Algorithm: {algo_name}"]

        if mode == '1':
            text = input("    Enter text to hash: ")
            result = self.hash_string(text, algo_func)

            report_lines.extend([
                f"Mode: Text String",
                f"Input: {text}",
                f"Hash: {result}"
            ])

            print(f"\n    ┌─────────────────────────────────────────────────────────┐")
            print(f"    │  Algorithm: {algo_name:<41} │")
            print(f"    │  Input: {text[:30]:<45} │")
            print(f"    ├─────────────────────────────────────────────────────────┤")
            print(f"    │  Hash: {result:<46} │")
            print("    └─────────────────────────────────────────────────────────┘")

            self.report.add_entry("Input Text", text)

        elif mode == '2':
            filepath = input("    Enter file path: ")
            result = self.hash_file(filepath, algo_func)

            report_lines.extend([
                f"Mode: File Hash",
                f"File Path: {filepath}",
                f"Hash: {result}"
            ])

            print(f"\n    ┌─────────────────────────────────────────────────────────┐")
            print(f"    │  Algorithm: {algo_name:<41} │")
            print(f"    │  File: {filepath[-40:]:<46} │")
            print(f"    ├─────────────────────────────────────────────────────────┤")
            print(f"    │  Hash: {result:<46} │")
            print("    └─────────────────────────────────────────────────────────┘")

            self.report.add_entry("File Path", filepath)

        self.report.add_entry("Hash Result", result)
        self.report.prompt_save(report_lines)


# ═══════════════════════════════════════════════════════════════════
# MODULE 3: HASH CHECKER
# ═══════════════════════════════════════════════════════════════════

class HashChecker:
    """Verify and compare file/text hashes against known values."""

    ALGORITHMS = {
        '1': ('MD5', 'md5', 32),
        '2': ('SHA-1', 'sha1', 40),
        '3': ('SHA-256', 'sha256', 64),
        '4': ('SHA-512', 'sha512', 128),
        '5': ('BLAKE2b', 'blake2b', 128)
    }

    def __init__(self):
        self.report = ReportManager("hash_checker")

    def verify_hash(self, data, expected_hash, algorithm='sha256', is_file=False):
        """Verify data/file against expected hash."""
        try:
            if is_file:
                if algorithm == 'blake2b':
                    hasher = hashlib.blake2b()
                else:
                    hasher = hashlib.new(algorithm)
                with open(data, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
                computed = hasher.hexdigest()
            else:
                if algorithm == 'blake2b':
                    computed = hashlib.blake2b(data.encode()).hexdigest()
                else:
                    hasher = hashlib.new(algorithm)
                    hasher.update(data.encode())
                    computed = hasher.hexdigest()

            match = computed.lower() == expected_hash.lower()
            return computed, match
        except Exception as e:
            return str(e), False

    def run(self):
        """Execute interactive hash verification."""
        print("    ┌─────────────────────────────────────────────────────────┐")
        print("    │              HASH CHECKER                               │")
        print("    ├─────────────────────────────────────────────────────────┤")
        print("    │  Select Algorithm:                                      │")
        for key, (name, _, length) in self.ALGORITHMS.items():
            print(f"    │    [{key}] {name:<10} (Expected length: {length})            │")
        print("    └─────────────────────────────────────────────────────────┘")

        choice = input("    Select algorithm [1-5]: ").strip()

        if choice not in self.ALGORITHMS:
            print("    Invalid selection!")
            return

        algo_name, algo_func, expected_len = self.ALGORITHMS[choice]

        print("\n    [1] Verify text")
        print("    [2] Verify file")
        mode = input("    Select mode [1-2]: ").strip()

        expected_hash = input(f"    Enter expected {algo_name} hash ({expected_len} chars): ").strip()

        if len(expected_hash) != expected_len:
            print(f"    Warning: Expected hash length is {expected_len}, got {len(expected_hash)}")

        report_lines = [
            f"Algorithm: {algo_name}",
            f"Expected Hash: {expected_hash}"
        ]

        if mode == '1':
            text = input("    Enter text to verify: ")
            computed, match = self.verify_hash(text, expected_hash, algo_func, False)

            status = "MATCH" if match else "MISMATCH"
            report_lines.extend([
                f"Mode: Text Verification",
                f"Input Text: {text}",
                f"Computed Hash: {computed}",
                f"Verification Result: {status}"
            ])

            print(f"\n    Computed: {computed}")
            print(f"    Expected: {expected_hash}")
            print(f"    Status:   {status}")

            self.report.add_entry("Input", text)

        elif mode == '2':
            filepath = input("    Enter file path: ")
            computed, match = self.verify_hash(filepath, expected_hash, algo_func, True)

            status = "MATCH" if match else "MISMATCH"
            report_lines.extend([
                f"Mode: File Verification",
                f"File Path: {filepath}",
                f"Computed Hash: {computed}",
                f"Verification Result: {status}"
            ])

            print(f"\n    File:     {filepath}")
            print(f"    Computed: {computed}")
            print(f"    Expected: {expected_hash}")
            print(f"    Status:   {status}")

            self.report.add_entry("File", filepath)

        self.report.add_entry("Computed Hash", computed)
        self.report.add_entry("Status", status)
        self.report.prompt_save(report_lines)


# ═══════════════════════════════════════════════════════════════════
# MODULE 4: IP CHECKER
# ═══════════════════════════════════════════════════════════════════

class IPChecker:
    """Network interface and IP information tool."""

    def __init__(self):
        self.report = ReportManager("ip_checker")

    def get_local_ip(self):
        """Get primary local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_all_interfaces(self):
        """Get all network interfaces."""
        interfaces = []
        try:
            if PSUTIL_AVAILABLE:
                import psutil
                stats = psutil.net_if_addrs()
                for interface, addrs in stats.items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            interfaces.append({
                                'name': interface,
                                'ip': addr.address,
                                'netmask': addr.netmask,
                                'broadcast': addr.broadcast
                            })
            else:
                hostname = socket.gethostname()
                interfaces.append({
                    'name': 'default',
                    'ip': socket.gethostbyname(hostname),
                    'netmask': 'N/A',
                    'broadcast': 'N/A'
                })
        except Exception as e:
            interfaces.append({'error': str(e)})
        return interfaces

    def get_public_ip(self):
        """Get public IP address."""
        services = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://icanhazip.com'
        ]
        for service in services:
            try:
                with urllib.request.urlopen(service, timeout=5) as response:
                    return response.read().decode().strip()
            except:
                continue
        return "Unable to retrieve"

    def run(self):
        """Execute IP information display."""
        print("    ┌─────────────────────────────────────────────────────────┐")
        print("    │              IP CHECKER                                 │")
        print("    └─────────────────────────────────────────────────────────┘")

        local_ip = self.get_local_ip()
        public_ip = self.get_public_ip()
        interfaces = self.get_all_interfaces()

        report_lines = [
            f"Public IP: {public_ip}",
            f"Primary Local IP: {local_ip}",
            "",
            "Network Interfaces:"
        ]

        print(f"\n    Public IP:  {public_ip}")
        print(f"    Local IP:   {local_ip}")
        print(f"    Hostname:   {socket.gethostname()}")
        print("\n    Network Interfaces:")
        print("    " + "-" * 55)

        for iface in interfaces:
            if 'error' in iface:
                print(f"    Error: {iface['error']}")
                report_lines.append(f"  Error: {iface['error']}")
            else:
                print(f"    {iface['name']:<15} {iface['ip']:<15} {iface['netmask']}")
                report_lines.append(f"  {iface['name']}: {iface['ip']} (Netmask: {iface['netmask']})")

        self.report.add_entry("Public IP", public_ip)
        self.report.add_entry("Local IP", local_ip)
        self.report.add_entry("Interfaces", str(interfaces))
        self.report.prompt_save(report_lines)


# ═══════════════════════════════════════════════════════════════════
# MODULE 5: PORT SCANNER
# ═══════════════════════════════════════════════════════════════════

class PortScanner:
    """TCP port scanning tool."""

    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 8080: 'HTTP-Proxy'
    }

    def __init__(self):
        self.report = ReportManager("port_scanner")
        self.open_ports = []

    def scan_port(self, target, port, timeout=1):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return port, result == 0
        except:
            return port, False

    def scan_range(self, target, start_port, end_port, max_threads=100):
        """Scan a range of ports using threading."""
        print(f"\n    Scanning {target} from port {start_port} to {end_port}...")
        print(f"    Using {max_threads} threads...\n")

        open_ports = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_port, target, port): port 
                      for port in range(start_port, end_port + 1)}

            completed = 0
            total = end_port - start_port + 1

            for future in as_completed(futures):
                completed += 1
                port, is_open = future.result()
                if is_open:
                    service = self.COMMON_PORTS.get(port, 'Unknown')
                    open_ports.append((port, service))
                    print(f"    [OPEN] Port {port:<5} - {service}")

                if completed % 100 == 0 or completed == total:
                    print(f"    Progress: {completed}/{total} ports scanned", end='\r')

        return open_ports

    def run(self):
        """Execute interactive port scanning."""
        print("    ┌─────────────────────────────────────────────────────────┐")
        print("    │              PORT SCANNER                               │")
        print("    └─────────────────────────────────────────────────────────┘")

        target = input("    Enter target IP/hostname [127.0.0.1]: ").strip() or "127.0.0.1"

        print("\n    [1] Quick scan (common ports)")
        print("    [2] Full range scan")
        print("    [3] Custom range")
        choice = input("    Select scan type [1-3]: ").strip()

        report_lines = [f"Target: {target}"]

        if choice == '1':
            ports = list(self.COMMON_PORTS.keys())
            print(f"\n    Scanning {len(ports)} common ports...")
            open_ports = []
            for port in ports:
                port_num, is_open = self.scan_port(target, port)
                if is_open:
                    service = self.COMMON_PORTS.get(port_num, 'Unknown')
                    open_ports.append((port_num, service))
                    print(f"    [OPEN] Port {port_num:<5} - {service}")

            report_lines.append(f"Scan Type: Quick Scan (Common Ports)")

        elif choice == '2':
            open_ports = self.scan_range(target, 1, 1024)
            report_lines.append(f"Scan Type: Full Range (1-1024)")

        elif choice == '3':
            try:
                start = int(input("    Start port: "))
                end = int(input("    End port: "))
                open_ports = self.scan_range(target, start, end)
                report_lines.append(f"Scan Type: Custom Range ({start}-{end})")
            except ValueError:
                print("    Invalid port numbers!")
                return
        else:
            print("    Invalid selection!")
            return

        print(f"\n    Scan complete. Found {len(open_ports)} open ports.")

        if open_ports:
            report_lines.extend(["", "Open Ports:"])
            for port, service in open_ports:
                report_lines.append(f"  Port {port}: {service}")
        else:
            report_lines.append("No open ports found.")

        self.report.add_entry("Target", target)
        self.report.add_entry("Open Ports", str(open_ports))
        self.report.prompt_save(report_lines)


# ═══════════════════════════════════════════════════════════════════
# MODULE 6: SYSTEM INFORMATION
# ═══════════════════════════════════════════════════════════════════

class SystemInfo:
    """System resource and information display."""

    def __init__(self):
        self.report = ReportManager("system_info")

    def get_cpu_info(self):
        """Get CPU information."""
        info = {
            'processor': platform.processor(),
            'cores_physical': 'N/A',
            'cores_logical': 'N/A',
            'frequency': 'N/A',
            'usage_percent': 'N/A'
        }

        if PSUTIL_AVAILABLE:
            import psutil
            info['cores_physical'] = psutil.cpu_count(logical=False)
            info['cores_logical'] = psutil.cpu_count(logical=True)
            freq = psutil.cpu_freq()
            if freq:
                info['frequency'] = f"{freq.current:.0f} MHz"
            info['usage_percent'] = f"{psutil.cpu_percent(interval=1)}%"

        return info

    def get_memory_info(self):
        """Get memory information."""
        info = {'total': 'N/A', 'available': 'N/A', 'percent': 'N/A', 'used': 'N/A'}

        if PSUTIL_AVAILABLE:
            import psutil
            mem = psutil.virtual_memory()
            info['total'] = f"{mem.total / (1024**3):.2f} GB"
            info['available'] = f"{mem.available / (1024**3):.2f} GB"
            info['percent'] = f"{mem.percent}%"
            info['used'] = f"{mem.used / (1024**3):.2f} GB"

        return info

    def get_disk_info(self):
        """Get disk information."""
        info = []

        if PSUTIL_AVAILABLE:
            import psutil
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': f"{usage.total / (1024**3):.2f} GB",
                        'used': f"{usage.used / (1024**3):.2f} GB",
                        'free': f"{usage.free / (1024**3):.2f} GB",
                        'percent': f"{usage.percent}%"
                    })
                except:
                    pass

        return info

    def get_network_info(self):
        """Get network statistics."""
        info = {'bytes_sent': 'N/A', 'bytes_recv': 'N/A', 'packets_sent': 'N/A', 'packets_recv': 'N/A'}

        if PSUTIL_AVAILABLE:
            import psutil
            net = psutil.net_io_counters()
            info['bytes_sent'] = f"{net.bytes_sent / (1024**2):.2f} MB"
            info['bytes_recv'] = f"{net.bytes_recv / (1024**2):.2f} MB"
            info['packets_sent'] = net.packets_sent
            info['packets_recv'] = net.packets_recv

        return info

    def run(self):
        """Execute system information display."""
        print("    ┌─────────────────────────────────────────────────────────┐")
        print("    │              SYSTEM INFORMATION                         │")
        print("    └─────────────────────────────────────────────────────────┘")

        report_lines = [
            f"Platform: {platform.system()} {platform.release()}",
            f"Architecture: {platform.machine()}",
            f"Python Version: {platform.python_version()}",
            ""
        ]

        print(f"\n    Platform:        {platform.system()} {platform.release()}")
        print(f"    Architecture:    {platform.machine()}")
        print(f"    Python Version:  {platform.python_version()}")

        # CPU Info
        cpu = self.get_cpu_info()
        print("\n    [CPU]")
        print(f"    Processor:       {cpu['processor']}")
        print(f"    Physical Cores:  {cpu['cores_physical']}")
        print(f"    Logical Cores:   {cpu['cores_logical']}")
        print(f"    Frequency:       {cpu['frequency']}")
        print(f"    Usage:           {cpu['usage_percent']}")

        report_lines.extend([
            "[CPU Information]",
            f"  Processor: {cpu['processor']}",
            f"  Physical Cores: {cpu['cores_physical']}",
            f"  Logical Cores: {cpu['cores_logical']}",
            f"  Frequency: {cpu['frequency']}",
            f"  Usage: {cpu['usage_percent']}",
            ""
        ])

        # Memory Info
        mem = self.get_memory_info()
        print("\n    [Memory]")
        print(f"    Total:           {mem['total']}")
        print(f"    Used:            {mem['used']}")
        print(f"    Available:       {mem['available']}")
        print(f"    Usage:           {mem['percent']}")

        report_lines.extend([
            "[Memory Information]",
            f"  Total: {mem['total']}",
            f"  Used: {mem['used']}",
            f"  Available: {mem['available']}",
            f"  Usage: {mem['percent']}",
            ""
        ])

        # Disk Info
        print("\n    [Disk Partitions]")
        disks = self.get_disk_info()
        report_lines.append("[Disk Information]")
        for disk in disks:
            print(f"    {disk['device']:<15} {disk['mountpoint']:<15} {disk['percent']:<6} used")
            report_lines.append(f"  {disk['device']} ({disk['mountpoint']}): {disk['used']} / {disk['total']} ({disk['percent']} used)")

        # Network Info
        net = self.get_network_info()
        print("\n    [Network I/O]")
        print(f"    Bytes Sent:      {net['bytes_sent']}")
        print(f"    Bytes Received:  {net['bytes_recv']}")
        print(f"    Packets Sent:    {net['packets_sent']}")
        print(f"    Packets Received: {net['packets_recv']}")

        report_lines.extend([
            "",
            "[Network I/O]",
            f"  Bytes Sent: {net['bytes_sent']}",
            f"  Bytes Received: {net['bytes_recv']}",
            f"  Packets Sent: {net['packets_sent']}",
            f"  Packets Received: {net['packets_recv']}"
        ])

        self.report.add_entry("CPU", str(cpu))
        self.report.add_entry("Memory", str(mem))
        self.report.add_entry("Disks", str(disks))
        self.report.add_entry("Network", str(net))
        self.report.prompt_save(report_lines)


# ═══════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════

def print_banner():
    """Print the application banner."""
    print("""
═══════════════════════════════════════════════════════════════════════
                    MINI CYBER TOOLKIT v1.0
═══════════════════════════════════════════════════════════════════════
    [1] Password Generator    - Secure password generation
    [2] Hash Generator        - Multi-algorithm hashing
    [3] Hash Checker          - Verify and compare hashes
    [4] IP Checker            - Network interface information
    [5] Port Scanner          - TCP port scanning
    [6] System Information    - CPU, Memory, Disk, Network stats
    [0] Exit
═══════════════════════════════════════════════════════════════════════
Author: @x404ctl - MAliX  |  Educational Use Only
═══════════════════════════════════════════════════════════════════════
""")


def main():
    """Main application loop."""
    modules = {
        '1': PasswordGenerator(),
        '2': HashGenerator(),
        '3': HashChecker(),
        '4': IPChecker(),
        '5': PortScanner(),
        '6': SystemInfo()
    }

    while True:
        print_banner()
        choice = input("    Select module [0-6]: ").strip()

        if choice == '0':
            print("\n    Thank you for using Mini Cyber Toolkit v1.0!")
            print("    Author: @x404ctl - MAliX\n")
            break
        elif choice in modules:
            print("\n")
            try:
                modules[choice].run()
            except KeyboardInterrupt:
                print("\n\n    Operation cancelled by user.")
            except Exception as e:
                print(f"\n    Error: {e}")
            input("\n    Press Enter to continue...")
        else:
            print("\n    Invalid selection! Please choose 0-6.")
            input("    Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n    Exiting Mini Cyber Toolkit...")
        print("    Author: @x404ctl - MAliX")
        sys.exit(0)