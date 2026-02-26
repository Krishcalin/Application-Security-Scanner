#!/usr/bin/env python3
"""
Cisco IOS Router/Switch Security Scanner v1.0.0
Network security scanner for Cisco IOS and IOS-XE devices.

Performs live network scanning across an IP range to:
  - Discover Cisco routers and switches via SSH / SNMP
  - Enumerate IOS versions and device models
  - Check for known CVEs based on IOS version
  - Audit running-config for security misconfigurations

Supported protocols:
  - SSH (netmiko) — full config analysis + version enumeration
  - SNMP v2c (pysnmp) — lightweight version enumeration only

Usage:
  python cisco_scanner.py -r 192.168.1.0/24 -u admin -p secret
  python cisco_scanner.py -r 10.0.0.1-10.0.0.50 -u admin -p secret --enable-password en123
  python cisco_scanner.py -r 192.168.1.1 --protocol snmp --snmp-community public

Env var fallback:  CISCO_RANGE  CISCO_USERNAME  CISCO_PASSWORD  CISCO_ENABLE  CISCO_SNMP_COMMUNITY
"""

import os
import re
import sys
import json
import html as html_mod
import socket
import argparse
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from netmiko import ConnectHandler
    HAS_NETMIKO = True
except ImportError:
    HAS_NETMIKO = False

try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
    )
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False

VERSION = "1.0.0"

# ============================================================
# IOS CVE DATABASE
# Each entry: affected version range, CVE, severity, description, fix.
# Range format: comma-separated conditions, e.g. ">=12.0,<15.2.7"
# ============================================================
IOS_CVE_DATABASE = [
    {
        "id": "CISCO-CVE-001",
        "cve": "CVE-2023-20198",
        "platform": "ios-xe",
        "affected": ">=16.0,<17.9.5",
        "severity": "CRITICAL",
        "name": "Web UI privilege escalation — unauthenticated admin account creation",
        "description": (
            "A vulnerability in the web UI of Cisco IOS XE allows an unauthenticated "
            "remote attacker to create a privileged account on the device. This was "
            "actively exploited in the wild (October 2023)."
        ),
        "recommendation": "Upgrade to IOS-XE 17.9.4a or later. Disable ip http server / ip http secure-server.",
        "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-002",
        "cve": "CVE-2023-20273",
        "platform": "ios-xe",
        "affected": ">=16.0,<17.9.5",
        "severity": "CRITICAL",
        "name": "Web UI command injection — root-level command execution",
        "description": (
            "A vulnerability in the web UI of Cisco IOS XE allows an authenticated "
            "attacker to inject commands that execute at the root level. Chained with "
            "CVE-2023-20198 for unauthenticated RCE."
        ),
        "recommendation": "Upgrade to IOS-XE 17.9.4a or later. Disable HTTP/HTTPS server if not needed.",
        "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-003",
        "cve": "CVE-2018-0171",
        "platform": "ios",
        "affected": ">=12.0,<15.2.7",
        "severity": "CRITICAL",
        "name": "Smart Install RCE — stack-based buffer overflow",
        "description": (
            "A stack-based buffer overflow in the Cisco Smart Install client allows an "
            "unauthenticated remote attacker to execute arbitrary code or cause a DoS. "
            "Targets TCP port 4786."
        ),
        "recommendation": "Upgrade to IOS 15.2(7) or later. Disable Smart Install with 'no vstack'.",
        "cwe": "CWE-121",
    },
    {
        "id": "CISCO-CVE-004",
        "cve": "CVE-2017-6742",
        "platform": "ios",
        "affected": ">=12.0,<15.1.5",
        "severity": "CRITICAL",
        "name": "SNMP RCE — multiple buffer overflows in SNMP subsystem",
        "description": (
            "Multiple buffer overflow vulnerabilities in the SNMP subsystem of Cisco IOS "
            "allow an authenticated remote attacker to execute arbitrary code on the device. "
            "Requires knowledge of the SNMP community string."
        ),
        "recommendation": "Upgrade to a fixed IOS release. Restrict SNMP access with ACLs. Migrate to SNMPv3.",
        "cwe": "CWE-119",
    },
    {
        "id": "CISCO-CVE-005",
        "cve": "CVE-2017-3881",
        "platform": "ios",
        "affected": ">=12.0,<15.2.5",
        "severity": "CRITICAL",
        "name": "Telnet CMP RCE — Cluster Management Protocol remote code execution",
        "description": (
            "A vulnerability in the Cisco Cluster Management Protocol (CMP) processing "
            "in Cisco IOS could allow an unauthenticated remote attacker to execute "
            "arbitrary code via Telnet. Originally disclosed in Vault 7 leaks."
        ),
        "recommendation": "Upgrade to a fixed IOS release. Disable Telnet and use SSH exclusively.",
        "cwe": "CWE-119",
    },
    {
        "id": "CISCO-CVE-006",
        "cve": "CVE-2018-0150",
        "platform": "ios-xe",
        "affected": ">=16.0,<16.5.2",
        "severity": "CRITICAL",
        "name": "Hardcoded credentials — default undocumented privileged account",
        "description": (
            "Cisco IOS XE contains an undocumented user account with a default username "
            "and password that has privilege level 15 access. An attacker could exploit "
            "this to gain full admin access."
        ),
        "recommendation": "Upgrade to IOS-XE 16.5.2 or later. Remove or change the default account credentials.",
        "cwe": "CWE-798",
    },
    {
        "id": "CISCO-CVE-007",
        "cve": "CVE-2019-12643",
        "platform": "ios-xe",
        "affected": ">=16.0,<16.9.4",
        "severity": "CRITICAL",
        "name": "REST API authentication bypass — unauthenticated admin access",
        "description": (
            "A vulnerability in the Cisco REST API virtual service container for Cisco "
            "IOS XE allows an unauthenticated remote attacker to bypass authentication "
            "and obtain full administrative access."
        ),
        "recommendation": "Upgrade to IOS-XE 16.9.4 or later. Disable the REST API if not required.",
        "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-008",
        "cve": "CVE-2021-34770",
        "platform": "ios-xe",
        "affected": ">=17.0,<17.3.4",
        "severity": "CRITICAL",
        "name": "CAPWAP RCE — heap buffer overflow in wireless controller",
        "description": (
            "A heap-based buffer overflow in the CAPWAP processing of Cisco IOS XE "
            "for Catalyst 9000 wireless controllers allows an unauthenticated remote "
            "attacker to execute arbitrary code."
        ),
        "recommendation": "Upgrade to IOS-XE 17.3.4 or later.",
        "cwe": "CWE-122",
    },
    {
        "id": "CISCO-CVE-009",
        "cve": "CVE-2018-0167",
        "platform": "ios",
        "affected": ">=12.0,<15.2.5",
        "severity": "CRITICAL",
        "name": "LLDP/CDP buffer overflow — remote code execution via crafted packets",
        "description": (
            "A buffer overflow in the LLDP subsystem of Cisco IOS allows an "
            "unauthenticated adjacent attacker to execute arbitrary code by sending "
            "crafted LLDP packets."
        ),
        "recommendation": "Upgrade to a fixed IOS release. Disable CDP/LLDP on untrusted interfaces.",
        "cwe": "CWE-119",
    },
    {
        "id": "CISCO-CVE-010",
        "cve": "CVE-2022-20695",
        "platform": "ios-xe",
        "affected": ">=17.0,<17.6.2",
        "severity": "CRITICAL",
        "name": "Wireless LAN Controller authentication bypass",
        "description": (
            "A vulnerability in the authentication functionality of Cisco IOS XE for "
            "Wireless LAN Controllers allows an unauthenticated remote attacker to "
            "bypass authentication and log in to the device."
        ),
        "recommendation": "Upgrade to IOS-XE 17.6.2 or later.",
        "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-011",
        "cve": "CVE-2024-20353",
        "platform": "ios-xe",
        "affected": ">=16.0,<17.12.2",
        "severity": "HIGH",
        "name": "Web UI denial of service — unauthenticated device reload",
        "description": (
            "A vulnerability in the management and VPN web servers of Cisco IOS XE "
            "allows an unauthenticated remote attacker to cause the device to reload, "
            "resulting in a denial of service."
        ),
        "recommendation": "Upgrade to IOS-XE 17.12.1a or later. Restrict management access with ACLs.",
        "cwe": "CWE-400",
    },
    {
        "id": "CISCO-CVE-012",
        "cve": "CVE-2018-0156",
        "platform": "ios",
        "affected": ">=12.0,<15.2.5",
        "severity": "HIGH",
        "name": "Smart Install DoS — malformed messages cause device reload",
        "description": (
            "A vulnerability in the Smart Install feature of Cisco IOS allows an "
            "unauthenticated remote attacker to cause a reload of the device by "
            "sending a malformed Smart Install message."
        ),
        "recommendation": "Upgrade to a fixed release. Disable Smart Install with 'no vstack'.",
        "cwe": "CWE-20",
    },
    {
        "id": "CISCO-CVE-013",
        "cve": "CVE-2021-1435",
        "platform": "ios-xe",
        "affected": ">=16.0,<17.3.5",
        "severity": "HIGH",
        "name": "Web UI command injection — authenticated remote code execution",
        "description": (
            "A vulnerability in the web UI of Cisco IOS XE allows an authenticated "
            "remote attacker to inject and execute arbitrary commands with root "
            "privileges on the underlying OS."
        ),
        "recommendation": "Upgrade to IOS-XE 17.3.4a or later. Disable HTTP server if not required.",
        "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-014",
        "cve": "CVE-2020-3566",
        "platform": "ios",
        "affected": ">=12.0,<15.9.4",
        "severity": "HIGH",
        "name": "IGMP/DVMRP memory exhaustion denial of service",
        "description": (
            "A vulnerability in the Distance Vector Multicast Routing Protocol (DVMRP) "
            "feature of Cisco IOS allows an unauthenticated remote attacker to exhaust "
            "process memory, causing a denial of service."
        ),
        "recommendation": "Upgrade to a fixed release. Apply rate-limiting for IGMP traffic.",
        "cwe": "CWE-400",
    },
    {
        "id": "CISCO-CVE-015",
        "cve": "CVE-2019-1737",
        "platform": "ios",
        "affected": ">=12.0,<15.6.4",
        "severity": "HIGH",
        "name": "IP SLA responder DoS — memory corruption via crafted packets",
        "description": (
            "A vulnerability in the IP Service Level Agreements (IP SLA) responder "
            "of Cisco IOS allows an unauthenticated remote attacker to cause memory "
            "corruption, leading to a device reload."
        ),
        "recommendation": "Upgrade to IOS 15.6(3)M7 or later. Disable IP SLA responder if not required.",
        "cwe": "CWE-119",
    },
    {
        "id": "CISCO-CVE-016",
        "cve": "CVE-2024-20359",
        "platform": "ios",
        "affected": ">=12.0,<15.9.4",
        "severity": "HIGH",
        "name": "Persistent local code execution from ROM monitor",
        "description": (
            "A vulnerability in Cisco IOS allows an authenticated local attacker with "
            "level 15 privileges to install and execute arbitrary software images, "
            "persisting across reboots."
        ),
        "recommendation": "Upgrade to a fixed release. Restrict physical and console access. Enable secure boot.",
        "cwe": "CWE-94",
    },
    {
        "id": "CISCO-CVE-017",
        "cve": "CVE-2019-1862",
        "platform": "ios-xe",
        "affected": ">=16.0,<16.9.3",
        "severity": "HIGH",
        "name": "Web UI command injection — admin-level arbitrary command execution",
        "description": (
            "A vulnerability in the web-based UI of Cisco IOS XE allows an "
            "authenticated admin attacker to execute arbitrary commands on the "
            "underlying Linux OS with root privileges."
        ),
        "recommendation": "Upgrade to IOS-XE 16.9.3 or later. Disable HTTP server.",
        "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-018",
        "cve": "CVE-2020-3580",
        "platform": "ios-xe",
        "affected": ">=16.0,<16.12.4",
        "severity": "MEDIUM",
        "name": "Stored XSS in web management interface",
        "description": (
            "Multiple vulnerabilities in the web services interface of Cisco IOS XE "
            "allow an authenticated remote attacker to conduct stored cross-site "
            "scripting (XSS) attacks against users of the interface."
        ),
        "recommendation": "Upgrade to IOS-XE 16.12.4 or later.",
        "cwe": "CWE-79",
    },
    {
        "id": "CISCO-CVE-019",
        "cve": "CVE-2020-3200",
        "platform": "ios",
        "affected": ">=15.0,<15.9.4",
        "severity": "MEDIUM",
        "name": "Secure Shell DoS — crafted SSH session causes device reload",
        "description": (
            "A vulnerability in the Secure Shell (SSH) server of Cisco IOS allows an "
            "authenticated remote attacker to cause a device reload by sending a "
            "crafted SSH packet during session negotiation."
        ),
        "recommendation": "Upgrade to a fixed release. Restrict SSH access with ACLs.",
        "cwe": "CWE-20",
    },
    {
        "id": "CISCO-CVE-020",
        "cve": "CVE-2016-6380",
        "platform": "ios",
        "affected": ">=12.0,<15.2.5",
        "severity": "MEDIUM",
        "name": "DNS response parsing DoS — malformed DNS packets cause reload",
        "description": (
            "A vulnerability in the DNS forwarder functionality of Cisco IOS allows an "
            "unauthenticated remote attacker to cause a device reload by sending a "
            "crafted DNS response."
        ),
        "recommendation": "Upgrade to a fixed release. Use external DNS servers instead of IOS DNS forwarder.",
        "cwe": "CWE-20",
    },
]


# ============================================================
# Finding data class  (identical schema to all other scanners)
# ============================================================
class Finding:
    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = file_path       # repurposed: device IP address
        self.line_num = line_num         # config line number or None
        self.line_content = line_content # repurposed: config line or version info
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe or ""
        self.cve = cve or ""

    def to_dict(self):
        return {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_num,
            "code": self.line_content,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "cve": self.cve,
        }


# ============================================================
# Cisco IOS Router/Switch Security Scanner
# ============================================================
class CiscoScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def __init__(self, ip_range: str, username: str = "",
                 password: str = "", enable_password: str = "",
                 snmp_community: str = "", protocol: str = "ssh",
                 port: int = 22, timeout: int = 10,
                 max_hosts: int = 256, verbose: bool = False):
        self.ip_range = ip_range
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.snmp_community = snmp_community
        self.protocol = protocol
        self.port = port
        self.timeout = timeout
        self.max_hosts = max_hosts
        self.verbose = verbose
        self.findings: list = []
        self.devices: list = []
        self._failed_hosts: list = []

    # ----------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------
    def scan(self):
        print(f"[*] Cisco IOS Security Scanner v{VERSION}")
        print(f"[*] Protocol: {self.protocol.upper()}")

        hosts = self._expand_range(self.ip_range)
        if not hosts:
            print("[!] No valid hosts in the specified range.", file=sys.stderr)
            return
        if len(hosts) > self.max_hosts:
            print(f"[!] Range contains {len(hosts)} hosts, capped at --max-hosts {self.max_hosts}.",
                  file=sys.stderr)
            hosts = hosts[:self.max_hosts]

        print(f"[*] Probing {len(hosts)} host(s) for reachability ...")
        reachable = self._probe_hosts(hosts)
        print(f"[*] {len(reachable)} host(s) reachable.")

        if not reachable:
            print("[!] No reachable hosts found.", file=sys.stderr)
            return

        for ip in reachable:
            print(f"\n[*] Scanning {ip} ...")
            try:
                device_info = self._identify_device(ip)
                if not device_info or not device_info.get("is_cisco"):
                    self._vprint(f"  [skip] {ip} is not a Cisco device or could not be identified")
                    continue

                self.devices.append(device_info)
                model = device_info.get("model", "Unknown")
                ios_ver = device_info.get("ios_version_raw", "Unknown")
                platform = device_info.get("platform", "Unknown")
                print(f"  [+] Cisco {model} — {platform} {ios_ver}")

                # CVE checks
                self._check_cves(device_info, ip)

                # Config checks (SSH only)
                if self.protocol in ("ssh", "both") and self.username:
                    config_text = self._get_running_config(ip)
                    if config_text:
                        sections = self._parse_config_sections(config_text)
                        self._check_authentication(sections, ip)
                        self._check_ssh_config(sections, ip)
                        self._check_vty_lines(sections, ip)
                        self._check_snmp_config(sections, ip)
                        self._check_logging(sections, ip)
                        self._check_ntp(sections, ip)
                        self._check_services(sections, ip)
                        self._check_interfaces(sections, ip)
                        self._check_discovery_protocols(sections, ip)
                        self._check_banners(sections, ip)
                        self._check_console_aux(sections, ip)
                        self._check_routing_protocols(sections, ip)
                        self._check_layer2_security(sections, ip)
                        self._check_control_plane(sections, ip)
                        self._check_misc_hardening(sections, ip)
                    else:
                        self._warn(f"Could not retrieve running-config from {ip}")
                elif self.protocol == "snmp":
                    self._vprint(f"  [info] SNMP-only mode — skipping config checks for {ip}")

            except Exception as e:
                self._warn(f"Error scanning {ip}: {e}")
                self._failed_hosts.append(ip)

        total = len(self.devices)
        failed = len(self._failed_hosts)
        print(f"\n[*] Scan complete. {total} device(s) analyzed, "
              f"{failed} failed, {len(self.findings)} finding(s).")

    # ----------------------------------------------------------
    # IP Range Expansion
    # ----------------------------------------------------------
    def _expand_range(self, range_str: str) -> list:
        """Parse CIDR, start-end, single IP, or comma-separated IPs."""
        hosts = []
        for part in range_str.split(","):
            part = part.strip()
            if not part:
                continue
            # Range notation: 192.168.1.1-192.168.1.254 or 192.168.1.1-254
            if "-" in part and "/" not in part:
                try:
                    pieces = part.split("-")
                    start = ipaddress.ip_address(pieces[0].strip())
                    end_str = pieces[1].strip()
                    if "." in end_str:
                        end = ipaddress.ip_address(end_str)
                    else:
                        # Short form: 192.168.1.1-254
                        octets = str(start).rsplit(".", 1)
                        end = ipaddress.ip_address(f"{octets[0]}.{end_str}")
                    current = int(start)
                    while current <= int(end):
                        hosts.append(str(ipaddress.ip_address(current)))
                        current += 1
                except (ValueError, IndexError) as e:
                    self._warn(f"Invalid range '{part}': {e}")
            # CIDR notation
            elif "/" in part:
                try:
                    network = ipaddress.ip_network(part, strict=False)
                    for addr in network.hosts():
                        hosts.append(str(addr))
                except ValueError as e:
                    self._warn(f"Invalid CIDR '{part}': {e}")
            # Single IP
            else:
                try:
                    ipaddress.ip_address(part)
                    hosts.append(part)
                except ValueError as e:
                    self._warn(f"Invalid IP '{part}': {e}")
        return hosts

    # ----------------------------------------------------------
    # Host Probing (parallel TCP connect)
    # ----------------------------------------------------------
    def _probe_hosts(self, hosts: list) -> list:
        """Probe hosts in parallel using TCP connect to identify reachable ones."""
        reachable = []

        def _probe(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, self.port))
                sock.close()
                return ip if result == 0 else None
            except OSError:
                return None

        workers = min(50, len(hosts))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_probe, ip): ip for ip in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    reachable.append(result)
                    self._vprint(f"  [+] {result} — port {self.port} open")
                else:
                    self._vprint(f"  [-] {futures[future]} — unreachable")

        # Preserve original order
        return [ip for ip in hosts if ip in set(reachable)]

    # ----------------------------------------------------------
    # Device Identification
    # ----------------------------------------------------------
    def _identify_device(self, ip: str) -> dict:
        """Identify a Cisco device via SNMP and/or SSH."""
        info = {"ip": ip, "is_cisco": False, "model": "", "hostname": "",
                "ios_version_raw": "", "ios_version_normalized": "",
                "platform": "", "serial": "", "uptime": ""}

        # Try SNMP first if available
        if self.protocol in ("snmp", "both") and self.snmp_community and HAS_PYSNMP:
            snmp_info = self._identify_via_snmp(ip)
            if snmp_info:
                info.update(snmp_info)

        # Try SSH if needed
        if self.protocol in ("ssh", "both") and self.username:
            if not info["is_cisco"]:
                ssh_info = self._identify_via_ssh(ip)
                if ssh_info:
                    info.update(ssh_info)

        return info

    def _identify_via_snmp(self, ip: str) -> dict:
        """Query SNMP sysDescr to identify Cisco device."""
        self._vprint(f"  [snmp] Querying sysDescr on {ip} ...")
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(self.snmp_community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=self.timeout, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),  # sysName
            )
            error_indication, error_status, _, var_binds = next(iterator)
            if error_indication or error_status:
                self._vprint(f"  [snmp] SNMP error on {ip}: {error_indication or error_status}")
                return None

            sys_descr = str(var_binds[0][1]) if var_binds else ""
            sys_name = str(var_binds[1][1]) if len(var_binds) > 1 else ""

            if "cisco" not in sys_descr.lower():
                return None

            version_info = self._parse_ios_version(sys_descr)
            model = self._extract_model(sys_descr)

            return {
                "is_cisco": True,
                "model": model,
                "hostname": sys_name,
                "ios_version_raw": version_info.get("raw", ""),
                "ios_version_normalized": version_info.get("normalized", ""),
                "platform": version_info.get("platform", "IOS"),
                "sys_descr": sys_descr,
            }
        except Exception as e:
            self._vprint(f"  [snmp] SNMP failed on {ip}: {e}")
            return None

    def _identify_via_ssh(self, ip: str) -> dict:
        """Connect via SSH and run 'show version' to identify device."""
        self._vprint(f"  [ssh] Connecting to {ip} ...")
        try:
            device_params = {
                "device_type": "cisco_ios",
                "host": ip,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "timeout": self.timeout,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
                "banner_timeout": self.timeout,
            }
            if self.enable_password:
                device_params["secret"] = self.enable_password

            conn = ConnectHandler(**device_params)
            if self.enable_password:
                conn.enable()

            output = conn.send_command("show version", read_timeout=30)
            conn.disconnect()

            if not output:
                return None

            # Check if it's a Cisco device
            if "cisco" not in output.lower():
                return None

            version_info = self._parse_ios_version(output)
            model = self._extract_model(output)
            hostname = self._extract_hostname(output)
            serial = self._extract_serial(output)
            uptime = self._extract_uptime(output)

            return {
                "is_cisco": True,
                "model": model,
                "hostname": hostname,
                "ios_version_raw": version_info.get("raw", ""),
                "ios_version_normalized": version_info.get("normalized", ""),
                "platform": version_info.get("platform", "IOS"),
                "serial": serial,
                "uptime": uptime,
                "show_version": output,
            }
        except Exception as e:
            self._vprint(f"  [ssh] SSH failed on {ip}: {e}")
            return None

    # ----------------------------------------------------------
    # IOS Version Parsing
    # ----------------------------------------------------------
    def _parse_ios_version(self, text: str) -> dict:
        """Extract IOS version from sysDescr or show version output."""
        result = {"raw": "", "normalized": "", "platform": "IOS"}

        # Detect platform
        text_lower = text.lower()
        if "ios-xe" in text_lower or "ios xe" in text_lower or "iosxe" in text_lower:
            result["platform"] = "IOS-XE"
        elif "ios xr" in text_lower or "ios-xr" in text_lower:
            result["platform"] = "IOS-XR"
        elif "nx-os" in text_lower or "nxos" in text_lower:
            result["platform"] = "NX-OS"

        # IOS-XE dotted format: Version 16.09.04, 17.6.3a
        m = re.search(r"Version\s+((\d+)\.(\d+)\.(\d+)[a-zA-Z]*)", text)
        if m:
            result["raw"] = m.group(1)
            major, minor, patch = m.group(2), m.group(3), m.group(4)
            result["normalized"] = f"{int(major)}.{int(minor)}.{int(patch)}"
            # Dotted versions >= 16.x are IOS-XE
            if int(major) >= 16:
                result["platform"] = "IOS-XE"
            return result

        # Classic IOS parenthetical: Version 15.0(2)SE11
        m = re.search(r"Version\s+((\d+)\.(\d+)\((\d+)\)[a-zA-Z0-9]*)", text)
        if m:
            result["raw"] = m.group(1)
            major, minor, release = m.group(2), m.group(3), m.group(4)
            result["normalized"] = f"{int(major)}.{int(minor)}.{int(release)}"
            return result

        return result

    def _extract_model(self, text: str) -> str:
        """Extract device model from show version or sysDescr."""
        # Try common patterns
        patterns = [
            r"[Cc]isco\s+((?:C|WS-C|ISR|ASR|CSR|IE-|N\d+K-)\S+)",
            r"[Cc]isco\s+(\S+)\s+(?:Software|processor|Chassis)",
            r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)",
            r"(?:C|WS-C)\d{4}\S*",
        ]
        for pattern in patterns:
            m = re.search(pattern, text)
            if m:
                return m.group(1) if m.lastindex else m.group(0)
        return "Unknown"

    def _extract_hostname(self, text: str) -> str:
        m = re.search(r"(\S+)\s+uptime is", text)
        return m.group(1) if m else ""

    def _extract_serial(self, text: str) -> str:
        m = re.search(r"[Pp]rocessor board ID\s+(\S+)", text)
        return m.group(1) if m else ""

    def _extract_uptime(self, text: str) -> str:
        m = re.search(r"uptime is\s+(.+)", text)
        return m.group(1).strip() if m else ""

    # ----------------------------------------------------------
    # Running Config Retrieval
    # ----------------------------------------------------------
    def _get_running_config(self, ip: str) -> str:
        """Retrieve running-config via SSH."""
        self._vprint(f"  [ssh] Retrieving running-config from {ip} ...")
        try:
            device_params = {
                "device_type": "cisco_ios",
                "host": ip,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "timeout": self.timeout,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
                "banner_timeout": self.timeout,
            }
            if self.enable_password:
                device_params["secret"] = self.enable_password

            conn = ConnectHandler(**device_params)
            if self.enable_password:
                conn.enable()

            config = conn.send_command("show running-config", read_timeout=60)
            conn.disconnect()
            return config
        except Exception as e:
            self._warn(f"Failed to get running-config from {ip}: {e}")
            return ""

    # ----------------------------------------------------------
    # Config Section Parser
    # ----------------------------------------------------------
    def _parse_config_sections(self, config_text: str) -> dict:
        """
        Parse IOS running-config into sections.
        Returns: {"_global": [lines], "interface Gi0/1": [lines], ...}
        """
        sections = {"_global": []}
        current_section = "_global"
        lines = config_text.splitlines()

        for line in lines:
            stripped = line.rstrip()
            if not stripped or stripped.startswith("!"):
                continue

            # Top-level line (no leading whitespace) starts a new section
            if stripped and not line[0:1].isspace():
                # Check if this is a section header (has sub-commands)
                section_headers = (
                    "interface ", "line ", "router ", "ip access-list ",
                    "route-map ", "class-map ", "policy-map ", "control-plane",
                    "crypto ", "key chain ", "spanning-tree ", "vlan ",
                    "ip dhcp ", "ip nat ", "snmp-server ", "ntp ",
                    "logging ", "aaa ", "tacacs", "radius",
                )
                is_header = any(stripped.lower().startswith(h) for h in section_headers)
                if is_header:
                    current_section = stripped
                    if current_section not in sections:
                        sections[current_section] = []
                else:
                    # Global config line
                    sections["_global"].append(stripped)
                    current_section = "_global"
            else:
                # Indented line belongs to current section
                sections.setdefault(current_section, []).append(stripped.strip())

        return sections

    # ----------------------------------------------------------
    # Version Comparison Utilities
    # ----------------------------------------------------------
    @staticmethod
    def _parse_ver(s):
        """Parse a version string into a comparable tuple of ints."""
        s = re.sub(r"[-.]?(RELEASE|FINAL|GA|alpha\d*|beta\d*|rc\d*|[a-zA-Z]+).*$",
                   "", s, flags=re.IGNORECASE)
        parts = re.split(r"[.\-]", s)
        try:
            return tuple(int(p) for p in parts if p.isdigit())
        except ValueError:
            return None

    def _version_in_range(self, version, range_str):
        """Evaluate a version against a constraint like '<15.2.7' or '>=16.0,<17.9.5'."""
        pv = self._parse_ver(version)
        if pv is None:
            return False
        for cond in range_str.split(","):
            cond = cond.strip()
            m = re.match(r"([<>]=?)([\d.]+)", cond)
            if not m:
                continue
            op, ver_str = m.groups()
            tv = self._parse_ver(ver_str)
            if tv is None:
                continue
            length = max(len(pv), len(tv))
            a = pv + (0,) * (length - len(pv))
            b = tv + (0,) * (length - len(tv))
            checks = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}
            if not checks.get(op, False):
                return False
        return True

    # ----------------------------------------------------------
    # CVE Checks
    # ----------------------------------------------------------
    def _check_cves(self, device_info: dict, ip: str):
        """Match device IOS version against known CVE database."""
        normalized = device_info.get("ios_version_normalized", "")
        platform = device_info.get("platform", "IOS").lower()
        raw_ver = device_info.get("ios_version_raw", "Unknown")

        if not normalized:
            self._vprint(f"  [info] No version to check CVEs against for {ip}")
            return

        for entry in IOS_CVE_DATABASE:
            entry_platform = entry["platform"].lower()
            # Match platform: "ios" matches IOS, "ios-xe" matches IOS-XE
            if entry_platform == "ios" and platform not in ("ios",):
                continue
            if entry_platform == "ios-xe" and platform not in ("ios-xe",):
                continue

            if self._version_in_range(normalized, entry["affected"]):
                self._add(Finding(
                    rule_id=entry["id"],
                    name=entry["name"],
                    category="Known Vulnerabilities",
                    severity=entry["severity"],
                    file_path=ip,
                    line_num=None,
                    line_content=f"IOS Version = {raw_ver} ({platform})",
                    description=entry["description"],
                    recommendation=entry["recommendation"],
                    cwe=entry.get("cwe", ""),
                    cve=entry.get("cve", ""),
                ))

    # ----------------------------------------------------------
    # Configuration Check: Authentication
    # ----------------------------------------------------------
    def _check_authentication(self, sections: dict, ip: str):
        gl = sections.get("_global", [])
        gl_text = "\n".join(gl)

        # CISCO-AUTH-001: enable password used instead of enable secret
        for line in gl:
            if re.match(r"^enable password\s+", line):
                self._add(Finding(
                    rule_id="CISCO-AUTH-001", name="Enable password used instead of enable secret",
                    category="Authentication", severity="CRITICAL", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        "The 'enable password' command stores the password using a weak reversible "
                        "algorithm (type 7). An attacker with access to the config can trivially "
                        "recover the plaintext password."
                    ),
                    recommendation="Replace 'enable password' with 'enable secret' which uses a strong hash.",
                    cwe="CWE-261",
                ))
                break

        # CISCO-AUTH-002: no enable secret configured
        if not any(re.match(r"^enable secret\s+", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-AUTH-002", name="No enable secret configured",
                category="Authentication", severity="HIGH", file_path=ip, line_num=None,
                line_content="enable secret = (missing)",
                description=(
                    "No 'enable secret' is configured. Without it, privilege level 15 "
                    "access may be unprotected or relying on the weak 'enable password'."
                ),
                recommendation="Configure 'enable secret <strong-password>' using a complex passphrase.",
                cwe="CWE-862",
            ))

        # CISCO-AUTH-003: service password-encryption not enabled
        if not any(re.match(r"^service password-encryption", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-AUTH-003", name="Service password-encryption not enabled",
                category="Authentication", severity="HIGH", file_path=ip, line_num=None,
                line_content="service password-encryption = (missing)",
                description=(
                    "Without 'service password-encryption', passwords in the running-config "
                    "are stored in plaintext and visible to anyone who can view the configuration."
                ),
                recommendation="Enable 'service password-encryption'. Note: type 7 encryption is weak — prefer type 8/9 secrets.",
                cwe="CWE-256",
            ))

        # CISCO-AUTH-004: plaintext password in config
        for line in gl:
            if re.match(r"^username\s+\S+\s+password\s+0\s+", line):
                self._add(Finding(
                    rule_id="CISCO-AUTH-004", name="Plaintext password found in running-config",
                    category="Authentication", severity="CRITICAL", file_path=ip, line_num=None,
                    line_content=re.sub(r"password\s+0\s+\S+", "password 0 ****", line),
                    description=(
                        "A username is configured with a type 0 (plaintext) password. Anyone "
                        "with config access can read the credentials directly."
                    ),
                    recommendation="Use 'username <name> secret <password>' for scrypt/SHA-256 hashing.",
                    cwe="CWE-256",
                ))
                break

        # CISCO-AUTH-005: AAA not configured
        if not any(re.match(r"^aaa new-model", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-AUTH-005", name="AAA not configured",
                category="Authentication", severity="HIGH", file_path=ip, line_num=None,
                line_content="aaa new-model = (missing)",
                description=(
                    "AAA (Authentication, Authorization, and Accounting) is not enabled. "
                    "Without AAA, the device uses legacy line-based authentication which "
                    "lacks centralized control, audit logging, and granular authorization."
                ),
                recommendation="Enable 'aaa new-model' and configure TACACS+ or RADIUS for centralized authentication.",
                cwe="CWE-862",
            ))

        # CISCO-AUTH-006: local user with password (not secret)
        for line in gl:
            m = re.match(r"^username\s+(\S+)\s+password\s+", line)
            if m and "secret" not in line:
                self._add(Finding(
                    rule_id="CISCO-AUTH-006", name="Local user configured with weak password type",
                    category="Authentication", severity="MEDIUM", file_path=ip, line_num=None,
                    line_content=f"username {m.group(1)} password (type 0 or 7)",
                    description=(
                        "A local user account uses 'password' instead of 'secret'. The 'password' "
                        "command uses type 7 encryption which is trivially reversible."
                    ),
                    recommendation="Replace with 'username <name> secret <password>' for strong hashing.",
                    cwe="CWE-916",
                ))
                break

    # ----------------------------------------------------------
    # Configuration Check: SSH Security
    # ----------------------------------------------------------
    def _check_ssh_config(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-SSH-001: SSH version 1 enabled
        for line in gl:
            if re.match(r"^ip ssh version\s+1\b", line):
                self._add(Finding(
                    rule_id="CISCO-SSH-001", name="SSH version 1 enabled",
                    category="SSH Security", severity="HIGH", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        "SSH version 1 has known cryptographic weaknesses including vulnerability "
                        "to man-in-the-middle attacks and session hijacking."
                    ),
                    recommendation="Configure 'ip ssh version 2' to enforce SSHv2 only.",
                    cwe="CWE-327",
                ))
                break

        # CISCO-SSH-002: SSH version 2 not explicitly configured
        if not any(re.match(r"^ip ssh version\s+2", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-SSH-002", name="SSH version 2 not explicitly enforced",
                category="SSH Security", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="ip ssh version 2 = (missing)",
                description=(
                    "Without explicitly setting 'ip ssh version 2', the device may negotiate "
                    "SSHv1 connections if a client requests it."
                ),
                recommendation="Configure 'ip ssh version 2' to enforce SSHv2 only.",
                cwe="CWE-327",
            ))

        # CISCO-SSH-003: SSH timeout too long
        for line in gl:
            m = re.match(r"^ip ssh time-out\s+(\d+)", line)
            if m and int(m.group(1)) > 60:
                self._add(Finding(
                    rule_id="CISCO-SSH-003", name="SSH authentication timeout too long",
                    category="SSH Security", severity="LOW", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        f"SSH authentication timeout is set to {m.group(1)} seconds. "
                        "Long timeouts allow attackers more time for brute-force attempts."
                    ),
                    recommendation="Set 'ip ssh time-out 60' or lower.",
                    cwe="CWE-307",
                ))
                break

        # CISCO-SSH-004: SSH authentication retries too high
        for line in gl:
            m = re.match(r"^ip ssh authentication-retries\s+(\d+)", line)
            if m and int(m.group(1)) > 3:
                self._add(Finding(
                    rule_id="CISCO-SSH-004", name="SSH authentication retries too high",
                    category="SSH Security", severity="LOW", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        f"SSH allows {m.group(1)} authentication retries. High retry counts "
                        "facilitate brute-force password guessing attacks."
                    ),
                    recommendation="Set 'ip ssh authentication-retries 3' or lower.",
                    cwe="CWE-307",
                ))
                break

    # ----------------------------------------------------------
    # Configuration Check: VTY Lines (Remote Access)
    # ----------------------------------------------------------
    def _check_vty_lines(self, sections: dict, ip: str):
        vty_sections = {k: v for k, v in sections.items() if k.lower().startswith("line vty")}
        if not vty_sections:
            return

        for section_name, lines in vty_sections.items():
            lines_text = "\n".join(lines)

            # CISCO-VTY-001: Telnet enabled
            for line in lines:
                if re.match(r"^transport input\s+(?:telnet|all)\s*$", line, re.IGNORECASE):
                    self._add(Finding(
                        rule_id="CISCO-VTY-001", name="Telnet enabled on VTY lines",
                        category="Remote Access", severity="HIGH", file_path=ip, line_num=None,
                        line_content=f"{section_name}: {line}",
                        description=(
                            "Telnet transmits credentials and commands in plaintext. An attacker "
                            "on the network can capture login credentials using packet sniffing."
                        ),
                        recommendation="Configure 'transport input ssh' on all VTY lines to allow only SSH.",
                        cwe="CWE-319",
                    ))
                    break

            # CISCO-VTY-002: No access-class on VTY
            if not any("access-class" in l for l in lines):
                self._add(Finding(
                    rule_id="CISCO-VTY-002", name="No access-class on VTY lines",
                    category="Remote Access", severity="HIGH", file_path=ip, line_num=None,
                    line_content=f"{section_name}: access-class = (missing)",
                    description=(
                        "VTY lines have no access-class ACL applied. Any IP address can attempt "
                        "to connect to the device management interface."
                    ),
                    recommendation="Apply an ACL with 'access-class <acl> in' to restrict VTY access to trusted management IPs.",
                    cwe="CWE-284",
                ))

            # CISCO-VTY-003: No exec-timeout or timeout too long
            has_timeout = False
            for line in lines:
                m = re.match(r"^exec-timeout\s+(\d+)\s+(\d+)", line)
                if m:
                    has_timeout = True
                    mins, secs = int(m.group(1)), int(m.group(2))
                    if mins > 10 or (mins == 0 and secs == 0):
                        label = "disabled" if (mins == 0 and secs == 0) else f"{mins}m {secs}s"
                        self._add(Finding(
                            rule_id="CISCO-VTY-003", name="VTY exec-timeout too long or disabled",
                            category="Remote Access", severity="MEDIUM", file_path=ip, line_num=None,
                            line_content=f"{section_name}: exec-timeout {mins} {secs} ({label})",
                            description=(
                                "A long or disabled exec-timeout on VTY lines means idle sessions "
                                "remain open indefinitely, increasing the risk of session hijacking."
                            ),
                            recommendation="Set 'exec-timeout 10 0' (10 minutes) or lower on all VTY lines.",
                            cwe="CWE-613",
                        ))
                    break
            if not has_timeout:
                self._add(Finding(
                    rule_id="CISCO-VTY-003", name="VTY exec-timeout not configured",
                    category="Remote Access", severity="MEDIUM", file_path=ip, line_num=None,
                    line_content=f"{section_name}: exec-timeout = (missing, default 10 min)",
                    description=(
                        "No explicit exec-timeout on VTY lines. While the default is 10 minutes, "
                        "best practice is to explicitly set a short timeout."
                    ),
                    recommendation="Explicitly set 'exec-timeout 10 0' or lower on all VTY lines.",
                    cwe="CWE-613",
                ))

            # CISCO-VTY-004: Transport input not restricted to SSH only
            has_transport = False
            for line in lines:
                if re.match(r"^transport input\s+ssh\s*$", line, re.IGNORECASE):
                    has_transport = True
                    break
            if not has_transport:
                # Only add if we didn't already flag telnet (VTY-001)
                has_telnet_finding = any(
                    f.rule_id == "CISCO-VTY-001" and section_name in (f.line_content or "")
                    for f in self.findings
                )
                if not has_telnet_finding:
                    self._add(Finding(
                        rule_id="CISCO-VTY-004", name="VTY transport input not restricted to SSH",
                        category="Remote Access", severity="MEDIUM", file_path=ip, line_num=None,
                        line_content=f"{section_name}: transport input = (not 'ssh' only)",
                        description=(
                            "VTY lines do not explicitly restrict transport to SSH only. "
                            "This may allow less secure protocols."
                        ),
                        recommendation="Configure 'transport input ssh' on all VTY lines.",
                        cwe="CWE-319",
                    ))

            # CISCO-VTY-005: No login method on VTY
            if not any(re.match(r"^login\s+", l) or l.strip() == "login" for l in lines):
                self._add(Finding(
                    rule_id="CISCO-VTY-005", name="No login authentication on VTY lines",
                    category="Remote Access", severity="HIGH", file_path=ip, line_num=None,
                    line_content=f"{section_name}: login = (missing)",
                    description=(
                        "VTY lines have no login method configured. Depending on the IOS version, "
                        "this may allow unauthenticated access to the device CLI."
                    ),
                    recommendation="Configure 'login local' or 'login authentication <method>' on VTY lines.",
                    cwe="CWE-287",
                ))

    # ----------------------------------------------------------
    # Configuration Check: SNMP Security
    # ----------------------------------------------------------
    def _check_snmp_config(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        has_snmp = any(re.match(r"^snmp-server community\s+", l) for l in gl)
        if not has_snmp:
            return  # SNMP not configured, skip checks

        # CISCO-SNMP-001: Default community 'public'
        for line in gl:
            if re.match(r"^snmp-server community\s+public\b", line, re.IGNORECASE):
                self._add(Finding(
                    rule_id="CISCO-SNMP-001", name="Default SNMP community string 'public'",
                    category="SNMP Security", severity="CRITICAL", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        "The default SNMP community string 'public' is well-known and grants "
                        "read access to device information. Attackers routinely scan for this."
                    ),
                    recommendation="Remove the 'public' community string. Use a complex, unique community string or migrate to SNMPv3.",
                    cwe="CWE-798",
                ))
                break

        # CISCO-SNMP-002: Default community 'private'
        for line in gl:
            if re.match(r"^snmp-server community\s+private\b", line, re.IGNORECASE):
                self._add(Finding(
                    rule_id="CISCO-SNMP-002", name="Default SNMP community string 'private'",
                    category="SNMP Security", severity="CRITICAL", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        "The default SNMP community string 'private' typically grants read-write "
                        "access. An attacker can modify device configuration remotely."
                    ),
                    recommendation="Remove the 'private' community string immediately. Use SNMPv3 with authentication and encryption.",
                    cwe="CWE-798",
                ))
                break

        # CISCO-SNMP-003: SNMP RW community configured
        for line in gl:
            if re.match(r"^snmp-server community\s+\S+\s+RW", line, re.IGNORECASE):
                self._add(Finding(
                    rule_id="CISCO-SNMP-003", name="SNMP read-write community string configured",
                    category="SNMP Security", severity="HIGH", file_path=ip, line_num=None,
                    line_content=re.sub(r"community\s+\S+", "community ****", line),
                    description=(
                        "An SNMP community string with read-write (RW) access is configured. "
                        "If compromised, an attacker can modify the device configuration remotely."
                    ),
                    recommendation="Remove RW community strings. Use SNMPv3 with auth and priv for write access, restricted by ACL.",
                    cwe="CWE-732",
                ))
                break

        # CISCO-SNMP-004: No SNMPv3 configured
        has_v3 = any(re.match(r"^snmp-server group\s+\S+\s+v3", l) for l in gl)
        if not has_v3:
            self._add(Finding(
                rule_id="CISCO-SNMP-004", name="SNMPv3 not configured (using v1/v2c only)",
                category="SNMP Security", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="snmp-server group v3 = (missing)",
                description=(
                    "Only SNMPv1/v2c is configured. These versions transmit community strings "
                    "in plaintext and lack authentication/encryption."
                ),
                recommendation="Migrate to SNMPv3 with authPriv security level for encrypted and authenticated SNMP.",
                cwe="CWE-319",
            ))

    # ----------------------------------------------------------
    # Configuration Check: Logging
    # ----------------------------------------------------------
    def _check_logging(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-LOG-001: No remote syslog server
        if not any(re.match(r"^logging\s+(?:host\s+)?\d+\.\d+\.\d+\.\d+", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-LOG-001", name="No remote syslog server configured",
                category="Logging", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="logging host = (missing)",
                description=(
                    "No remote syslog server is configured. Device logs are only stored locally "
                    "in the buffer and will be lost on reboot or if an attacker clears them."
                ),
                recommendation="Configure 'logging host <syslog-server-ip>' to send logs to a centralized SIEM.",
                cwe="CWE-778",
            ))

        # CISCO-LOG-002: Logging buffered not configured
        if not any(re.match(r"^logging buffered", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-LOG-002", name="Logging buffered not configured",
                category="Logging", severity="LOW", file_path=ip, line_num=None,
                line_content="logging buffered = (missing)",
                description=(
                    "Buffered logging is not configured. Without it, log messages may only go "
                    "to the console and be lost."
                ),
                recommendation="Configure 'logging buffered <size> informational' to retain logs in device memory.",
                cwe="CWE-778",
            ))

        # CISCO-LOG-003: Service timestamps for logging not enabled
        if not any(re.match(r"^service timestamps log datetime", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-LOG-003", name="Service timestamps for logging not enabled",
                category="Logging", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="service timestamps log datetime = (missing)",
                description=(
                    "Log messages do not include date-time timestamps, making forensic "
                    "analysis and incident correlation difficult."
                ),
                recommendation="Configure 'service timestamps log datetime msec localtime show-timezone'.",
                cwe="CWE-778",
            ))

        # CISCO-LOG-004: Console logging not rate-limited
        if not any(re.match(r"^logging rate-limit", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-LOG-004", name="Logging not rate-limited",
                category="Logging", severity="LOW", file_path=ip, line_num=None,
                line_content="logging rate-limit = (missing)",
                description=(
                    "Log rate-limiting is not configured. During a log flood event (e.g., "
                    "scanning or routing flap), excessive logging can impact device CPU."
                ),
                recommendation="Configure 'logging rate-limit <messages-per-second>' to protect against log flooding.",
                cwe="CWE-400",
            ))

    # ----------------------------------------------------------
    # Configuration Check: NTP
    # ----------------------------------------------------------
    def _check_ntp(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-NTP-001: No NTP server configured
        if not any(re.match(r"^ntp server\s+", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-NTP-001", name="No NTP server configured",
                category="NTP", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="ntp server = (missing)",
                description=(
                    "No NTP server is configured. Without synchronized time, log timestamps "
                    "are unreliable, certificate validation may fail, and forensic timelines "
                    "cannot be correlated across devices."
                ),
                recommendation="Configure 'ntp server <trusted-ntp-server>' with at least two sources.",
                cwe="CWE-778",
            ))

        # CISCO-NTP-002: NTP authentication not enabled
        if not any(re.match(r"^ntp authenticate\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-NTP-002", name="NTP authentication not enabled",
                category="NTP", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="ntp authenticate = (missing)",
                description=(
                    "NTP authentication is not enabled. An attacker could inject false time "
                    "updates to manipulate log timestamps or disrupt time-dependent services."
                ),
                recommendation="Enable 'ntp authenticate' and configure trusted NTP keys.",
                cwe="CWE-345",
            ))

        # CISCO-NTP-003: NTP access-group not restricted
        if not any(re.match(r"^ntp access-group", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-NTP-003", name="NTP access-group not restricted",
                category="NTP", severity="LOW", file_path=ip, line_num=None,
                line_content="ntp access-group = (missing)",
                description=(
                    "No NTP access-group is configured. The device accepts NTP packets from "
                    "any source, increasing the attack surface for NTP amplification or spoofing."
                ),
                recommendation="Configure 'ntp access-group peer <acl>' to restrict NTP communication to trusted servers.",
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # Configuration Check: Network Services
    # ----------------------------------------------------------
    def _check_services(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-SVC-001: HTTP server enabled
        has_http = any(re.match(r"^ip http server\b", l) for l in gl)
        has_no_http = any(re.match(r"^no ip http server\b", l) for l in gl)
        if has_http and not has_no_http:
            self._add(Finding(
                rule_id="CISCO-SVC-001", name="HTTP server enabled (plaintext web management)",
                category="Network Services", severity="HIGH", file_path=ip, line_num=None,
                line_content="ip http server",
                description=(
                    "The HTTP server is enabled, exposing the web management interface over "
                    "unencrypted HTTP. Credentials and configuration data are transmitted in plaintext."
                ),
                recommendation="Disable with 'no ip http server'. Use 'ip http secure-server' (HTTPS) if web management is needed.",
                cwe="CWE-319",
            ))

        # CISCO-SVC-002: HTTPS without HTTP disabled
        has_https = any(re.match(r"^ip http secure-server\b", l) for l in gl)
        if has_https and has_http and not has_no_http:
            self._add(Finding(
                rule_id="CISCO-SVC-002", name="HTTPS enabled but HTTP not disabled",
                category="Network Services", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="ip http server + ip http secure-server (both active)",
                description=(
                    "Both HTTP and HTTPS servers are running. Users may inadvertently "
                    "connect over unencrypted HTTP."
                ),
                recommendation="Disable HTTP with 'no ip http server' while keeping 'ip http secure-server'.",
                cwe="CWE-319",
            ))

        # CISCO-SVC-003: IP source routing enabled
        if not any(re.match(r"^no ip source-route\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-SVC-003", name="IP source routing enabled",
                category="Network Services", severity="HIGH", file_path=ip, line_num=None,
                line_content="no ip source-route = (missing)",
                description=(
                    "IP source routing allows a sender to specify the route a packet takes "
                    "through the network. Attackers can use this to bypass firewalls and ACLs."
                ),
                recommendation="Disable with 'no ip source-route'.",
                cwe="CWE-284",
            ))

        # CISCO-SVC-004: IP directed broadcast (checked per interface in _check_interfaces)
        # Handled in _check_interfaces

        # CISCO-SVC-005: TCP small servers enabled
        for line in gl:
            if re.match(r"^service tcp-small-servers\b", line):
                self._add(Finding(
                    rule_id="CISCO-SVC-005", name="TCP small servers enabled",
                    category="Network Services", severity="MEDIUM", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        "TCP small servers (echo, chargen, daytime, discard) are enabled. "
                        "These legacy services can be used for reconnaissance and amplification attacks."
                    ),
                    recommendation="Disable with 'no service tcp-small-servers'.",
                    cwe="CWE-284",
                ))
                break

        # CISCO-SVC-006: UDP small servers enabled
        for line in gl:
            if re.match(r"^service udp-small-servers\b", line):
                self._add(Finding(
                    rule_id="CISCO-SVC-006", name="UDP small servers enabled",
                    category="Network Services", severity="MEDIUM", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        "UDP small servers (echo, chargen, daytime, discard) are enabled. "
                        "These can be exploited for UDP amplification and reflected DoS attacks."
                    ),
                    recommendation="Disable with 'no service udp-small-servers'.",
                    cwe="CWE-284",
                ))
                break

        # CISCO-SVC-007: Finger service enabled
        for line in gl:
            if re.match(r"^service finger\b", line):
                self._add(Finding(
                    rule_id="CISCO-SVC-007", name="Finger service enabled",
                    category="Network Services", severity="LOW", file_path=ip, line_num=None,
                    line_content=line,
                    description=(
                        "The finger service exposes information about logged-in users. "
                        "This is an unnecessary information disclosure risk."
                    ),
                    recommendation="Disable with 'no service finger' (or 'no ip finger').",
                    cwe="CWE-200",
                ))
                break

    # ----------------------------------------------------------
    # Configuration Check: Interface Security
    # ----------------------------------------------------------
    def _check_interfaces(self, sections: dict, ip: str):
        intf_sections = {k: v for k, v in sections.items()
                        if k.lower().startswith("interface ")}

        for section_name, lines in intf_sections.items():
            lines_text = "\n".join(lines)
            is_l3 = not any("switchport" in l.lower() for l in lines)
            is_shutdown = any(l.strip() == "shutdown" for l in lines)

            if is_shutdown:
                continue  # Skip shutdown interfaces

            if is_l3:
                # CISCO-INTF-001: Proxy ARP enabled
                if not any("no ip proxy-arp" in l for l in lines):
                    has_ip = any(re.match(r"^ip address\s+", l) for l in lines)
                    if has_ip:
                        self._add(Finding(
                            rule_id="CISCO-INTF-001", name="Proxy ARP enabled on routed interface",
                            category="Interface Security", severity="MEDIUM", file_path=ip, line_num=None,
                            line_content=f"{section_name}: no ip proxy-arp = (missing)",
                            description=(
                                "Proxy ARP is enabled by default on routed interfaces. It allows the "
                                "router to respond to ARP requests on behalf of other hosts, which can "
                                "be exploited for traffic interception."
                            ),
                            recommendation=f"Add 'no ip proxy-arp' under {section_name}.",
                            cwe="CWE-441",
                        ))

                # CISCO-INTF-003: IP redirects not disabled
                if not any("no ip redirects" in l for l in lines):
                    has_ip = any(re.match(r"^ip address\s+", l) for l in lines)
                    if has_ip:
                        self._add(Finding(
                            rule_id="CISCO-INTF-003", name="ICMP redirects not disabled",
                            category="Interface Security", severity="LOW", file_path=ip, line_num=None,
                            line_content=f"{section_name}: no ip redirects = (missing)",
                            description=(
                                "ICMP redirects can be used to alter a host's routing table, "
                                "potentially directing traffic through an attacker-controlled path."
                            ),
                            recommendation=f"Add 'no ip redirects' under {section_name}.",
                            cwe="CWE-284",
                        ))

                # CISCO-INTF-004: IP unreachables not disabled
                if not any("no ip unreachables" in l for l in lines):
                    has_ip = any(re.match(r"^ip address\s+", l) for l in lines)
                    if has_ip:
                        self._add(Finding(
                            rule_id="CISCO-INTF-004", name="ICMP unreachables not disabled",
                            category="Interface Security", severity="LOW", file_path=ip, line_num=None,
                            line_content=f"{section_name}: no ip unreachables = (missing)",
                            description=(
                                "ICMP unreachable messages can leak network topology information "
                                "and are used in network scanning/reconnaissance."
                            ),
                            recommendation=f"Add 'no ip unreachables' under {section_name}.",
                            cwe="CWE-200",
                        ))

        # CISCO-INTF-002: Unused interfaces not shut down
        for section_name, lines in intf_sections.items():
            is_shutdown = any(l.strip() == "shutdown" for l in lines)
            has_ip = any(re.match(r"^ip address\s+", l) for l in lines)
            has_switchport = any("switchport" in l.lower() for l in lines)
            has_description = any(re.match(r"^description\s+", l) for l in lines)
            # Flag interfaces with no IP, no switchport config, and not shut down
            if not is_shutdown and not has_ip and not has_switchport and not has_description:
                self._add(Finding(
                    rule_id="CISCO-INTF-002", name="Potentially unused interface not shut down",
                    category="Interface Security", severity="MEDIUM", file_path=ip, line_num=None,
                    line_content=f"{section_name}: shutdown = (missing)",
                    description=(
                        "An interface appears to be unused (no IP address, no switchport config, "
                        "no description) but is not administratively shut down. Unused active "
                        "interfaces can be exploited for unauthorized network access."
                    ),
                    recommendation=f"Shut down unused interfaces with 'shutdown' under {section_name}.",
                    cwe="CWE-284",
                ))

    # ----------------------------------------------------------
    # Configuration Check: Discovery Protocols
    # ----------------------------------------------------------
    def _check_discovery_protocols(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-CDP-001: CDP globally enabled
        if not any(re.match(r"^no cdp run\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-CDP-001", name="CDP globally enabled",
                category="Discovery Protocols", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="no cdp run = (missing, CDP enabled by default)",
                description=(
                    "Cisco Discovery Protocol (CDP) is enabled globally by default. CDP announces "
                    "device identity, IOS version, IP addresses, and platform details to adjacent "
                    "devices, which aids attacker reconnaissance."
                ),
                recommendation="Disable globally with 'no cdp run', or disable per-interface with 'no cdp enable' on untrusted ports.",
                cwe="CWE-200",
            ))

        # CISCO-CDP-002: LLDP globally enabled
        if any(re.match(r"^lldp run\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-CDP-002", name="LLDP globally enabled",
                category="Discovery Protocols", severity="LOW", file_path=ip, line_num=None,
                line_content="lldp run",
                description=(
                    "Link Layer Discovery Protocol (LLDP) is enabled. Like CDP, LLDP exposes "
                    "device information to adjacent devices on the network."
                ),
                recommendation="Disable with 'no lldp run' if not required, or disable on untrusted interfaces.",
                cwe="CWE-200",
            ))

    # ----------------------------------------------------------
    # Configuration Check: Banners
    # ----------------------------------------------------------
    def _check_banners(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-BAN-001: No login banner
        if not any(re.match(r"^banner login\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-BAN-001", name="No login banner configured",
                category="Banners", severity="MEDIUM", file_path=ip, line_num=None,
                line_content="banner login = (missing)",
                description=(
                    "No login banner is configured. A legal warning banner is required by many "
                    "compliance frameworks (PCI-DSS, NIST, CIS) to establish legal grounds for "
                    "prosecuting unauthorized access."
                ),
                recommendation="Configure 'banner login # Authorized access only. Unauthorized access is prohibited. #'.",
                cwe="CWE-284",
            ))

        # CISCO-BAN-002: No MOTD banner
        if not any(re.match(r"^banner motd\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-BAN-002", name="No MOTD banner configured",
                category="Banners", severity="LOW", file_path=ip, line_num=None,
                line_content="banner motd = (missing)",
                description=(
                    "No message-of-the-day banner is configured. While less critical than "
                    "the login banner, MOTD provides an additional warning to users."
                ),
                recommendation="Configure 'banner motd # Authorized use only #'. Avoid revealing hostname or IOS version in the banner.",
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # Configuration Check: Console/AUX Security
    # ----------------------------------------------------------
    def _check_console_aux(self, sections: dict, ip: str):
        # Console line
        con_sections = {k: v for k, v in sections.items() if k.lower().startswith("line con")}
        for section_name, lines in con_sections.items():
            # CISCO-CON-001: No exec-timeout on console
            has_timeout = False
            for line in lines:
                m = re.match(r"^exec-timeout\s+(\d+)\s+(\d+)", line)
                if m:
                    has_timeout = True
                    mins, secs = int(m.group(1)), int(m.group(2))
                    if mins == 0 and secs == 0:
                        self._add(Finding(
                            rule_id="CISCO-CON-001", name="Console exec-timeout disabled",
                            category="Console/AUX Security", severity="MEDIUM", file_path=ip,
                            line_num=None, line_content=f"{section_name}: exec-timeout 0 0 (disabled)",
                            description=(
                                "Console exec-timeout is disabled (0 0). A physical console session "
                                "will never time out, allowing anyone with physical access to use "
                                "an unattended session."
                            ),
                            recommendation="Set 'exec-timeout 5 0' under line con 0.",
                            cwe="CWE-613",
                        ))
                    break
            if not has_timeout:
                self._add(Finding(
                    rule_id="CISCO-CON-001", name="Console exec-timeout not configured",
                    category="Console/AUX Security", severity="MEDIUM", file_path=ip,
                    line_num=None, line_content=f"{section_name}: exec-timeout = (missing)",
                    description=(
                        "No explicit exec-timeout on the console line. Best practice is to "
                        "set a short timeout to prevent unauthorized use of unattended sessions."
                    ),
                    recommendation="Set 'exec-timeout 5 0' under line con 0.",
                    cwe="CWE-613",
                ))

            # CISCO-CON-002: No login on console
            if not any(re.match(r"^login\b", l) for l in lines):
                self._add(Finding(
                    rule_id="CISCO-CON-002", name="No login authentication on console",
                    category="Console/AUX Security", severity="HIGH", file_path=ip,
                    line_num=None, line_content=f"{section_name}: login = (missing)",
                    description=(
                        "No login method is configured on the console line. Anyone with "
                        "physical access to the console port gets direct CLI access without authentication."
                    ),
                    recommendation="Configure 'login local' or 'login authentication <method>' under line con 0.",
                    cwe="CWE-287",
                ))

        # AUX line
        aux_sections = {k: v for k, v in sections.items() if k.lower().startswith("line aux")}
        for section_name, lines in aux_sections.items():
            # CISCO-CON-003: AUX port not disabled
            has_no_exec = any(l.strip() == "no exec" for l in lines)
            has_transport_none = any(re.match(r"^transport input\s+none", l) for l in lines)
            if not has_no_exec and not has_transport_none:
                self._add(Finding(
                    rule_id="CISCO-CON-003", name="AUX port not disabled",
                    category="Console/AUX Security", severity="MEDIUM", file_path=ip,
                    line_num=None, line_content=f"{section_name}: no exec / transport input none = (missing)",
                    description=(
                        "The auxiliary (AUX) port is not disabled. If a modem or device is connected "
                        "to the AUX port, it could provide remote access bypassing normal security controls."
                    ),
                    recommendation="Disable with 'no exec' and 'transport input none' under line aux 0.",
                    cwe="CWE-284",
                ))

    # ----------------------------------------------------------
    # Configuration Check: Routing Protocol Security
    # ----------------------------------------------------------
    def _check_routing_protocols(self, sections: dict, ip: str):
        # CISCO-ROUTE-001: OSPF without authentication
        ospf_sections = {k: v for k, v in sections.items()
                         if k.lower().startswith("router ospf")}
        for section_name, lines in ospf_sections.items():
            has_auth = any("authentication" in l.lower() for l in lines)
            if not has_auth:
                self._add(Finding(
                    rule_id="CISCO-ROUTE-001", name="OSPF authentication not configured",
                    category="Routing Protocol Security", severity="MEDIUM", file_path=ip,
                    line_num=None, line_content=f"{section_name}: area authentication = (missing)",
                    description=(
                        "OSPF is configured without area authentication. An attacker on the "
                        "network could inject malicious routing updates to redirect traffic."
                    ),
                    recommendation="Enable 'area <id> authentication message-digest' and configure OSPF interface keys.",
                    cwe="CWE-345",
                ))

        # CISCO-ROUTE-002: EIGRP without authentication
        eigrp_sections = {k: v for k, v in sections.items()
                          if k.lower().startswith("router eigrp")}
        if eigrp_sections:
            # Check if any interface has EIGRP authentication
            intf_sections = {k: v for k, v in sections.items()
                            if k.lower().startswith("interface ")}
            has_eigrp_auth = False
            for _, intf_lines in intf_sections.items():
                if any("authentication mode" in l.lower() and "eigrp" in l.lower()
                       for l in intf_lines):
                    has_eigrp_auth = True
                    break
            if not has_eigrp_auth:
                self._add(Finding(
                    rule_id="CISCO-ROUTE-002", name="EIGRP authentication not configured",
                    category="Routing Protocol Security", severity="MEDIUM", file_path=ip,
                    line_num=None, line_content="EIGRP interface authentication = (missing)",
                    description=(
                        "EIGRP is configured without authentication on interfaces. An attacker "
                        "could inject or modify routing updates to cause traffic redirection or blackholing."
                    ),
                    recommendation="Configure EIGRP key chain authentication on all EIGRP-enabled interfaces.",
                    cwe="CWE-345",
                ))

    # ----------------------------------------------------------
    # Configuration Check: Layer 2 Security (Switches)
    # ----------------------------------------------------------
    def _check_layer2_security(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-L2-001: DHCP snooping not enabled
        if not any(re.match(r"^ip dhcp snooping\b", l) for l in gl):
            # Only flag if this looks like a switch (has switchport interfaces)
            has_switchport = any(
                any("switchport" in sl.lower() for sl in v)
                for k, v in sections.items() if k.lower().startswith("interface ")
            )
            if has_switchport:
                self._add(Finding(
                    rule_id="CISCO-L2-001", name="DHCP snooping not enabled",
                    category="Layer 2 Security", severity="MEDIUM", file_path=ip,
                    line_num=None, line_content="ip dhcp snooping = (missing)",
                    description=(
                        "DHCP snooping is not enabled. Without it, a rogue DHCP server can "
                        "assign malicious IP settings to clients, enabling man-in-the-middle attacks."
                    ),
                    recommendation="Enable 'ip dhcp snooping' globally and 'ip dhcp snooping vlan <vlan-list>'.",
                    cwe="CWE-346",
                ))

        # CISCO-L2-002: Port security not configured on access ports
        intf_sections = {k: v for k, v in sections.items()
                         if k.lower().startswith("interface ")}
        for section_name, lines in intf_sections.items():
            is_access = any(re.match(r"^switchport mode\s+access", l) for l in lines)
            is_shutdown = any(l.strip() == "shutdown" for l in lines)
            has_port_security = any("switchport port-security" in l for l in lines)
            if is_access and not is_shutdown and not has_port_security:
                self._add(Finding(
                    rule_id="CISCO-L2-002", name="Port security not configured on access port",
                    category="Layer 2 Security", severity="MEDIUM", file_path=ip,
                    line_num=None, line_content=f"{section_name}: switchport port-security = (missing)",
                    description=(
                        "An access port does not have port security configured. An attacker "
                        "could connect unauthorized devices or perform MAC flooding attacks."
                    ),
                    recommendation=f"Enable 'switchport port-security' under {section_name} with appropriate MAC limits.",
                    cwe="CWE-284",
                ))
                break  # Report once

        # CISCO-L2-003: BPDU guard not enabled
        if not any(re.match(r"^spanning-tree portfast bpduguard default\b", l) for l in gl):
            has_switchport = any(
                any("switchport" in sl.lower() for sl in v)
                for k, v in sections.items() if k.lower().startswith("interface ")
            )
            if has_switchport:
                self._add(Finding(
                    rule_id="CISCO-L2-003", name="BPDU guard not enabled globally",
                    category="Layer 2 Security", severity="MEDIUM", file_path=ip,
                    line_num=None, line_content="spanning-tree portfast bpduguard default = (missing)",
                    description=(
                        "Global BPDU guard is not enabled. Without it, an attacker can send "
                        "BPDUs on access ports to manipulate the Spanning Tree topology, "
                        "potentially causing network outages or becoming the root bridge."
                    ),
                    recommendation="Enable 'spanning-tree portfast bpduguard default' globally.",
                    cwe="CWE-284",
                ))

        # CISCO-L2-004: Root guard not on trunk interfaces
        trunk_found = False
        for section_name, lines in intf_sections.items():
            is_trunk = any(re.match(r"^switchport mode\s+trunk", l) for l in lines)
            if is_trunk:
                trunk_found = True
                has_root_guard = any("spanning-tree guard root" in l for l in lines)
                if not has_root_guard:
                    self._add(Finding(
                        rule_id="CISCO-L2-004", name="STP root guard not configured on trunk",
                        category="Layer 2 Security", severity="LOW", file_path=ip,
                        line_num=None, line_content=f"{section_name}: spanning-tree guard root = (missing)",
                        description=(
                            "A trunk port does not have STP root guard enabled. An attacker "
                            "connected to this trunk could send superior BPDUs to become the root bridge."
                        ),
                        recommendation=f"Add 'spanning-tree guard root' under {section_name}.",
                        cwe="CWE-284",
                    ))
                    break  # Report once

    # ----------------------------------------------------------
    # Configuration Check: Control Plane
    # ----------------------------------------------------------
    def _check_control_plane(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-CP-001: No control-plane policing
        cp_sections = {k: v for k, v in sections.items()
                       if k.lower().startswith("control-plane")}
        has_cpp = False
        for _, lines in cp_sections.items():
            if any("service-policy" in l for l in lines):
                has_cpp = True
                break
        if not has_cpp:
            self._add(Finding(
                rule_id="CISCO-CP-001", name="No control-plane policing configured",
                category="Control Plane", severity="MEDIUM", file_path=ip,
                line_num=None, line_content="control-plane service-policy = (missing)",
                description=(
                    "Control Plane Policing (CoPP) is not configured. Without CoPP, the device's "
                    "CPU is vulnerable to denial-of-service attacks from excessive control-plane traffic."
                ),
                recommendation="Configure a CoPP policy under 'control-plane' to rate-limit management and routing protocol traffic.",
                cwe="CWE-400",
            ))

        # CISCO-CP-002: TCP keepalives not enabled
        has_keepalive_in = any(re.match(r"^service tcp-keepalives-in\b", l) for l in gl)
        has_keepalive_out = any(re.match(r"^service tcp-keepalives-out\b", l) for l in gl)
        if not has_keepalive_in or not has_keepalive_out:
            missing = []
            if not has_keepalive_in:
                missing.append("tcp-keepalives-in")
            if not has_keepalive_out:
                missing.append("tcp-keepalives-out")
            self._add(Finding(
                rule_id="CISCO-CP-002", name="TCP keepalives not fully enabled",
                category="Control Plane", severity="LOW", file_path=ip,
                line_num=None, line_content=f"service {', '.join(missing)} = (missing)",
                description=(
                    "TCP keepalives are not fully enabled. Without keepalives, orphaned TCP "
                    "sessions (e.g., from crashed SSH clients) consume VTY lines indefinitely."
                ),
                recommendation="Enable both 'service tcp-keepalives-in' and 'service tcp-keepalives-out'.",
                cwe="CWE-400",
            ))

    # ----------------------------------------------------------
    # Configuration Check: Miscellaneous Hardening
    # ----------------------------------------------------------
    def _check_misc_hardening(self, sections: dict, ip: str):
        gl = sections.get("_global", [])

        # CISCO-MISC-001: Gratuitous ARP not disabled
        if not any(re.match(r"^no ip gratuitous-arps\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-MISC-001", name="Gratuitous ARP not disabled",
                category="Miscellaneous Hardening", severity="LOW", file_path=ip,
                line_num=None, line_content="no ip gratuitous-arps = (missing)",
                description=(
                    "Gratuitous ARP responses are not disabled. These can be exploited "
                    "for ARP cache poisoning attacks to intercept network traffic."
                ),
                recommendation="Disable with 'no ip gratuitous-arps'.",
                cwe="CWE-345",
            ))

        # CISCO-MISC-002: Service timestamps for debug not configured
        if not any(re.match(r"^service timestamps debug datetime", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-MISC-002", name="Service timestamps for debug not configured",
                category="Miscellaneous Hardening", severity="LOW", file_path=ip,
                line_num=None, line_content="service timestamps debug datetime = (missing)",
                description=(
                    "Debug messages do not include date-time timestamps. Without timestamps, "
                    "correlating debug output with events becomes difficult during troubleshooting."
                ),
                recommendation="Configure 'service timestamps debug datetime msec localtime show-timezone'.",
                cwe="CWE-778",
            ))

        # CISCO-MISC-003: IP options processing not disabled
        if not any(re.match(r"^no ip options\b", l) for l in gl):
            self._add(Finding(
                rule_id="CISCO-MISC-003", name="IP options processing not disabled",
                category="Miscellaneous Hardening", severity="LOW", file_path=ip,
                line_num=None, line_content="no ip options = (missing)",
                description=(
                    "IP options processing is not disabled. Certain IP options (record-route, "
                    "source-route, timestamp) can be used for network reconnaissance."
                ),
                recommendation="Disable with 'no ip options drop' (IOS-XE) or apply ACLs to filter IP options.",
                cwe="CWE-200",
            ))

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _add(self, finding: Finding):
        self.findings.append(finding)

    def _vprint(self, msg: str):
        if self.verbose:
            print(msg)

    def _warn(self, msg: str):
        print(f"  [!] {msg}", file=sys.stderr)

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    def summary(self) -> dict:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str):
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'='*72}{R}")
        print(f"{B}  Cisco IOS Security Scanner v{VERSION}  --  Scan Report{R}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Target    : {self.ip_range}")
        print(f"  Devices   : {len(self.devices)} scanned, {len(self._failed_hosts)} failed")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

        if self.devices:
            print(f"{B}  Discovered Devices:{R}")
            for d in self.devices:
                print(f"    {d['ip']:<16} {d.get('model','?'):<20} "
                      f"{d.get('platform','?'):<8} {d.get('ios_version_raw','?')}")
            print()

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        for f in sorted_findings:
            sev_color = self.SEVERITY_COLOR.get(f.severity, "")
            print(f"{sev_color}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Device   : {f.file_path}")
            print(f"  Context  : {f.line_content}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            if f.cve:
                print(f"  CVE      : {f.cve}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 72)
        for sev, order in sorted(self.SEVERITY_ORDER.items(), key=lambda x: x[1]):
            color = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 72)

    def save_json(self, path: str):
        report = {
            "scanner": "cisco_scanner",
            "version": VERSION,
            "generated": datetime.now().isoformat(),
            "target_range": self.ip_range,
            "devices_scanned": len(self.devices),
            "devices_failed": len(self._failed_hosts),
            "findings_count": len(self.findings),
            "devices": [
                {
                    "ip": d["ip"],
                    "model": d.get("model", ""),
                    "hostname": d.get("hostname", ""),
                    "ios_version": d.get("ios_version_raw", ""),
                    "platform": d.get("platform", ""),
                    "serial": d.get("serial", ""),
                    "uptime": d.get("uptime", ""),
                }
                for d in self.devices
            ],
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report saved to: {os.path.abspath(path)}")

    def save_html(self, path: str):
        esc = html_mod.escape
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = self.summary()

        sev_style = {
            "CRITICAL": "background:#c0392b;color:#fff",
            "HIGH":     "background:#e67e22;color:#fff",
            "MEDIUM":   "background:#2980b9;color:#fff",
            "LOW":      "background:#27ae60;color:#fff",
        }
        row_style = {
            "CRITICAL": "border-left:4px solid #c0392b",
            "HIGH":     "border-left:4px solid #e67e22",
            "MEDIUM":   "border-left:4px solid #2980b9",
            "LOW":      "border-left:4px solid #27ae60",
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        # Severity chips
        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        # Device inventory rows
        device_rows = ""
        for d in self.devices:
            device_rows += (
                f'<tr style="background:#1e1e2e">'
                f'<td style="padding:8px 14px;font-family:monospace">{esc(d.get("ip",""))}</td>'
                f'<td style="padding:8px 14px">{esc(d.get("hostname",""))}</td>'
                f'<td style="padding:8px 14px">{esc(d.get("model",""))}</td>'
                f'<td style="padding:8px 14px">{esc(d.get("platform",""))}</td>'
                f'<td style="padding:8px 14px;font-family:monospace">{esc(d.get("ios_version_raw",""))}</td>'
                f'</tr>'
            )

        # Finding rows
        rows_html = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rs = row_style.get(f.severity, "")
            st = sev_style.get(f.severity, "")
            rows_html += (
                f'<tr style="background:{bg};{rs}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px">'
                f'<span style="{st};padding:3px 10px;border-radius:10px;font-size:0.8em;font-weight:bold">'
                f'{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.9em">'
                f'{esc(f.rule_id)}</td>'
                f'<td style="padding:10px 14px;color:#a9b1d6">{esc(f.category)}</td>'
                f'<td style="padding:10px 14px;font-weight:bold;color:#cdd6f4">{esc(f.name)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.85em;color:#89b4fa">'
                f'{esc(f.file_path)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.82em;color:#a6e3a1">'
                f'{esc(f.line_content or "")}</td>'
                f'<td style="padding:10px 14px;color:#cdd6f4">{esc(f.cwe)}</td>'
                f'</tr>'
                f'<tr style="background:{bg}" data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td colspan="7" style="padding:6px 14px 14px 14px">'
                f'<div style="color:#bac2de;font-size:0.88em;margin-bottom:4px">'
                f'<b>Issue:</b> {esc(f.description)}</div>'
                f'<div style="color:#89dceb;font-size:0.88em">'
                f'<b>Fix:</b> {esc(f.recommendation)}</div>'
                f'</td></tr>'
            )

        categories_options = "".join(
            f'<option value="{esc(c)}">{esc(c)}</option>'
            for c in sorted({f.category for f in self.findings})
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cisco IOS Security Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1b2e; color: #cdd6f4; min-height: 100vh; }}
  header {{ background: linear-gradient(135deg, #049fd9 0%, #1a1b2e 100%); padding: 28px 36px; border-bottom: 2px solid #313244; }}
  header h1 {{ font-size: 1.7em; font-weight: 700; color: #fff; margin-bottom: 8px; }}
  header p {{ color: #c0d0e0; font-size: 0.95em; margin: 2px 0; }}
  .chips {{ padding: 20px 36px; background: #181825; border-bottom: 1px solid #313244; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .chips label {{ color: #a6adc8; font-size: 0.9em; margin-right: 6px; }}
  .filters {{ padding: 16px 36px; background: #1e1e2e; display: flex; gap: 12px; flex-wrap: wrap; border-bottom: 1px solid #313244; }}
  .filters select, .filters input {{ background: #313244; color: #cdd6f4; border: 1px solid #45475a; border-radius: 6px; padding: 6px 12px; font-size: 0.9em; }}
  .container {{ padding: 20px 36px 40px; }}
  .section-title {{ font-size: 1.2em; font-weight: 600; color: #89b4fa; margin: 20px 0 10px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  th {{ background: #313244; color: #89b4fa; padding: 12px 14px; text-align: left; font-weight: 600; position: sticky; top: 0; }}
  tr:hover td {{ filter: brightness(1.12); }}
  td {{ vertical-align: top; }}
  .no-findings {{ text-align: center; padding: 60px; color: #a6e3a1; font-size: 1.2em; }}
</style>
</head>
<body>
<header>
  <h1>Cisco IOS Security Scan Report</h1>
  <p>Scanner: Cisco IOS Security Scanner v{esc(VERSION)}</p>
  <p>Target: {esc(self.ip_range)}</p>
  <p>Generated: {esc(now)}</p>
  <p>Devices Scanned: <strong>{len(self.devices)}</strong> &nbsp;|&nbsp; Findings: <strong>{len(self.findings)}</strong></p>
</header>
<div class="chips">
  <label>Severity:</label>
  {chip_html}
</div>
<div class="filters">
  <select id="sevFilter" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option value="CRITICAL">CRITICAL</option>
    <option value="HIGH">HIGH</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="LOW">LOW</option>
  </select>
  <select id="catFilter" onchange="applyFilters()">
    <option value="">All Categories</option>
    {categories_options}
  </select>
  <input type="text" id="textFilter" placeholder="Search name / ID ..." oninput="applyFilters()" style="flex:1;min-width:200px">
</div>
<div class="container">
{'<div class="section-title">Device Inventory</div><table><thead><tr><th>IP Address</th><th>Hostname</th><th>Model</th><th>Platform</th><th>IOS Version</th></tr></thead><tbody>' + device_rows + '</tbody></table>' if self.devices else ''}
<div class="section-title">Findings</div>
{f'<div class="no-findings">No findings — all devices are clean!</div>' if not self.findings else f"""
<table id="findings-table">
<thead><tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th><th>Name</th>
  <th>Device</th><th>Context</th><th>CWE</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>"""}
</div>
<script>
function applyFilters() {{
  var sev = document.getElementById('sevFilter').value.toUpperCase();
  var cat = document.getElementById('catFilter').value.toLowerCase();
  var txt = document.getElementById('textFilter').value.toLowerCase();
  var rows = document.querySelectorAll('#findings-table tbody tr');
  rows.forEach(function(row) {{
    var rs = (row.getAttribute('data-severity') || '').toUpperCase();
    var rc = (row.getAttribute('data-category') || '').toLowerCase();
    var rt = row.textContent.toLowerCase();
    var show = (!sev || rs === sev) && (!cat || rc.includes(cat)) && (!txt || rt.includes(txt));
    row.style.display = show ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] HTML report saved to: {os.path.abspath(path)}")


# ============================================================
# CLI entry point
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        prog="cisco_scanner",
        description=(
            f"Cisco IOS Security Scanner v{VERSION} — "
            "Network security scanner for Cisco IOS routers and switches"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python cisco_scanner.py -r 192.168.1.0/24 -u admin -p secret\n"
            "  python cisco_scanner.py -r 10.0.0.1-10.0.0.50 -u admin -p secret --enable-password en123\n"
            "  python cisco_scanner.py -r 192.168.1.1 --protocol snmp --snmp-community mycomm\n"
            "  python cisco_scanner.py -r 192.168.1.0/24 -u admin -p secret --json out.json --html out.html\n"
            "\n"
            "Env var fallback:\n"
            "  CISCO_RANGE  CISCO_USERNAME  CISCO_PASSWORD  CISCO_ENABLE  CISCO_SNMP_COMMUNITY"
        ),
    )
    parser.add_argument(
        "--range", "-r",
        default=os.environ.get("CISCO_RANGE", ""),
        metavar="RANGE",
        help=(
            "IP range to scan. Supports CIDR (192.168.1.0/24), "
            "start-end (192.168.1.1-254), single IP, or comma-separated. "
            "Env: CISCO_RANGE"
        ),
    )
    parser.add_argument(
        "--username", "-u",
        default=os.environ.get("CISCO_USERNAME", ""),
        metavar="USERNAME",
        help="SSH username for device login. Env: CISCO_USERNAME",
    )
    parser.add_argument(
        "--password", "-p",
        default=os.environ.get("CISCO_PASSWORD", ""),
        metavar="PASSWORD",
        help="SSH password for device login. Env: CISCO_PASSWORD",
    )
    parser.add_argument(
        "--enable-password",
        default=os.environ.get("CISCO_ENABLE", ""),
        metavar="PASSWORD",
        help="Enable/privilege 15 password. Env: CISCO_ENABLE",
    )
    parser.add_argument(
        "--snmp-community",
        default=os.environ.get("CISCO_SNMP_COMMUNITY", ""),
        metavar="STRING",
        help="SNMP v2c community string. Env: CISCO_SNMP_COMMUNITY",
    )
    parser.add_argument(
        "--protocol",
        default="ssh",
        choices=["ssh", "snmp", "both"],
        help="Protocol to use: ssh, snmp, or both (default: ssh)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        metavar="PORT",
        help="SSH port (default: 22)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=256,
        metavar="N",
        help="Maximum number of hosts to scan from range (default: 256)",
    )
    parser.add_argument(
        "--severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save findings as JSON to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save findings as a self-contained HTML report to FILE",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (connection details, skipped hosts, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"cisco_scanner v{VERSION}",
    )

    args = parser.parse_args()

    # Dependency checks (after parse_args so --version/--help work without deps)
    if args.protocol in ("ssh", "both") and not HAS_NETMIKO:
        parser.error(
            "The 'netmiko' library is required for SSH scanning.\n"
            "  Install with:  pip install netmiko"
        )
    if args.protocol in ("snmp", "both") and not HAS_PYSNMP:
        parser.error(
            "The 'pysnmp' library is required for SNMP scanning.\n"
            "  Install with:  pip install pysnmp-lextudio"
        )

    # Validate required arguments
    if not args.range:
        parser.error("--range is required (or set CISCO_RANGE env var)")

    missing = []
    if args.protocol in ("ssh", "both"):
        if not args.username:
            missing.append("--username (or CISCO_USERNAME env var)")
        if not args.password:
            missing.append("--password (or CISCO_PASSWORD env var)")
    if args.protocol in ("snmp", "both"):
        if not args.snmp_community:
            missing.append("--snmp-community (or CISCO_SNMP_COMMUNITY env var)")
    if missing:
        parser.error("Missing required arguments:\n  " + "\n  ".join(missing))

    scanner = CiscoScanner(
        ip_range=args.range,
        username=args.username,
        password=args.password,
        enable_password=args.enable_password,
        snmp_community=args.snmp_community,
        protocol=args.protocol,
        port=args.port,
        timeout=args.timeout,
        max_hosts=args.max_hosts,
        verbose=args.verbose,
    )

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    # Exit code: 1 if any CRITICAL or HIGH findings remain
    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()
