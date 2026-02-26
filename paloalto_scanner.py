#!/usr/bin/env python3
"""
Palo Alto NGFW Security Scanner v1.0.0
Security scanner for Palo Alto Networks Next-Generation Firewalls.

Connects to the PAN-OS XML API to:
  - Identify PAN-OS version and check for known CVEs
  - Audit security policy rules for risky patterns
  - Verify security profile attachment on allow rules
  - Check threat prevention profile quality
  - Audit management interface, zone protection, NAT, decryption,
    dynamic updates, HA, GlobalProtect, and certificate configuration

Authentication: Username/password or pre-generated API key
  - PAN-OS XML API at https://<firewall>/api/

Usage:
  python paloalto_scanner.py -H 192.168.1.1 -u admin -p secret
  python paloalto_scanner.py -H 10.0.0.1 -k <api-key> --json out.json --html out.html
  python paloalto_scanner.py -H fw.corp.com -u admin -p secret --panorama --severity HIGH

Env var fallback:  PAN_HOST  PAN_USERNAME  PAN_PASSWORD  PAN_API_KEY
"""

import os
import re
import sys
import json
import html as html_mod
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "1.0.0"

# ============================================================
# PAN-OS CVE DATABASE
# Each CVE has a list of affected_branches: [{train, fixed}]
# If device version matches train and is < fixed → vulnerable.
# ============================================================
PANOS_CVE_DATABASE = [
    {
        "id": "PAN-CVE-001",
        "cve": "CVE-2024-3400",
        "severity": "CRITICAL",
        "name": "GlobalProtect command injection — actively exploited (CVSS 10.0)",
        "affected_branches": [
            {"train": "10.2", "fixed": "10.2.10"},
            {"train": "11.0", "fixed": "11.0.5"},
            {"train": "11.1", "fixed": "11.1.3"},
        ],
        "description": (
            "A command injection vulnerability in the GlobalProtect feature of PAN-OS "
            "allows an unauthenticated attacker to execute arbitrary code with root privileges. "
            "Actively exploited in the wild since March 2024."
        ),
        "recommendation": "Upgrade immediately. Apply hotfix. Disable GlobalProtect telemetry as interim mitigation.",
        "cwe": "CWE-78",
    },
    {
        "id": "PAN-CVE-002",
        "cve": "CVE-2024-0012",
        "severity": "CRITICAL",
        "name": "Management interface authentication bypass",
        "affected_branches": [
            {"train": "10.2", "fixed": "10.2.12"},
            {"train": "11.0", "fixed": "11.0.6"},
            {"train": "11.1", "fixed": "11.1.5"},
            {"train": "11.2", "fixed": "11.2.4"},
        ],
        "description": (
            "An authentication bypass in the PAN-OS management web interface allows an "
            "unauthenticated attacker with network access to the management interface to "
            "gain administrator privileges."
        ),
        "recommendation": "Upgrade to fixed version. Restrict management interface access to trusted IPs only.",
        "cwe": "CWE-287",
    },
    {
        "id": "PAN-CVE-003",
        "cve": "CVE-2024-9474",
        "severity": "CRITICAL",
        "name": "Management interface privilege escalation to root",
        "affected_branches": [
            {"train": "10.2", "fixed": "10.2.12"},
            {"train": "11.0", "fixed": "11.0.6"},
            {"train": "11.1", "fixed": "11.1.5"},
            {"train": "11.2", "fixed": "11.2.4"},
        ],
        "description": (
            "A privilege escalation vulnerability in PAN-OS allows an authenticated admin "
            "to perform actions on the firewall with root privileges. Chained with "
            "CVE-2024-0012 for unauthenticated RCE."
        ),
        "recommendation": "Upgrade to fixed version. Restrict management access. Monitor for exploitation indicators.",
        "cwe": "CWE-269",
    },
    {
        "id": "PAN-CVE-004",
        "cve": "CVE-2020-2021",
        "severity": "CRITICAL",
        "name": "SAML authentication bypass when certificate validation disabled (CVSS 10.0)",
        "affected_branches": [
            {"train": "8.1", "fixed": "8.1.15"},
            {"train": "9.0", "fixed": "9.0.9"},
            {"train": "9.1", "fixed": "9.1.3"},
        ],
        "description": (
            "When SAML authentication is enabled and the 'Validate Identity Provider Certificate' "
            "option is disabled, an unauthenticated attacker can bypass authentication and access "
            "protected resources, including the management interface."
        ),
        "recommendation": "Upgrade PAN-OS. Enable 'Validate Identity Provider Certificate' in SAML configuration.",
        "cwe": "CWE-347",
    },
    {
        "id": "PAN-CVE-005",
        "cve": "CVE-2021-3064",
        "severity": "CRITICAL",
        "name": "GlobalProtect portal/gateway buffer overflow (CVSS 9.8)",
        "affected_branches": [
            {"train": "8.1", "fixed": "8.1.17"},
        ],
        "description": (
            "A memory corruption vulnerability in the GlobalProtect portal and gateway "
            "interfaces allows an unauthenticated network-based attacker to disrupt system "
            "processes and potentially execute arbitrary code with root privileges."
        ),
        "recommendation": "Upgrade to PAN-OS 8.1.17 or later. Enable threat prevention signatures.",
        "cwe": "CWE-119",
    },
    {
        "id": "PAN-CVE-006",
        "cve": "CVE-2024-5910",
        "severity": "CRITICAL",
        "name": "Expedition migration tool — missing authentication (CVSS 9.3)",
        "affected_branches": [],
        "description": (
            "Missing authentication for a critical function in Palo Alto Networks Expedition "
            "allows an attacker with network access to Expedition to take over an admin account. "
            "Expedition stores firewall configs with credentials."
        ),
        "recommendation": "Upgrade Expedition to 1.2.92 or later. Restrict network access to Expedition server.",
        "cwe": "CWE-306",
    },
    {
        "id": "PAN-CVE-007",
        "cve": "CVE-2024-9463",
        "severity": "CRITICAL",
        "name": "Expedition OS command injection (CVSS 9.9)",
        "affected_branches": [],
        "description": (
            "An OS command injection vulnerability in Palo Alto Networks Expedition allows "
            "an unauthenticated attacker to run arbitrary OS commands as root, leading to "
            "disclosure of firewall usernames, cleartext passwords, and API keys."
        ),
        "recommendation": "Upgrade Expedition to 1.2.96 or later. Rotate all firewall credentials stored in Expedition.",
        "cwe": "CWE-78",
    },
    {
        "id": "PAN-CVE-008",
        "cve": "CVE-2024-9465",
        "severity": "CRITICAL",
        "name": "Expedition SQL injection (CVSS 9.2)",
        "affected_branches": [],
        "description": (
            "An SQL injection vulnerability in Palo Alto Networks Expedition allows an "
            "unauthenticated attacker to reveal Expedition database contents including "
            "password hashes, usernames, device configurations, and API keys."
        ),
        "recommendation": "Upgrade Expedition to 1.2.96 or later. Rotate all credentials.",
        "cwe": "CWE-89",
    },
    {
        "id": "PAN-CVE-009",
        "cve": "CVE-2017-15944",
        "severity": "CRITICAL",
        "name": "Management interface pre-auth RCE chain",
        "affected_branches": [
            {"train": "6.1", "fixed": "6.1.19"},
            {"train": "7.0", "fixed": "7.0.19"},
            {"train": "7.1", "fixed": "7.1.14"},
            {"train": "8.0", "fixed": "8.0.7"},
        ],
        "description": (
            "A chain of vulnerabilities (directory traversal + command injection) in the "
            "PAN-OS management web interface allows an unauthenticated attacker to execute "
            "arbitrary code with root privileges."
        ),
        "recommendation": "Upgrade PAN-OS to a supported version. This affects very old PAN-OS versions.",
        "cwe": "CWE-78",
    },
    {
        "id": "PAN-CVE-010",
        "cve": "CVE-2019-1579",
        "severity": "CRITICAL",
        "name": "GlobalProtect pre-auth remote code execution",
        "affected_branches": [
            {"train": "7.1", "fixed": "7.1.19"},
            {"train": "8.0", "fixed": "8.0.12"},
            {"train": "8.1", "fixed": "8.1.3"},
        ],
        "description": (
            "A format string vulnerability in the PAN-OS GlobalProtect portal and gateway "
            "allows an unauthenticated remote attacker to execute arbitrary code."
        ),
        "recommendation": "Upgrade PAN-OS. These are end-of-life versions that should be replaced.",
        "cwe": "CWE-134",
    },
    {
        "id": "PAN-CVE-011",
        "cve": "CVE-2022-0028",
        "severity": "HIGH",
        "name": "URL filtering reflected amplification denial of service",
        "affected_branches": [
            {"train": "8.1", "fixed": "8.1.23"},
            {"train": "9.0", "fixed": "9.0.17"},
            {"train": "9.1", "fixed": "9.1.16"},
            {"train": "10.0", "fixed": "10.0.13"},
            {"train": "10.1", "fixed": "10.1.9"},
            {"train": "10.2", "fixed": "10.2.4"},
        ],
        "description": (
            "A PAN-OS URL filtering policy misconfiguration could allow a network-based attacker "
            "to conduct reflected and amplified TCP denial-of-service attacks."
        ),
        "recommendation": "Upgrade PAN-OS. Ensure URL filtering is correctly configured.",
        "cwe": "CWE-406",
    },
    {
        "id": "PAN-CVE-012",
        "cve": "CVE-2020-2034",
        "severity": "HIGH",
        "name": "GlobalProtect OS command injection (authenticated)",
        "affected_branches": [
            {"train": "8.1", "fixed": "8.1.15"},
            {"train": "9.0", "fixed": "9.0.9"},
            {"train": "9.1", "fixed": "9.1.3"},
        ],
        "description": (
            "An OS command injection vulnerability in the GlobalProtect portal of PAN-OS "
            "allows an authenticated attacker to execute arbitrary OS commands with root privileges."
        ),
        "recommendation": "Upgrade PAN-OS to a fixed version.",
        "cwe": "CWE-78",
    },
    {
        "id": "PAN-CVE-013",
        "cve": "CVE-2021-3060",
        "severity": "HIGH",
        "name": "OS command injection via web interface",
        "affected_branches": [
            {"train": "8.1", "fixed": "8.1.20"},
            {"train": "9.0", "fixed": "9.0.14"},
            {"train": "9.1", "fixed": "9.1.11"},
            {"train": "10.0", "fixed": "10.0.8"},
            {"train": "10.1", "fixed": "10.1.3"},
        ],
        "description": (
            "An OS command injection vulnerability in PAN-OS web interface allows an "
            "authenticated administrator to execute arbitrary OS commands with root privileges."
        ),
        "recommendation": "Upgrade PAN-OS. Restrict management access.",
        "cwe": "CWE-78",
    },
    {
        "id": "PAN-CVE-014",
        "cve": "CVE-2024-0008",
        "severity": "HIGH",
        "name": "Web management session fixation",
        "affected_branches": [
            {"train": "10.1", "fixed": "10.1.12"},
            {"train": "10.2", "fixed": "10.2.10"},
            {"train": "11.0", "fixed": "11.0.5"},
            {"train": "11.1", "fixed": "11.1.4"},
        ],
        "description": (
            "A session fixation vulnerability in the web management interface allows an "
            "attacker to fixate the session of an administrator, potentially gaining "
            "unauthorized access."
        ),
        "recommendation": "Upgrade PAN-OS. Use certificate-based admin authentication.",
        "cwe": "CWE-384",
    },
    {
        "id": "PAN-CVE-015",
        "cve": "CVE-2022-0030",
        "severity": "HIGH",
        "name": "Authentication bypass in web management interface",
        "affected_branches": [
            {"train": "8.1", "fixed": "8.1.24"},
            {"train": "9.0", "fixed": "9.0.17"},
            {"train": "9.1", "fixed": "9.1.15"},
            {"train": "10.0", "fixed": "10.0.12"},
        ],
        "description": (
            "An authentication bypass vulnerability in the PAN-OS web interface allows "
            "a network-based attacker with specific knowledge of the target firewall to "
            "impersonate an existing administrator and perform privileged actions."
        ),
        "recommendation": "Upgrade PAN-OS. Use multi-factor authentication for admin access.",
        "cwe": "CWE-290",
    },
    {
        "id": "PAN-CVE-016",
        "cve": "CVE-2024-3383",
        "severity": "HIGH",
        "name": "Cloud Identity Engine authentication bypass",
        "affected_branches": [
            {"train": "10.1", "fixed": "10.1.12"},
            {"train": "10.2", "fixed": "10.2.8"},
            {"train": "11.0", "fixed": "11.0.4"},
            {"train": "11.1", "fixed": "11.1.2"},
        ],
        "description": (
            "A vulnerability in the Cloud Identity Engine (CIE) component of PAN-OS allows "
            "an attacker to bypass authentication for users configured via CIE, potentially "
            "gaining unauthorized network access."
        ),
        "recommendation": "Upgrade PAN-OS. Review CIE authentication logs for unauthorized access.",
        "cwe": "CWE-282",
    },
    {
        "id": "PAN-CVE-017",
        "cve": "CVE-2020-1975",
        "severity": "HIGH",
        "name": "Management interface XSS/RCE chain",
        "affected_branches": [
            {"train": "8.1", "fixed": "8.1.13"},
            {"train": "9.0", "fixed": "9.0.7"},
        ],
        "description": (
            "A combination of XSS and code execution vulnerabilities in the PAN-OS "
            "management interface could allow an attacker to execute arbitrary code."
        ),
        "recommendation": "Upgrade PAN-OS. Restrict management access to trusted networks.",
        "cwe": "CWE-79",
    },
    {
        "id": "PAN-CVE-018",
        "cve": "CVE-2023-6790",
        "severity": "MEDIUM",
        "name": "Web management interface cross-site scripting (XSS)",
        "affected_branches": [
            {"train": "9.0", "fixed": "9.0.17"},
            {"train": "9.1", "fixed": "9.1.17"},
            {"train": "10.1", "fixed": "10.1.12"},
            {"train": "10.2", "fixed": "10.2.9"},
            {"train": "11.0", "fixed": "11.0.4"},
        ],
        "description": (
            "A DOM-based cross-site scripting vulnerability in the PAN-OS web management "
            "interface allows a remote attacker to execute JavaScript in the context of "
            "an administrator's browser session."
        ),
        "recommendation": "Upgrade PAN-OS to a fixed version.",
        "cwe": "CWE-79",
    },
    {
        "id": "PAN-CVE-019",
        "cve": "CVE-2023-0007",
        "severity": "MEDIUM",
        "name": "Management interface stored cross-site scripting",
        "affected_branches": [
            {"train": "9.0", "fixed": "9.0.17"},
            {"train": "9.1", "fixed": "9.1.16"},
            {"train": "10.1", "fixed": "10.1.9"},
            {"train": "10.2", "fixed": "10.2.4"},
        ],
        "description": (
            "A stored cross-site scripting vulnerability in the PAN-OS management web "
            "interface enables an authenticated administrator to store a JavaScript payload "
            "that activates for other administrators."
        ),
        "recommendation": "Upgrade PAN-OS. Review admin access logs.",
        "cwe": "CWE-79",
    },
    {
        "id": "PAN-CVE-020",
        "cve": "CVE-2023-38046",
        "severity": "MEDIUM",
        "name": "Read system files vulnerability",
        "affected_branches": [
            {"train": "9.1", "fixed": "9.1.17"},
            {"train": "10.1", "fixed": "10.1.12"},
            {"train": "10.2", "fixed": "10.2.8"},
            {"train": "11.0", "fixed": "11.0.4"},
            {"train": "11.1", "fixed": "11.1.2"},
        ],
        "description": (
            "A vulnerability in PAN-OS allows an authenticated administrator with access "
            "to the web management interface to read arbitrary system files."
        ),
        "recommendation": "Upgrade PAN-OS. Restrict admin access to least privilege.",
        "cwe": "CWE-41",
    },
]

# High-risk applications that should be flagged when allowed
HIGH_RISK_TUNNEL_APPS = {
    "tor", "ultrasurf", "psiphon", "hotspot-shield", "hola-unblocker",
    "tunnelbear", "lantern", "freegate", "your-freedom", "opera-vpn",
}
HIGH_RISK_REMOTE_APPS = {
    "teamviewer", "anydesk", "vnc", "logmein", "splashtop",
    "screenconnect", "bomgar", "ammyy-admin", "ultraviewer",
}
HIGH_RISK_P2P_APPS = {
    "bittorrent", "emule", "gnutella", "kazaa", "ares",
    "limewire", "soulseek", "frostwire",
}
HIGH_RISK_TUNNEL_SSH_APPS = {
    "ssh-tunnel", "ssl-vpn", "socks-proxy", "http-tunnel",
}
HIGH_RISK_DOH_APPS = {
    "dns-over-https", "dns-over-tls",
}

# URL filtering categories that must be blocked
MUST_BLOCK_URL_CATEGORIES = {
    "malware", "phishing", "command-and-control", "grayware",
    "ransomware", "newly-registered-domain",
}


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
        self.file_path = file_path       # repurposed: rule name or config section
        self.line_num = line_num         # always None for API checks
        self.line_content = line_content # repurposed: setting = value
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
# Palo Alto NGFW Security Scanner
# ============================================================
class PaloAltoScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def __init__(self, host: str, username: str = "", password: str = "",
                 api_key: str = "", panorama: bool = False,
                 verify_ssl: bool = False, verbose: bool = False):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.api_key = api_key
        self.panorama = panorama
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.findings: list = []
        self.device_info: dict = {}
        self._config_root = None
        self._base_url = f"https://{self.host}/api/"

    # ----------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------
    def scan(self):
        print(f"[*] Palo Alto NGFW Security Scanner v{VERSION}")
        print(f"[*] Target: {self.host}")

        # Authenticate
        if not self.api_key:
            print("[*] Authenticating ...")
            self._authenticate()
        else:
            self._vprint("[*] Using provided API key")

        # Get system info
        print("[*] Retrieving system information ...")
        self._get_system_info()
        if self.device_info:
            model = self.device_info.get("model", "Unknown")
            version = self.device_info.get("sw-version", "Unknown")
            hostname = self.device_info.get("hostname", "Unknown")
            serial = self.device_info.get("serial", "Unknown")
            print(f"  [+] {hostname} — {model} — PAN-OS {version} (S/N: {serial})")

        # Retrieve running config
        print("[*] Retrieving running configuration ...")
        self._get_config()
        if self._config_root is None:
            print("[!] Failed to retrieve configuration. Aborting.", file=sys.stderr)
            return

        # Run all checks
        print("[*] Running security checks ...")
        self._check_cves()
        self._check_security_rules()
        self._check_dangerous_apps()
        self._check_rule_logging()
        self._check_security_profiles()
        self._check_threat_prevention()
        self._check_zone_protection()
        self._check_management()
        self._check_nat_policy()
        self._check_decryption()
        self._check_dynamic_updates()
        self._check_ha()
        self._check_globalprotect()
        self._check_certificates()
        self._check_network_config()

        print(f"\n[*] Scan complete. {len(self.findings)} finding(s).")

    # ----------------------------------------------------------
    # PAN-OS XML API Helpers
    # ----------------------------------------------------------
    def _api_request(self, params: dict) -> ET.Element:
        """Make an API request and return the parsed XML root element."""
        params["key"] = self.api_key
        try:
            resp = requests.get(
                self._base_url, params=params,
                verify=self.verify_ssl, timeout=30,
            )
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
            status = root.get("status", "")
            if status != "success":
                msg_el = root.find(".//msg/line")
                msg = msg_el.text if msg_el is not None else root.find(".//msg")
                if msg is not None and hasattr(msg, "text"):
                    msg = msg.text
                self._vprint(f"  [api] Status={status}, msg={msg}")
            return root
        except requests.exceptions.RequestException as e:
            self._warn(f"API request failed: {e}")
            return None
        except ET.ParseError as e:
            self._warn(f"Failed to parse API response: {e}")
            return None

    def _api_config_get(self, xpath: str) -> ET.Element:
        """Retrieve a configuration subtree."""
        self._vprint(f"  [api] config get: {xpath}")
        return self._api_request({
            "type": "config",
            "action": "get",
            "xpath": xpath,
        })

    def _api_op_cmd(self, cmd: str) -> ET.Element:
        """Execute an operational command."""
        self._vprint(f"  [api] op cmd: {cmd[:80]}...")
        return self._api_request({
            "type": "op",
            "cmd": cmd,
        })

    # ----------------------------------------------------------
    # Authentication
    # ----------------------------------------------------------
    def _authenticate(self):
        """Obtain an API key using username/password."""
        try:
            resp = requests.get(
                self._base_url,
                params={
                    "type": "keygen",
                    "user": self.username,
                    "password": self.password,
                },
                verify=self.verify_ssl, timeout=30,
            )
            root = ET.fromstring(resp.text)
            status = root.get("status", "")
            if status != "success":
                msg_el = root.find(".//msg")
                msg = msg_el.text if msg_el is not None else "Unknown error"
                raise RuntimeError(f"Authentication failed: {msg}")
            key_el = root.find(".//key")
            if key_el is None or not key_el.text:
                raise RuntimeError("No API key returned")
            self.api_key = key_el.text.strip()
            self._vprint("[*] API key obtained successfully")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Cannot connect to {self.host}: {e}")

    # ----------------------------------------------------------
    # System Info
    # ----------------------------------------------------------
    def _get_system_info(self):
        """Retrieve PAN-OS version, model, serial, hostname."""
        root = self._api_op_cmd("<show><system><info></info></system></show>")
        if root is None:
            return
        info = root.find(".//system")
        if info is None:
            return
        self.device_info = {}
        for child in info:
            self.device_info[child.tag] = (child.text or "").strip()

    # ----------------------------------------------------------
    # Full Config Retrieval
    # ----------------------------------------------------------
    def _get_config(self):
        """Retrieve the full running configuration."""
        root = self._api_config_get("/config")
        if root is None:
            return
        result = root.find(".//result")
        self._config_root = result if result is not None else root

    # ----------------------------------------------------------
    # XML Config Helpers
    # ----------------------------------------------------------
    def _find_all(self, xpath: str) -> list:
        """Find all elements matching xpath in the config."""
        if self._config_root is None:
            return []
        try:
            return self._config_root.findall(xpath)
        except Exception:
            return []

    def _find(self, xpath: str):
        """Find first element matching xpath in the config."""
        if self._config_root is None:
            return None
        try:
            return self._config_root.find(xpath)
        except Exception:
            return None

    def _find_text(self, xpath: str, default: str = "") -> str:
        """Find text of first element matching xpath."""
        el = self._find(xpath)
        return (el.text or "").strip() if el is not None else default

    def _get_entry_name(self, entry) -> str:
        """Get the @name attribute of an XML entry element."""
        return entry.get("name", "(unnamed)")

    def _get_member_list(self, parent, tag: str) -> list:
        """Get list of <member> text values under parent/tag."""
        if parent is None:
            return []
        container = parent.find(tag)
        if container is None:
            return []
        return [m.text.strip() for m in container.findall("member") if m.text]

    def _get_security_rules(self) -> list:
        """Get all security rules from all vsys."""
        rules = []
        # Device vsys rules
        for entry in self._find_all(".//vsys/entry"):
            vsys_name = self._get_entry_name(entry)
            rulebase = entry.find("rulebase/security/rules")
            if rulebase is not None:
                for rule in rulebase.findall("entry"):
                    rules.append((vsys_name, rule))
        # Also check pre/post rulebase for Panorama
        if self.panorama:
            for rulebase_path in [
                ".//pre-rulebase/security/rules",
                ".//post-rulebase/security/rules",
            ]:
                rulebase = self._find(rulebase_path)
                if rulebase is not None:
                    for rule in rulebase.findall("entry"):
                        rules.append(("shared", rule))
        return rules

    def _get_nat_rules(self) -> list:
        """Get all NAT rules from all vsys."""
        rules = []
        for entry in self._find_all(".//vsys/entry"):
            vsys_name = self._get_entry_name(entry)
            rulebase = entry.find("rulebase/nat/rules")
            if rulebase is not None:
                for rule in rulebase.findall("entry"):
                    rules.append((vsys_name, rule))
        return rules

    # ----------------------------------------------------------
    # Version Comparison Utilities
    # ----------------------------------------------------------
    @staticmethod
    def _parse_ver(s):
        """Parse a version string into a comparable tuple of ints."""
        s = re.sub(r"[-]?(h\d+|c\d+|xfr|b\d+).*$", "", s, flags=re.IGNORECASE)
        parts = re.split(r"[.\-]", s)
        try:
            return tuple(int(p) for p in parts if p.isdigit())
        except ValueError:
            return None

    def _version_in_range(self, version, range_str):
        """Evaluate a version against a constraint like '<10.2.12'."""
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
    def _check_cves(self):
        """Match PAN-OS version against known CVE database."""
        sw_version = self.device_info.get("sw-version", "")
        if not sw_version:
            self._vprint("  [info] No PAN-OS version found, skipping CVE checks")
            return

        # Extract major.minor train (e.g., "10.2" from "10.2.7-h1")
        m = re.match(r"(\d+\.\d+)", sw_version)
        if not m:
            return
        device_train = m.group(1)
        normalized = self._parse_ver(sw_version)

        for entry in PANOS_CVE_DATABASE:
            # Skip Expedition-only CVEs (no affected_branches)
            if not entry["affected_branches"]:
                # Still report as informational
                self._add(Finding(
                    rule_id=entry["id"], name=entry["name"],
                    category="Known Vulnerabilities", severity=entry["severity"],
                    file_path="Expedition Tool", line_num=None,
                    line_content=f"Advisory: {entry['cve']}",
                    description=entry["description"],
                    recommendation=entry["recommendation"],
                    cwe=entry.get("cwe", ""), cve=entry.get("cve", ""),
                ))
                continue

            for branch in entry["affected_branches"]:
                if branch["train"] == device_train:
                    fixed_ver = self._parse_ver(branch["fixed"])
                    if normalized and fixed_ver and normalized < fixed_ver:
                        self._add(Finding(
                            rule_id=entry["id"], name=entry["name"],
                            category="Known Vulnerabilities", severity=entry["severity"],
                            file_path=f"PAN-OS {sw_version}", line_num=None,
                            line_content=f"Affected: {entry['cve']} (fixed in {branch['fixed']})",
                            description=entry["description"],
                            recommendation=entry["recommendation"],
                            cwe=entry.get("cwe", ""), cve=entry.get("cve", ""),
                        ))
                    break

    # ----------------------------------------------------------
    # Security Rule Checks
    # ----------------------------------------------------------
    def _check_security_rules(self):
        """Check security rules for overly permissive patterns."""
        rules = self._get_security_rules()
        if not rules:
            self._vprint("  [info] No security rules found")
            return

        for vsys, rule in rules:
            rule_name = self._get_entry_name(rule)
            action_el = rule.find("action")
            action = action_el.text.strip() if action_el is not None and action_el.text else "allow"
            disabled_el = rule.find("disabled")
            is_disabled = disabled_el is not None and (disabled_el.text or "").strip().lower() == "yes"

            src_zones = self._get_member_list(rule, "from")
            dst_zones = self._get_member_list(rule, "to")
            src_addrs = self._get_member_list(rule, "source")
            dst_addrs = self._get_member_list(rule, "destination")
            apps = self._get_member_list(rule, "application")
            services = self._get_member_list(rule, "service")
            desc_el = rule.find("description")
            has_desc = desc_el is not None and desc_el.text and desc_el.text.strip()

            is_allow = action == "allow"
            has_any_src = "any" in src_addrs
            has_any_dst = "any" in dst_addrs
            has_any_app = "any" in apps
            has_any_svc = "any" in services
            has_any_src_zone = "any" in src_zones
            has_any_dst_zone = "any" in dst_zones

            # PAN-RULE-008: Disabled rule
            if is_disabled:
                self._add(Finding(
                    rule_id="PAN-RULE-008", name="Disabled security rule (potential shadow rule)",
                    category="Security Rules", severity="LOW", file_path=rule_name, line_num=None,
                    line_content=f"disabled=yes, action={action}",
                    description=(
                        f"Rule '{rule_name}' is disabled. Disabled rules can be shadow rules from "
                        "previous configurations and may contain overly permissive access that could "
                        "be accidentally re-enabled."
                    ),
                    recommendation="Review and remove disabled rules that are no longer needed.",
                    cwe="CWE-284",
                ))
                continue  # Skip further checks on disabled rules

            if not is_allow:
                continue  # Only check allow rules for permissiveness

            # PAN-RULE-001: Allow-all rule
            if has_any_src and has_any_dst and has_any_app and has_any_src_zone and has_any_dst_zone:
                self._add(Finding(
                    rule_id="PAN-RULE-001",
                    name="Rule allows any source, destination, and application (allow-all)",
                    category="Security Rules", severity="CRITICAL", file_path=rule_name, line_num=None,
                    line_content=f"from=any, to=any, source=any, dest=any, app=any",
                    description=(
                        f"Rule '{rule_name}' is a complete allow-all rule with no restrictions on "
                        "zones, addresses, or applications. This effectively disables the firewall "
                        "for matched traffic."
                    ),
                    recommendation="Replace with specific rules that follow least-privilege. Remove this rule.",
                    cwe="CWE-284",
                ))
                continue  # Skip granular checks — already flagged as critical

            # PAN-RULE-004: Untrust to trust with broad access
            untrust_zones = {"untrust", "internet", "external", "outside", "wan", "public"}
            trust_zones = {"trust", "internal", "inside", "lan", "private", "dmz"}
            src_has_untrust = any(z.lower() in untrust_zones for z in src_zones) or has_any_src_zone
            dst_has_trust = any(z.lower() in trust_zones for z in dst_zones) or has_any_dst_zone
            if src_has_untrust and dst_has_trust and (has_any_app or has_any_src):
                self._add(Finding(
                    rule_id="PAN-RULE-004",
                    name="Rule from untrust to trust with broad access",
                    category="Security Rules", severity="CRITICAL", file_path=rule_name, line_num=None,
                    line_content=f"from={','.join(src_zones)}, to={','.join(dst_zones)}, app={','.join(apps[:3])}",
                    description=(
                        f"Rule '{rule_name}' allows traffic from an untrusted zone to a trusted zone "
                        "with overly broad source or application criteria, creating a significant "
                        "attack surface from the internet."
                    ),
                    recommendation="Restrict source addresses, specify exact applications, and apply security profiles.",
                    cwe="CWE-284",
                ))

            # PAN-RULE-002: Any application
            if has_any_app:
                self._add(Finding(
                    rule_id="PAN-RULE-002", name="Rule allows 'any' application (bypasses App-ID)",
                    category="Security Rules", severity="HIGH", file_path=rule_name, line_num=None,
                    line_content=f"application=any",
                    description=(
                        f"Rule '{rule_name}' allows any application. This bypasses Palo Alto's "
                        "App-ID technology, which is the core value of an NGFW. All traffic matching "
                        "this rule avoids application-layer inspection."
                    ),
                    recommendation="Specify allowed applications explicitly to leverage App-ID.",
                    cwe="CWE-284",
                ))

            # PAN-RULE-003: Any service
            if has_any_svc:
                self._add(Finding(
                    rule_id="PAN-RULE-003", name="Rule allows 'any' service (not application-based)",
                    category="Security Rules", severity="HIGH", file_path=rule_name, line_num=None,
                    line_content=f"service=any",
                    description=(
                        f"Rule '{rule_name}' uses service 'any' instead of 'application-default'. "
                        "This allows applications to run on non-standard ports, bypassing port-based "
                        "application identification."
                    ),
                    recommendation="Use 'application-default' to enforce standard ports for each application.",
                    cwe="CWE-284",
                ))

            # PAN-RULE-005: Any source and destination zones
            if has_any_src_zone and has_any_dst_zone:
                self._add(Finding(
                    rule_id="PAN-RULE-005", name="Rule with 'any' source and destination zones",
                    category="Security Rules", severity="HIGH", file_path=rule_name, line_num=None,
                    line_content=f"from=any, to=any",
                    description=(
                        f"Rule '{rule_name}' matches traffic between any zones. This defeats zone-based "
                        "segmentation, which is a core NGFW security control."
                    ),
                    recommendation="Specify explicit source and destination zones.",
                    cwe="CWE-284",
                ))

            # PAN-RULE-006: Any source address
            if has_any_src and not has_any_src_zone:
                self._add(Finding(
                    rule_id="PAN-RULE-006", name="Rule with 'any' source address",
                    category="Security Rules", severity="MEDIUM", file_path=rule_name, line_num=None,
                    line_content=f"source=any",
                    description=(
                        f"Rule '{rule_name}' allows traffic from any source address. Consider "
                        "restricting to known address objects or groups."
                    ),
                    recommendation="Define address objects for allowed sources.",
                    cwe="CWE-284",
                ))

            # PAN-RULE-007: Any destination address
            if has_any_dst and not has_any_dst_zone:
                self._add(Finding(
                    rule_id="PAN-RULE-007", name="Rule with 'any' destination address",
                    category="Security Rules", severity="MEDIUM", file_path=rule_name, line_num=None,
                    line_content=f"destination=any",
                    description=(
                        f"Rule '{rule_name}' allows traffic to any destination address. Consider "
                        "restricting to specific address objects or groups."
                    ),
                    recommendation="Define address objects for allowed destinations.",
                    cwe="CWE-284",
                ))

            # PAN-RULE-009: No description
            if not has_desc:
                self._add(Finding(
                    rule_id="PAN-RULE-009", name="Rule with no description",
                    category="Security Rules", severity="LOW", file_path=rule_name, line_num=None,
                    line_content="description = (empty)",
                    description=(
                        f"Rule '{rule_name}' has no description. Descriptions are essential for "
                        "audit trail, change management, and understanding rule purpose."
                    ),
                    recommendation="Add a meaningful description to every rule including business justification.",
                    cwe="CWE-1078",
                ))

            # PAN-RULE-010: application-default with any application
            app_default_svcs = [s for s in services if s == "application-default"]
            if app_default_svcs and has_any_app:
                self._add(Finding(
                    rule_id="PAN-RULE-010",
                    name="Rule using 'application-default' service with 'any' application",
                    category="Security Rules", severity="HIGH", file_path=rule_name, line_num=None,
                    line_content=f"service=application-default, application=any",
                    description=(
                        f"Rule '{rule_name}' uses 'application-default' for service but allows "
                        "'any' application. This combination is contradictory and allows all "
                        "applications on their default ports."
                    ),
                    recommendation="Specify explicit applications instead of 'any'.",
                    cwe="CWE-284",
                ))

    # ----------------------------------------------------------
    # Dangerous Application Checks
    # ----------------------------------------------------------
    def _check_dangerous_apps(self):
        """Check for high-risk applications allowed in security rules."""
        rules = self._get_security_rules()

        for vsys, rule in rules:
            rule_name = self._get_entry_name(rule)
            action_el = rule.find("action")
            action = action_el.text.strip() if action_el is not None and action_el.text else "allow"
            disabled_el = rule.find("disabled")
            is_disabled = disabled_el is not None and (disabled_el.text or "").strip().lower() == "yes"

            if action != "allow" or is_disabled:
                continue

            apps = self._get_member_list(rule, "application")
            apps_lower = {a.lower() for a in apps}

            # PAN-APP-001: Tunnel/evasion apps
            matched = apps_lower & HIGH_RISK_TUNNEL_APPS
            if matched:
                self._add(Finding(
                    rule_id="PAN-APP-001",
                    name="Rule allows high-risk tunnel/evasion applications",
                    category="Dangerous Applications", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content=f"applications: {', '.join(sorted(matched))}",
                    description=(
                        f"Rule '{rule_name}' allows anonymization/evasion applications "
                        f"({', '.join(sorted(matched))}). These can be used to bypass security "
                        "controls, exfiltrate data, or hide malicious activity."
                    ),
                    recommendation="Block these applications unless there is a documented business requirement.",
                    cwe="CWE-284",
                ))

            # PAN-APP-002: Remote access apps
            matched = apps_lower & HIGH_RISK_REMOTE_APPS
            if matched:
                self._add(Finding(
                    rule_id="PAN-APP-002",
                    name="Rule allows remote access applications",
                    category="Dangerous Applications", severity="MEDIUM",
                    file_path=rule_name, line_num=None,
                    line_content=f"applications: {', '.join(sorted(matched))}",
                    description=(
                        f"Rule '{rule_name}' allows remote access applications "
                        f"({', '.join(sorted(matched))}). These can be used for unauthorized "
                        "remote control of internal systems."
                    ),
                    recommendation="Block or restrict to specific users/groups. Use sanctioned VPN instead.",
                    cwe="CWE-284",
                ))

            # PAN-APP-003: P2P apps
            matched = apps_lower & HIGH_RISK_P2P_APPS
            if matched:
                self._add(Finding(
                    rule_id="PAN-APP-003",
                    name="Rule allows peer-to-peer applications",
                    category="Dangerous Applications", severity="MEDIUM",
                    file_path=rule_name, line_num=None,
                    line_content=f"applications: {', '.join(sorted(matched))}",
                    description=(
                        f"Rule '{rule_name}' allows P2P file-sharing applications "
                        f"({', '.join(sorted(matched))}). P2P traffic can introduce malware, "
                        "consume bandwidth, and violate data handling policies."
                    ),
                    recommendation="Block P2P applications in enterprise environments.",
                    cwe="CWE-284",
                ))

            # PAN-APP-004: DNS-over-HTTPS
            matched = apps_lower & HIGH_RISK_DOH_APPS
            if matched:
                self._add(Finding(
                    rule_id="PAN-APP-004",
                    name="Rule allows DNS-over-HTTPS (DoH) — bypasses DNS security",
                    category="Dangerous Applications", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content=f"applications: {', '.join(sorted(matched))}",
                    description=(
                        f"Rule '{rule_name}' allows DNS-over-HTTPS/TLS. DoH bypasses the "
                        "firewall's DNS Security features, preventing visibility into DNS queries "
                        "and enabling C2 communication and data exfiltration."
                    ),
                    recommendation="Block DoH/DoT and enforce DNS through the firewall's DNS proxy with DNS Security.",
                    cwe="CWE-693",
                ))

            # PAN-APP-005: SSH tunneling
            matched = apps_lower & HIGH_RISK_TUNNEL_SSH_APPS
            if matched:
                self._add(Finding(
                    rule_id="PAN-APP-005",
                    name="Rule allows SSH tunneling applications",
                    category="Dangerous Applications", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content=f"applications: {', '.join(sorted(matched))}",
                    description=(
                        f"Rule '{rule_name}' allows SSH/SSL tunneling applications "
                        f"({', '.join(sorted(matched))}). These create encrypted tunnels that "
                        "bypass firewall inspection for all encapsulated traffic."
                    ),
                    recommendation="Block tunneling applications. Allow only standard SSH for administration.",
                    cwe="CWE-693",
                ))

    # ----------------------------------------------------------
    # PAN-LOG-001 to PAN-LOG-005: Rule Logging Checks
    # ----------------------------------------------------------
    def _check_rule_logging(self):
        self._vprint("  [*] Checking rule logging configuration ...")

        # Check syslog config
        syslog_entries = self._find_all(".//log-settings/syslog/entry")
        if not syslog_entries:
            shared_syslog = self._find_all(".//shared/log-settings/syslog/entry")
            if not shared_syslog:
                self._add(Finding(
                    rule_id="PAN-LOG-003",
                    name="No syslog server profile configured",
                    category="Logging & Monitoring", severity="MEDIUM",
                    file_path="log-settings/syslog", line_num=None,
                    line_content="syslog server profiles: none",
                    description=(
                        "No syslog server profile is configured. Firewall logs are only stored "
                        "locally and will be lost if the device fails or runs out of storage. "
                        "External log collection is critical for SIEM, incident response, and compliance."
                    ),
                    recommendation="Configure syslog server profiles to forward logs to a SIEM or log collector.",
                    cwe="CWE-778",
                ))

        # Check SNMP trap config
        snmp_entries = self._find_all(".//log-settings/snmptrap/entry")
        if not snmp_entries:
            shared_snmp = self._find_all(".//shared/log-settings/snmptrap/entry")
            if not shared_snmp:
                self._add(Finding(
                    rule_id="PAN-LOG-004",
                    name="No SNMP trap destination configured",
                    category="Logging & Monitoring", severity="LOW",
                    file_path="log-settings/snmptrap", line_num=None,
                    line_content="SNMP trap destinations: none",
                    description=(
                        "No SNMP trap destinations are configured. SNMP traps provide real-time "
                        "alerts for critical system events and can complement syslog forwarding."
                    ),
                    recommendation="Configure SNMP trap destinations for critical event alerting.",
                    cwe="CWE-778",
                ))

        # Check per-rule logging
        for vsys_name, rule in self._get_security_rules():
            rule_name = self._get_entry_name(rule)
            action_el = rule.find("action")
            action = action_el.text.strip().lower() if action_el is not None and action_el.text else "allow"
            disabled_el = rule.find("disabled")
            disabled = disabled_el is not None and disabled_el.text and disabled_el.text.lower() == "yes"
            if disabled:
                continue

            log_start_el = rule.find("log-start")
            log_end_el = rule.find("log-end")
            log_start = log_start_el is not None and log_start_el.text and log_start_el.text.lower() == "yes"
            log_end = log_end_el is not None and log_end_el.text and log_end_el.text.lower() == "yes"

            # PAN-LOG-001: No logging at all
            if not log_start and not log_end:
                self._add(Finding(
                    rule_id="PAN-LOG-001",
                    name="Rule with logging disabled",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content=f"log-start: no, log-end: no",
                    description=(
                        f"Rule '{rule_name}' has both log-start and log-end disabled. "
                        "No traffic matching this rule will be logged, creating a blind spot "
                        "for security monitoring and incident investigation."
                    ),
                    recommendation="Enable log-end at minimum on all rules. Enable log-start for deny rules.",
                    cwe="CWE-778",
                ))

            # PAN-LOG-005: Allow rule with only log-start
            elif log_start and not log_end and action == "allow":
                self._add(Finding(
                    rule_id="PAN-LOG-005",
                    name="Allow rule with only log-start (no log-end)",
                    category="Logging & Monitoring", severity="LOW",
                    file_path=rule_name, line_num=None,
                    line_content=f"log-start: yes, log-end: no",
                    description=(
                        f"Allow rule '{rule_name}' logs session start but not session end. "
                        "Log-end provides session duration, bytes transferred, and final disposition — "
                        "critical data for threat detection and forensics."
                    ),
                    recommendation="Enable log-end on allow rules to capture complete session data.",
                    cwe="CWE-778",
                ))

            # PAN-LOG-002: No log-forwarding profile
            log_fwd = rule.find("log-setting")
            if log_fwd is None or not (log_fwd.text and log_fwd.text.strip()):
                self._add(Finding(
                    rule_id="PAN-LOG-002",
                    name="Rule without log-forwarding profile",
                    category="Logging & Monitoring", severity="MEDIUM",
                    file_path=rule_name, line_num=None,
                    line_content="log-setting: none",
                    description=(
                        f"Rule '{rule_name}' does not have a log-forwarding profile assigned. "
                        "Without a forwarding profile, logs stay on the firewall only and are "
                        "not sent to Panorama, syslog, or other external collectors."
                    ),
                    recommendation="Assign a log-forwarding profile to send logs to external collectors.",
                    cwe="CWE-778",
                ))

    # ----------------------------------------------------------
    # PAN-PROF-001 to PAN-PROF-008: Security Profile Checks
    # ----------------------------------------------------------
    def _check_security_profiles(self):
        self._vprint("  [*] Checking security profile attachment ...")

        for vsys_name, rule in self._get_security_rules():
            rule_name = self._get_entry_name(rule)
            action_el = rule.find("action")
            action = action_el.text.strip().lower() if action_el is not None and action_el.text else "allow"
            disabled_el = rule.find("disabled")
            disabled = disabled_el is not None and disabled_el.text and disabled_el.text.lower() == "yes"
            if disabled or action != "allow":
                continue

            # Check for security profile group
            profile_setting = rule.find("profile-setting")
            has_profiles = False
            has_av = False
            has_as = False
            has_vp = False
            has_url = False
            has_fb = False
            has_wf = False

            if profile_setting is not None:
                # Check group
                group = profile_setting.find("group")
                if group is not None:
                    members = self._get_member_list(group, "member")
                    if members:
                        has_profiles = True
                        # When a group is used we assume all profile types are covered
                        has_av = has_as = has_vp = has_url = has_fb = has_wf = True

                # Check individual profiles
                profiles = profile_setting.find("profiles")
                if profiles is not None:
                    if profiles.find("virus") is not None:
                        has_av = True
                        has_profiles = True
                    if profiles.find("spyware") is not None:
                        has_as = True
                        has_profiles = True
                    if profiles.find("vulnerability") is not None:
                        has_vp = True
                        has_profiles = True
                    if profiles.find("url-filtering") is not None:
                        has_url = True
                        has_profiles = True
                    if profiles.find("file-blocking") is not None:
                        has_fb = True
                        has_profiles = True
                    if profiles.find("wildfire-analysis") is not None:
                        has_wf = True
                        has_profiles = True

            # PAN-PROF-007: No profiles at all
            if not has_profiles:
                self._add(Finding(
                    rule_id="PAN-PROF-007",
                    name="Allow rule without any security profile or group",
                    category="Security Profiles", severity="CRITICAL",
                    file_path=rule_name, line_num=None,
                    line_content="profile-setting: none",
                    description=(
                        f"Allow rule '{rule_name}' has no security profile or security profile "
                        "group attached. Traffic matching this rule bypasses all threat inspection "
                        "including antivirus, anti-spyware, vulnerability protection, and URL filtering."
                    ),
                    recommendation=(
                        "Attach a security profile group (e.g. 'strict') or individual profiles "
                        "to all allow rules."
                    ),
                    cwe="CWE-693",
                ))

                # Check inter-zone specifically
                from_zones = self._get_member_list(rule, "from/member")
                to_zones = self._get_member_list(rule, "to/member")
                if from_zones and to_zones:
                    from_set = set(z.lower() for z in from_zones)
                    to_set = set(z.lower() for z in to_zones)
                    if from_set != to_set and "any" not in from_set and "any" not in to_set:
                        self._add(Finding(
                            rule_id="PAN-PROF-008",
                            name="Inter-zone allow rule without security profiles",
                            category="Security Profiles", severity="HIGH",
                            file_path=rule_name, line_num=None,
                            line_content=f"from: {', '.join(from_zones)} → to: {', '.join(to_zones)}",
                            description=(
                                f"Inter-zone allow rule '{rule_name}' ({' → '.join(from_zones)} to "
                                f"{' → '.join(to_zones)}) has no security profiles. Inter-zone traffic "
                                "should always be inspected for threats."
                            ),
                            recommendation="Attach security profiles to all inter-zone allow rules.",
                            cwe="CWE-693",
                        ))
                continue  # skip individual profile checks if no profiles at all

            # Individual profile checks
            if not has_av:
                self._add(Finding(
                    rule_id="PAN-PROF-001",
                    name="Allow rule without antivirus profile",
                    category="Security Profiles", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content="profiles/virus: not set",
                    description=(
                        f"Allow rule '{rule_name}' does not have an antivirus profile attached. "
                        "Malware in permitted traffic will not be detected or blocked."
                    ),
                    recommendation="Attach an antivirus profile to this allow rule.",
                    cwe="CWE-693",
                ))
            if not has_as:
                self._add(Finding(
                    rule_id="PAN-PROF-002",
                    name="Allow rule without anti-spyware profile",
                    category="Security Profiles", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content="profiles/spyware: not set",
                    description=(
                        f"Allow rule '{rule_name}' does not have an anti-spyware profile attached. "
                        "Spyware, C2 callbacks, and phone-home traffic will not be detected."
                    ),
                    recommendation="Attach an anti-spyware profile to this allow rule.",
                    cwe="CWE-693",
                ))
            if not has_vp:
                self._add(Finding(
                    rule_id="PAN-PROF-003",
                    name="Allow rule without vulnerability protection profile",
                    category="Security Profiles", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content="profiles/vulnerability: not set",
                    description=(
                        f"Allow rule '{rule_name}' does not have a vulnerability protection profile. "
                        "Exploit attempts against known vulnerabilities will not be blocked."
                    ),
                    recommendation="Attach a vulnerability protection profile to this allow rule.",
                    cwe="CWE-693",
                ))
            if not has_url:
                self._add(Finding(
                    rule_id="PAN-PROF-004",
                    name="Allow rule without URL filtering profile",
                    category="Security Profiles", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content="profiles/url-filtering: not set",
                    description=(
                        f"Allow rule '{rule_name}' does not have a URL filtering profile. "
                        "Users can access malicious, phishing, and policy-violating websites."
                    ),
                    recommendation="Attach a URL filtering profile to this allow rule.",
                    cwe="CWE-693",
                ))
            if not has_fb:
                self._add(Finding(
                    rule_id="PAN-PROF-005",
                    name="Allow rule without file-blocking profile",
                    category="Security Profiles", severity="MEDIUM",
                    file_path=rule_name, line_num=None,
                    line_content="profiles/file-blocking: not set",
                    description=(
                        f"Allow rule '{rule_name}' does not have a file-blocking profile. "
                        "Dangerous file types (PE, DLL, EXE, HTA, etc.) can pass through unchecked."
                    ),
                    recommendation="Attach a file-blocking profile to block dangerous file types.",
                    cwe="CWE-434",
                ))
            if not has_wf:
                self._add(Finding(
                    rule_id="PAN-PROF-006",
                    name="Allow rule without WildFire analysis profile",
                    category="Security Profiles", severity="MEDIUM",
                    file_path=rule_name, line_num=None,
                    line_content="profiles/wildfire-analysis: not set",
                    description=(
                        f"Allow rule '{rule_name}' does not have a WildFire analysis profile. "
                        "Unknown files will not be submitted for sandbox analysis to detect zero-day malware."
                    ),
                    recommendation="Attach a WildFire analysis profile to detect unknown threats.",
                    cwe="CWE-693",
                ))

    # ----------------------------------------------------------
    # PAN-THREAT-001 to PAN-THREAT-008: Threat Prevention Checks
    # ----------------------------------------------------------
    def _check_threat_prevention(self):
        self._vprint("  [*] Checking threat prevention profile quality ...")

        # PAN-THREAT-001: Antivirus profiles using only default actions
        for entry in self._find_all(".//profiles/virus/entry"):
            profile_name = self._get_entry_name(entry)
            decoders = entry.findall(".//decoder/entry")
            all_default = True
            for dec in decoders:
                action_el = dec.find("action")
                if action_el is not None and action_el.text and action_el.text.strip().lower() != "default":
                    all_default = False
                    break
            if all_default and decoders:
                self._add(Finding(
                    rule_id="PAN-THREAT-001",
                    name="Antivirus profile using only default actions",
                    category="Threat Prevention", severity="MEDIUM",
                    file_path=profile_name, line_num=None,
                    line_content="all decoder actions: default",
                    description=(
                        f"Antivirus profile '{profile_name}' uses only default actions for all "
                        "decoders. Default actions may allow certain threat types. Customize actions "
                        "to 'reset-both' or 'drop' for all decoders."
                    ),
                    recommendation="Set antivirus decoder actions to 'reset-both' or 'drop' for all protocols.",
                    cwe="CWE-693",
                ))

        # PAN-THREAT-002: Anti-spyware not blocking C2
        for entry in self._find_all(".//profiles/spyware/entry"):
            profile_name = self._get_entry_name(entry)
            rules = entry.findall(".//rules/entry")
            blocks_c2 = False
            for r in rules:
                category_el = r.find("category")
                action_el = r.find("action")
                if category_el is not None and action_el is not None:
                    cat_text = category_el.text or ""
                    act = action_el.text.strip().lower() if action_el.text else ""
                    # Check if any rule covers command-and-control with blocking action
                    if "command-and-control" in cat_text.lower() or "any" in cat_text.lower():
                        if act in ("reset-both", "drop", "reset-client", "reset-server", "block-ip"):
                            blocks_c2 = True
                            break
            # Also check botnet-domains
            botnet = entry.find("botnet-domains")
            if botnet is not None:
                lists = botnet.find("lists")
                if lists is not None:
                    for l in lists.findall("entry"):
                        action_el = l.find("action")
                        if action_el is not None:
                            act_child = list(action_el)
                            if act_child and act_child[0].tag in ("block", "sinkhole"):
                                blocks_c2 = True
                                break

            if not blocks_c2 and rules:
                self._add(Finding(
                    rule_id="PAN-THREAT-002",
                    name="Anti-spyware profile not blocking C2 traffic",
                    category="Threat Prevention", severity="HIGH",
                    file_path=profile_name, line_num=None,
                    line_content="C2/botnet blocking: not configured",
                    description=(
                        f"Anti-spyware profile '{profile_name}' does not appear to block "
                        "command-and-control (C2) traffic. Compromised hosts can communicate "
                        "with attacker infrastructure unimpeded."
                    ),
                    recommendation=(
                        "Configure anti-spyware rules to block C2 categories and enable DNS sinkhole "
                        "for botnet domains."
                    ),
                    cwe="CWE-693",
                ))

        # PAN-THREAT-003: Vulnerability protection not blocking critical/high
        for entry in self._find_all(".//profiles/vulnerability/entry"):
            profile_name = self._get_entry_name(entry)
            rules = entry.findall(".//rules/entry")
            blocks_critical = False
            blocks_high = False
            for r in rules:
                severity_el = r.find("severity")
                action_el = r.find("action")
                if severity_el is not None and action_el is not None:
                    sevs = self._get_member_list(severity_el, "member")
                    act = action_el.text.strip().lower() if action_el.text else ""
                    is_blocking = act in ("reset-both", "drop", "reset-client", "reset-server", "block-ip")
                    sev_lower = [s.lower() for s in sevs]
                    if ("critical" in sev_lower or "any" in sev_lower) and is_blocking:
                        blocks_critical = True
                    if ("high" in sev_lower or "any" in sev_lower) and is_blocking:
                        blocks_high = True

            if rules and (not blocks_critical or not blocks_high):
                missing = []
                if not blocks_critical:
                    missing.append("critical")
                if not blocks_high:
                    missing.append("high")
                self._add(Finding(
                    rule_id="PAN-THREAT-003",
                    name="Vulnerability protection profile not blocking critical/high severity",
                    category="Threat Prevention", severity="HIGH",
                    file_path=profile_name, line_num=None,
                    line_content=f"not blocking: {', '.join(missing)} severity",
                    description=(
                        f"Vulnerability protection profile '{profile_name}' does not block "
                        f"{' and '.join(missing)} severity exploits. Active exploitation of known "
                        "vulnerabilities may succeed."
                    ),
                    recommendation="Set action to 'reset-both' for critical and high severity rules.",
                    cwe="CWE-693",
                ))

        # PAN-THREAT-004/005/006: URL filtering checks
        for entry in self._find_all(".//profiles/url-filtering/entry"):
            profile_name = self._get_entry_name(entry)

            # Collect blocked categories
            blocked_cats = set()
            # PAN-OS 9.x+ uses block-list, older uses action per category
            block_list = entry.find("block-list")
            if block_list is not None:
                for member in block_list.findall("member"):
                    if member.text:
                        blocked_cats.add(member.text.strip().lower())

            # Also check individual category actions (PAN-OS 10+)
            for cat_entry in entry.findall(".//*/entry"):
                action_el = cat_entry.find("action")
                if action_el is not None and action_el.text:
                    if action_el.text.strip().lower() in ("block", "override"):
                        cat_name = self._get_entry_name(cat_entry)
                        blocked_cats.add(cat_name.lower())

            if "malware" not in blocked_cats and "ransomware" not in blocked_cats:
                self._add(Finding(
                    rule_id="PAN-THREAT-004",
                    name="URL filtering not blocking malware category",
                    category="Threat Prevention", severity="HIGH",
                    file_path=profile_name, line_num=None,
                    line_content="malware category: not blocked",
                    description=(
                        f"URL filtering profile '{profile_name}' does not block the malware "
                        "category. Users can access known malware distribution sites."
                    ),
                    recommendation="Block 'malware' and 'ransomware' URL categories.",
                    cwe="CWE-693",
                ))

            if "phishing" not in blocked_cats:
                self._add(Finding(
                    rule_id="PAN-THREAT-005",
                    name="URL filtering not blocking phishing category",
                    category="Threat Prevention", severity="HIGH",
                    file_path=profile_name, line_num=None,
                    line_content="phishing category: not blocked",
                    description=(
                        f"URL filtering profile '{profile_name}' does not block the phishing "
                        "category. Users can access credential harvesting and phishing sites."
                    ),
                    recommendation="Block the 'phishing' URL category.",
                    cwe="CWE-693",
                ))

            if "command-and-control" not in blocked_cats:
                self._add(Finding(
                    rule_id="PAN-THREAT-006",
                    name="URL filtering not blocking command-and-control category",
                    category="Threat Prevention", severity="HIGH",
                    file_path=profile_name, line_num=None,
                    line_content="C2 category: not blocked",
                    description=(
                        f"URL filtering profile '{profile_name}' does not block the "
                        "command-and-control category. Compromised hosts can reach C2 servers via HTTP/S."
                    ),
                    recommendation="Block the 'command-and-control' URL category.",
                    cwe="CWE-693",
                ))

        # PAN-THREAT-007: WildFire not configured or report-only
        wf_entries = self._find_all(".//profiles/wildfire-analysis/entry")
        if not wf_entries:
            self._add(Finding(
                rule_id="PAN-THREAT-007",
                name="WildFire not configured or set to report-only",
                category="Threat Prevention", severity="HIGH",
                file_path="profiles/wildfire-analysis", line_num=None,
                line_content="wildfire-analysis profiles: none",
                description=(
                    "No WildFire analysis profiles are configured. Unknown files are not submitted "
                    "to the WildFire sandbox for analysis, limiting zero-day malware detection."
                ),
                recommendation="Create and attach WildFire analysis profiles with all file types forwarded.",
                cwe="CWE-693",
            ))

        # PAN-THREAT-008: DNS Security
        dns_security_found = False
        for entry in self._find_all(".//profiles/spyware/entry"):
            dns_sec = entry.find("mica-engine-spyware-enabled")
            if dns_sec is not None:
                for bool_entry in dns_sec.findall("entry"):
                    val_el = bool_entry.find("inline-policy-action")
                    if val_el is not None and val_el.text:
                        dns_security_found = True
                        break
            # Also check dns-security element (PAN-OS 10.1+)
            dns_el = entry.find("dns-security")
            if dns_el is not None and list(dns_el):
                dns_security_found = True

        if not dns_security_found:
            self._add(Finding(
                rule_id="PAN-THREAT-008",
                name="DNS Security not enabled",
                category="Threat Prevention", severity="MEDIUM",
                file_path="profiles/spyware", line_num=None,
                line_content="DNS Security: not configured",
                description=(
                    "DNS Security is not enabled in any anti-spyware profile. DNS Security uses "
                    "cloud-based analytics to detect DNS-based threats including DGA domains, "
                    "DNS tunneling, and newly registered domains used for attacks."
                ),
                recommendation="Enable DNS Security in anti-spyware profiles with sinkhole action for malicious domains.",
                cwe="CWE-693",
            ))

    # ----------------------------------------------------------
    # PAN-ZONE-001 to PAN-ZONE-003: Zone Protection Checks
    # ----------------------------------------------------------
    def _check_zone_protection(self):
        self._vprint("  [*] Checking zone protection profiles ...")

        # Gather defined zone protection profiles
        zp_profiles = {}
        for entry in self._find_all(".//zone-protection-profile/entry"):
            pname = self._get_entry_name(entry)
            zp_profiles[pname] = entry

        # Iterate zones
        for entry in self._find_all(".//zone/entry"):
            zone_name = self._get_entry_name(entry)
            zp_el = entry.find("network/zone-protection-profile")

            # PAN-ZONE-001: Zone without zone protection profile
            if zp_el is None or not (zp_el.text and zp_el.text.strip()):
                self._add(Finding(
                    rule_id="PAN-ZONE-001",
                    name="Zone without zone protection profile",
                    category="Zone Protection", severity="HIGH",
                    file_path=zone_name, line_num=None,
                    line_content="zone-protection-profile: none",
                    description=(
                        f"Zone '{zone_name}' does not have a zone protection profile assigned. "
                        "Without zone protection, the zone is vulnerable to flood attacks, "
                        "reconnaissance (port scans), and packet-based attacks."
                    ),
                    recommendation="Create and assign a zone protection profile with flood, reconnaissance, and packet-based protection.",
                    cwe="CWE-693",
                ))
            else:
                zp_name = zp_el.text.strip()
                zp_entry = zp_profiles.get(zp_name)
                if zp_entry is not None:
                    # PAN-ZONE-002: No flood protection
                    flood = zp_entry.find("flood-protection")
                    if flood is None or not list(flood):
                        self._add(Finding(
                            rule_id="PAN-ZONE-002",
                            name="Zone protection profile without flood protection",
                            category="Zone Protection", severity="MEDIUM",
                            file_path=zone_name, line_num=None,
                            line_content=f"zone-protection-profile: {zp_name} (no flood protection)",
                            description=(
                                f"Zone protection profile '{zp_name}' on zone '{zone_name}' "
                                "does not have flood protection configured. SYN/UDP/ICMP/ICMPv6/other "
                                "flood attacks can overwhelm the zone."
                            ),
                            recommendation="Enable SYN, UDP, ICMP, and other flood protection with appropriate thresholds.",
                            cwe="CWE-400",
                        ))

                    # PAN-ZONE-003: No reconnaissance protection
                    recon = zp_entry.find("scan")
                    if recon is None or not list(recon):
                        self._add(Finding(
                            rule_id="PAN-ZONE-003",
                            name="Zone protection profile without reconnaissance protection",
                            category="Zone Protection", severity="MEDIUM",
                            file_path=zone_name, line_num=None,
                            line_content=f"zone-protection-profile: {zp_name} (no recon protection)",
                            description=(
                                f"Zone protection profile '{zp_name}' on zone '{zone_name}' "
                                "does not have reconnaissance (scan) protection enabled. Port scans, "
                                "host sweeps, and similar reconnaissance can proceed undetected."
                            ),
                            recommendation="Enable scan protection to block TCP/UDP port scans and host sweeps.",
                            cwe="CWE-693",
                        ))

    # ----------------------------------------------------------
    # PAN-MGMT-001 to PAN-MGMT-009: Management Config Checks
    # ----------------------------------------------------------
    def _check_management(self):
        self._vprint("  [*] Checking management configuration ...")

        # Check interface management profiles
        for entry in self._find_all(".//interface-management-profile/entry"):
            profile_name = self._get_entry_name(entry)

            # PAN-MGMT-001: HTTP enabled
            http_el = entry.find("http")
            if http_el is not None and http_el.text and http_el.text.lower() == "yes":
                self._add(Finding(
                    rule_id="PAN-MGMT-001",
                    name="HTTP enabled on management interface profile",
                    category="Management", severity="HIGH",
                    file_path=profile_name, line_num=None,
                    line_content="http: yes",
                    description=(
                        f"Management interface profile '{profile_name}' allows HTTP access. "
                        "HTTP transmits credentials and session tokens in cleartext, enabling "
                        "interception via network sniffing."
                    ),
                    recommendation="Disable HTTP and use HTTPS only for management access.",
                    cwe="CWE-319",
                ))

            # PAN-MGMT-002: Telnet enabled
            telnet_el = entry.find("telnet")
            if telnet_el is not None and telnet_el.text and telnet_el.text.lower() == "yes":
                self._add(Finding(
                    rule_id="PAN-MGMT-002",
                    name="Telnet enabled on management interface profile",
                    category="Management", severity="CRITICAL",
                    file_path=profile_name, line_num=None,
                    line_content="telnet: yes",
                    description=(
                        f"Management interface profile '{profile_name}' allows Telnet access. "
                        "Telnet transmits all data including credentials in cleartext and is "
                        "considered a critical security risk."
                    ),
                    recommendation="Disable Telnet immediately. Use SSH or HTTPS for management.",
                    cwe="CWE-319",
                ))

            # PAN-MGMT-003: Permitted-IP not restricted
            permitted_ip = entry.find("permitted-ip")
            if permitted_ip is None or not list(permitted_ip):
                self._add(Finding(
                    rule_id="PAN-MGMT-003",
                    name="Management permitted-ip not restricted",
                    category="Management", severity="HIGH",
                    file_path=profile_name, line_num=None,
                    line_content="permitted-ip: not configured",
                    description=(
                        f"Management interface profile '{profile_name}' does not restrict "
                        "source IPs. Any host in the connected zone can attempt management access."
                    ),
                    recommendation="Configure permitted-ip to allow management access only from trusted IPs/subnets.",
                    cwe="CWE-284",
                ))

        # PAN-MGMT-004: Admin lockout policy
        lockout = self._find(".//deviceconfig/setting/management/admin-lockout")
        if lockout is None:
            self._add(Finding(
                rule_id="PAN-MGMT-004",
                name="No admin lockout policy configured",
                category="Management", severity="MEDIUM",
                file_path="deviceconfig/setting/management", line_num=None,
                line_content="admin-lockout: not configured",
                description=(
                    "No administrator lockout policy is configured. Without lockout, brute-force "
                    "password attacks against the management interface can proceed without limit."
                ),
                recommendation="Configure admin lockout (e.g. 5 failed attempts, 30-minute lockout).",
                cwe="CWE-307",
            ))
        else:
            failed_attempts = lockout.find("failed-attempts")
            lockout_time = lockout.find("lockout-time")
            if failed_attempts is None or lockout_time is None:
                self._add(Finding(
                    rule_id="PAN-MGMT-004",
                    name="No admin lockout policy configured",
                    category="Management", severity="MEDIUM",
                    file_path="deviceconfig/setting/management", line_num=None,
                    line_content="admin-lockout: incomplete configuration",
                    description=(
                        "Administrator lockout policy is not fully configured. Both failed-attempts "
                        "threshold and lockout-time must be set to prevent brute-force attacks."
                    ),
                    recommendation="Configure both failed-attempts (e.g. 5) and lockout-time (e.g. 30 min).",
                    cwe="CWE-307",
                ))

        # PAN-MGMT-005: Minimum password length
        pwd_complexity = self._find(".//deviceconfig/setting/management/password-complexity")
        if pwd_complexity is not None:
            min_len_el = pwd_complexity.find("minimum-length")
            if min_len_el is not None and min_len_el.text:
                try:
                    min_len = int(min_len_el.text.strip())
                    if min_len < 8:
                        self._add(Finding(
                            rule_id="PAN-MGMT-005",
                            name="Minimum password length too short",
                            category="Management", severity="MEDIUM",
                            file_path="password-complexity", line_num=None,
                            line_content=f"minimum-length: {min_len}",
                            description=(
                                f"Minimum password length is set to {min_len} characters. "
                                "Short passwords are vulnerable to brute-force and dictionary attacks."
                            ),
                            recommendation="Set minimum password length to at least 12 characters.",
                            cwe="CWE-521",
                        ))
                except ValueError:
                    pass

            # PAN-MGMT-006: Password complexity
            enabled_el = pwd_complexity.find("enabled")
            if enabled_el is None or not enabled_el.text or enabled_el.text.lower() != "yes":
                self._add(Finding(
                    rule_id="PAN-MGMT-006",
                    name="Password complexity requirements not enforced",
                    category="Management", severity="MEDIUM",
                    file_path="password-complexity", line_num=None,
                    line_content="password-complexity/enabled: no",
                    description=(
                        "Password complexity requirements are not enforced. Administrators can set "
                        "weak passwords without uppercase, lowercase, numeric, or special character requirements."
                    ),
                    recommendation="Enable password complexity requiring uppercase, lowercase, numbers, and special characters.",
                    cwe="CWE-521",
                ))
        else:
            self._add(Finding(
                rule_id="PAN-MGMT-005",
                name="Minimum password length too short",
                category="Management", severity="MEDIUM",
                file_path="password-complexity", line_num=None,
                line_content="password-complexity: not configured",
                description=(
                    "No password complexity policy is configured. Administrators can set "
                    "any password without length or complexity requirements."
                ),
                recommendation="Configure password complexity with minimum 12 characters and mixed character types.",
                cwe="CWE-521",
            ))
            self._add(Finding(
                rule_id="PAN-MGMT-006",
                name="Password complexity requirements not enforced",
                category="Management", severity="MEDIUM",
                file_path="password-complexity", line_num=None,
                line_content="password-complexity: not configured",
                description=(
                    "Password complexity requirements are not configured. Administrators can set "
                    "weak passwords without any complexity requirements."
                ),
                recommendation="Enable password complexity requiring uppercase, lowercase, numbers, and special characters.",
                cwe="CWE-521",
            ))

        # PAN-MGMT-007: Idle timeout
        idle_timeout = self._find_text(".//deviceconfig/setting/management/idle-timeout")
        if not idle_timeout or idle_timeout == "0":
            self._add(Finding(
                rule_id="PAN-MGMT-007",
                name="No idle timeout for admin sessions",
                category="Management", severity="MEDIUM",
                file_path="deviceconfig/setting/management", line_num=None,
                line_content=f"idle-timeout: {idle_timeout or 'not set'}",
                description=(
                    "No idle timeout is configured for administrator sessions. Unattended "
                    "management sessions remain active indefinitely, increasing risk of "
                    "unauthorized access from unlocked workstations."
                ),
                recommendation="Set idle timeout to 10-15 minutes for admin sessions.",
                cwe="CWE-613",
            ))

        # PAN-MGMT-008: SNMP v2c instead of v3
        snmp_v2_entries = self._find_all(".//deviceconfig/system/snmp-setting/access-setting/version/v2c/entry")
        if snmp_v2_entries:
            for entry in snmp_v2_entries:
                community = self._get_entry_name(entry)
                self._add(Finding(
                    rule_id="PAN-MGMT-008",
                    name="SNMP using v2c instead of v3",
                    category="Management", severity="MEDIUM",
                    file_path="snmp-setting", line_num=None,
                    line_content=f"SNMPv2c community: {community}",
                    description=(
                        f"SNMP v2c is configured with community string '{community}'. "
                        "SNMPv2c uses community strings in cleartext for authentication, "
                        "making it vulnerable to interception and replay attacks."
                    ),
                    recommendation="Migrate to SNMPv3 with authentication and encryption (authPriv).",
                    cwe="CWE-319",
                ))

        # PAN-MGMT-009: Default admin password check
        # We check if 'admin' user exists with phash that matches known default
        for entry in self._find_all(".//deviceconfig/system/admin/entry"):
            admin_name = self._get_entry_name(entry)
            if admin_name.lower() == "admin":
                phash_el = entry.find("phash")
                if phash_el is not None and phash_el.text:
                    # The default PAN-OS admin password hash is known; we check for the
                    # factory-default indicator (no phash or empty phash means password never changed
                    # on some versions, but typically the API won't expose the hash).
                    # We flag if the admin user exists and has no password-profile assigned.
                    pass
                # Check if password-profile is set (good practice)
                pwd_profile = entry.find("password-profile")
                if pwd_profile is None or not (pwd_profile.text and pwd_profile.text.strip()):
                    self._add(Finding(
                        rule_id="PAN-MGMT-009",
                        name="Default admin account without password profile",
                        category="Management", severity="CRITICAL",
                        file_path="admin/admin", line_num=None,
                        line_content="admin user: no password-profile assigned",
                        description=(
                            "The default 'admin' account does not have a password profile assigned. "
                            "The default admin account is the primary target for brute-force attacks. "
                            "Ensure the password has been changed from default and a strong password profile is enforced."
                        ),
                        recommendation=(
                            "Change the default admin password, assign a password profile, "
                            "and consider creating named admin accounts with role-based access."
                        ),
                        cwe="CWE-798",
                    ))

    # ----------------------------------------------------------
    # PAN-NAT-001 to PAN-NAT-004: NAT Policy Checks
    # ----------------------------------------------------------
    def _check_nat_policy(self):
        self._vprint("  [*] Checking NAT policy configuration ...")

        sec_rules = self._get_security_rules()

        for vsys_name, rule in self._get_nat_rules():
            rule_name = self._get_entry_name(rule)
            disabled_el = rule.find("disabled")
            if disabled_el is not None and disabled_el.text and disabled_el.text.lower() == "yes":
                continue

            src_zones = self._get_member_list(rule, "from/member")
            dst_zones = self._get_member_list(rule, "to/member")
            src_addrs = self._get_member_list(rule, "source/member")
            dst_addrs = self._get_member_list(rule, "destination/member")

            src_zones_lower = [z.lower() for z in src_zones]
            src_addrs_lower = [a.lower() for a in src_addrs]

            # Check for destination NAT (DNAT)
            dst_translation = rule.find("destination-translation")
            has_dnat = dst_translation is not None and dst_translation.find("translated-address") is not None

            # PAN-NAT-001: DNAT exposing server to any source
            if has_dnat and "any" in src_addrs_lower:
                self._add(Finding(
                    rule_id="PAN-NAT-001",
                    name="Destination NAT exposing internal server to any source",
                    category="NAT Policy", severity="HIGH",
                    file_path=rule_name, line_num=None,
                    line_content=f"source: any → destination-translation: configured",
                    description=(
                        f"NAT rule '{rule_name}' performs destination NAT with source address 'any'. "
                        "Any external host can reach the translated internal server. This significantly "
                        "increases the attack surface."
                    ),
                    recommendation="Restrict source addresses to known/expected origins for DNAT rules.",
                    cwe="CWE-284",
                ))

            # PAN-NAT-002: Bidirectional NAT
            src_translation = rule.find("source-translation")
            bi_dir = rule.find("bi-directional")
            if bi_dir is not None and bi_dir.text and bi_dir.text.lower() == "yes":
                self._add(Finding(
                    rule_id="PAN-NAT-002",
                    name="Bidirectional NAT rule present",
                    category="NAT Policy", severity="MEDIUM",
                    file_path=rule_name, line_num=None,
                    line_content="bi-directional: yes",
                    description=(
                        f"NAT rule '{rule_name}' is configured as bidirectional. Bidirectional "
                        "NAT automatically creates a reverse translation, which may expose internal "
                        "servers unintentionally."
                    ),
                    recommendation="Use explicit NAT rules in each direction for better control and visibility.",
                    cwe="CWE-284",
                ))

            # PAN-NAT-003: Any source zone
            if "any" in src_zones_lower:
                self._add(Finding(
                    rule_id="PAN-NAT-003",
                    name="NAT rule with any source zone",
                    category="NAT Policy", severity="MEDIUM",
                    file_path=rule_name, line_num=None,
                    line_content=f"from: any",
                    description=(
                        f"NAT rule '{rule_name}' matches traffic from 'any' source zone. "
                        "NAT rules should be scoped to specific zones to prevent unintended "
                        "address translation."
                    ),
                    recommendation="Specify source zones explicitly in NAT rules.",
                    cwe="CWE-284",
                ))

            # PAN-NAT-004: DNAT without corresponding security policy
            if has_dnat and sec_rules:
                translated_addr_el = dst_translation.find("translated-address")
                translated_addr = translated_addr_el.text.strip() if translated_addr_el is not None and translated_addr_el.text else ""
                if translated_addr:
                    has_matching_sec = False
                    for _vsys, sec_rule in sec_rules:
                        sec_dst = self._get_member_list(sec_rule, "destination/member")
                        sec_dst_lower = [a.lower() for a in sec_dst]
                        if translated_addr.lower() in sec_dst_lower or "any" in sec_dst_lower:
                            has_matching_sec = True
                            break
                    if not has_matching_sec:
                        self._add(Finding(
                            rule_id="PAN-NAT-004",
                            name="NAT rule without corresponding security policy",
                            category="NAT Policy", severity="HIGH",
                            file_path=rule_name, line_num=None,
                            line_content=f"translated-address: {translated_addr}",
                            description=(
                                f"Destination NAT rule '{rule_name}' translates to '{translated_addr}' "
                                "but no security policy explicitly references this address. The traffic "
                                "may be implicitly denied or allowed by an overly broad rule."
                            ),
                            recommendation="Create explicit security policies for NAT-translated addresses.",
                            cwe="CWE-284",
                        ))

    # ----------------------------------------------------------
    # PAN-DECRYPT-001 to PAN-DECRYPT-004: Decryption Checks
    # ----------------------------------------------------------
    def _check_decryption(self):
        self._vprint("  [*] Checking SSL/TLS decryption configuration ...")

        decrypt_rules = []
        for entry in self._find_all(".//vsys/entry"):
            rulebase = entry.find("rulebase/decryption/rules")
            if rulebase is not None:
                for rule in rulebase.findall("entry"):
                    decrypt_rules.append(rule)

        # PAN-DECRYPT-001: No decryption policy
        if not decrypt_rules:
            self._add(Finding(
                rule_id="PAN-DECRYPT-001",
                name="No SSL decryption policy configured",
                category="Decryption", severity="MEDIUM",
                file_path="rulebase/decryption", line_num=None,
                line_content="decryption rules: none",
                description=(
                    "No SSL/TLS decryption policies are configured. Encrypted traffic cannot be "
                    "inspected for threats, malware, or data exfiltration. This limits the "
                    "effectiveness of all security profiles."
                ),
                recommendation="Implement SSL forward proxy decryption for outbound traffic with appropriate exclusions.",
                cwe="CWE-693",
            ))
            return

        has_forward_proxy = False
        for rule in decrypt_rules:
            rule_name = self._get_entry_name(rule)
            disabled_el = rule.find("disabled")
            if disabled_el is not None and disabled_el.text and disabled_el.text.lower() == "yes":
                continue

            action_el = rule.find("action")
            action = action_el.text.strip().lower() if action_el is not None and action_el.text else ""
            type_el = rule.find("type")

            # Check for forward proxy (ssl-forward-proxy)
            if type_el is not None:
                if type_el.find("ssl-forward-proxy") is not None:
                    has_forward_proxy = True

            # PAN-DECRYPT-002: Overly broad exclusions (no-decrypt with any)
            if action in ("no-decrypt", "no-decrypt-action"):
                src_addrs = self._get_member_list(rule, "source/member")
                dst_addrs = self._get_member_list(rule, "destination/member")
                if ("any" in [a.lower() for a in src_addrs] and
                    "any" in [a.lower() for a in dst_addrs]):
                    self._add(Finding(
                        rule_id="PAN-DECRYPT-002",
                        name="SSL decryption with overly broad exclusions",
                        category="Decryption", severity="MEDIUM",
                        file_path=rule_name, line_num=None,
                        line_content=f"action: {action}, source: any, destination: any",
                        description=(
                            f"Decryption rule '{rule_name}' excludes all traffic from decryption "
                            "(any source, any destination). This effectively disables SSL inspection."
                        ),
                        recommendation="Narrow no-decrypt exclusions to specific categories (e.g. financial, health).",
                        cwe="CWE-693",
                    ))

        # PAN-DECRYPT-003: No forward proxy for outbound
        if not has_forward_proxy:
            self._add(Finding(
                rule_id="PAN-DECRYPT-003",
                name="SSL forward proxy not configured for outbound",
                category="Decryption", severity="MEDIUM",
                file_path="rulebase/decryption", line_num=None,
                line_content="ssl-forward-proxy: not configured",
                description=(
                    "No SSL forward proxy decryption rule is configured for outbound traffic. "
                    "Malware C2, data exfiltration, and policy violations over HTTPS "
                    "cannot be detected."
                ),
                recommendation="Configure SSL forward proxy decryption for outbound user traffic.",
                cwe="CWE-693",
            ))

        # PAN-DECRYPT-004: Decryption certificate checks
        for entry in self._find_all(".//ssl-decrypt/entry"):
            cert_name = self._get_entry_name(entry)
            # Check for self-signed forward trust certificate
            forward_trust = entry.find("forward-trust-certificate")
            if forward_trust is not None:
                cert_ref = forward_trust.text.strip() if forward_trust.text else ""
                # Look up the certificate
                for cert_entry in self._find_all(".//certificate/entry"):
                    if self._get_entry_name(cert_entry) == cert_ref:
                        # Check expiry
                        not_valid_after = cert_entry.find("not-valid-after")
                        if not_valid_after is not None and not_valid_after.text:
                            try:
                                expiry_str = not_valid_after.text.strip()
                                # PAN-OS uses various date formats
                                for fmt in ("%b %d %H:%M:%S %Y GMT", "%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                                    try:
                                        expiry = datetime.strptime(expiry_str, fmt)
                                        now = datetime.now()
                                        if expiry < now:
                                            self._add(Finding(
                                                rule_id="PAN-DECRYPT-004",
                                                name="Decryption certificate expired",
                                                category="Decryption", severity="HIGH",
                                                file_path=cert_ref, line_num=None,
                                                line_content=f"not-valid-after: {expiry_str}",
                                                description=(
                                                    f"Decryption certificate '{cert_ref}' expired on {expiry_str}. "
                                                    "SSL decryption with an expired certificate will cause errors "
                                                    "and may cause decryption to fail silently."
                                                ),
                                                recommendation="Renew the decryption certificate before expiry.",
                                                cwe="CWE-324",
                                            ))
                                        break
                                    except ValueError:
                                        continue
                            except Exception:
                                pass

    # ----------------------------------------------------------
    # PAN-UPDATE-001 to PAN-UPDATE-004: Dynamic Update Checks
    # ----------------------------------------------------------
    def _check_dynamic_updates(self):
        self._vprint("  [*] Checking dynamic update schedules ...")

        update_sched = self._find(".//deviceconfig/system/update-schedule")

        # PAN-UPDATE-001: Threat content updates
        threats_sched = None
        if update_sched is not None:
            threats_sched = update_sched.find("threats")
        if threats_sched is None or not list(threats_sched):
            self._add(Finding(
                rule_id="PAN-UPDATE-001",
                name="Threat content updates not scheduled",
                category="Dynamic Updates", severity="HIGH",
                file_path="update-schedule/threats", line_num=None,
                line_content="threats update schedule: not configured",
                description=(
                    "No automatic schedule for threat content updates. The firewall will not "
                    "receive new threat signatures, leaving it unable to detect recently "
                    "discovered exploits and malware."
                ),
                recommendation="Schedule automatic threat content updates (recommended: hourly or every 30 minutes).",
                cwe="CWE-693",
            ))
        else:
            # PAN-UPDATE-004: Check update interval
            recurring = threats_sched.find("recurring")
            if recurring is not None:
                # Check if using weekly (> 24h interval effectively)
                if recurring.find("weekly") is not None:
                    self._add(Finding(
                        rule_id="PAN-UPDATE-004",
                        name="Application and threat update interval too long",
                        category="Dynamic Updates", severity="MEDIUM",
                        file_path="update-schedule/threats", line_num=None,
                        line_content="threats recurring: weekly",
                        description=(
                            "Threat content updates are scheduled weekly. New threat signatures "
                            "should be applied within 24 hours of availability to minimize exposure."
                        ),
                        recommendation="Increase update frequency to at minimum daily, preferably hourly.",
                        cwe="CWE-693",
                    ))

        # PAN-UPDATE-002: Antivirus updates
        av_sched = None
        if update_sched is not None:
            av_sched = update_sched.find("anti-virus")
            if av_sched is None:
                av_sched = update_sched.find("wildfire")  # Some versions combine
        if av_sched is None or not list(av_sched if av_sched is not None else []):
            self._add(Finding(
                rule_id="PAN-UPDATE-002",
                name="Antivirus updates not scheduled",
                category="Dynamic Updates", severity="HIGH",
                file_path="update-schedule/anti-virus", line_num=None,
                line_content="anti-virus update schedule: not configured",
                description=(
                    "No automatic schedule for antivirus content updates. The firewall's "
                    "antivirus signatures will become stale, reducing detection of known malware."
                ),
                recommendation="Schedule automatic antivirus updates (recommended: hourly).",
                cwe="CWE-693",
            ))

        # PAN-UPDATE-003: WildFire updates
        wf_sched = None
        if update_sched is not None:
            wf_sched = update_sched.find("wildfire")
        if wf_sched is None or not list(wf_sched if wf_sched is not None else []):
            self._add(Finding(
                rule_id="PAN-UPDATE-003",
                name="WildFire updates not scheduled",
                category="Dynamic Updates", severity="MEDIUM",
                file_path="update-schedule/wildfire", line_num=None,
                line_content="wildfire update schedule: not configured",
                description=(
                    "No automatic schedule for WildFire content updates. WildFire updates contain "
                    "signatures generated from sandbox analysis of unknown files. Without updates, "
                    "newly discovered malware variants will not be blocked."
                ),
                recommendation="Schedule automatic WildFire updates (recommended: every 15 minutes).",
                cwe="CWE-693",
            ))

    # ----------------------------------------------------------
    # PAN-HA-001 to PAN-HA-003: High Availability Checks
    # ----------------------------------------------------------
    def _check_ha(self):
        self._vprint("  [*] Checking high availability configuration ...")

        ha_config = self._find(".//high-availability")

        # PAN-HA-001: HA not configured
        if ha_config is None or not list(ha_config):
            self._add(Finding(
                rule_id="PAN-HA-001",
                name="HA not configured (single point of failure)",
                category="High Availability", severity="MEDIUM",
                file_path="high-availability", line_num=None,
                line_content="high-availability: not configured",
                description=(
                    "High availability is not configured. The firewall is a single point of failure. "
                    "If the device fails, all traffic through it will be disrupted."
                ),
                recommendation="Configure active/passive or active/active HA for redundancy.",
                cwe="CWE-693",
            ))
            return

        enabled_el = ha_config.find("enabled")
        if enabled_el is None or not enabled_el.text or enabled_el.text.lower() != "yes":
            self._add(Finding(
                rule_id="PAN-HA-001",
                name="HA not configured (single point of failure)",
                category="High Availability", severity="MEDIUM",
                file_path="high-availability", line_num=None,
                line_content="high-availability/enabled: no",
                description=(
                    "High availability is present in config but not enabled. The firewall is a "
                    "single point of failure."
                ),
                recommendation="Enable HA and configure a peer firewall for redundancy.",
                cwe="CWE-693",
            ))
            return

        # PAN-HA-002: Link monitoring
        link_mon = ha_config.find(".//link-monitoring")
        if link_mon is None:
            self._add(Finding(
                rule_id="PAN-HA-002",
                name="HA link monitoring not configured",
                category="High Availability", severity="MEDIUM",
                file_path="high-availability/link-monitoring", line_num=None,
                line_content="link-monitoring: not configured",
                description=(
                    "HA link monitoring is not configured. If a critical link fails, the firewall "
                    "will not automatically failover to the peer, causing traffic disruption."
                ),
                recommendation="Configure link monitoring for critical interfaces to trigger HA failover.",
                cwe="CWE-693",
            ))
        else:
            enabled_el = link_mon.find("enabled")
            if enabled_el is None or not enabled_el.text or enabled_el.text.lower() != "yes":
                self._add(Finding(
                    rule_id="PAN-HA-002",
                    name="HA link monitoring not configured",
                    category="High Availability", severity="MEDIUM",
                    file_path="high-availability/link-monitoring", line_num=None,
                    line_content="link-monitoring/enabled: no",
                    description=(
                        "HA link monitoring is present but not enabled. Interface failures will "
                        "not trigger automatic failover."
                    ),
                    recommendation="Enable link monitoring for critical interfaces.",
                    cwe="CWE-693",
                ))

        # PAN-HA-003: Path monitoring
        path_mon = ha_config.find(".//path-monitoring")
        if path_mon is None:
            self._add(Finding(
                rule_id="PAN-HA-003",
                name="HA path monitoring not configured",
                category="High Availability", severity="LOW",
                file_path="high-availability/path-monitoring", line_num=None,
                line_content="path-monitoring: not configured",
                description=(
                    "HA path monitoring is not configured. If upstream/downstream network paths fail "
                    "while the interfaces remain up, the firewall will not detect the failure and failover."
                ),
                recommendation="Configure path monitoring to critical destinations (default gateway, core router).",
                cwe="CWE-693",
            ))
        else:
            enabled_el = path_mon.find("enabled")
            if enabled_el is None or not enabled_el.text or enabled_el.text.lower() != "yes":
                self._add(Finding(
                    rule_id="PAN-HA-003",
                    name="HA path monitoring not configured",
                    category="High Availability", severity="LOW",
                    file_path="high-availability/path-monitoring", line_num=None,
                    line_content="path-monitoring/enabled: no",
                    description=(
                        "HA path monitoring is present but not enabled. Network path failures "
                        "will not trigger automatic failover."
                    ),
                    recommendation="Enable path monitoring to critical upstream/downstream destinations.",
                    cwe="CWE-693",
                ))

    # ----------------------------------------------------------
    # PAN-GP-001 to PAN-GP-004: GlobalProtect Checks
    # ----------------------------------------------------------
    def _check_globalprotect(self):
        self._vprint("  [*] Checking GlobalProtect configuration ...")

        gp_portals = self._find_all(".//global-protect/global-protect-portal/entry")
        gp_gateways = self._find_all(".//global-protect/global-protect-gateway/entry")

        if not gp_portals and not gp_gateways:
            self._vprint("  [-] GlobalProtect not configured — skipping GP checks")
            return

        # PAN-GP-001: Portal on non-standard port
        for entry in gp_portals:
            portal_name = self._get_entry_name(entry)
            # Check portal config for non-standard port
            portal_config = entry.find("portal-config")
            if portal_config is not None:
                local_addr = portal_config.find("local-address")
                if local_addr is not None:
                    interface_el = local_addr.find("interface")
                    # Non-standard port is a low finding — informational
                    ip_el = local_addr.find("ip")
                    if ip_el is not None and ip_el.text and ":" in ip_el.text:
                        port = ip_el.text.split(":")[-1]
                        if port not in ("443", ""):
                            self._add(Finding(
                                rule_id="PAN-GP-001",
                                name="GlobalProtect portal on non-standard port",
                                category="GlobalProtect", severity="LOW",
                                file_path=portal_name, line_num=None,
                                line_content=f"portal port: {port}",
                                description=(
                                    f"GlobalProtect portal '{portal_name}' is configured on non-standard "
                                    f"port {port}. While security through obscurity has limited value, "
                                    "non-standard ports may cause client connectivity issues."
                                ),
                                recommendation="Use standard HTTPS port 443 for GlobalProtect portal unless there's a specific requirement.",
                                cwe="CWE-693",
                            ))

        # PAN-GP-002: No MFA/certificate authentication
        for entry in gp_gateways:
            gw_name = self._get_entry_name(entry)
            remote_user = entry.find(".//remote-user-tunnel-configs")
            if remote_user is not None:
                for tunnel in remote_user.findall("entry"):
                    auth_profile = tunnel.find("authentication-override")
                    cert_profile = tunnel.find("certificate-profile")
                    # Check if certificate-based or multi-factor auth is used
                    has_cert = cert_profile is not None and cert_profile.text and cert_profile.text.strip()
                    has_2fa = False
                    if auth_profile is not None:
                        cookie_el = auth_profile.find("generate-cookie")
                        # If auth override with just cookie — not true MFA
                        two_factor = auth_profile.find("two-factor")
                        if two_factor is not None:
                            has_2fa = True
                    if not has_cert and not has_2fa:
                        self._add(Finding(
                            rule_id="PAN-GP-002",
                            name="GlobalProtect without MFA/certificate authentication",
                            category="GlobalProtect", severity="HIGH",
                            file_path=gw_name, line_num=None,
                            line_content="certificate-profile: none, MFA: not configured",
                            description=(
                                f"GlobalProtect gateway '{gw_name}' does not require certificate-based "
                                "or multi-factor authentication. Username/password alone is insufficient "
                                "for VPN access and vulnerable to credential stuffing and phishing."
                            ),
                            recommendation="Enable certificate authentication or MFA for GlobalProtect gateway access.",
                            cwe="CWE-308",
                        ))
                        break  # One finding per gateway

        # PAN-GP-003: Split tunnel enabled
        for entry in gp_gateways:
            gw_name = self._get_entry_name(entry)
            for tunnel in entry.findall(".//remote-user-tunnel-configs/entry"):
                split_tunnel = tunnel.find("split-tunneling")
                if split_tunnel is not None:
                    access_route = split_tunnel.find("access-route")
                    if access_route is not None:
                        include_routes = access_route.findall("include/member")
                        # If there are specific include routes (not 0.0.0.0/0), it's split tunnel
                        routes = [m.text for m in include_routes if m.text]
                        if routes and "0.0.0.0/0" not in routes:
                            self._add(Finding(
                                rule_id="PAN-GP-003",
                                name="GlobalProtect split-tunnel enabled",
                                category="GlobalProtect", severity="MEDIUM",
                                file_path=gw_name, line_num=None,
                                line_content=f"split-tunnel include routes: {', '.join(routes[:5])}",
                                description=(
                                    f"GlobalProtect gateway '{gw_name}' has split-tunneling enabled. "
                                    "Internet traffic from remote users bypasses the firewall, eliminating "
                                    "threat inspection, URL filtering, and DLP for non-corporate traffic."
                                ),
                                recommendation="Use full tunnel (route all traffic through VPN) for maximum security visibility.",
                                cwe="CWE-693",
                            ))
                            break

        # PAN-GP-004: HIP check not configured
        for entry in gp_gateways:
            gw_name = self._get_entry_name(entry)
            hip_notification = entry.find(".//hip-notification")
            hip_profiles = self._find_all(".//global-protect/global-protect-gateway/entry/remote-user-tunnel-configs/entry/hip-profiles")
            has_hip = False
            for hp in hip_profiles:
                if list(hp):
                    has_hip = True
                    break
            if not has_hip:
                self._add(Finding(
                    rule_id="PAN-GP-004",
                    name="GlobalProtect HIP check not configured",
                    category="GlobalProtect", severity="MEDIUM",
                    file_path=gw_name, line_num=None,
                    line_content="HIP profiles: not configured",
                    description=(
                        f"GlobalProtect gateway '{gw_name}' does not enforce Host Information Profile "
                        "(HIP) checks. Devices connecting via VPN are not verified for patch level, "
                        "antivirus status, disk encryption, or other compliance requirements."
                    ),
                    recommendation="Configure HIP profiles to verify endpoint compliance before granting VPN access.",
                    cwe="CWE-693",
                ))
                break

    # ----------------------------------------------------------
    # PAN-CERT-001 to PAN-CERT-003: Certificate Checks
    # ----------------------------------------------------------
    def _check_certificates(self):
        self._vprint("  [*] Checking certificate configuration ...")

        for entry in self._find_all(".//certificate/entry"):
            cert_name = self._get_entry_name(entry)

            # PAN-CERT-001: Self-signed certificate for management
            # Check if cert is used for management and is self-signed
            issuer = entry.find("issuer")
            subject = entry.find("subject")
            if issuer is not None and subject is not None:
                issuer_text = issuer.text.strip() if issuer.text else ""
                subject_text = subject.text.strip() if subject.text else ""
                if issuer_text and subject_text and issuer_text == subject_text:
                    self._add(Finding(
                        rule_id="PAN-CERT-001",
                        name="Self-signed certificate detected",
                        category="Certificates", severity="MEDIUM",
                        file_path=cert_name, line_num=None,
                        line_content=f"issuer == subject: {issuer_text[:60]}",
                        description=(
                            f"Certificate '{cert_name}' is self-signed (issuer equals subject). "
                            "Self-signed certificates cannot be validated by clients and are "
                            "susceptible to man-in-the-middle attacks."
                        ),
                        recommendation="Replace with a certificate signed by a trusted CA.",
                        cwe="CWE-295",
                    ))

            # PAN-CERT-002: Certificate expiring within 30 days
            not_valid_after = entry.find("not-valid-after")
            if not_valid_after is not None and not_valid_after.text:
                try:
                    expiry_str = not_valid_after.text.strip()
                    for fmt in ("%b %d %H:%M:%S %Y GMT", "%Y/%m/%d %H:%M:%S",
                                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            expiry = datetime.strptime(expiry_str, fmt)
                            now = datetime.now()
                            days_left = (expiry - now).days
                            if days_left < 0:
                                self._add(Finding(
                                    rule_id="PAN-CERT-002",
                                    name="Certificate expired",
                                    category="Certificates", severity="HIGH",
                                    file_path=cert_name, line_num=None,
                                    line_content=f"expired: {expiry_str} ({abs(days_left)} days ago)",
                                    description=(
                                        f"Certificate '{cert_name}' expired {abs(days_left)} days ago "
                                        f"on {expiry_str}. Expired certificates cause service disruptions "
                                        "and security warnings."
                                    ),
                                    recommendation="Renew the certificate immediately.",
                                    cwe="CWE-324",
                                ))
                            elif days_left <= 30:
                                self._add(Finding(
                                    rule_id="PAN-CERT-002",
                                    name="Certificate expiring within 30 days",
                                    category="Certificates", severity="HIGH",
                                    file_path=cert_name, line_num=None,
                                    line_content=f"expires: {expiry_str} ({days_left} days remaining)",
                                    description=(
                                        f"Certificate '{cert_name}' expires in {days_left} days "
                                        f"on {expiry_str}. Certificate expiration causes service "
                                        "disruptions and may disable security features like SSL decryption."
                                    ),
                                    recommendation="Renew the certificate before expiration.",
                                    cwe="CWE-324",
                                ))
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass

            # PAN-CERT-003: Weak key size
            key_size_el = entry.find("public-key/key-length")
            if key_size_el is None:
                key_size_el = entry.find("key-length")
            if key_size_el is not None and key_size_el.text:
                try:
                    key_size = int(key_size_el.text.strip())
                    if key_size < 2048:
                        self._add(Finding(
                            rule_id="PAN-CERT-003",
                            name="Certificate using weak key size",
                            category="Certificates", severity="MEDIUM",
                            file_path=cert_name, line_num=None,
                            line_content=f"key-length: {key_size} bits",
                            description=(
                                f"Certificate '{cert_name}' uses a {key_size}-bit key. "
                                "Keys shorter than 2048 bits are considered weak and may be "
                                "susceptible to factoring attacks."
                            ),
                            recommendation="Use certificates with at least 2048-bit RSA or 256-bit EC keys.",
                            cwe="CWE-326",
                        ))
                except ValueError:
                    pass

    # ----------------------------------------------------------
    # PAN-NET-001 to PAN-NET-002: Network Configuration Checks
    # ----------------------------------------------------------
    def _check_network_config(self):
        self._vprint("  [*] Checking network configuration ...")

        # Build set of external-facing interfaces (interfaces in untrust/external zones)
        external_interfaces = set()
        for entry in self._find_all(".//zone/entry"):
            zone_name = self._get_entry_name(entry).lower()
            if any(kw in zone_name for kw in ("untrust", "external", "outside", "internet", "dmz")):
                for layer3 in entry.findall(".//layer3/member"):
                    if layer3.text:
                        external_interfaces.add(layer3.text.strip())
                for layer2 in entry.findall(".//layer2/member"):
                    if layer2.text:
                        external_interfaces.add(layer2.text.strip())

        # PAN-NET-001: DNS proxy on external interface
        for entry in self._find_all(".//network/dns-proxy/entry"):
            proxy_name = self._get_entry_name(entry)
            interface_el = entry.find("interface")
            if interface_el is not None:
                for member in interface_el.findall("member"):
                    if member.text and member.text.strip() in external_interfaces:
                        self._add(Finding(
                            rule_id="PAN-NET-001",
                            name="DNS proxy configured on external interface",
                            category="Network Configuration", severity="MEDIUM",
                            file_path=proxy_name, line_num=None,
                            line_content=f"dns-proxy interface: {member.text.strip()}",
                            description=(
                                f"DNS proxy '{proxy_name}' is configured on external-facing interface "
                                f"'{member.text.strip()}'. This could expose the DNS proxy service to "
                                "the internet, enabling DNS amplification attacks or information disclosure."
                            ),
                            recommendation="Remove DNS proxy from external-facing interfaces or restrict access via security policy.",
                            cwe="CWE-668",
                        ))

        # PAN-NET-002: DHCP server on external interface
        for entry in self._find_all(".//network/dhcp/interface/entry"):
            intf_name = self._get_entry_name(entry)
            if intf_name in external_interfaces:
                server = entry.find("server")
                if server is not None:
                    self._add(Finding(
                        rule_id="PAN-NET-002",
                        name="DHCP server on external-facing interface",
                        category="Network Configuration", severity="MEDIUM",
                        file_path=intf_name, line_num=None,
                        line_content=f"dhcp server on: {intf_name}",
                        description=(
                            f"A DHCP server is configured on external-facing interface '{intf_name}'. "
                            "Running DHCP on an external interface is unusual and could expose "
                            "internal network configuration to attackers."
                        ),
                        recommendation="Remove DHCP server from external-facing interfaces.",
                        cwe="CWE-668",
                    ))

    # ----------------------------------------------------------
    # Helper Methods
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
        print(f"{B}  Palo Alto NGFW Security Scanner v{VERSION}  --  Scan Report{R}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Target    : {self.host}")
        if self.device_info:
            hostname = self.device_info.get("hostname", "Unknown")
            model = self.device_info.get("model", "Unknown")
            version = self.device_info.get("sw-version", "Unknown")
            serial = self.device_info.get("serial", "Unknown")
            uptime = self.device_info.get("uptime", "Unknown")
            print(f"  Hostname  : {hostname}")
            print(f"  Model     : {model}")
            print(f"  PAN-OS    : {version}")
            print(f"  Serial    : {serial}")
            print(f"  Uptime    : {uptime}")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

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
            print(f"  Location : {f.file_path}")
            if f.line_content:
                print(f"  Context  : {f.line_content}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            if f.cve:
                print(f"  CVE      : {f.cve}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        # Summary table
        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 72)
        for sev, order in sorted(self.SEVERITY_ORDER.items(), key=lambda x: x[1]):
            color = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 72)

    def save_json(self, path: str):
        device = {}
        if self.device_info:
            device = {
                "hostname": self.device_info.get("hostname", ""),
                "model": self.device_info.get("model", ""),
                "serial": self.device_info.get("serial", ""),
                "panos_version": self.device_info.get("sw-version", ""),
                "uptime": self.device_info.get("uptime", ""),
            }
        report = {
            "scanner": "paloalto_scanner",
            "version": VERSION,
            "generated": datetime.now().isoformat(),
            "target": self.host,
            "device": device,
            "findings_count": len(self.findings),
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

        # Device info header
        device_html = ""
        if self.device_info:
            hostname = esc(self.device_info.get("hostname", "Unknown"))
            model = esc(self.device_info.get("model", "Unknown"))
            version = esc(self.device_info.get("sw-version", "Unknown"))
            serial = esc(self.device_info.get("serial", "Unknown"))
            uptime = esc(self.device_info.get("uptime", "Unknown"))
            device_html = (
                f"<p>Hostname: <strong>{hostname}</strong> &mdash; "
                f"Model: <strong>{model}</strong> &mdash; "
                f"PAN-OS: <strong>{version}</strong></p>"
                f"<p>Serial: {serial} &mdash; Uptime: {uptime}</p>"
            )

        # Chip summary
        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        # Table rows
        rows_html = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rs = row_style.get(f.severity, "")
            st = sev_style.get(f.severity, "")
            cve_text = f" ({esc(f.cve)})" if f.cve else ""
            rows_html += (
                f'<tr style="background:{bg};{rs}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px">'
                f'<span style="{st};padding:3px 10px;border-radius:10px;font-size:0.8em;font-weight:bold">'
                f'{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.9em">'
                f'{esc(f.rule_id)}{cve_text}</td>'
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

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Palo Alto NGFW Security Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1b2e; color: #cdd6f4; min-height: 100vh; }}
  header {{ background: linear-gradient(135deg, #FA582D 0%, #1a1b2e 100%); padding: 28px 36px; border-bottom: 2px solid #313244; }}
  header h1 {{ font-size: 1.7em; font-weight: 700; color: #ffffff; margin-bottom: 8px; }}
  header p {{ color: #e6d5d0; font-size: 0.95em; margin: 2px 0; }}
  .chips {{ padding: 20px 36px; background: #181825; border-bottom: 1px solid #313244; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .chips label {{ color: #a6adc8; font-size: 0.9em; margin-right: 6px; }}
  .filters {{ padding: 16px 36px; background: #1e1e2e; display: flex; gap: 12px; flex-wrap: wrap; border-bottom: 1px solid #313244; }}
  .filters select, .filters input {{ background: #313244; color: #cdd6f4; border: 1px solid #45475a; border-radius: 6px; padding: 6px 12px; font-size: 0.9em; }}
  .container {{ padding: 20px 36px 40px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  th {{ background: #313244; color: #FA582D; padding: 12px 14px; text-align: left; font-weight: 600; position: sticky; top: 0; }}
  tr:hover td {{ filter: brightness(1.12); }}
  td {{ vertical-align: top; }}
  .no-findings {{ text-align: center; padding: 60px; color: #a6e3a1; font-size: 1.2em; }}
</style>
</head>
<body>
<header>
  <h1>Palo Alto NGFW Security Scan Report</h1>
  <p>Scanner: Palo Alto NGFW Security Scanner v{esc(VERSION)}</p>
  <p>Target: {esc(self.host)}</p>
  {device_html}
  <p>Generated: {esc(now)}</p>
  <p>Total Findings: <strong>{len(self.findings)}</strong></p>
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
    {''.join(f'<option value="{esc(c)}">{esc(c)}</option>' for c in sorted({f.category for f in self.findings})) }
  </select>
  <input type="text" id="textFilter" placeholder="Search name / rule ID / CVE …" oninput="applyFilters()" style="flex:1;min-width:200px">
</div>
<div class="container">
{f'<div class="no-findings">No findings — firewall configuration is clean!</div>' if not self.findings else f"""
<table id="findings-table">
<thead><tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th><th>Name</th>
  <th>Location</th><th>Context</th><th>CWE</th>
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
        prog="paloalto_scanner",
        description=(
            f"Palo Alto NGFW Security Scanner v{VERSION} — "
            "Audits PAN-OS firewall rules, CVEs, and misconfigurations via XML API"
        ),
    )
    parser.add_argument(
        "--host", "-H",
        default=os.environ.get("PAN_HOST", ""),
        metavar="HOST",
        help="Firewall IP or hostname. Env: PAN_HOST",
    )
    parser.add_argument(
        "--username", "-u",
        default=os.environ.get("PAN_USERNAME", ""),
        metavar="USERNAME",
        help="Admin username. Env: PAN_USERNAME",
    )
    parser.add_argument(
        "--password", "-p",
        default=os.environ.get("PAN_PASSWORD", ""),
        metavar="PASSWORD",
        help="Admin password. Env: PAN_PASSWORD",
    )
    parser.add_argument(
        "--api-key", "-k",
        default=os.environ.get("PAN_API_KEY", ""),
        metavar="KEY",
        help="Pre-generated API key (alternative to user/pass). Env: PAN_API_KEY",
    )
    parser.add_argument(
        "--panorama",
        action="store_true",
        help="Target is a Panorama management server (adjusts config xpaths)",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificate (default: disabled for self-signed certs)",
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
        help="Verbose output (API calls, config details, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"paloalto_scanner v{VERSION}",
    )

    args = parser.parse_args()

    # Requests check comes after parse_args so --version/--help work without requests installed
    if not HAS_REQUESTS:
        parser.error(
            "The 'requests' library is required.\n"
            "  Install with:  pip install requests"
        )

    # Validate required arguments
    if not args.host:
        parser.error("--host / -H is required (or set PAN_HOST env var)")

    if not args.api_key and (not args.username or not args.password):
        parser.error(
            "Provide either --api-key (-k) or both --username (-u) and --password (-p).\n"
            "  Env vars: PAN_API_KEY or PAN_USERNAME + PAN_PASSWORD"
        )

    scanner = PaloAltoScanner(
        host=args.host,
        username=args.username,
        password=args.password,
        api_key=args.api_key,
        panorama=args.panorama,
        verify_ssl=args.verify_ssl,
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
