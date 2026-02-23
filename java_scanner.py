#!/usr/bin/env python3
"""
Java Security Scanner v1.0
Scans Java applications for security vulnerabilities and misconfigurations.

Author: Krishnendu De

Supports:
  - Java source files (.java)
  - Maven build files (pom.xml)
  - Gradle build files (build.gradle / build.gradle.kts)
  - WAR / JAR / EAR archives
  - Servlet descriptors (web.xml)
  - Spring Boot configuration (.properties / .yml / .yaml)
"""

import os
import re
import sys
import json
import zipfile
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

VERSION = "1.0.0"

# ============================================================
# SAST RULES  (Java source code patterns)
# ============================================================
SAST_RULES = [
    # --- Insecure Deserialization ---
    {
        "id": "DESER-001",
        "category": "Insecure Deserialization",
        "name": "Unsafe ObjectInputStream usage",
        "severity": "CRITICAL",
        "pattern": r"\bnew\s+ObjectInputStream\s*\(",
        "description": (
            "ObjectInputStream.readObject() can execute arbitrary code when the "
            "serialized data comes from an untrusted source. This is the root cause "
            "of CVE-2015-7501, CVE-2015-8103, and many other Java deserialization CVEs."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Use an ObjectInputFilter (Java 9+) to restrict which classes can be "
            "deserialized. Prefer safer formats (JSON, Protobuf) for untrusted data."
        ),
    },
    {
        "id": "DESER-002",
        "category": "Insecure Deserialization",
        "name": "Custom readObject() method – potential gadget endpoint",
        "severity": "HIGH",
        "pattern": r"private\s+void\s+readObject\s*\(\s*ObjectInputStream",
        "description": (
            "Custom readObject() methods are invoked automatically during deserialization "
            "and can be exploited as gadget chain endpoints."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Ensure readObject() does not perform sensitive operations and validates "
            "all fields before use."
        ),
    },
    {
        "id": "DESER-003",
        "category": "Insecure Deserialization",
        "name": "XMLDecoder – code execution via XML deserialization",
        "severity": "CRITICAL",
        "pattern": r"\bnew\s+XMLDecoder\s*\(",
        "description": (
            "XMLDecoder executes arbitrary Java code embedded in XML. Feeding it "
            "attacker-controlled data is equivalent to remote code execution."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Replace XMLDecoder with a safe XML parser (JAXB, Jackson XML, etc.). "
            "Never parse untrusted input with XMLDecoder."
        ),
    },
    {
        "id": "DESER-004",
        "category": "Insecure Deserialization",
        "name": "SnakeYAML unsafe load – potential RCE",
        "severity": "CRITICAL",
        "pattern": r"(?:new\s+Yaml\s*\(\s*\)|\.load\s*\([^)]*\))",
        "description": (
            "SnakeYAML's Yaml.load() without a SafeConstructor can instantiate arbitrary "
            "Java types, enabling remote code execution via crafted YAML."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Use new Yaml(new SafeConstructor()) or Yaml.safeLoad() to restrict "
            "allowed types."
        ),
    },
    {
        "id": "DESER-005",
        "category": "Insecure Deserialization",
        "name": "XStream deserialization without security framework",
        "severity": "CRITICAL",
        "pattern": r"\bnew\s+XStream\s*\(",
        "description": (
            "XStream without an allowlist security framework allows RCE via crafted XML "
            "(CVE-2021-39144, CVE-2013-7285)."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Configure XStream with an explicit allowlist: "
            "xstream.allowTypesByWildcard(new String[]{\"com.example.**\"})."
        ),
    },

    # --- SQL Injection ---
    {
        "id": "SQLI-001",
        "category": "SQL Injection",
        "name": "String concatenation in JDBC query",
        "severity": "CRITICAL",
        "pattern": r'"(?:SELECT|INSERT|UPDATE|DELETE|EXEC|CALL)[^"]*"\s*\+',
        "description": (
            "Building SQL queries via string concatenation with user data enables "
            "SQL injection, allowing attackers to read, modify, or delete database content."
        ),
        "cwe": "CWE-89",
        "recommendation": (
            "Use PreparedStatement with parameterized placeholders (?). "
            "Never concatenate user input into SQL strings."
        ),
    },
    {
        "id": "SQLI-002",
        "category": "SQL Injection",
        "name": "Dynamic query passed to execute/prepareStatement",
        "severity": "HIGH",
        "pattern": r"(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*\w+\s*\+",
        "description": (
            "A dynamically built string is passed to a JDBC execute method. "
            "If any component is user-controlled this is exploitable."
        ),
        "cwe": "CWE-89",
        "recommendation": "Use parameterized PreparedStatement queries.",
    },

    # --- Command Injection ---
    {
        "id": "CMDI-001",
        "category": "Command Injection",
        "name": "Runtime.exec() – potential command injection",
        "severity": "CRITICAL",
        "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(",
        "description": (
            "Runtime.exec() executes OS commands. Arguments that contain unsanitized "
            "user input allow arbitrary command execution."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Avoid passing user input to Runtime.exec(). Use an allowlist for "
            "permitted commands and split arguments as an array, not a shell string."
        ),
    },
    {
        "id": "CMDI-002",
        "category": "Command Injection",
        "name": "ProcessBuilder – review for user-controlled arguments",
        "severity": "HIGH",
        "pattern": r"\bnew\s+ProcessBuilder\s*\(",
        "description": (
            "ProcessBuilder executes OS commands. Verify no argument is derived from "
            "user-supplied data."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Pass commands as a fixed string array. Sanitize and validate any "
            "argument that may originate from external input."
        ),
    },

    # --- Path Traversal ---
    {
        "id": "PATH-001",
        "category": "Path Traversal",
        "name": "File path built from request parameter",
        "severity": "HIGH",
        "pattern": r"\bnew\s+File\s*\(\s*(?:request\.|req\.|getParameter)",
        "description": (
            "Constructing a file path from HTTP request parameters enables path "
            "traversal attacks (e.g. ../../etc/passwd)."
        ),
        "cwe": "CWE-22",
        "recommendation": (
            "Call File.getCanonicalPath() and verify the result starts with the "
            "expected base directory. Reject paths containing '..'."
        ),
    },
    {
        "id": "PATH-002",
        "category": "Path Traversal",
        "name": "Paths.get() with user input",
        "severity": "HIGH",
        "pattern": r"Paths\.get\s*\(\s*(?:request\.|req\.|getParameter)",
        "description": "Path constructed from request parameter without canonicalization.",
        "cwe": "CWE-22",
        "recommendation": "Canonicalize the path and validate it is within an expected root.",
    },

    # --- Cross-Site Scripting ---
    {
        "id": "XSS-001",
        "category": "Cross-Site Scripting (XSS)",
        "name": "Unencoded user input written to HTTP response",
        "severity": "HIGH",
        "pattern": r"(?:getWriter|PrintWriter).*\.(?:print|println|write)\s*\(",
        "description": (
            "Writing unsanitized user input to the HTTP response enables reflected XSS."
        ),
        "cwe": "CWE-79",
        "recommendation": (
            "HTML-encode all user-supplied data before writing to the response. "
            "Use OWASP Java Encoder: Encode.forHtml(userInput)."
        ),
    },

    # --- Hardcoded Credentials ---
    {
        "id": "CRED-001",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded password / secret in source code",
        "severity": "HIGH",
        "pattern": r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?token)\s*=\s*"[^"]{4,}"',
        "description": (
            "Hardcoded credentials can be extracted from the compiled artifact or "
            "source repository by any reader."
        ),
        "cwe": "CWE-798",
        "recommendation": (
            "Load credentials from environment variables or a secrets manager "
            "(HashiCorp Vault, AWS Secrets Manager, etc.)."
        ),
    },
    {
        "id": "CRED-002",
        "category": "Hardcoded Credentials",
        "name": "JDBC URL with embedded password",
        "severity": "HIGH",
        "pattern": r'jdbc:[a-z]+://[^"\']*(?:password|pwd)=[^"\'&\s]+',
        "description": "Database connection string with an embedded plaintext password.",
        "cwe": "CWE-798",
        "recommendation": "Supply database passwords via environment variables or a vault.",
    },

    # --- Weak Cryptography ---
    {
        "id": "CRYPTO-001",
        "category": "Weak Cryptography",
        "name": "MD5 used as cryptographic hash",
        "severity": "MEDIUM",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)',
        "description": (
            "MD5 is cryptographically broken and vulnerable to collision attacks. "
            "It must not be used for security purposes."
        ),
        "cwe": "CWE-327",
        "recommendation": "Use SHA-256 or SHA-3. For passwords, use bcrypt, scrypt, or Argon2.",
    },
    {
        "id": "CRYPTO-002",
        "category": "Weak Cryptography",
        "name": "SHA-1 used as cryptographic hash",
        "severity": "MEDIUM",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"\s*\)',
        "description": "SHA-1 is deprecated for security use due to demonstrated collision vulnerabilities.",
        "cwe": "CWE-327",
        "recommendation": "Replace with SHA-256 or SHA-3.",
    },
    {
        "id": "CRYPTO-003",
        "category": "Weak Cryptography",
        "name": "DES / 3DES (DESede) cipher",
        "severity": "HIGH",
        "pattern": r'Cipher\.getInstance\s*\(\s*"(?:DES|DESede|TripleDES)',
        "description": "DES has a 56-bit key and is trivially brute-forced. 3DES is deprecated by NIST (SP 800-131A).",
        "cwe": "CWE-327",
        "recommendation": "Use AES-256 in GCM mode: Cipher.getInstance(\"AES/GCM/NoPadding\").",
    },
    {
        "id": "CRYPTO-004",
        "category": "Weak Cryptography",
        "name": "ECB cipher mode",
        "severity": "HIGH",
        "pattern": r'Cipher\.getInstance\s*\(\s*"[^"]+/ECB/',
        "description": (
            "ECB mode is deterministic — identical plaintext blocks produce identical "
            "ciphertext blocks, leaking patterns in the data."
        ),
        "cwe": "CWE-327",
        "recommendation": "Use AES/GCM/NoPadding for authenticated encryption.",
    },
    {
        "id": "CRYPTO-005",
        "category": "Weak Cryptography",
        "name": "java.util.Random – not cryptographically secure",
        "severity": "MEDIUM",
        "pattern": r"\bnew\s+(?:java\.util\.)?Random\s*\(",
        "description": (
            "java.util.Random is a predictable PRNG unsuitable for security tokens, "
            "nonces, session IDs, or key material."
        ),
        "cwe": "CWE-338",
        "recommendation": "Replace with java.security.SecureRandom.",
    },

    # --- XXE ---
    {
        "id": "XXE-001",
        "category": "XML External Entity (XXE)",
        "name": "DocumentBuilderFactory without external entity protection",
        "severity": "HIGH",
        "pattern": r"DocumentBuilderFactory\.newInstance\s*\(",
        "description": (
            "Default DocumentBuilderFactory processes external entity references, "
            "enabling XXE attacks that can read local files or perform SSRF."
        ),
        "cwe": "CWE-611",
        "recommendation": (
            'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'
        ),
    },
    {
        "id": "XXE-002",
        "category": "XML External Entity (XXE)",
        "name": "SAXParserFactory without external entity protection",
        "severity": "HIGH",
        "pattern": r"SAXParserFactory\.newInstance\s*\(",
        "description": "SAXParserFactory without XXE protection is vulnerable to external entity injection.",
        "cwe": "CWE-611",
        "recommendation": (
            'Enable FEATURE_SECURE_PROCESSING and set '
            '"http://xml.org/sax/features/external-general-entities" to false.'
        ),
    },
    {
        "id": "XXE-003",
        "category": "XML External Entity (XXE)",
        "name": "XMLInputFactory without external entity protection",
        "severity": "HIGH",
        "pattern": r"XMLInputFactory\.newInstance\s*\(",
        "description": "StAX XMLInputFactory without XXE hardening.",
        "cwe": "CWE-611",
        "recommendation": (
            'factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);'
        ),
    },

    # --- SSRF ---
    {
        "id": "SSRF-001",
        "category": "Server-Side Request Forgery (SSRF)",
        "name": "URL opened from user-supplied value",
        "severity": "HIGH",
        "pattern": r"\bnew\s+URL\s*\(\s*(?:request\.|req\.|getParameter)",
        "description": (
            "Opening a network connection to a user-supplied URL lets attackers "
            "route requests through the server to internal services."
        ),
        "cwe": "CWE-918",
        "recommendation": "Validate URLs against an allowlist of trusted hosts. Block private IP ranges.",
    },

    # --- Open Redirect ---
    {
        "id": "REDIR-001",
        "category": "Open Redirect",
        "name": "sendRedirect with user-supplied URL",
        "severity": "MEDIUM",
        "pattern": r"response\.sendRedirect\s*\(\s*(?:request\.|req\.|getParameter)",
        "description": "Redirecting to a user-controlled URL enables phishing via a trusted domain.",
        "cwe": "CWE-601",
        "recommendation": "Validate redirect targets against an allowlist of permitted destinations.",
    },

    # --- SSL/TLS ---
    {
        "id": "TLS-001",
        "category": "Insecure TLS Configuration",
        "name": "SSL certificate validation disabled",
        "severity": "CRITICAL",
        "pattern": r"(?:TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})",
        "description": (
            "Disabling certificate validation makes every TLS connection transparent "
            "to a network attacker (MITM)."
        ),
        "cwe": "CWE-295",
        "recommendation": "Always validate certificates. Remove any custom trust managers that blindly trust all certs.",
    },

    # --- Log Injection / Log4Shell ---
    {
        "id": "LOG-001",
        "category": "Log Injection",
        "name": "Unsanitized user input written to log",
        "severity": "MEDIUM",
        "pattern": r"(?:log|logger|LOG|LOGGER)\s*\.\s*(?:info|debug|warn|error|trace|fatal)\s*\(\s*(?:request\.|req\.|getParameter)",
        "description": (
            "Logging raw user input can cause log injection and, in Log4j 2.x < 2.15.0, "
            "trigger JNDI lookups via ${jndi:...} sequences (Log4Shell, CVE-2021-44228)."
        ),
        "cwe": "CWE-117",
        "recommendation": (
            "Sanitize user input before logging (strip/escape ${...} sequences). "
            "Upgrade Log4j to 2.17.1+ or set log4j2.formatMsgNoLookups=true."
        ),
    },

    # --- Insecure HTTP method handling ---
    {
        "id": "HTTP-001",
        "category": "Insecure Configuration",
        "name": "doGet processes data-mutation requests",
        "severity": "MEDIUM",
        "pattern": r"protected\s+void\s+doGet\s*\(.*HttpServletRequest",
        "description": (
            "Using HTTP GET for state-changing operations bypasses CSRF protections "
            "and may be triggered via img tags or prefetch."
        ),
        "cwe": "CWE-352",
        "recommendation": "Use POST/PUT/DELETE for state-changing operations and implement CSRF tokens.",
    },
]

# ============================================================
# KNOWN VULNERABLE DEPENDENCIES
# ============================================================
VULNERABLE_DEPENDENCIES = {
    "commons-collections": [
        {
            "affected": "<3.2.2",
            "cve": "CVE-2015-7501",
            "severity": "CRITICAL",
            "description": "Commons Collections deserialization gadget chains (CC1–CC6) enable unauthenticated RCE.",
            "fix": "3.2.2",
        },
        {
            "affected": ">=4.0,<4.1",
            "cve": "CVE-2015-8103",
            "severity": "CRITICAL",
            "description": "CommonsCollections4 gadget chain enables RCE via unsafe deserialization.",
            "fix": "4.1",
        },
    ],
    "log4j-core": [
        {
            "affected": ">=2.0-beta9,<2.15.0",
            "cve": "CVE-2021-44228",
            "severity": "CRITICAL",
            "description": "Log4Shell: JNDI injection via log messages allows unauthenticated RCE.",
            "fix": "2.15.0",
        },
        {
            "affected": ">=2.15.0,<2.16.0",
            "cve": "CVE-2021-45046",
            "severity": "CRITICAL",
            "description": "Incomplete fix for Log4Shell; still exploitable in non-default configurations.",
            "fix": "2.16.0",
        },
        {
            "affected": ">=2.0-alpha1,<2.17.0",
            "cve": "CVE-2021-45105",
            "severity": "HIGH",
            "description": "Log4j infinite recursion DoS via crafted lookup strings.",
            "fix": "2.17.0",
        },
    ],
    "spring-core": [
        {
            "affected": "<5.3.18",
            "cve": "CVE-2022-22965",
            "severity": "CRITICAL",
            "description": "Spring4Shell: data-binding RCE on Tomcat with JDK 9+ via ClassLoader manipulation.",
            "fix": "5.3.18",
        },
    ],
    "spring-webmvc": [
        {
            "affected": "<5.3.18",
            "cve": "CVE-2022-22965",
            "severity": "CRITICAL",
            "description": "Spring4Shell affects Spring MVC applications on JDK 9+.",
            "fix": "5.3.18",
        },
    ],
    "struts2-core": [
        {
            "affected": ">=2.3.5,<2.3.35",
            "cve": "CVE-2017-5638",
            "severity": "CRITICAL",
            "description": "Jakarta Multipart parser RCE via Content-Type header (Equifax breach vector).",
            "fix": "2.3.35",
        },
        {
            "affected": ">=2.0.0,<2.5.22",
            "cve": "CVE-2019-0230",
            "severity": "CRITICAL",
            "description": "OGNL expression injection via forced double evaluation.",
            "fix": "2.5.22",
        },
    ],
    "jackson-databind": [
        {
            "affected": "<2.9.10",
            "cve": "CVE-2019-14379",
            "severity": "CRITICAL",
            "description": "Polymorphic type handling gadget allows RCE via deserialization.",
            "fix": "2.9.10",
        },
        {
            "affected": "<2.13.2",
            "cve": "CVE-2022-42003",
            "severity": "HIGH",
            "description": "Deep recursion DoS via specially crafted JSON.",
            "fix": "2.13.2",
        },
    ],
    "shiro-core": [
        {
            "affected": "<1.2.5",
            "cve": "CVE-2016-4437",
            "severity": "CRITICAL",
            "description": "RememberMe cookie deserialization enables unauthenticated RCE (Shiro-550).",
            "fix": "1.2.5",
        },
        {
            "affected": "<1.7.1",
            "cve": "CVE-2020-17523",
            "severity": "HIGH",
            "description": "Authentication bypass via path traversal in URL pattern matching.",
            "fix": "1.7.1",
        },
    ],
    "xstream": [
        {
            "affected": "<1.4.7",
            "cve": "CVE-2013-7285",
            "severity": "CRITICAL",
            "description": "XStream allows arbitrary code execution via crafted XML.",
            "fix": "1.4.7",
        },
        {
            "affected": "<1.4.18",
            "cve": "CVE-2021-39144",
            "severity": "CRITICAL",
            "description": "XStream RCE via crafted XML without allowlist security framework.",
            "fix": "1.4.18",
        },
    ],
    "fastjson": [
        {
            "affected": "<1.2.68",
            "cve": "CVE-2020-9547",
            "severity": "CRITICAL",
            "description": "Fastjson autoType deserialization enables RCE with crafted JSON.",
            "fix": "1.2.68",
        },
    ],
    "h2": [
        {
            "affected": ">=1.1.100,<2.1.210",
            "cve": "CVE-2021-42392",
            "severity": "CRITICAL",
            "description": "JNDI injection via H2 JDBC URL / console allows RCE.",
            "fix": "2.1.210",
        },
    ],
    "bcprov-jdk15on": [
        {
            "affected": "<1.61",
            "cve": "CVE-2018-1000613",
            "severity": "HIGH",
            "description": "Bouncy Castle deserialization issue in certificate parsing.",
            "fix": "1.61",
        },
    ],
    "netty-codec": [
        {
            "affected": "<4.1.68.Final",
            "cve": "CVE-2021-37136",
            "severity": "HIGH",
            "description": "Bzip2Decoder DoS via excessive memory allocation.",
            "fix": "4.1.68.Final",
        },
    ],
}

# ============================================================
# SPRING BOOT / PROPERTIES MISCONFIGURATION RULES
# ============================================================
SPRING_RULES = [
    {
        "id": "SPRING-001",
        "name": "All actuator endpoints exposed",
        "severity": "HIGH",
        "pattern": r"management\.endpoints\.web\.exposure\.include\s*=\s*\*",
        "description": "Wildcard actuator exposure leaks /env, /heapdump, /logfile, and other sensitive endpoints.",
        "recommendation": "Restrict to: management.endpoints.web.exposure.include=health,info",
    },
    {
        "id": "SPRING-002",
        "name": "Spring debug mode enabled",
        "severity": "MEDIUM",
        "pattern": r"(?:^|\s)debug\s*=\s*true",
        "description": "Debug mode enables verbose logging and may expose sensitive data in error responses.",
        "recommendation": "Set debug=false in production.",
    },
    {
        "id": "SPRING-003",
        "name": "H2 console enabled",
        "severity": "HIGH",
        "pattern": r"spring\.h2\.console\.enabled\s*=\s*true",
        "description": "The H2 console exposes unrestricted database access and can be used for JNDI injection (CVE-2021-42392).",
        "recommendation": "Disable in production: spring.h2.console.enabled=false",
    },
    {
        "id": "SPRING-004",
        "name": "Spring DevTools remote secret configured",
        "severity": "HIGH",
        "pattern": r"spring\.devtools\.remote\.secret\s*=",
        "description": "Remote DevTools provide a remote code execution entry point.",
        "recommendation": "Remove remote DevTools configuration from production builds.",
    },
    {
        "id": "SPRING-005",
        "name": "Wildcard CORS origin",
        "severity": "MEDIUM",
        "pattern": r"(?:allowed-origins|allowedOrigins)\s*[=:]\s*\*",
        "description": "Allowing all origins bypasses the same-origin policy and enables cross-origin attacks.",
        "recommendation": "Restrict CORS to specific trusted origins.",
    },
    {
        "id": "SPRING-006",
        "name": "Plaintext datasource password in config",
        "severity": "HIGH",
        "pattern": r"spring\.datasource\.password\s*=\s*\S+",
        "description": "Database password stored in plaintext in configuration.",
        "recommendation": "Use environment variables or an encrypted secrets store.",
    },
    {
        "id": "SPRING-007",
        "name": "SSL disabled",
        "severity": "HIGH",
        "pattern": r"server\.ssl\.enabled\s*=\s*false",
        "description": "TLS/SSL is explicitly disabled, transmitting all traffic in cleartext.",
        "recommendation": "Enable TLS and configure a valid certificate.",
    },
    {
        "id": "SPRING-008",
        "name": "Request details logging enabled",
        "severity": "MEDIUM",
        "pattern": r"spring\.mvc\.log-request-details\s*=\s*true",
        "description": "Logging full request details may expose headers, cookies, and request bodies.",
        "recommendation": "Disable in production.",
    },
]


# ============================================================
# Finding data class
# ============================================================
class Finding:
    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = str(file_path)
        self.line_num = line_num
        self.line_content = line_content.strip() if line_content else ""
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe
        self.cve = cve


# ============================================================
# Main scanner class
# ============================================================
class JavaScanner:
    SKIP_DIRS = {".git", "node_modules", "target", "build", ".gradle", ".idea", "__pycache__"}

    def __init__(self, verbose=False):
        self.findings = []
        self.verbose = verbose
        self.scanned_files = 0

    # ----------------------------------------------------------
    # Entry points
    # ----------------------------------------------------------
    def scan_path(self, path):
        path = Path(path)
        if path.is_file():
            self._dispatch_file(path)
        elif path.is_dir():
            self._scan_directory(path)
        else:
            print(f"[-] Path not found: {path}", file=sys.stderr)

    def _scan_directory(self, directory):
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for filename in files:
                self._dispatch_file(Path(root) / filename)

    def _dispatch_file(self, filepath):
        name = filepath.name.lower()
        suffix = filepath.suffix.lower()
        if suffix == ".java":
            self._scan_java_source(filepath)
        elif name == "pom.xml":
            self._scan_pom_xml(filepath)
        elif name in ("build.gradle", "build.gradle.kts"):
            self._scan_gradle(filepath)
        elif name == "web.xml":
            self._scan_webxml_file(filepath)
        elif suffix in (".properties", ".yml", ".yaml"):
            self._scan_properties_file(filepath)
        elif suffix in (".jar", ".war", ".ear"):
            self._scan_archive(filepath)

    # ----------------------------------------------------------
    # Java source SAST
    # ----------------------------------------------------------
    def _scan_java_source(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [java] {filepath}")

        compiled = [(rule, re.compile(rule["pattern"])) for rule in SAST_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                if rx.search(line):
                    self._add(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        file_path=filepath,
                        line_num=lineno,
                        line_content=line.rstrip(),
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe"),
                    ))

    # ----------------------------------------------------------
    # Maven pom.xml
    # ----------------------------------------------------------
    def _scan_pom_xml(self, filepath):
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except Exception as exc:
            self._warn(f"Cannot parse {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [pom] {filepath}")

        # Detect namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        for dep in root.iter(f"{ns}dependency"):
            artifact_el = dep.find(f"{ns}artifactId")
            version_el = dep.find(f"{ns}version")
            if artifact_el is None:
                continue
            artifact = artifact_el.text or ""
            version = (version_el.text or "") if version_el is not None else ""
            if version.startswith("${") or not version:
                continue
            self._check_dep(filepath, artifact, version)

    # ----------------------------------------------------------
    # Gradle build files
    # ----------------------------------------------------------
    def _scan_gradle(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [gradle] {filepath}")

        # Matches: 'group:artifact:version' or "group:artifact:version"
        rx = re.compile(r"""['"]([a-zA-Z0-9._\-]+):([a-zA-Z0-9._\-]+):([a-zA-Z0-9._+\-]+)['"]""")
        for m in rx.finditer(content):
            _group, artifact, version = m.groups()
            self._check_dep(filepath, artifact, version)

    # ----------------------------------------------------------
    # Dependency version check
    # ----------------------------------------------------------
    def _check_dep(self, filepath, artifact, version):
        for vuln in VULNERABLE_DEPENDENCIES.get(artifact, []):
            if self._version_in_range(version, vuln["affected"]):
                self._add(Finding(
                    rule_id=f"DEP-{vuln['cve'].replace('-', '')}",
                    name=f"Vulnerable dependency: {artifact} {version}",
                    category="Vulnerable Dependency",
                    severity=vuln["severity"],
                    file_path=filepath,
                    line_num=0,
                    line_content=f"{artifact}:{version}",
                    description=vuln["description"],
                    recommendation=f"Upgrade {artifact} to {vuln['fix']} or later.",
                    cve=vuln["cve"],
                ))

    @staticmethod
    def _parse_ver(s):
        """Parse a version string into a comparable tuple of ints."""
        s = re.sub(r"[-.]?(RELEASE|FINAL|GA|SNAPSHOT|alpha\d*|beta\d*|rc\d*).*$",
                   "", s, flags=re.IGNORECASE)
        parts = re.split(r"[.\-]", s)
        try:
            return tuple(int(p) for p in parts if p.isdigit())
        except ValueError:
            return None

    def _version_in_range(self, version, range_str):
        """Evaluate a version against a constraint like '<3.2.2' or '>=2.0,<2.15.0'."""
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
            # Pad to equal length
            length = max(len(pv), len(tv))
            a = pv + (0,) * (length - len(pv))
            b = tv + (0,) * (length - len(tv))
            checks = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}
            if not checks.get(op, False):
                return False
        return True

    # ----------------------------------------------------------
    # web.xml
    # ----------------------------------------------------------
    def _scan_webxml_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return
        self.scanned_files += 1
        self._vprint(f"  [web.xml] {filepath}")
        self._scan_webxml_content(filepath, content)

    def _scan_webxml_content(self, label, content):
        # Directory listing
        if re.search(
            r"<param-name>\s*listings\s*</param-name>\s*<param-value>\s*true\s*</param-value>",
            content, re.DOTALL
        ):
            self._add(Finding(
                rule_id="WEBXML-001", name="Directory listing enabled",
                category="Misconfiguration", severity="MEDIUM",
                file_path=label, line_num=0, line_content="listings=true",
                description="DefaultServlet directory listing exposes the application's file structure.",
                recommendation="Set listings=false for the DefaultServlet.",
            ))

        if "<session-config>" in content:
            if not re.search(r"<http-only>\s*true", content, re.IGNORECASE):
                self._add(Finding(
                    rule_id="WEBXML-002", name="Session cookie missing HttpOnly flag",
                    category="Misconfiguration", severity="HIGH",
                    file_path=label, line_num=0, line_content="<session-config>",
                    description="Cookies without HttpOnly are accessible to JavaScript, enabling theft via XSS.",
                    recommendation="Add <cookie-config><http-only>true</http-only></cookie-config>.",
                ))
            if not re.search(r"<secure>\s*true", content, re.IGNORECASE):
                self._add(Finding(
                    rule_id="WEBXML-003", name="Session cookie missing Secure flag",
                    category="Misconfiguration", severity="HIGH",
                    file_path=label, line_num=0, line_content="<session-config>",
                    description="Cookies without Secure can be sent over unencrypted HTTP connections.",
                    recommendation="Add <cookie-config><secure>true</secure></cookie-config>.",
                ))

        if "<security-constraint>" not in content:
            self._add(Finding(
                rule_id="WEBXML-004", name="No security-constraint defined",
                category="Misconfiguration", severity="LOW",
                file_path=label, line_num=0, line_content="",
                description="No HTTP security constraints found; access controls may be absent.",
                recommendation="Define <security-constraint> blocks to restrict URL access and HTTP methods.",
            ))

        # Error page not configured (stack traces leaked)
        if "<error-page>" not in content:
            self._add(Finding(
                rule_id="WEBXML-005", name="No error page configured",
                category="Misconfiguration", severity="LOW",
                file_path=label, line_num=0, line_content="",
                description="Without a custom error page, stack traces may be exposed to users.",
                recommendation="Configure <error-page> elements for 400, 403, 404, and 500 status codes.",
            ))

    # ----------------------------------------------------------
    # .properties / .yml / .yaml
    # ----------------------------------------------------------
    def _scan_properties_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return
        self.scanned_files += 1
        self._vprint(f"  [props] {filepath}")
        self._scan_properties_lines(filepath, lines)

    def _scan_properties_lines(self, label, lines):
        compiled = [(rule, re.compile(rule["pattern"], re.IGNORECASE)) for rule in SPRING_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("!"):
                    continue
                if rx.search(line):
                    self._add(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category="Misconfiguration",
                        severity=rule["severity"],
                        file_path=label,
                        line_num=lineno,
                        line_content=line.rstrip(),
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                    ))

    # ----------------------------------------------------------
    # JAR / WAR / EAR archives
    # ----------------------------------------------------------
    def _scan_archive(self, filepath):
        self._vprint(f"  [archive] {filepath}")
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                self._scan_zip(zf, str(filepath))
        except zipfile.BadZipFile:
            self._warn(f"Not a valid ZIP archive: {filepath}")
        except Exception as exc:
            self._warn(f"Error scanning archive {filepath}: {exc}")
        self.scanned_files += 1

    def _scan_zip(self, zf, label_prefix):
        import io
        for entry in zf.namelist():
            lower = entry.lower()
            entry_label = f"{label_prefix}!{entry}"

            if lower.endswith("web.xml"):
                try:
                    self._scan_webxml_content(entry_label, zf.read(entry).decode("utf-8", errors="ignore"))
                except Exception:
                    pass

            elif lower.endswith((".properties", ".yml", ".yaml")):
                try:
                    lines = zf.read(entry).decode("utf-8", errors="ignore").splitlines()
                    self._scan_properties_lines(entry_label, lines)
                except Exception:
                    pass

            elif lower.endswith("pom.properties"):
                try:
                    self._check_pom_properties(entry_label, zf.read(entry).decode("utf-8", errors="ignore"))
                except Exception:
                    pass

            elif lower.endswith(".jar"):
                # Embedded JAR — check name and recurse into it
                jar_name = os.path.basename(entry)
                self._check_jar_name(entry_label, jar_name)
                try:
                    nested = zipfile.ZipFile(io.BytesIO(zf.read(entry)), "r")
                    self._scan_zip(nested, entry_label)
                except Exception:
                    pass

    def _check_jar_name(self, label, jar_name):
        """Infer artifact and version from a JAR filename like commons-collections-3.2.1.jar."""
        m = re.match(r"^(.+?)-(\d+(?:\.\d+)+(?:\.[a-zA-Z0-9_\-]+)?)\.jar$", jar_name)
        if m:
            artifact, version = m.group(1), m.group(2)
            self._check_dep(label, artifact, version)

    def _check_pom_properties(self, label, content):
        props = {}
        for line in content.splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()
        artifact = props.get("artifactId", "")
        version = props.get("version", "")
        if artifact and version:
            self._check_dep(label, artifact, version)

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _add(self, finding):
        self.findings.append(finding)

    def _vprint(self, msg):
        if self.verbose:
            print(msg)

    def _warn(self, msg):
        if self.verbose:
            print(f"  [!] {msg}", file=sys.stderr)

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
        "INFO":     "\033[97m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def summary(self):
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity):
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'='*72}{R}")
        print(f"{B}  Java Security Scanner v{VERSION}  —  Scan Report{R}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Scanned   : {self.scanned_files} file(s)")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.file_path, f.line_num),
        )

        for f in sorted_findings:
            color = self.SEVERITY_COLOR.get(f.severity, "")
            loc = f.file_path + (f":{f.line_num}" if f.line_num else "")
            print(f"{color}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Location : {loc}")
            if f.line_content:
                snippet = f.line_content[:120]
                print(f"  Code     : {snippet}")
            if f.cve:
                print(f"  CVE      : {f.cve}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print(f"{'='*72}")
        for sev in self.SEVERITY_ORDER:
            n = counts.get(sev, 0)
            if n:
                color = self.SEVERITY_COLOR.get(sev, "")
                print(f"  {color}{sev:<10}{R}  {n}")
        print(f"{'='*72}\n")

    def save_json(self, output_path):
        report = {
            "scanner": f"Java Security Scanner v{VERSION}",
            "generated": datetime.now().isoformat(),
            "files_scanned": self.scanned_files,
            "total_findings": len(self.findings),
            "summary": self.summary(),
            "findings": [
                {
                    "id":             f.rule_id,
                    "name":           f.name,
                    "category":       f.category,
                    "severity":       f.severity,
                    "file":           f.file_path,
                    "line":           f.line_num,
                    "code":           f.line_content,
                    "description":    f.description,
                    "recommendation": f.recommendation,
                    "cwe":            f.cwe,
                    "cve":            f.cve,
                }
                for f in self.findings
            ],
        }
        with open(output_path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] JSON report saved to: {output_path}")


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description=f"Java Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 java_scanner.py /path/to/project
  python3 java_scanner.py /path/to/app.war --json report.json
  python3 java_scanner.py pom.xml --verbose
  python3 java_scanner.py /src --severity HIGH
""",
    )
    parser.add_argument("target", help="File or directory to scan (supports .java, pom.xml, .gradle, .war, .jar, .ear)")
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Only report findings at this severity or above")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print(f"[*] Java Security Scanner v{VERSION}")
    print(f"[*] Target: {args.target}\n")

    scanner = JavaScanner(verbose=args.verbose)
    scanner.scan_path(args.target)

    if args.severity:
        scanner.filter_severity(args.severity)

    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)

    counts = scanner.summary()
    sys.exit(1 if (counts["CRITICAL"] or counts["HIGH"]) else 0)


if __name__ == "__main__":
    main()
