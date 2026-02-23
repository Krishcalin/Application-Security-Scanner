#!/usr/bin/env python3
"""
Java & PHP Security Scanner v2.0
Scans Java and PHP applications for security vulnerabilities and misconfigurations.

Supported inputs:
  Java
    - Source files (.java)
    - Maven build files (pom.xml)
    - Gradle build files (build.gradle / build.gradle.kts)
    - WAR / JAR / EAR archives
    - Servlet descriptors (web.xml)
    - Spring Boot configuration (.properties / .yml / .yaml)
  PHP
    - Source files (.php, .phtml, .php5, .php7, .php8)
    - Runtime configuration (php.ini)
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

VERSION = "2.0.0"

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
# PHP SAST RULES  (PHP source code patterns)
# ============================================================
PHP_SAST_RULES = [
    # --- SQL Injection ---
    {
        "id": "PHP-SQLI-001",
        "category": "SQL Injection",
        "name": "User input concatenated into SQL query",
        "severity": "CRITICAL",
        "pattern": r'(?:mysql_query|mysqli_query|pg_query|mssql_query|sqlite_query)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)',
        "description": (
            "User-supplied superglobal data is concatenated directly into a SQL query. "
            "This allows attackers to manipulate the query structure (SQLi)."
        ),
        "cwe": "CWE-89",
        "recommendation": (
            "Use PDO or MySQLi prepared statements with bound parameters. "
            "Never interpolate $_GET / $_POST into query strings."
        ),
    },
    {
        "id": "PHP-SQLI-002",
        "category": "SQL Injection",
        "name": "SQL string built with superglobal concatenation",
        "severity": "CRITICAL",
        "pattern": r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|EXEC|CALL)\s+[^;\'"\n]*["\'][^;\'"\n]*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": "SQL statement assembled by concatenating a $_GET/$_POST variable.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries (PDO::prepare / bindParam).",
    },
    {
        "id": "PHP-SQLI-003",
        "category": "SQL Injection",
        "name": "Deprecated mysql_* function usage",
        "severity": "HIGH",
        "pattern": r'\bmysql_(?:query|connect|select_db|fetch_array|num_rows)\s*\(',
        "description": (
            "The mysql_* extension was removed in PHP 7 and provides no prepared-statement "
            "support, making SQL injection trivially easy."
        ),
        "cwe": "CWE-89",
        "recommendation": "Replace with PDO or MySQLi, both of which support prepared statements.",
    },

    # --- Command Injection ---
    {
        "id": "PHP-CMDI-001",
        "category": "Command Injection",
        "name": "exec() / system() / passthru() with user input",
        "severity": "CRITICAL",
        "pattern": r'\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)',
        "description": (
            "A shell execution function is called with unsanitized user input, "
            "enabling arbitrary OS command execution."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Never pass user input to shell functions. If unavoidable, use "
            "escapeshellarg() for each argument and escapeshellcmd() for the command."
        ),
    },
    {
        "id": "PHP-CMDI-002",
        "category": "Command Injection",
        "name": "Backtick operator (shell execution)",
        "severity": "HIGH",
        "pattern": r'`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": "PHP backtick operator executes its content as a shell command; user input embedded here enables command injection.",
        "cwe": "CWE-78",
        "recommendation": "Remove backtick operator usage; use escapeshellarg() if shell calls are truly required.",
    },

    # --- Remote Code Execution ---
    {
        "id": "PHP-RCE-001",
        "category": "Remote Code Execution",
        "name": "eval() with user-controlled input",
        "severity": "CRITICAL",
        "pattern": r'\beval\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": (
            "eval() interprets its argument as PHP code. Passing user input "
            "directly to eval() allows unauthenticated remote code execution."
        ),
        "cwe": "CWE-95",
        "recommendation": "Remove eval() usage. There is almost never a legitimate reason to eval user input.",
    },
    {
        "id": "PHP-RCE-002",
        "category": "Remote Code Execution",
        "name": "preg_replace() with /e modifier (deprecated RCE vector)",
        "severity": "CRITICAL",
        "pattern": r'preg_replace\s*\(\s*[\'"][^\'"]*/e[\'"]',
        "description": (
            "The /e modifier causes preg_replace() to evaluate the replacement string "
            "as PHP code — a well-known RCE vector removed in PHP 7."
        ),
        "cwe": "CWE-95",
        "recommendation": "Replace with preg_replace_callback() using a safe, non-executing callback.",
    },
    {
        "id": "PHP-RCE-003",
        "category": "Remote Code Execution",
        "name": "assert() with string argument (code execution)",
        "severity": "HIGH",
        "pattern": r'\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": "assert() evaluates string arguments as PHP code. User-controlled input enables RCE.",
        "cwe": "CWE-95",
        "recommendation": "Never pass user input to assert(). Disable assert evaluation: assert.active=0 in php.ini.",
    },
    {
        "id": "PHP-RCE-004",
        "category": "Remote Code Execution",
        "name": "Dynamic function call via variable function",
        "severity": "HIGH",
        "pattern": r'\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]+\]\s*\(',
        "description": (
            "Calling a function whose name comes from user input (variable functions) "
            "allows an attacker to invoke any PHP function, including exec/system."
        ),
        "cwe": "CWE-95",
        "recommendation": "Validate function names against a strict allowlist before calling them.",
    },

    # --- Local / Remote File Inclusion ---
    {
        "id": "PHP-LFI-001",
        "category": "File Inclusion",
        "name": "include / require with user-controlled path",
        "severity": "CRITICAL",
        "pattern": r'\b(?:include|require|include_once|require_once)\s*[(\s][^;]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": (
            "Including a file whose path is derived from user input allows Local File "
            "Inclusion (LFI) and, if allow_url_include is On, Remote File Inclusion (RFI)."
        ),
        "cwe": "CWE-98",
        "recommendation": (
            "Never include files based on user input. Use a whitelist mapping of "
            "known-safe filenames and resolve paths with realpath()."
        ),
    },
    {
        "id": "PHP-LFI-002",
        "category": "File Inclusion",
        "name": "file_get_contents() / readfile() with user-controlled path",
        "severity": "HIGH",
        "pattern": r'\b(?:file_get_contents|file|readfile|fopen)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": "Reading a file whose path comes from user input enables path traversal and LFI.",
        "cwe": "CWE-22",
        "recommendation": (
            "Validate and canonicalize file paths. Ensure the resolved path is "
            "within an expected base directory before opening it."
        ),
    },

    # --- XSS ---
    {
        "id": "PHP-XSS-001",
        "category": "Cross-Site Scripting (XSS)",
        "name": "Reflected XSS – superglobal echoed without encoding",
        "severity": "HIGH",
        "pattern": r'\b(?:echo|print)\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)',
        "description": (
            "User-supplied data is echoed directly into the HTML response without "
            "HTML encoding, enabling reflected XSS attacks."
        ),
        "cwe": "CWE-79",
        "recommendation": "Wrap all output in htmlspecialchars($val, ENT_QUOTES, 'UTF-8').",
    },
    {
        "id": "PHP-XSS-002",
        "category": "Cross-Site Scripting (XSS)",
        "name": "Potential stored XSS – variable echoed without encoding",
        "severity": "MEDIUM",
        "pattern": r'\b(?:echo|print)\s+\$(?!_(?:GET|POST|REQUEST|COOKIE))\w+\s*;',
        "description": (
            "A PHP variable is echoed without explicit encoding. If the variable "
            "originates from user input or a database, this can cause stored XSS."
        ),
        "cwe": "CWE-79",
        "recommendation": "Always use htmlspecialchars() or htmlentities() before echoing any variable.",
    },

    # --- Insecure Deserialization ---
    {
        "id": "PHP-DESER-001",
        "category": "Insecure Deserialization",
        "name": "unserialize() with user input",
        "severity": "CRITICAL",
        "pattern": r'\bunserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": (
            "PHP's unserialize() can instantiate arbitrary classes and trigger magic "
            "methods (__wakeup, __destruct) during deserialization. Combined with a "
            "suitable gadget chain, user input passed to unserialize() enables RCE."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Never pass untrusted data to unserialize(). Use JSON "
            "(json_decode / json_encode) as a safe serialization format."
        ),
    },

    # --- Hardcoded Credentials ---
    {
        "id": "PHP-CRED-001",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded password / secret in PHP source",
        "severity": "HIGH",
        "pattern": r'(?i)\$(?:password|passwd|pwd|secret|api_?key|auth_?token|db_?pass)\s*=\s*[\'"][^\'"]{4,}[\'"]',
        "description": (
            "A credential is hardcoded as a PHP string literal and will be exposed "
            "to anyone with access to the source code or repository."
        ),
        "cwe": "CWE-798",
        "recommendation": "Store credentials in environment variables and read them with getenv() or $_ENV.",
    },
    {
        "id": "PHP-CRED-002",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded database DSN / password",
        "severity": "HIGH",
        "pattern": r'new\s+PDO\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*[\'"][^\'"]*[\'"]\s*,\s*[\'"][^\'"]{1,}[\'"]',
        "description": "PDO connection string contains a literal password argument.",
        "cwe": "CWE-798",
        "recommendation": "Pass the password as getenv('DB_PASSWORD') instead of a string literal.",
    },

    # --- Weak Cryptography ---
    {
        "id": "PHP-CRYPTO-001",
        "category": "Weak Cryptography",
        "name": "md5() used for password hashing",
        "severity": "HIGH",
        "pattern": r'\bmd5\s*\(',
        "description": (
            "MD5 is cryptographically broken. Using it for passwords is especially "
            "dangerous because unsalted MD5 hashes can be cracked via rainbow tables "
            "in seconds."
        ),
        "cwe": "CWE-327",
        "recommendation": "Use password_hash($password, PASSWORD_BCRYPT) and password_verify().",
    },
    {
        "id": "PHP-CRYPTO-002",
        "category": "Weak Cryptography",
        "name": "sha1() used for password / security token",
        "severity": "MEDIUM",
        "pattern": r'\bsha1\s*\(',
        "description": "SHA-1 is deprecated for security use. Unsalted SHA-1 hashes are trivially cracked.",
        "cwe": "CWE-327",
        "recommendation": "Use password_hash() for passwords; use hash('sha256', ...) for non-password hashing.",
    },
    {
        "id": "PHP-CRYPTO-003",
        "category": "Weak Cryptography",
        "name": "rand() / mt_rand() used for security purpose",
        "severity": "MEDIUM",
        "pattern": r'\b(?:rand|mt_rand)\s*\(',
        "description": (
            "rand() and mt_rand() are not cryptographically secure. Values they produce "
            "can be predicted after observing enough output."
        ),
        "cwe": "CWE-338",
        "recommendation": "Use random_bytes() or random_int() for all security-sensitive randomness.",
    },
    {
        "id": "PHP-CRYPTO-004",
        "category": "Weak Cryptography",
        "name": "mcrypt usage (removed in PHP 7.2)",
        "severity": "HIGH",
        "pattern": r'\bmcrypt_(?:encrypt|decrypt|module_open)\s*\(',
        "description": (
            "The mcrypt extension was deprecated in PHP 7.1 and removed in PHP 7.2. "
            "It uses outdated algorithms and its APIs are error-prone."
        ),
        "cwe": "CWE-327",
        "recommendation": "Use the OpenSSL extension: openssl_encrypt() / openssl_decrypt() with AES-256-GCM.",
    },

    # --- XXE ---
    {
        "id": "PHP-XXE-001",
        "category": "XML External Entity (XXE)",
        "name": "simplexml_load_string/file without disabling external entities",
        "severity": "HIGH",
        "pattern": r'\bsimplexml_load_(?:string|file)\s*\(',
        "description": (
            "PHP's SimpleXML and DOMDocument parsers process external entity "
            "declarations by default, enabling XXE attacks."
        ),
        "cwe": "CWE-611",
        "recommendation": (
            "Call libxml_disable_entity_loader(true) before parsing (PHP < 8.0), "
            "or use LIBXML_NONET | LIBXML_NOENT flags carefully. "
            "Prefer libxml_set_external_entity_loader() on PHP 8+."
        ),
    },
    {
        "id": "PHP-XXE-002",
        "category": "XML External Entity (XXE)",
        "name": "DOMDocument::loadXML / load without XXE hardening",
        "severity": "HIGH",
        "pattern": r'\$\w+\s*->\s*(?:loadXML|load)\s*\(',
        "description": "DOMDocument XML loading without disabling external entities is vulnerable to XXE.",
        "cwe": "CWE-611",
        "recommendation": "Set libxml_disable_entity_loader(true) prior to parsing on PHP < 8; use LIBXML_NONET on PHP 8+.",
    },

    # --- SSRF ---
    {
        "id": "PHP-SSRF-001",
        "category": "Server-Side Request Forgery (SSRF)",
        "name": "curl with user-supplied URL",
        "severity": "HIGH",
        "pattern": r'curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": (
            "A cURL request is made to a URL supplied by the user, allowing the server "
            "to be used as a proxy to reach internal services."
        ),
        "cwe": "CWE-918",
        "recommendation": "Validate URLs against an allowlist of permitted hosts. Block RFC-1918 / loopback targets.",
    },
    {
        "id": "PHP-SSRF-002",
        "category": "Server-Side Request Forgery (SSRF)",
        "name": "file_get_contents() with user-supplied URL",
        "severity": "HIGH",
        "pattern": r'\bfile_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": "file_get_contents() with a user-controlled URL enables SSRF and, if allow_url_include is On, RFI.",
        "cwe": "CWE-918",
        "recommendation": "Validate and restrict URLs. Prefer cURL with explicit option hardening over file_get_contents for HTTP requests.",
    },

    # --- Open Redirect ---
    {
        "id": "PHP-REDIR-001",
        "category": "Open Redirect",
        "name": "header('Location:') with user-controlled value",
        "severity": "MEDIUM",
        "pattern": r'header\s*\(\s*[\'"]Location:\s*[\'"][^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": "Redirecting to a user-supplied URL enables phishing attacks via a trusted domain.",
        "cwe": "CWE-601",
        "recommendation": "Validate redirect targets against an allowlist of permitted internal URLs.",
    },

    # --- Session Security ---
    {
        "id": "PHP-SESS-001",
        "category": "Session Security",
        "name": "session_start() without secure configuration",
        "severity": "MEDIUM",
        "pattern": r'\bsession_start\s*\(\s*\)',
        "description": (
            "session_start() with default settings may produce non-HttpOnly, non-Secure "
            "cookies and is vulnerable to session fixation if session IDs are not "
            "regenerated after login."
        ),
        "cwe": "CWE-614",
        "recommendation": (
            "Configure session options in php.ini or pass them to session_start(): "
            "cookie_httponly=1, cookie_secure=1, cookie_samesite=Strict, "
            "use_strict_mode=1. Call session_regenerate_id(true) on privilege changes."
        ),
    },
    {
        "id": "PHP-SESS-002",
        "category": "Session Security",
        "name": "session_id() set from user input – session fixation",
        "severity": "HIGH",
        "pattern": r'\bsession_id\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
        "description": "Setting the session ID from user input enables session fixation attacks.",
        "cwe": "CWE-384",
        "recommendation": "Never set session IDs from user-supplied values. Let PHP generate a fresh, random session ID.",
    },

    # --- phpinfo / Dangerous Functions ---
    {
        "id": "PHP-INFO-001",
        "category": "Information Disclosure",
        "name": "phpinfo() call in production code",
        "severity": "MEDIUM",
        "pattern": r'\bphpinfo\s*\(',
        "description": (
            "phpinfo() outputs the full PHP configuration, loaded extensions, "
            "environment variables (potentially including secrets), and server paths."
        ),
        "cwe": "CWE-200",
        "recommendation": "Remove all phpinfo() calls from production code.",
    },
    {
        "id": "PHP-INFO-002",
        "category": "Information Disclosure",
        "name": "Error details exposed via display_errors",
        "severity": "MEDIUM",
        "pattern": r'\bini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]?1[\'"]?\s*\)',
        "description": "Enabling display_errors at runtime exposes stack traces and file paths to end users.",
        "cwe": "CWE-209",
        "recommendation": "Set display_errors=Off in php.ini for production. Log errors with error_log instead.",
    },

    # --- Type Juggling ---
    {
        "id": "PHP-TYPE-001",
        "category": "Type Juggling",
        "name": "Loose comparison (==) in authentication/security context",
        "severity": "MEDIUM",
        "pattern": r'(?:if|while)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)[^)]*==(?!=)',
        "description": (
            "PHP's loose comparison (==) applies type coercion: '0e123' == '0e456' is true, "
            "'admin' == 0 is true, etc. This has led to numerous authentication bypasses."
        ),
        "cwe": "CWE-697",
        "recommendation": "Use strict comparison (===) in all security-sensitive comparisons.",
    },

    # --- Webshell indicators ---
    {
        "id": "PHP-SHELL-001",
        "category": "Webshell / Backdoor Indicator",
        "name": "base64_decode()+eval() – common webshell pattern",
        "severity": "CRITICAL",
        "pattern": r'\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|rawurldecode|hex2bin)\s*\(',
        "description": (
            "Chaining an obfuscation function with eval() is the canonical PHP webshell "
            "technique. This code almost certainly executes attacker-supplied payloads."
        ),
        "cwe": "CWE-95",
        "recommendation": "Treat this file as compromised. Remove it and audit how it was placed on the server.",
    },
    {
        "id": "PHP-SHELL-002",
        "category": "Webshell / Backdoor Indicator",
        "name": "PHP code execution via create_function()",
        "severity": "HIGH",
        "pattern": r'\bcreate_function\s*\(',
        "description": (
            "create_function() compiles a PHP function from a string and was removed in PHP 8. "
            "It is widely used in obfuscated backdoors."
        ),
        "cwe": "CWE-95",
        "recommendation": "Replace with anonymous functions (closures). Flag any dynamic use for security review.",
    },
]

# ============================================================
# PHP CONFIGURATION RULES (php.ini)
# ============================================================
PHP_INI_RULES = [
    {
        "id": "PHPINI-001",
        "name": "display_errors enabled",
        "severity": "MEDIUM",
        "pattern": r"^\s*display_errors\s*=\s*(?:On|1|true)",
        "description": "PHP error messages (including stack traces and file paths) are shown to end users.",
        "recommendation": "Set display_errors=Off; log_errors=On; error_log=/var/log/php_errors.log",
    },
    {
        "id": "PHPINI-002",
        "name": "allow_url_include enabled – Remote File Inclusion risk",
        "severity": "CRITICAL",
        "pattern": r"^\s*allow_url_include\s*=\s*(?:On|1|true)",
        "description": (
            "allow_url_include=On permits include/require to load PHP code from remote URLs, "
            "enabling Remote File Inclusion (RFI) if user input reaches an include statement."
        ),
        "recommendation": "Set allow_url_include=Off. There is no legitimate production use for this setting.",
    },
    {
        "id": "PHPINI-003",
        "name": "allow_url_fopen enabled",
        "severity": "LOW",
        "pattern": r"^\s*allow_url_fopen\s*=\s*(?:On|1|true)",
        "description": "allow_url_fopen allows file functions to open remote URLs, increasing the SSRF attack surface.",
        "recommendation": "Disable if not explicitly required. Use cURL with explicit validation instead.",
    },
    {
        "id": "PHPINI-004",
        "name": "expose_php enabled – version disclosure",
        "severity": "LOW",
        "pattern": r"^\s*expose_php\s*=\s*(?:On|1|true)",
        "description": "PHP adds an X-Powered-By header revealing the PHP version, aiding fingerprinting.",
        "recommendation": "Set expose_php=Off.",
    },
    {
        "id": "PHPINI-005",
        "name": "register_globals enabled (catastrophic misconfiguration)",
        "severity": "CRITICAL",
        "pattern": r"^\s*register_globals\s*=\s*(?:On|1|true)",
        "description": (
            "register_globals automatically injects GET/POST/COOKIE values as global PHP variables, "
            "which historically led to massive authentication bypasses and variable injection. "
            "Removed in PHP 5.4."
        ),
        "recommendation": "Set register_globals=Off. Upgrade to PHP 7+.",
    },
    {
        "id": "PHPINI-006",
        "name": "session.cookie_httponly not enabled",
        "severity": "HIGH",
        "pattern": r"^\s*session\.cookie_httponly\s*=\s*(?:Off|0|false)",
        "description": "Session cookie without HttpOnly is accessible to JavaScript, enabling theft via XSS.",
        "recommendation": "Set session.cookie_httponly=1",
    },
    {
        "id": "PHPINI-007",
        "name": "session.cookie_secure not enabled",
        "severity": "HIGH",
        "pattern": r"^\s*session\.cookie_secure\s*=\s*(?:Off|0|false)",
        "description": "Session cookie without the Secure flag can be transmitted over plaintext HTTP.",
        "recommendation": "Set session.cookie_secure=1 and enforce HTTPS.",
    },
    {
        "id": "PHPINI-008",
        "name": "session.use_strict_mode disabled – session fixation risk",
        "severity": "MEDIUM",
        "pattern": r"^\s*session\.use_strict_mode\s*=\s*(?:Off|0|false)",
        "description": "Strict mode rejects unrecognized session IDs; without it the server is vulnerable to session fixation.",
        "recommendation": "Set session.use_strict_mode=1",
    },
    {
        "id": "PHPINI-009",
        "name": "disable_functions not configured",
        "severity": "LOW",
        "pattern": r"^\s*disable_functions\s*=\s*$",
        "description": "No PHP functions are disabled, leaving dangerous functions (exec, system, passthru) accessible.",
        "recommendation": (
            "Disable dangerous functions: "
            "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,"
            "curl_multi_exec,parse_ini_file,show_source"
        ),
    },
    {
        "id": "PHPINI-010",
        "name": "file_uploads enabled without restriction",
        "severity": "MEDIUM",
        "pattern": r"^\s*file_uploads\s*=\s*(?:On|1|true)",
        "description": "File uploads are enabled. Without server-side type validation, attackers can upload webshells.",
        "recommendation": (
            "If uploads are required, validate MIME type and extension server-side, "
            "store files outside the web root, and set upload_max_filesize conservatively."
        ),
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
        elif suffix in (".php", ".phtml", ".php5", ".php7", ".php8"):
            self._scan_php_source(filepath)
        elif name == "php.ini":
            self._scan_php_ini(filepath)

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
    # PHP source SAST
    # ----------------------------------------------------------
    def _scan_php_source(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [php] {filepath}")

        compiled = [(rule, re.compile(rule["pattern"], re.IGNORECASE)) for rule in PHP_SAST_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                # Skip single-line comments and docblock lines
                if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
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
    # php.ini misconfiguration checks
    # ----------------------------------------------------------
    def _scan_php_ini(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [php.ini] {filepath}")

        compiled = [(rule, re.compile(rule["pattern"], re.IGNORECASE)) for rule in PHP_INI_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(";"):  # ini comment
                    continue
                if rx.search(line):
                    self._add(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category="Misconfiguration",
                        severity=rule["severity"],
                        file_path=filepath,
                        line_num=lineno,
                        line_content=line.rstrip(),
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                    ))

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
        print(f"{B}  Java & PHP Security Scanner v{VERSION}  —  Scan Report{R}")
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
            "scanner": f"Java & PHP Security Scanner v{VERSION}",
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
        description=f"Java & PHP Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 java_scanner.py /path/to/project
  python3 java_scanner.py /path/to/app.war --json report.json
  python3 java_scanner.py /var/www/html --severity HIGH
  python3 java_scanner.py pom.xml --verbose
  python3 java_scanner.py index.php --json report.json
""",
    )
    parser.add_argument("target", help="File or directory to scan (.java, .php, pom.xml, .gradle, .war, .jar, .ear, php.ini)")
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Only report findings at this severity or above")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print(f"[*] Java & PHP Security Scanner v{VERSION}")
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
