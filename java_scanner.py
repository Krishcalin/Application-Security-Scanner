#!/usr/bin/env python3
"""
Java, PHP, Python, MERN & LAMP Security Scanner v5.0
Scans Java, PHP, Python (including AI/agentic), MERN stack, and LAMP stack
applications for security vulnerabilities and misconfigurations.

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
  Python
    - Source files (.py, .pyw)
    - Dependency manifests (requirements.txt, Pipfile, pyproject.toml)
  MERN (MongoDB / Express / React / Node.js)
    - JavaScript / TypeScript source files (.js, .jsx, .ts, .tsx, .mjs, .cjs)
    - npm dependency manifests (package.json)
    - Environment configuration (.env)
  LAMP (Linux / Apache / MySQL / PHP)
    - Apache HTTP Server config (httpd.conf, apache2.conf, .conf, .htaccess)
    - MySQL / MariaDB config (my.cnf, my.ini, mysqld.cnf)
    - Additional PHP LAMP-specific SAST rules applied to PHP source files
    - Apache httpd CVEs (2021–2024) and MySQL/MariaDB CVEs (2021–2024)
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

VERSION = "5.0.0"

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
# PYTHON SAST RULES  (Python source code patterns)
# ============================================================
PYTHON_SAST_RULES = [
    # --- Insecure Deserialization ---
    {
        "id": "PY-DESER-001",
        "category": "Insecure Deserialization",
        "name": "pickle.load/loads() – arbitrary code execution",
        "severity": "CRITICAL",
        "pattern": r"\bpickle\.(?:loads?|Unpickler)\s*\(",
        "description": (
            "pickle can execute arbitrary Python code when deserializing. "
            "Any attacker-controlled pickle payload achieves full RCE."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Use JSON or MessagePack for untrusted data. If pickle is required, "
            "sign payloads with HMAC and verify the signature before unpickling."
        ),
    },
    {
        "id": "PY-DESER-002",
        "category": "Insecure Deserialization",
        "name": "yaml.load() without SafeLoader – code execution",
        "severity": "CRITICAL",
        "pattern": r"\byaml\.load\s*\([^,)]+\)",
        "description": (
            "yaml.load() with the default Loader constructs arbitrary Python objects, "
            "enabling RCE via crafted YAML. CVE-2017-18342."
        ),
        "cwe": "CWE-502",
        "recommendation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
    },
    {
        "id": "PY-DESER-003",
        "category": "Insecure Deserialization",
        "name": "marshal.loads() – unsafe deserialization",
        "severity": "CRITICAL",
        "pattern": r"\bmarshal\.loads?\s*\(",
        "description": "marshal is not safe against untrusted data and can crash the interpreter or execute code.",
        "cwe": "CWE-502",
        "recommendation": "Use JSON for data interchange. Never deserialize marshal data from untrusted sources.",
    },
    {
        "id": "PY-DESER-004",
        "category": "Insecure Deserialization",
        "name": "jsonpickle.decode() – arbitrary code execution",
        "severity": "CRITICAL",
        "pattern": r"\bjsonpickle\.decode\s*\(",
        "description": "jsonpickle.decode() instantiates arbitrary Python objects, enabling RCE via crafted JSON.",
        "cwe": "CWE-502",
        "recommendation": "Use json.loads() for untrusted input. Never use jsonpickle with untrusted data.",
    },
    {
        "id": "PY-DESER-005",
        "category": "Insecure Deserialization",
        "name": "torch.load() without weights_only=True – model file RCE",
        "severity": "CRITICAL",
        "pattern": r"\btorch\.load\s*\(",
        "description": (
            "torch.load() uses pickle by default; a malicious model file achieves RCE. "
            "CVE-2022-45907."
        ),
        "cwe": "CWE-502",
        "recommendation": "Use torch.load(f, weights_only=True) (PyTorch ≥ 2.0) to prevent arbitrary object loading.",
    },

    # --- Code Execution ---
    {
        "id": "PY-RCE-001",
        "category": "Remote Code Execution",
        "name": "eval() with dynamic argument",
        "severity": "CRITICAL",
        "pattern": r"\beval\s*\([^)]*(?:input\s*\(|request\b|args\b|kwargs\b|sys\.argv|os\.environ|getenv)",
        "description": "eval() executes arbitrary Python code. Any user-controlled input enables RCE.",
        "cwe": "CWE-95",
        "recommendation": "Remove eval(). Use ast.literal_eval() only for safe literal parsing of constants.",
    },
    {
        "id": "PY-RCE-002",
        "category": "Remote Code Execution",
        "name": "exec() with dynamic argument",
        "severity": "CRITICAL",
        "pattern": r"\bexec\s*\([^)]*(?:input\s*\(|request\b|args\b|kwargs\b|sys\.argv|os\.environ|getenv)",
        "description": "exec() compiles and runs arbitrary Python. User-controlled input enables RCE.",
        "cwe": "CWE-95",
        "recommendation": "Remove exec(). There is no safe way to exec user-supplied strings.",
    },
    {
        "id": "PY-RCE-003",
        "category": "Remote Code Execution",
        "name": "LLM output passed to eval() or exec() – AI prompt injection → RCE",
        "severity": "CRITICAL",
        "pattern": r"\b(?:eval|exec)\s*\([^)]*(?:response|completion|message|content|llm_output|agent_output|generated|result)\b",
        "description": (
            "Executing LLM-generated text with eval()/exec() allows prompt injection "
            "to achieve arbitrary code execution on the host."
        ),
        "cwe": "CWE-95",
        "recommendation": (
            "Never execute LLM output as code. Use a sandboxed interpreter "
            "(RestrictedPython, isolated subprocess) with strict resource limits."
        ),
    },
    {
        "id": "PY-RCE-004",
        "category": "Remote Code Execution",
        "name": "compile() with user-controlled source",
        "severity": "HIGH",
        "pattern": r"\bcompile\s*\([^)]*(?:input\s*\(|request\b|args\b)",
        "description": "compile() + exec() is equivalent to eval(); user-controlled source enables RCE.",
        "cwe": "CWE-95",
        "recommendation": "Avoid compiling user-supplied strings. Use whitelisted operations instead.",
    },

    # --- Command Injection ---
    {
        "id": "PY-CMDI-001",
        "category": "Command Injection",
        "name": "os.system() – shell command injection",
        "severity": "CRITICAL",
        "pattern": r"\bos\.system\s*\(",
        "description": (
            "os.system() passes its argument to the shell. String interpolation of "
            "user data enables arbitrary command execution."
        ),
        "cwe": "CWE-78",
        "recommendation": "Replace with subprocess.run([...], shell=False). Never interpolate user data into shell strings.",
    },
    {
        "id": "PY-CMDI-002",
        "category": "Command Injection",
        "name": "subprocess with shell=True",
        "severity": "CRITICAL",
        "pattern": r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
        "description": (
            "shell=True routes the command string through the OS shell, enabling injection "
            "via any interpolated variable."
        ),
        "cwe": "CWE-78",
        "recommendation": "Use shell=False (the default) with a list of arguments: subprocess.run(['cmd', arg1]).",
    },
    {
        "id": "PY-CMDI-003",
        "category": "Command Injection",
        "name": "os.popen() – shell execution",
        "severity": "HIGH",
        "pattern": r"\bos\.popen\s*\(",
        "description": "os.popen() executes a shell command. User-controlled input enables command injection.",
        "cwe": "CWE-78",
        "recommendation": "Replace with subprocess.run([...], shell=False, capture_output=True).",
    },
    {
        "id": "PY-CMDI-004",
        "category": "Command Injection",
        "name": "LLM/agent output passed to subprocess – AI prompt injection → RCE",
        "severity": "CRITICAL",
        "pattern": r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\([^)]*(?:response|completion|message|content|llm_output|agent_output|generated|result)",
        "description": (
            "Running LLM-generated strings as OS commands allows prompt injection to "
            "execute arbitrary commands on the host."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Never pass LLM output to subprocess. Validate all commands against a strict "
            "allowlist of permitted operations."
        ),
    },

    # --- SQL Injection ---
    {
        "id": "PY-SQLI-001",
        "category": "SQL Injection",
        "name": "f-string used to build SQL query",
        "severity": "CRITICAL",
        "pattern": r'(?:execute|executemany)\s*\(\s*f["\']',
        "description": "Building SQL queries with f-strings enables injection when any variable is user-controlled.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
    },
    {
        "id": "PY-SQLI-002",
        "category": "SQL Injection",
        "name": "String concatenation / % formatting in SQL query",
        "severity": "CRITICAL",
        "pattern": r'(?:execute|executemany)\s*\(\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\'\s]*%\s*[^,\)]+\)',
        "description": "% string formatting in SQL statements enables injection when the operand contains user data.",
        "cwe": "CWE-89",
        "recommendation": "Always use DB-API parameterized placeholders (%s, ?, :name).",
    },
    {
        "id": "PY-SQLI-003",
        "category": "SQL Injection",
        "name": "Django ORM raw() with format string",
        "severity": "HIGH",
        "pattern": r"\.raw\s*\(\s*f['\"]|\.raw\s*\([^)]*%\s*(?:request|args|kwargs|input|params)",
        "description": "Django's raw() bypasses ORM protections. Formatting user data into the query string enables SQLi.",
        "cwe": "CWE-89",
        "recommendation": "Use ORM filters or pass parameters: Model.objects.raw('SELECT … WHERE id=%s', [uid])",
    },

    # --- Path Traversal ---
    {
        "id": "PY-PATH-001",
        "category": "Path Traversal",
        "name": "open() with user-controlled path",
        "severity": "HIGH",
        "pattern": r"\bopen\s*\([^)]*(?:request\b|args\b|kwargs\b|input\s*\(|os\.environ|sys\.argv)",
        "description": "Opening files with user-controlled paths enables path traversal (../../etc/passwd).",
        "cwe": "CWE-22",
        "recommendation": (
            "Resolve the path: p = Path(base, user_input).resolve(); "
            "assert str(p).startswith(str(base_resolved))"
        ),
    },
    {
        "id": "PY-PATH-002",
        "category": "Path Traversal",
        "name": "os.path.join() with user input – base-path bypass",
        "severity": "HIGH",
        "pattern": r"\bos\.path\.join\s*\([^)]*(?:request\b|args\b|kwargs\b|input\s*\()",
        "description": (
            "If user input is an absolute path, os.path.join() discards all earlier components, "
            "bypassing any base-directory restriction."
        ),
        "cwe": "CWE-22",
        "recommendation": "Use pathlib.Path.resolve() and verify the result is within the expected directory.",
    },

    # --- Server-Side Request Forgery ---
    {
        "id": "PY-SSRF-001",
        "category": "Server-Side Request Forgery (SSRF)",
        "name": "requests library call with user-controlled URL",
        "severity": "HIGH",
        "pattern": r"\brequests\.(?:get|post|put|patch|delete|head|request)\s*\([^)]*(?:request\b|args\b|kwargs\b|input\s*\(|url\b)",
        "description": "Making HTTP requests to user-supplied URLs allows SSRF, exposing internal services and metadata endpoints.",
        "cwe": "CWE-918",
        "recommendation": (
            "Validate URLs against an allowlist of permitted domains. "
            "Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)."
        ),
    },
    {
        "id": "PY-SSRF-002",
        "category": "Server-Side Request Forgery (SSRF)",
        "name": "urllib.request.urlopen() with user-controlled URL",
        "severity": "HIGH",
        "pattern": r"\burllib\.request\.urlopen\s*\([^)]*(?:request\b|args\b|kwargs\b|input)",
        "description": "urlopen() with user-controlled URLs enables SSRF.",
        "cwe": "CWE-918",
        "recommendation": "Validate and allowlist URLs. Prefer requests with a custom adapter that restricts target hosts.",
    },
    {
        "id": "PY-SSRF-003",
        "category": "Server-Side Request Forgery (SSRF)",
        "name": "httpx / aiohttp request – common in AI agent tooling",
        "severity": "HIGH",
        "pattern": r"\b(?:httpx|aiohttp)\.(?:get|post|AsyncClient|ClientSession)\s*\(",
        "description": (
            "HTTP clients used by AI agents are common SSRF vectors when the URL is "
            "derived from LLM output or user input without validation."
        ),
        "cwe": "CWE-918",
        "recommendation": "Validate all URLs against an allowlist. Implement egress filtering at the network level.",
    },

    # --- Server-Side Template Injection ---
    {
        "id": "PY-SSTI-001",
        "category": "Server-Side Template Injection (SSTI)",
        "name": "Jinja2 Template() instantiated with user input",
        "severity": "CRITICAL",
        "pattern": r"\bTemplate\s*\([^)]*(?:request\b|args\b|kwargs\b|input\s*\(|user)",
        "description": "Rendering Jinja2 templates built from user strings enables SSTI → RCE via {{''.__class__.__mro__[1]...}}.",
        "cwe": "CWE-94",
        "recommendation": "Use render_template() with static .html files; pass user data only as template context variables.",
    },
    {
        "id": "PY-SSTI-002",
        "category": "Server-Side Template Injection (SSTI)",
        "name": "Flask render_template_string() with user input",
        "severity": "CRITICAL",
        "pattern": r"\brender_template_string\s*\([^)]*(?:request\b|args\b|kwargs\b|input)",
        "description": "render_template_string() with user-supplied content enables SSTI/RCE.",
        "cwe": "CWE-94",
        "recommendation": "Use render_template() with a predefined template file. Never render user-supplied strings as templates.",
    },

    # --- Hardcoded Credentials ---
    {
        "id": "PY-CRED-001",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded password / secret key",
        "severity": "HIGH",
        "pattern": r'(?i)(?:password|passwd|pwd|secret_?key|api_?key|auth_?token|access_?key|private_?key)\s*=\s*["\'][^"\']{4,}["\']',
        "description": "Credentials hardcoded in source are exposed in version control and compiled artifacts.",
        "cwe": "CWE-798",
        "recommendation": "Load from environment: os.environ.get('SECRET_KEY') or use python-dotenv / a secrets manager.",
    },
    {
        "id": "PY-CRED-002",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded AI provider API key (OpenAI / Anthropic / Google / HuggingFace)",
        "severity": "CRITICAL",
        "pattern": r'(?:openai\.api_key|OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|COHERE_API_KEY)\s*=\s*["\'][^"\']{10,}["\']',
        "description": (
            "AI provider API keys hardcoded in source code will be exposed in git history. "
            "Billing abuse and data access begin within minutes of a key leak."
        ),
        "cwe": "CWE-798",
        "recommendation": "Use environment variables: openai.api_key = os.environ['OPENAI_API_KEY']. Add key patterns to .gitignore.",
    },
    {
        "id": "PY-CRED-003",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded cloud provider credentials (AWS / GCP / Azure)",
        "severity": "CRITICAL",
        "pattern": r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET)\s*=\s*["\'][^"\']{8,}["\']',
        "description": "Cloud credentials in source code lead to account takeover and data breaches.",
        "cwe": "CWE-798",
        "recommendation": "Use IAM roles, instance profiles, or Workload Identity. Never hardcode cloud credentials.",
    },
    {
        "id": "PY-CRED-004",
        "category": "Hardcoded Credentials",
        "name": "Literal API key pattern detected",
        "severity": "CRITICAL",
        "pattern": r'["\'](?:sk-[a-zA-Z0-9]{32,}|sk-ant-api[a-zA-Z0-9\-]{20,}|AIza[a-zA-Z0-9\-_]{30,})["\']',
        "description": "A string matching a known AI/cloud API key format is present in source code.",
        "cwe": "CWE-798",
        "recommendation": "Revoke the key immediately. Load keys from environment variables or a vault.",
    },

    # --- Weak Cryptography ---
    {
        "id": "PY-CRYPTO-001",
        "category": "Weak Cryptography",
        "name": "hashlib.md5() – broken hash",
        "severity": "MEDIUM",
        "pattern": r"\bhashlib\.md5\s*\(",
        "description": "MD5 is cryptographically broken. Do not use for passwords, HMAC, or integrity checks.",
        "cwe": "CWE-327",
        "recommendation": "Use hashlib.sha256() or better. For passwords use bcrypt, scrypt, or argon2-cffi.",
    },
    {
        "id": "PY-CRYPTO-002",
        "category": "Weak Cryptography",
        "name": "hashlib.sha1() – deprecated for security use",
        "severity": "MEDIUM",
        "pattern": r"\bhashlib\.sha1\s*\(",
        "description": "SHA-1 is deprecated for security use due to demonstrated collision vulnerabilities.",
        "cwe": "CWE-327",
        "recommendation": "Use hashlib.sha256() or hashlib.sha3_256().",
    },
    {
        "id": "PY-CRYPTO-003",
        "category": "Weak Cryptography",
        "name": "random module used for security-sensitive value",
        "severity": "MEDIUM",
        "pattern": r"\brandom\.(?:random|randint|choice|choices|sample|shuffle|randrange|randbytes)\s*\(",
        "description": "The random module is not cryptographically secure; its output is predictable.",
        "cwe": "CWE-338",
        "recommendation": "Use the secrets module: secrets.token_hex(), secrets.token_bytes(), secrets.choice().",
    },
    {
        "id": "PY-CRYPTO-004",
        "category": "Weak Cryptography",
        "name": "DES / 3DES cipher",
        "severity": "HIGH",
        "pattern": r"\bDES(?:3|EDE)?\s*\.new\s*\(|Crypto\.Cipher\.DES\b",
        "description": "DES has a 56-bit key; 3DES is deprecated by NIST SP 800-131A Rev. 2. Both are insecure.",
        "cwe": "CWE-327",
        "recommendation": "Use AES-256-GCM via the cryptography library: from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
    },

    # --- XML / XXE ---
    {
        "id": "PY-XXE-001",
        "category": "XML External Entity (XXE)",
        "name": "lxml etree imported – verify XXE hardening",
        "severity": "HIGH",
        "pattern": r"\blxml\.etree\b|from\s+lxml\s+import\s+etree",
        "description": "lxml resolves external entities and DTDs by default, enabling XXE attacks on untrusted XML.",
        "cwe": "CWE-611",
        "recommendation": "Use defusedxml, or configure: parser = etree.XMLParser(resolve_entities=False, no_network=True)",
    },
    {
        "id": "PY-XXE-002",
        "category": "XML External Entity (XXE)",
        "name": "xml.etree.ElementTree on untrusted data – DoS risk",
        "severity": "MEDIUM",
        "pattern": r"\bxml\.etree\.ElementTree\.(?:parse|fromstring|XML)\s*\(",
        "description": "The stdlib XML parser is vulnerable to Billion Laughs and quadratic blowup DoS attacks.",
        "cwe": "CWE-611",
        "recommendation": "Use defusedxml.ElementTree instead of xml.etree.ElementTree for any untrusted input.",
    },

    # --- Flask misconfigurations ---
    {
        "id": "PY-FLASK-001",
        "category": "Misconfiguration",
        "name": "Flask debug mode enabled in production",
        "severity": "CRITICAL",
        "pattern": r"\bapp\.run\s*\([^)]*debug\s*=\s*True",
        "description": (
            "Flask debug=True enables the Werkzeug interactive debugger in the browser — "
            "this is instant, unauthenticated RCE on the server."
        ),
        "cwe": "CWE-94",
        "recommendation": "Set debug=False in production. Drive via env: debug=os.environ.get('FLASK_DEBUG','0')=='1'",
    },
    {
        "id": "PY-FLASK-002",
        "category": "Misconfiguration",
        "name": "Flask SECRET_KEY hardcoded",
        "severity": "HIGH",
        "pattern": r"(?:app\.secret_key|app\.config\s*\[\s*['\"]SECRET_KEY['\"])\s*=\s*['\"][^'\"]{1,}['\"]",
        "description": "A hardcoded SECRET_KEY allows forging session cookies (HMAC bypass).",
        "cwe": "CWE-798",
        "recommendation": "Load from environment: app.secret_key = os.environ['SECRET_KEY']",
    },

    # --- Django misconfigurations ---
    {
        "id": "PY-DJANGO-001",
        "category": "Misconfiguration",
        "name": "Django DEBUG = True",
        "severity": "HIGH",
        "pattern": r"^\s*DEBUG\s*=\s*True",
        "description": "Django DEBUG=True exposes full stack traces, local variables, and all settings to any HTTP client.",
        "cwe": "CWE-215",
        "recommendation": "Set DEBUG=False in production. Use: DEBUG = os.environ.get('DJANGO_DEBUG','False') == 'True'",
    },
    {
        "id": "PY-DJANGO-002",
        "category": "Misconfiguration",
        "name": "Django SECRET_KEY hardcoded",
        "severity": "HIGH",
        "pattern": r"SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]",
        "description": "Django's SECRET_KEY signs CSRF tokens, sessions, and password-reset links. Exposure allows forgery of all three.",
        "cwe": "CWE-798",
        "recommendation": "Load from environment: SECRET_KEY = os.environ['DJANGO_SECRET_KEY']",
    },
    {
        "id": "PY-DJANGO-003",
        "category": "Misconfiguration",
        "name": "Django ALLOWED_HOSTS = ['*']",
        "severity": "HIGH",
        "pattern": r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]",
        "description": "Wildcard ALLOWED_HOSTS disables host-header validation, enabling host-header injection attacks.",
        "cwe": "CWE-346",
        "recommendation": "List explicit hostnames: ALLOWED_HOSTS = ['www.example.com']",
    },

    # --- AI / Agentic-specific ---
    {
        "id": "PY-AI-001",
        "category": "AI / Agentic Security",
        "name": "LangChain allow_dangerous_deserialization=True",
        "severity": "CRITICAL",
        "pattern": r"allow_dangerous_deserialization\s*=\s*True",
        "description": (
            "This flag disables safety checks in LangChain's pickle-based loader. "
            "A malicious chain/tool file achieves arbitrary code execution."
        ),
        "cwe": "CWE-502",
        "recommendation": "Remove this flag. Only load chain files from trusted, integrity-verified sources.",
    },
    {
        "id": "PY-AI-002",
        "category": "AI / Agentic Security",
        "name": "Unsanitized user input passed directly as LLM prompt",
        "severity": "HIGH",
        "pattern": r'(?:messages|prompt|content)\s*[=:]\s*(?:\[|f["\'])[^)]*(?:request\b|input\s*\(|args\b|kwargs\b)',
        "description": (
            "Passing raw user input as an LLM prompt enables prompt injection: attackers "
            "manipulate model behaviour, exfiltrate system prompts, or abuse tools."
        ),
        "cwe": "CWE-20",
        "recommendation": (
            "Separate system instructions from user data using distinct message roles. "
            "Apply input length limits, strip control characters, and validate intent."
        ),
    },
    {
        "id": "PY-AI-003",
        "category": "AI / Agentic Security",
        "name": "Shell / bash tool exposed to AI agent",
        "severity": "CRITICAL",
        "pattern": r'(?:ShellTool|BashTool|SystemCommandTool|Terminal)\s*\(\s*\)|tool\s*=\s*["\'](?:shell|bash|terminal)["\']',
        "description": (
            "Exposing shell execution tools to an agent that processes untrusted input allows "
            "prompt injection to run arbitrary OS commands."
        ),
        "cwe": "CWE-78",
        "recommendation": "Do not expose shell tools to agents handling untrusted input. Use purpose-specific, sandboxed tools.",
    },
    {
        "id": "PY-AI-004",
        "category": "AI / Agentic Security",
        "name": "Code interpreter / Python REPL tool in agent",
        "severity": "HIGH",
        "pattern": r'(?:PythonREPLTool|PythonAstREPLTool|CodeInterpreter|python_repl)\s*\(',
        "description": (
            "Code-interpreter tools execute LLM-generated Python. Without sandboxing, "
            "prompt injection achieves host RCE."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Run interpreters in isolated containers with no network access, "
            "restricted filesystem, and CPU/memory limits."
        ),
    },
    {
        "id": "PY-AI-005",
        "category": "AI / Agentic Security",
        "name": "LangChain chain loaded from file (pickle deserialization)",
        "severity": "HIGH",
        "pattern": r"(?:load_chain|Chain\.load|BaseChain\.load)\s*\(",
        "description": "Loading LangChain chains from files uses pickle; a malicious file achieves RCE.",
        "cwe": "CWE-502",
        "recommendation": "Prefer LCEL definitions over serialised chains. Only load from integrity-verified sources.",
    },
    {
        "id": "PY-AI-006",
        "category": "AI / Agentic Security",
        "name": "Agent with verbose=True leaking internal chain details",
        "severity": "LOW",
        "pattern": r"\bAgent(?:Executor)?\s*\([^)]*verbose\s*=\s*True",
        "description": "verbose=True logs full chain inputs/outputs including tool results that may contain sensitive data.",
        "cwe": "CWE-532",
        "recommendation": "Disable verbose in production or route logs to a restricted, secured log sink.",
    },

    # --- Sensitive data in logs ---
    {
        "id": "PY-LOG-001",
        "category": "Sensitive Data Exposure",
        "name": "Potential logging of credentials or tokens",
        "severity": "MEDIUM",
        "pattern": r'(?:logging|logger|log)\s*\.\s*(?:info|debug|warning|error|critical)\s*\([^)]*(?:password|token|secret|api_key|credential)',
        "description": "Logging credential-related variables persists secrets in log files and monitoring systems.",
        "cwe": "CWE-532",
        "recommendation": "Redact sensitive fields before logging. Use structured logging with field-level masking.",
    },

    # --- Insecure temp files ---
    {
        "id": "PY-TMPFILE-001",
        "category": "Insecure Temporary File",
        "name": "tempfile.mktemp() – TOCTOU race condition",
        "severity": "MEDIUM",
        "pattern": r"\btempfile\.mktemp\s*\(",
        "description": "mktemp() returns a filename without creating it; an attacker can win the race and create a symlink at that path.",
        "cwe": "CWE-377",
        "recommendation": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() which atomically create and open the file.",
    },

    # --- Open Redirect ---
    {
        "id": "PY-REDIR-001",
        "category": "Open Redirect",
        "name": "Flask / Django redirect with user-controlled URL",
        "severity": "MEDIUM",
        "pattern": r"\b(?:redirect|HttpResponseRedirect)\s*\([^)]*(?:request\b|args\b|kwargs\b|input)",
        "description": "Redirecting to a user-supplied URL enables phishing via a trusted domain.",
        "cwe": "CWE-601",
        "recommendation": "Validate redirect targets against an allowlist of permitted paths or domains.",
    },

    # --- XSS ---
    {
        "id": "PY-XSS-001",
        "category": "Cross-Site Scripting (XSS)",
        "name": "HTTP response built with unescaped user input",
        "severity": "HIGH",
        "pattern": r"(?:make_response|Response|HttpResponse)\s*\([^)]*(?:request\b|args\b|kwargs\b|input)",
        "description": "Returning user-supplied data in HTTP responses without HTML encoding enables XSS.",
        "cwe": "CWE-79",
        "recommendation": "Use template engines with auto-escaping, or explicitly escape with html.escape() / markupsafe.escape().",
    },
]

# ============================================================
# PYTHON VULNERABLE PACKAGES
# ============================================================
PYTHON_VULNERABLE_PACKAGES = {
    # --- Web frameworks ---
    "django": [
        {
            "affected": "<3.2.21",
            "cve": "CVE-2023-43665",
            "severity": "HIGH",
            "description": "ReDoS in django.utils.text.Truncator.words().",
            "fix": "3.2.21",
        },
        {
            "affected": "<4.2.7",
            "cve": "CVE-2023-46695",
            "severity": "HIGH",
            "description": "Potential DoS via crafted username on Windows in UsernameField.",
            "fix": "4.2.7",
        },
        {
            "affected": "<2.2.28",
            "cve": "CVE-2022-28347",
            "severity": "CRITICAL",
            "description": "SQL injection via QuerySet.explain() on PostgreSQL.",
            "fix": "2.2.28",
        },
    ],
    "flask": [
        {
            "affected": "<2.3.2",
            "cve": "CVE-2023-30861",
            "severity": "HIGH",
            "description": "Session cookie exposed in redirect responses when Vary header is absent.",
            "fix": "2.3.2",
        },
    ],
    "fastapi": [
        {
            "affected": "<0.109.1",
            "cve": "CVE-2024-24762",
            "severity": "HIGH",
            "description": "ReDoS in multipart/form-data content-type header parsing.",
            "fix": "0.109.1",
        },
    ],
    # --- HTTP / Networking ---
    "requests": [
        {
            "affected": "<2.31.0",
            "cve": "CVE-2023-32681",
            "severity": "MEDIUM",
            "description": "Proxy-Authorization header leaked to destination servers on redirect.",
            "fix": "2.31.0",
        },
    ],
    "urllib3": [
        {
            "affected": "<1.26.5",
            "cve": "CVE-2021-33503",
            "severity": "HIGH",
            "description": "ReDoS via crafted HTTP URL.",
            "fix": "1.26.5",
        },
        {
            "affected": "<2.0.7",
            "cve": "CVE-2023-45803",
            "severity": "MEDIUM",
            "description": "Request body not stripped when method changes to GET on redirect.",
            "fix": "2.0.7",
        },
    ],
    "aiohttp": [
        {
            "affected": "<3.9.2",
            "cve": "CVE-2024-23334",
            "severity": "HIGH",
            "description": "Path traversal in static file serving.",
            "fix": "3.9.2",
        },
        {
            "affected": "<3.9.4",
            "cve": "CVE-2024-27306",
            "severity": "MEDIUM",
            "description": "XSS via multipart/form-data content-type header.",
            "fix": "3.9.4",
        },
    ],
    # --- Templating ---
    "jinja2": [
        {
            "affected": "<3.1.3",
            "cve": "CVE-2024-22195",
            "severity": "MEDIUM",
            "description": "XSS via xmlattr filter accepting keys with spaces.",
            "fix": "3.1.3",
        },
    ],
    # --- Serialization / Config ---
    "pyyaml": [
        {
            "affected": "<6.0",
            "cve": "CVE-2017-18342",
            "severity": "CRITICAL",
            "description": "yaml.load() with default Loader allows arbitrary code execution.",
            "fix": "6.0",
        },
    ],
    # --- Cryptography ---
    "cryptography": [
        {
            "affected": "<41.0.6",
            "cve": "CVE-2023-49083",
            "severity": "MEDIUM",
            "description": "NULL pointer dereference in PKCS12 parsing allows DoS.",
            "fix": "41.0.6",
        },
        {
            "affected": "<42.0.4",
            "cve": "CVE-2024-26130",
            "severity": "HIGH",
            "description": "NULL pointer dereference in PKCS12 serialisation allows DoS.",
            "fix": "42.0.4",
        },
    ],
    "paramiko": [
        {
            "affected": "<2.10.1",
            "cve": "CVE-2022-24302",
            "severity": "MEDIUM",
            "description": "Race condition when writing private key files allows information disclosure.",
            "fix": "2.10.1",
        },
    ],
    # --- Image processing ---
    "pillow": [
        {
            "affected": "<10.0.1",
            "cve": "CVE-2023-44271",
            "severity": "HIGH",
            "description": "Uncontrolled resource consumption when processing crafted image files.",
            "fix": "10.0.1",
        },
        {
            "affected": "<9.3.0",
            "cve": "CVE-2022-45198",
            "severity": "HIGH",
            "description": "JPEG parsing heap buffer overflow enables arbitrary code execution.",
            "fix": "9.3.0",
        },
    ],
    # --- Database ---
    "sqlalchemy": [
        {
            "affected": "<1.4.0",
            "cve": "CVE-2019-7548",
            "severity": "HIGH",
            "description": "SQL injection via order_by parameter in certain dialects.",
            "fix": "1.4.0",
        },
    ],
    "celery": [
        {
            "affected": "<5.2.2",
            "cve": "CVE-2021-23727",
            "severity": "HIGH",
            "description": "Stored command injection via broker configuration.",
            "fix": "5.2.2",
        },
    ],
    # --- AI / ML frameworks ---
    "langchain": [
        {
            "affected": "<0.0.312",
            "cve": "CVE-2023-46229",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via unsafe pickle deserialization of chain/tool files.",
            "fix": "0.0.312",
        },
        {
            "affected": "<0.1.17",
            "cve": "CVE-2024-28088",
            "severity": "HIGH",
            "description": "Path traversal in LocalFileStore allows reading arbitrary files.",
            "fix": "0.1.17",
        },
    ],
    "transformers": [
        {
            "affected": "<4.36.0",
            "cve": "CVE-2023-6730",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via unsafe pickle deserialization in model loading.",
            "fix": "4.36.0",
        },
    ],
    "torch": [
        {
            "affected": "<2.0.1",
            "cve": "CVE-2022-45907",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via torch.load() with malicious model files (pickle).",
            "fix": "2.0.1",
        },
    ],
    "gradio": [
        {
            "affected": "<4.11.0",
            "cve": "CVE-2024-0964",
            "severity": "HIGH",
            "description": "Path traversal in file serving endpoint allows reading arbitrary server files.",
            "fix": "4.11.0",
        },
    ],
    "mlflow": [
        {
            "affected": "<2.9.2",
            "cve": "CVE-2023-6977",
            "severity": "CRITICAL",
            "description": "Path traversal allows reading arbitrary files outside the artifact directory.",
            "fix": "2.9.2",
        },
    ],
}



# ============================================================
# MERN SAST RULES  (JavaScript / TypeScript source code patterns)
# ============================================================
MERN_SAST_RULES = [
    # --- NoSQL Injection ---
    {
        "id": "MERN-NOSQL-001",
        "category": "NoSQL Injection",
        "name": "req.body passed directly to MongoDB/Mongoose query",
        "severity": "CRITICAL",
        "pattern": r"(?:find|findOne|findById|updateOne|updateMany|deleteOne|deleteMany|replaceOne|count|countDocuments)\s*\(\s*req\.(?:body|query|params)",
        "description": (
            "Passing unsanitized request data directly to a MongoDB/Mongoose query "
            "allows NoSQL injection. Attackers can supply MongoDB operators ($where, $regex, "
            "$gt) to bypass authentication or extract all documents."
        ),
        "cwe": "CWE-943",
        "recommendation": (
            "Validate and sanitize all query parameters. Use an allowlist of expected fields "
            "and types (e.g., express-mongo-sanitize). Never spread req.body into a query object."
        ),
    },
    {
        "id": "MERN-NOSQL-002",
        "category": "NoSQL Injection",
        "name": "$where operator with user-controlled expression",
        "severity": "CRITICAL",
        "pattern": r'\$where\s*[=:]\s*[`\'"].*?(?:req\.|params\.|query\.|body\.)',
        "description": (
            "$where evaluates a JavaScript string in the MongoDB engine. "
            "User-controlled input enables full data exfiltration and DoS via ReDoS."
        ),
        "cwe": "CWE-943",
        "recommendation": "Never use $where with user-supplied data. Use standard query operators instead.",
    },
    {
        "id": "MERN-NOSQL-003",
        "category": "NoSQL Injection",
        "name": "Mongoose model spread from req.body (mass assignment)",
        "severity": "HIGH",
        "pattern": r"new\s+\w+\s*\(\s*req\.body\s*\)",
        "description": (
            "Constructing a Mongoose model directly from req.body allows attackers to "
            "set any field, including privileged ones (isAdmin, role, __proto__)."
        ),
        "cwe": "CWE-915",
        "recommendation": (
            "Explicitly pick allowed fields from req.body. "
            "Use a validation library (Joi, Zod, express-validator) and define strict schemas."
        ),
    },

    # --- Command Injection ---
    {
        "id": "MERN-CMDI-001",
        "category": "Command Injection",
        "name": "child_process.exec() with user-controlled input",
        "severity": "CRITICAL",
        "pattern": r"(?:exec|execSync)\s*\([^)]*(?:req\.|params\.|query\.|body\.|process\.argv)",
        "description": (
            "child_process.exec() passes its argument to the OS shell. "
            "Any unsanitized user input enables arbitrary command execution."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Use child_process.execFile() or spawn() with a fixed command and a list of "
            "arguments—never a shell string. Validate and allowlist all user-supplied values."
        ),
    },
    {
        "id": "MERN-CMDI-002",
        "category": "Command Injection",
        "name": "child_process.exec() call (review for user-controlled args)",
        "severity": "HIGH",
        "pattern": r"\bexec\s*\([^)]*\$\{",
        "description": (
            "Template literal interpolation inside exec() suggests dynamic command "
            "construction. Verify no component originates from user-supplied data."
        ),
        "cwe": "CWE-78",
        "recommendation": "Replace exec() with execFile()/spawn() using a fixed command array.",
    },
    {
        "id": "MERN-CMDI-003",
        "category": "Command Injection",
        "name": "eval() with dynamic argument in Node.js",
        "severity": "CRITICAL",
        "pattern": r"\beval\s*\([^)]*(?:req\.|params\.|query\.|body\.|process\.env|JSON\.parse)",
        "description": (
            "eval() executes arbitrary JavaScript. User-controlled or externally sourced "
            "input enables full remote code execution."
        ),
        "cwe": "CWE-95",
        "recommendation": "Remove eval(). Use JSON.parse() for data, or a sandboxed vm.Script for code isolation.",
    },
    {
        "id": "MERN-CMDI-004",
        "category": "Command Injection",
        "name": "vm.runInNewContext/runInThisContext with user input",
        "severity": "CRITICAL",
        "pattern": r"vm\.run(?:InNewContext|InThisContext|Script)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "Node.js vm module sandbox is not a security boundary. "
            "Attackers can escape the sandbox and execute arbitrary code."
        ),
        "cwe": "CWE-95",
        "recommendation": (
            "Never run user-supplied code via vm. Use a purpose-built sandbox "
            "(isolated-vm, Deno subprocess) with strict resource limits."
        ),
    },

    # --- Path Traversal ---
    {
        "id": "MERN-PATH-001",
        "category": "Path Traversal",
        "name": "fs.readFile/readFileSync with user-controlled path",
        "severity": "HIGH",
        "pattern": r"fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "Reading or writing files using paths derived from user input enables "
            "path traversal (../../etc/passwd) and arbitrary file read/write."
        ),
        "cwe": "CWE-22",
        "recommendation": (
            "Use path.resolve() and verify the result starts with the intended base directory. "
            "Reject any path containing '..' before resolving."
        ),
    },
    {
        "id": "MERN-PATH-002",
        "category": "Path Traversal",
        "name": "path.join() with user-controlled segments",
        "severity": "HIGH",
        "pattern": r"path\.(?:join|resolve)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "path.join() does not sanitize '..'. An attacker supplying '../' segments "
            "can escape the intended base directory."
        ),
        "cwe": "CWE-22",
        "recommendation": (
            "After path.join/resolve, check that the result starts with the base directory. "
            "Strip or reject paths containing '..'."
        ),
    },

    # --- Cross-Site Scripting ---
    {
        "id": "MERN-XSS-001",
        "category": "Cross-Site Scripting (XSS)",
        "name": "React dangerouslySetInnerHTML with user data",
        "severity": "HIGH",
        "pattern": r"dangerouslySetInnerHTML\s*=\s*\{.*?(?:__html\s*:\s*(?:props\.|state\.|this\.|data\.|content\.|html\.|userInput|req\.))",
        "description": (
            "dangerouslySetInnerHTML bypasses React's XSS protection. "
            "Injecting user-controlled HTML enables stored or reflected XSS."
        ),
        "cwe": "CWE-79",
        "recommendation": (
            "Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML. "
            "Prefer safe React text rendering (children prop) wherever possible."
        ),
    },
    {
        "id": "MERN-XSS-002",
        "category": "Cross-Site Scripting (XSS)",
        "name": "Direct innerHTML assignment with user data",
        "severity": "HIGH",
        "pattern": r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])[^;]*(?:req\.|params\.|query\.|body\.|location\.|document\.)",
        "description": (
            "Assigning user-controlled data to innerHTML interprets it as HTML, "
            "enabling XSS attacks."
        ),
        "cwe": "CWE-79",
        "recommendation": "Use textContent or innerText for plain text. If HTML is needed, sanitize with DOMPurify.",
    },
    {
        "id": "MERN-XSS-003",
        "category": "Cross-Site Scripting (XSS)",
        "name": "document.write() with dynamic content",
        "severity": "HIGH",
        "pattern": r"document\.write\s*\([^)]*(?:req\.|location\.|document\.|window\.|params\.|query\.)",
        "description": (
            "document.write() with dynamic content allows HTML/script injection. "
            "It also blocks HTML parsing in modern browsers."
        ),
        "cwe": "CWE-79",
        "recommendation": "Remove document.write(). Use DOM manipulation APIs (createElement, textContent) instead.",
    },
    {
        "id": "MERN-XSS-004",
        "category": "Cross-Site Scripting (XSS)",
        "name": "res.send() / res.write() with unsanitized user input",
        "severity": "HIGH",
        "pattern": r"res\.(?:send|write|end)\s*\([^)]*(?:req\.(?:body|query|params))",
        "description": (
            "Sending unsanitized request data directly in an HTTP response enables "
            "reflected XSS when the response Content-Type is text/html."
        ),
        "cwe": "CWE-79",
        "recommendation": (
            "Encode output for the target context. Set Content-Type: application/json "
            "for API responses. Use a templating engine with auto-escaping for HTML."
        ),
    },

    # --- SQL Injection (Sequelize / Knex / raw queries) ---
    {
        "id": "MERN-SQLI-001",
        "category": "SQL Injection",
        "name": "Sequelize.query() with raw template literal",
        "severity": "CRITICAL",
        "pattern": r"sequelize\.query\s*\(`[^`]*\$\{",
        "description": (
            "Embedding template-literal interpolation in a Sequelize raw query enables "
            "SQL injection if any interpolated value is user-controlled."
        ),
        "cwe": "CWE-89",
        "recommendation": (
            "Use Sequelize parameterized queries: sequelize.query(sql, { replacements: [...] }). "
            "Never interpolate user data into raw SQL strings."
        ),
    },
    {
        "id": "MERN-SQLI-002",
        "category": "SQL Injection",
        "name": "Knex raw() with template literal interpolation",
        "severity": "CRITICAL",
        "pattern": r"knex\.raw\s*\(`[^`]*\$\{",
        "description": "Knex raw() with string interpolation enables SQL injection on any interpolated user value.",
        "cwe": "CWE-89",
        "recommendation": "Use knex.raw('SELECT ? WHERE id = ?', [value]) with bound parameters.",
    },

    # --- SSRF ---
    {
        "id": "MERN-SSRF-001",
        "category": "Server-Side Request Forgery (SSRF)",
        "name": "axios/fetch/node-fetch with user-controlled URL",
        "severity": "HIGH",
        "pattern": r"(?:axios\.(?:get|post|put|delete|request)|fetch|nodeFetch|https?\.(?:get|request))\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "Making HTTP requests to URLs derived from user input enables SSRF. "
            "Attackers can reach internal services, cloud metadata endpoints "
            "(169.254.169.254), and internal APIs."
        ),
        "cwe": "CWE-918",
        "recommendation": (
            "Validate and allowlist target URLs/hostnames. Block requests to private "
            "IP ranges and cloud metadata addresses. Use a dedicated HTTP proxy with egress controls."
        ),
    },

    # --- Open Redirect ---
    {
        "id": "MERN-REDIR-001",
        "category": "Open Redirect",
        "name": "res.redirect() with user-controlled URL",
        "severity": "MEDIUM",
        "pattern": r"res\.redirect\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "Redirecting to a URL derived from user input enables open redirect "
            "attacks used for phishing and OAuth token theft."
        ),
        "cwe": "CWE-601",
        "recommendation": (
            "Validate redirect targets against a strict allowlist of permitted hostnames. "
            "Reject absolute URLs or enforce same-origin redirects."
        ),
    },

    # --- JWT Misconfigurations ---
    {
        "id": "MERN-JWT-001",
        "category": "Broken Authentication",
        "name": "JWT signed with hardcoded or weak secret",
        "severity": "CRITICAL",
        "pattern": r"jwt\.sign\s*\([^)]*[,\s]['\"](?:[a-zA-Z0-9]{1,20}|secret|password|mysecret|changeme|jwt_secret)['\"]",
        "description": (
            "A short or guessable JWT secret allows attackers to forge tokens and "
            "impersonate any user, including admins."
        ),
        "cwe": "CWE-330",
        "recommendation": (
            "Generate a cryptographically random secret of at least 256 bits. "
            "Store it in an environment variable—never hardcode it."
        ),
    },
    {
        "id": "MERN-JWT-002",
        "category": "Broken Authentication",
        "name": "JWT verification with algorithms: ['none']",
        "severity": "CRITICAL",
        "pattern": r"jwt\.verify\s*\([^)]*algorithms\s*:\s*\[.*?['\"]none['\"]",
        "description": (
            "Allowing the 'none' algorithm in JWT verification lets attackers strip "
            "the signature and forge arbitrary tokens (CVE-2015-9235)."
        ),
        "cwe": "CWE-347",
        "recommendation": "Explicitly specify only HMAC or RSA algorithms: { algorithms: ['HS256'] }. Never allow 'none'.",
    },
    {
        "id": "MERN-JWT-003",
        "category": "Broken Authentication",
        "name": "JWT verified without expiry check",
        "severity": "MEDIUM",
        "pattern": r"jwt\.verify\s*\([^,)]+,\s*[^,)]+\s*\)",
        "description": (
            "Calling jwt.verify() with only two arguments skips options like "
            "maxAge/expiresIn enforcement if not embedded in the token."
        ),
        "cwe": "CWE-613",
        "recommendation": "Pass a third options argument: jwt.verify(token, secret, { algorithms: ['HS256'], maxAge: '1h' }).",
    },

    # --- Prototype Pollution ---
    {
        "id": "MERN-PROTO-001",
        "category": "Prototype Pollution",
        "name": "lodash _.merge() / _.defaultsDeep() with req.body",
        "severity": "HIGH",
        "pattern": r"_\.(?:merge|defaultsDeep|mergeWith|extend|assign)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "lodash _.merge() and _.defaultsDeep() recursively merge properties including "
            "__proto__. Supplying {\"__proto__\":{\"admin\":true}} pollutes Object.prototype "
            "and can escalate privileges or crash the server."
        ),
        "cwe": "CWE-1321",
        "recommendation": (
            "Use JSON.parse(JSON.stringify(input)) to deep-clone before merging, "
            "or validate input against a strict schema. Upgrade lodash ≥ 4.17.21."
        ),
    },
    {
        "id": "MERN-PROTO-002",
        "category": "Prototype Pollution",
        "name": "Object.assign() with user-controlled source",
        "severity": "MEDIUM",
        "pattern": r"Object\.assign\s*\(\s*(?:\{\}|\w+)\s*,\s*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "Object.assign() copies enumerable own properties. "
            "A source object with __proto__ manipulation can pollute prototypes in older Node.js."
        ),
        "cwe": "CWE-1321",
        "recommendation": "Validate and sanitize user-supplied objects before merging. Use a schema validator (Joi, Zod).",
    },

    # --- Hardcoded Secrets ---
    {
        "id": "MERN-SEC-001",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded JWT / session secret in source",
        "severity": "CRITICAL",
        "pattern": r"(?:jwt(?:Secret|_secret)|session(?:Secret|_secret)|JWT_SECRET|SESSION_SECRET)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
        "description": (
            "A hardcoded JWT or session secret is exposed to anyone with read access "
            "to the source, enabling token forgery and session hijacking."
        ),
        "cwe": "CWE-798",
        "recommendation": "Load secrets from environment variables via process.env. Use a secrets manager (Vault, AWS SSM).",
    },
    {
        "id": "MERN-SEC-002",
        "category": "Hardcoded Credentials",
        "name": "MongoDB connection string with embedded credentials",
        "severity": "HIGH",
        "pattern": r"mongodb(?:\+srv)?://[^@\s]+:[^@\s]+@",
        "description": (
            "Embedding MongoDB credentials directly in the connection URI exposes them "
            "in source code, logs, and error messages."
        ),
        "cwe": "CWE-798",
        "recommendation": "Store the connection string in an environment variable. Use MongoDB Atlas credential rotation.",
    },
    {
        "id": "MERN-SEC-003",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded API key or token literal",
        "severity": "HIGH",
        "pattern": r"(?:apiKey|api_key|accessToken|access_token|authToken|auth_token|privateKey|private_key)\s*[=:]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]",
        "description": "Hardcoded API keys or tokens can be extracted from source or compiled bundles.",
        "cwe": "CWE-798",
        "recommendation": "Load secrets from environment variables. Rotate any key that was ever committed to source control.",
    },

    # --- Insecure Deserialization ---
    {
        "id": "MERN-DESER-001",
        "category": "Insecure Deserialization",
        "name": "node-serialize unserialize() with user input – RCE",
        "severity": "CRITICAL",
        "pattern": r"(?:serialize|unserialize)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "node-serialize's unserialize() executes Immediately Invoked Function Expressions "
            "(IIFEs) embedded in serialized data, enabling unauthenticated RCE "
            "(CVE-2017-5941)."
        ),
        "cwe": "CWE-502",
        "recommendation": "Never deserialize user-supplied data with node-serialize. Use JSON.parse() for data exchange.",
    },
    {
        "id": "MERN-DESER-002",
        "category": "Insecure Deserialization",
        "name": "YAML.load() without safeLoad in Node.js",
        "severity": "CRITICAL",
        "pattern": r"(?:yaml|YAML)\.load\s*\([^)]*(?:req\.|params\.|query\.|body\.|fs\.)",
        "description": (
            "js-yaml's YAML.load() in DEFAULT_FULL_SCHEMA mode instantiates arbitrary "
            "JavaScript types, including functions, enabling RCE."
        ),
        "cwe": "CWE-502",
        "recommendation": "Use YAML.safeLoad() (js-yaml ≤ 3.x) or yaml.load() with { schema: FAILSAFE_SCHEMA } (js-yaml 4+).",
    },

    # --- Security Misconfiguration ---
    {
        "id": "MERN-CONF-001",
        "category": "Security Misconfiguration",
        "name": "CORS configured with wildcard origin (*)",
        "severity": "MEDIUM",
        "pattern": r"(?:cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]?\*['\"]?)",
        "description": (
            "Allowing all origins with CORS (*) allows any website to make "
            "authenticated cross-origin requests to this API, enabling CSRF and data theft."
        ),
        "cwe": "CWE-942",
        "recommendation": "Restrict CORS to specific trusted origins. Never use '*' with credentials:true.",
    },
    {
        "id": "MERN-CONF-002",
        "category": "Security Misconfiguration",
        "name": "Express app running with debug mode or stack traces exposed",
        "severity": "MEDIUM",
        "pattern": r"app\.(?:set|use)\s*\([^)]*(?:['\"]x-powered-by['\"]|debug\s*:\s*true|stackError\s*:\s*true)",
        "description": (
            "Exposing the X-Powered-By header, enabling debug mode, or returning "
            "stack traces to clients leaks implementation details useful for exploitation."
        ),
        "cwe": "CWE-209",
        "recommendation": "Use app.disable('x-powered-by'). Catch errors centrally and return generic messages to clients.",
    },
    {
        "id": "MERN-CONF-003",
        "category": "Security Misconfiguration",
        "name": "Helmet.js not used (missing security headers)",
        "severity": "LOW",
        "pattern": r"(?:const|let|var)\s+app\s*=\s*express\s*\(\s*\)",
        "description": (
            "Express apps without helmet() lack security headers: "
            "Content-Security-Policy, X-Frame-Options, X-XSS-Protection, etc."
        ),
        "cwe": "CWE-16",
        "recommendation": "Add helmet() as the first middleware: app.use(require('helmet')()).",
    },
    {
        "id": "MERN-CONF-004",
        "category": "Security Misconfiguration",
        "name": "Cookie without httpOnly or secure flag",
        "severity": "MEDIUM",
        "pattern": r"res\.cookie\s*\([^)]*\{[^}]*\}(?!\s*,\s*\{[^}]*(?:httpOnly|secure)\s*:\s*true)",
        "description": (
            "Cookies without httpOnly are accessible to JavaScript (XSS → session theft). "
            "Cookies without secure may be transmitted over HTTP."
        ),
        "cwe": "CWE-614",
        "recommendation": "Set { httpOnly: true, secure: true, sameSite: 'strict' } on all session/auth cookies.",
    },

    # --- ReDoS / Regex Safety ---
    {
        "id": "MERN-REDOS-001",
        "category": "Regular Expression DoS (ReDoS)",
        "name": "Complex nested quantifiers in regex pattern",
        "severity": "MEDIUM",
        "pattern": r"new\s+RegExp\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
        "description": (
            "Constructing a RegExp from user-supplied input and running it against "
            "long strings can trigger catastrophic backtracking (ReDoS), "
            "blocking the Node.js event loop."
        ),
        "cwe": "CWE-1333",
        "recommendation": "Never build RegExp from user input. Use a safe-regex library to audit all regex patterns.",
    },
]


# ============================================================
# NODE.JS / NPM PACKAGE CVE DATABASE
# ============================================================
NODE_PACKAGE_CVES = {
    "lodash": [
        {
            "affected": "<4.17.21",
            "cve": "CVE-2021-23337",
            "severity": "HIGH",
            "description": "Command injection via template() function with user-controlled options.",
            "fix": "4.17.21",
        },
        {
            "affected": "<4.17.19",
            "cve": "CVE-2020-8203",
            "severity": "HIGH",
            "description": "Prototype pollution via _.merge() or _.defaultsDeep() with crafted payload.",
            "fix": "4.17.19",
        },
    ],
    "express": [
        {
            "affected": "<4.19.2",
            "cve": "CVE-2024-29041",
            "severity": "MEDIUM",
            "description": "Open redirect via malformed URL in res.location() / res.redirect().",
            "fix": "4.19.2",
        },
    ],
    "mongoose": [
        {
            "affected": "<7.6.3",
            "cve": "CVE-2023-3696",
            "severity": "HIGH",
            "description": "Prototype pollution via schema options object with crafted __proto__ key.",
            "fix": "7.6.3",
        },
    ],
    "jsonwebtoken": [
        {
            "affected": "<9.0.0",
            "cve": "CVE-2022-23529",
            "severity": "HIGH",
            "description": "Insecure default allows 'none' algorithm when verifying tokens without explicit algorithm option.",
            "fix": "9.0.0",
        },
        {
            "affected": "<9.0.0",
            "cve": "CVE-2022-23540",
            "severity": "MEDIUM",
            "description": "ReDoS in jwt.verify() via crafted JWT string in the NotBefore claim.",
            "fix": "9.0.0",
        },
    ],
    "axios": [
        {
            "affected": "<1.6.0",
            "cve": "CVE-2023-45857",
            "severity": "MEDIUM",
            "description": "Cross-site request forgery token exposed to third parties via XSRF-TOKEN header on redirect.",
            "fix": "1.6.0",
        },
        {
            "affected": "<0.21.2",
            "cve": "CVE-2021-3749",
            "severity": "HIGH",
            "description": "ReDoS via crafted input to the trim() call inside the URL sanitizer.",
            "fix": "0.21.2",
        },
    ],
    "node-fetch": [
        {
            "affected": "<2.6.7",
            "cve": "CVE-2022-0235",
            "severity": "HIGH",
            "description": "Exposure of sensitive authentication headers to third parties on cross-origin redirect.",
            "fix": "2.6.7",
        },
    ],
    "ejs": [
        {
            "affected": "<3.1.10",
            "cve": "CVE-2024-33883",
            "severity": "HIGH",
            "description": "Template injection via __proto__ pollution allows arbitrary JavaScript execution.",
            "fix": "3.1.10",
        },
        {
            "affected": "<3.1.7",
            "cve": "CVE-2022-29078",
            "severity": "CRITICAL",
            "description": "Server-Side Template Injection (SSTI) via outputFunctionName option allows RCE.",
            "fix": "3.1.7",
        },
    ],
    "semver": [
        {
            "affected": "<7.5.2",
            "cve": "CVE-2022-25883",
            "severity": "MEDIUM",
            "description": "ReDoS via crafted semver version string with excessive repetition.",
            "fix": "7.5.2",
        },
    ],
    "json5": [
        {
            "affected": "<2.2.2",
            "cve": "CVE-2022-46175",
            "severity": "HIGH",
            "description": "Prototype pollution via crafted __proto__ key in parsed JSON5 object.",
            "fix": "2.2.2",
        },
    ],
    "minimist": [
        {
            "affected": "<1.2.6",
            "cve": "CVE-2021-44906",
            "severity": "CRITICAL",
            "description": "Prototype pollution via crafted CLI argument --__proto__.admin=1.",
            "fix": "1.2.6",
        },
    ],
    "tough-cookie": [
        {
            "affected": "<4.1.3",
            "cve": "CVE-2023-26136",
            "severity": "HIGH",
            "description": "Prototype pollution via crafted cookie domain in CookieJar.",
            "fix": "4.1.3",
        },
    ],
    "next": [
        {
            "affected": "<14.1.1",
            "cve": "CVE-2024-34351",
            "severity": "HIGH",
            "description": "SSRF via Host header manipulation in Server Actions redirects.",
            "fix": "14.1.1",
        },
        {
            "affected": "<13.5.1",
            "cve": "CVE-2023-46298",
            "severity": "HIGH",
            "description": "DoS via crafted HEAD request to pages with getServerSideProps.",
            "fix": "13.5.1",
        },
    ],
    "ws": [
        {
            "affected": "<8.17.1",
            "cve": "CVE-2024-37890",
            "severity": "HIGH",
            "description": "DoS via crafted HTTP/1.1 upgrade request with Sec-WebSocket-Protocol header.",
            "fix": "8.17.1",
        },
    ],
    "body-parser": [
        {
            "affected": "<1.20.3",
            "cve": "CVE-2024-45590",
            "severity": "HIGH",
            "description": "DoS via crafted payload that triggers excessive CPU usage in URL-encoded body parsing.",
            "fix": "1.20.3",
        },
    ],
    "cross-spawn": [
        {
            "affected": "<7.0.5",
            "cve": "CVE-2024-21538",
            "severity": "HIGH",
            "description": "ReDoS via crafted shell argument string in Windows path handling.",
            "fix": "7.0.5",
        },
    ],
    "multer": [
        {
            "affected": "<1.4.5-lts.1",
            "cve": "CVE-2022-24434",
            "severity": "HIGH",
            "description": "Denial of service via malformed multipart/form-data request body.",
            "fix": "1.4.5-lts.1",
        },
    ],
    "path-to-regexp": [
        {
            "affected": "<0.1.12",
            "cve": "CVE-2024-45296",
            "severity": "HIGH",
            "description": "ReDoS via crafted URL path pattern with excessive backtracking.",
            "fix": "0.1.12",
        },
    ],
    "serialize-javascript": [
        {
            "affected": "<6.0.1",
            "cve": "CVE-2022-25878",
            "severity": "MEDIUM",
            "description": "ReDoS via crafted serialized input with deeply nested regex literals.",
            "fix": "6.0.1",
        },
    ],
    "passport": [
        {
            "affected": "<0.6.0",
            "cve": "CVE-2022-25896",
            "severity": "MEDIUM",
            "description": "Session fixation vulnerability allows attacker to maintain session after logout.",
            "fix": "0.6.0",
        },
    ],
    "socket.io": [
        {
            "affected": "<4.6.2",
            "cve": "CVE-2023-31125",
            "severity": "HIGH",
            "description": "DoS via crafted HTTP request to Socket.IO server endpoint.",
            "fix": "4.6.2",
        },
    ],
}


# ============================================================
# .ENV FILE MISCONFIGURATION RULES
# ============================================================
ENV_RULES = [
    {
        "id": "ENV-001",
        "name": "NODE_ENV not set to production",
        "severity": "MEDIUM",
        "pattern": r"^\s*NODE_ENV\s*=\s*(?:development|dev|test|staging|local)\s*$",
        "description": (
            "NODE_ENV=development enables verbose error messages, stack traces, "
            "and debug logging that should never be exposed in production."
        ),
        "recommendation": "Set NODE_ENV=production in the deployment environment.",
    },
    {
        "id": "ENV-002",
        "name": "JWT_SECRET with weak or default value",
        "severity": "CRITICAL",
        "pattern": r"^\s*JWT_SECRET\s*=\s*(?:secret|password|changeme|mysecret|your.secret|jwt_secret|[a-zA-Z0-9]{1,20})\s*$",
        "description": (
            "A short or default JWT secret allows attackers to brute-force or guess "
            "the secret and forge tokens to impersonate any user."
        ),
        "recommendation": "Use a randomly generated 256-bit secret: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"",
    },
    {
        "id": "ENV-003",
        "name": "SESSION_SECRET with weak or default value",
        "severity": "CRITICAL",
        "pattern": r"^\s*SESSION_SECRET\s*=\s*(?:secret|password|changeme|mysecret|[a-zA-Z0-9]{1,20})\s*$",
        "description": "A weak session secret allows session cookie forgery and full account takeover.",
        "recommendation": "Generate a strong random secret with at least 64 characters of entropy.",
    },
    {
        "id": "ENV-004",
        "name": "DEBUG wildcard enabled",
        "severity": "MEDIUM",
        "pattern": r"^\s*DEBUG\s*=\s*\*",
        "description": (
            "DEBUG=* enables verbose debug output for all modules, potentially leaking "
            "database credentials, request bodies, and internal state to logs."
        ),
        "recommendation": "Disable DEBUG in production or restrict to specific namespaces: DEBUG=myapp:error",
    },
    {
        "id": "ENV-005",
        "name": "MongoDB URI with hardcoded credentials",
        "severity": "HIGH",
        "pattern": r"^\s*(?:MONGO(?:DB)?_URI|DATABASE_URL|MONGO_URL)\s*=\s*mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@",
        "description": "MongoDB credentials are embedded directly in the connection URI in the .env file.",
        "recommendation": (
            "Use MongoDB Atlas with IP allowlisting and rotate credentials. "
            "Ensure .env is in .gitignore and never committed to source control."
        ),
    },
    {
        "id": "ENV-006",
        "name": "Plaintext password or secret value in .env",
        "severity": "HIGH",
        "pattern": r"^\s*(?:DB_PASS(?:WORD)?|REDIS_PASSWORD|SMTP_PASS(?:WORD)?|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET_KEY|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN)\s*=\s*.{8,}",
        "description": (
            "Service credentials stored in .env files are frequently committed to source "
            "control or exposed through misconfigured deployments."
        ),
        "recommendation": "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault). Verify .env is in .gitignore.",
    },
    {
        "id": "ENV-007",
        "name": "CORS origin set to wildcard",
        "severity": "MEDIUM",
        "pattern": r"^\s*(?:CORS_ORIGIN|ALLOWED_ORIGINS)\s*=\s*\*",
        "description": "A wildcard CORS origin allows any website to make authenticated cross-origin requests to this API.",
        "recommendation": "Set CORS_ORIGIN to a specific list of allowed frontend domains.",
    },
]


# ============================================================
# LAMP STACK — APACHE HTTP SERVER SAST RULES
# ============================================================
LAMP_APACHE_RULES = [
    # --- Server Information Disclosure ---
    {
        "id": "LAMP-APACHE-001",
        "name": "ServerTokens not set to Prod – server version disclosed",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"^\s*ServerTokens\s+(?!Prod\b)(?:Full|Major|Minor|OS|Minimal)\b",
        "description": (
            "ServerTokens controls how much information Apache exposes in HTTP headers. "
            "Any value other than 'Prod' reveals the Apache version and loaded modules, "
            "helping attackers identify exploitable CVEs."
        ),
        "cwe": "CWE-200",
        "recommendation": "Set 'ServerTokens Prod' in httpd.conf or apache2.conf.",
    },
    {
        "id": "LAMP-APACHE-002",
        "name": "ServerSignature On – server version appended to error pages",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"^\s*ServerSignature\s+On\b",
        "description": (
            "ServerSignature On appends the server version and virtual host name to Apache "
            "error pages, leaking version info to attackers."
        ),
        "cwe": "CWE-200",
        "recommendation": "Set 'ServerSignature Off' in httpd.conf.",
    },
    {
        "id": "LAMP-APACHE-003",
        "name": "TraceEnable On – HTTP TRACE method enabled",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"^\s*TraceEnable\s+On\b",
        "description": (
            "HTTP TRACE can enable Cross-Site Tracing (XST) attacks when combined with XSS, "
            "allowing cookie theft even when HttpOnly is set."
        ),
        "cwe": "CWE-16",
        "recommendation": "Set 'TraceEnable Off' in httpd.conf.",
    },
    {
        "id": "LAMP-APACHE-004",
        "name": "Options Indexes – directory listing enabled",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"^\s*Options\s+[^#\n]*\bIndexes\b",
        "description": (
            "Options Indexes enables directory browsing, exposing file listings to attackers "
            "when no index file exists. This may reveal source code, configuration files, and "
            "other sensitive resources."
        ),
        "cwe": "CWE-548",
        "recommendation": "Remove 'Indexes' from Options directive. Use 'Options -Indexes'.",
    },
    {
        "id": "LAMP-APACHE-005",
        "name": "FollowSymLinks without SymLinksIfOwnerMatch – symlink traversal risk",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"^\s*Options\s+[^#\n]*\bFollowSymLinks\b",
        "description": (
            "FollowSymLinks without SymLinksIfOwnerMatch allows attackers who can create "
            "symlinks to read any file the Apache process can access, bypassing file permissions."
        ),
        "cwe": "CWE-59",
        "recommendation": "Use 'Options SymLinksIfOwnerMatch' instead of 'FollowSymLinks'.",
    },
    {
        "id": "LAMP-APACHE-006",
        "name": "AllowOverride All – unrestricted .htaccess override",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"^\s*AllowOverride\s+All\b",
        "description": (
            "AllowOverride All permits .htaccess files to override any server configuration, "
            "including security settings. This increases the attack surface if any directory "
            "is writable by application code."
        ),
        "cwe": "CWE-16",
        "recommendation": "Restrict to specific directives: 'AllowOverride AuthConfig Limit'.",
    },
    {
        "id": "LAMP-APACHE-007",
        "name": "ProxyRequests On – open HTTP proxy",
        "category": "Apache Misconfiguration",
        "severity": "CRITICAL",
        "pattern": r"^\s*ProxyRequests\s+On\b",
        "description": (
            "ProxyRequests On enables forward proxying, allowing external clients to route "
            "arbitrary requests through the server. This creates an open proxy that attackers "
            "can abuse for SSRF, amplification, and bypassing IP blocks."
        ),
        "cwe": "CWE-441",
        "recommendation": "Set 'ProxyRequests Off'. Only enable mod_proxy_http for reverse proxy use cases.",
    },
    {
        "id": "LAMP-APACHE-008",
        "name": "Weak SSLProtocol – legacy TLS/SSL protocols allowed",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"^\s*SSLProtocol\s+all\b",
        "description": (
            "SSLProtocol all enables SSLv2, SSLv3, TLS 1.0, and TLS 1.1, which are all "
            "deprecated and vulnerable to POODLE, BEAST, and other protocol-level attacks."
        ),
        "cwe": "CWE-326",
        "recommendation": "Use 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1' or 'SSLProtocol TLSv1.2 TLSv1.3'.",
    },
    {
        "id": "LAMP-APACHE-009",
        "name": "SSLv2 or SSLv3 explicitly enabled",
        "category": "Apache Misconfiguration",
        "severity": "CRITICAL",
        "pattern": r"^\s*SSLProtocol\s+[^#\n]*\b(?:SSLv2|SSLv3)\b",
        "description": (
            "SSLv2 and SSLv3 are cryptographically broken. SSLv3 is vulnerable to POODLE "
            "(CVE-2014-3566). SSLv2 allows MD5-signed handshakes trivially broken by offline attack."
        ),
        "cwe": "CWE-326",
        "recommendation": "Remove SSLv2 and SSLv3 from SSLProtocol. Enable only TLSv1.2 and TLSv1.3.",
    },
    {
        "id": "LAMP-APACHE-010",
        "name": "Weak SSLCipherSuite – RC4, DES, NULL, or EXPORT ciphers allowed",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"^\s*SSLCipherSuite\s+[^#\n]*\b(?:RC4|3DES|DES|NULL|EXPORT|ADH|AECDH|aNULL|eNULL|LOW)\b",
        "description": (
            "Weak cipher suites allow downgrade attacks (BEAST, SWEET32, FREAK). "
            "RC4, DES, and NULL ciphers are cryptographically broken or provide no encryption."
        ),
        "cwe": "CWE-327",
        "recommendation": (
            "Use modern cipher suites: 'SSLCipherSuite ECDH+AESGCM:DH+AESGCM:ECDH+AES256:"
            "DH+AES256:!aNULL:!MD5:!DSS'. Enable SSLHonorCipherOrder On."
        ),
    },
    {
        "id": "LAMP-APACHE-011",
        "name": "SSLVerifyClient none – client certificate verification disabled",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"^\s*SSLVerifyClient\s+none\b",
        "description": "Client certificate verification is disabled. For mTLS configurations this means no client authentication.",
        "cwe": "CWE-295",
        "recommendation": "Use 'SSLVerifyClient require' and 'SSLVerifyDepth 2' if mTLS is intended.",
    },
    {
        "id": "LAMP-APACHE-012",
        "name": "mod_status exposed – server status accessible",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)server-status",
        "description": (
            "Apache mod_status at /server-status exposes real-time server activity, "
            "loaded modules, and request details. Without access controls this leaks "
            "internal URLs and can facilitate enumeration attacks."
        ),
        "cwe": "CWE-200",
        "recommendation": "Restrict server-status to localhost: 'Require ip 127.0.0.1 ::1'.",
    },
    {
        "id": "LAMP-APACHE-013",
        "name": "mod_info exposed – server configuration accessible",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)server-info",
        "description": (
            "Apache mod_info at /server-info exposes the complete server configuration "
            "including loaded modules, directives, and virtual host details. This provides "
            "attackers with detailed intelligence for targeted attacks."
        ),
        "cwe": "CWE-200",
        "recommendation": "Disable mod_info in production. If needed, restrict to 'Require ip 127.0.0.1'.",
    },
    {
        "id": "LAMP-APACHE-014",
        "name": "LimitRequestBody 0 – no request size limit (DoS risk)",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"^\s*LimitRequestBody\s+0\b",
        "description": (
            "LimitRequestBody 0 disables request size limits, allowing unlimited upload sizes "
            "that can be used for denial-of-service attacks consuming disk space or memory."
        ),
        "cwe": "CWE-400",
        "recommendation": "Set LimitRequestBody to a reasonable limit (e.g., 10485760 for 10MB).",
    },
    {
        "id": "LAMP-APACHE-015",
        "name": "Apache 2.2 access control – Order allow,deny/Allow from all",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)Allow\s+from\s+all",
        "description": (
            "Apache 2.2-style 'Allow from all' grants access to all hosts. In Apache 2.4 with "
            "mod_access_compat, this may be silently ignored or produce unexpected behaviour. "
            "Verify that this block does not grant unintended access."
        ),
        "cwe": "CWE-284",
        "recommendation": "Migrate to Apache 2.4 authorization: 'Require all denied' or 'Require ip 127.0.0.1'.",
    },
    {
        "id": "LAMP-APACHE-016",
        "name": "php_value register_globals on – PHP register_globals enabled via Apache",
        "category": "Apache Misconfiguration",
        "severity": "CRITICAL",
        "pattern": r"(?i)^\s*php_(?:value|flag)\s+register_globals\s+(?:on|1|true)",
        "description": (
            "register_globals injects GET/POST/COOKIE variables directly into PHP scope, "
            "enabling trivial variable injection attacks. Removed in PHP 5.4."
        ),
        "cwe": "CWE-473",
        "recommendation": "Remove this setting. Upgrade to PHP 5.4+ and use $_GET/$_POST explicitly.",
    },
    {
        "id": "LAMP-APACHE-017",
        "name": "X-Frame-Options set to ALLOW – clickjacking protection disabled",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)Header\s+(?:set|always\s+set)\s+X-Frame-Options\s+['\"]?ALLOW",
        "description": (
            "X-Frame-Options ALLOW* permits the page to be framed by any origin, "
            "enabling clickjacking attacks."
        ),
        "cwe": "CWE-693",
        "recommendation": "Set 'Header always set X-Frame-Options \"SAMEORIGIN\"' or \"DENY\".",
    },
    {
        "id": "LAMP-APACHE-018",
        "name": "HSTS max-age too short – insufficient HSTS protection",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)Strict-Transport-Security[^;\n]*max-age=(?:[0-9]|[1-9][0-9]{1,4})\b",
        "description": (
            "A Strict-Transport-Security max-age below 31536000 (1 year) reduces "
            "protection against SSL stripping attacks."
        ),
        "cwe": "CWE-319",
        "recommendation": "Set 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"'.",
    },
    {
        "id": "LAMP-APACHE-019",
        "name": "Content-Security-Policy with unsafe-inline or unsafe-eval",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)Content-Security-Policy[^'\"\n]*(?:'unsafe-inline'|'unsafe-eval')",
        "description": (
            "'unsafe-inline' and 'unsafe-eval' in Content-Security-Policy defeat CSP protection "
            "against XSS attacks by allowing inline scripts and eval() execution."
        ),
        "cwe": "CWE-693",
        "recommendation": "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts.",
    },
    {
        "id": "LAMP-APACHE-020",
        "name": "RewriteRule with [P] proxy flag – potential SSRF",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)RewriteRule[^\n]+\[(?:[^\]]*,)?P(?:,|\])",
        "description": (
            "RewriteRule with [P] (proxy) flag forwards matching requests to a backend URL. "
            "If the target URL contains user-supplied captured groups, this enables SSRF attacks."
        ),
        "cwe": "CWE-918",
        "recommendation": "Validate and allowlist proxy targets. Avoid using captured groups in proxy URLs.",
    },
    {
        "id": "LAMP-APACHE-021",
        "name": "ETag exposes inode information",
        "category": "Apache Misconfiguration",
        "severity": "LOW",
        "pattern": r"(?i)^\s*FileETag\s+(?:All|INode)",
        "description": (
            "ETag with INode includes filesystem inode numbers in ETags, leaking inode "
            "information that was historically used to reveal cluster nodes in load-balanced environments."
        ),
        "cwe": "CWE-200",
        "recommendation": "Set 'FileETag MTime Size' to exclude inode information from ETags.",
    },
    {
        "id": "LAMP-APACHE-022",
        "name": "Timeout set too high – Slowloris DoS amplification",
        "category": "Apache Misconfiguration",
        "severity": "LOW",
        "pattern": r"^\s*Timeout\s+(?:[3-9][0-9]{2,}|[1-9][0-9]{3,})\b",
        "description": (
            "A high Timeout value (300+ seconds) keeps connections open longer, "
            "increasing vulnerability to Slowloris-style DoS attacks."
        ),
        "cwe": "CWE-400",
        "recommendation": "Set 'Timeout 60' or lower. Enable mod_reqtimeout for additional protection.",
    },
    {
        "id": "LAMP-APACHE-023",
        "name": "Access log disabled – no audit trail",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)^\s*CustomLog\s+/dev/null\b",
        "description": (
            "Routing access logs to /dev/null disables request logging, preventing forensic "
            "analysis of attacks and compliance auditing."
        ),
        "cwe": "CWE-778",
        "recommendation": "Enable access logging: 'CustomLog /var/log/apache2/access.log combined'.",
    },
    {
        "id": "LAMP-APACHE-024",
        "name": "mod_negotiation MultiViews enabled – file extension probing risk",
        "category": "Apache Misconfiguration",
        "severity": "LOW",
        "pattern": r"(?i)^\s*Options\s+[^#\n]*\bMultiViews\b",
        "description": (
            "MultiViews allows content negotiation, letting attackers probe for file extensions "
            "and enumerate scripts. It can also result in unexpected file serving."
        ),
        "cwe": "CWE-200",
        "recommendation": "Remove MultiViews from Options. Use explicit DirectoryIndex instead.",
    },
    {
        "id": "LAMP-APACHE-025",
        "name": "Deprecated Allow/Deny access control (Apache 2.2 syntax)",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)^\s*(?:Allow|Deny)\s+from\s+",
        "description": (
            "Apache 2.2 Allow/Deny directives are deprecated in Apache 2.4 and may be silently "
            "ignored if mod_access_compat is not loaded, leading to unexpected access grants."
        ),
        "cwe": "CWE-284",
        "recommendation": "Migrate to Apache 2.4 authorization: 'Require ip' and 'Require all denied/granted'.",
    },
    {
        "id": "LAMP-APACHE-026",
        "name": "SSL compression enabled – CRIME attack vulnerability",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*SSLCompression\s+on\b",
        "description": (
            "SSL compression is vulnerable to the CRIME attack (CVE-2012-4929) which can "
            "recover session tokens and other secrets from compressed TLS traffic."
        ),
        "cwe": "CWE-311",
        "recommendation": "Set 'SSLCompression off' (default in OpenSSL 1.0.0+). Ensure TLS compression is disabled.",
    },
    {
        "id": "LAMP-APACHE-027",
        "name": "Weak SSLSessionCacheTimeout – session replay window",
        "category": "Apache Misconfiguration",
        "severity": "LOW",
        "pattern": r"(?i)^\s*SSLSessionCacheTimeout\s+(?:[5-9][0-9]{3,}|[1-9][0-9]{4,})\b",
        "description": (
            "A high SSLSessionCacheTimeout keeps TLS session data cached for longer, "
            "extending the window for session replay attacks if session data is compromised."
        ),
        "cwe": "CWE-613",
        "recommendation": "Set SSLSessionCacheTimeout to 300 seconds or less.",
    },
    {
        "id": "LAMP-APACHE-028",
        "name": "HTTP/2 over cleartext (h2c) enabled in production",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)^\s*Protocols\s+[^\n]*\bh2c\b",
        "description": (
            "h2c (HTTP/2 over cleartext) transmits data without encryption. "
            "Sensitive data including credentials can be intercepted in transit."
        ),
        "cwe": "CWE-319",
        "recommendation": "Remove h2c from Protocols. Use only 'h2 http/1.1' over TLS.",
    },
    {
        "id": "LAMP-APACHE-029",
        "name": "PHP engine enabled in upload directory",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)php_(?:flag|value)\s+engine\s+(?:on|1|true)",
        "description": (
            "PHP execution is explicitly enabled via php_flag/php_value. If this appears in "
            "an upload directory context, uploaded PHP files can be executed as server-side scripts."
        ),
        "cwe": "CWE-434",
        "recommendation": "Add 'php_flag engine off' to upload directory .htaccess or VirtualHost config.",
    },
    {
        "id": "LAMP-APACHE-030",
        "name": "CGI execution enabled – code execution via uploaded scripts",
        "category": "Apache Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*Options\s+[^#\n]*\bExecCGI\b",
        "description": (
            "Options ExecCGI enables CGI script execution in the directory. "
            "If an attacker can write files to this directory, arbitrary OS commands can be executed."
        ),
        "cwe": "CWE-78",
        "recommendation": "Remove ExecCGI from Options. Restrict CGI execution to specific, non-user-writable directories.",
    },
]

# Whole-file presence checks for Apache — flags when security directives are ABSENT
LAMP_APACHE_FILE_CHECKS = [
    {
        "id": "LAMP-APACHE-F01",
        "name": "Missing 'ServerTokens Prod' directive",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "check_absent": r"(?i)^\s*ServerTokens\s+Prod\b",
        "description": "ServerTokens is not set to Prod. Apache may expose version details in HTTP response headers.",
        "cwe": "CWE-200",
        "recommendation": "Add 'ServerTokens Prod' to httpd.conf.",
    },
    {
        "id": "LAMP-APACHE-F02",
        "name": "Missing 'ServerSignature Off' directive",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "check_absent": r"(?i)^\s*ServerSignature\s+Off\b",
        "description": "ServerSignature is not disabled. Apache appends version info to error pages.",
        "cwe": "CWE-200",
        "recommendation": "Add 'ServerSignature Off' to httpd.conf.",
    },
    {
        "id": "LAMP-APACHE-F03",
        "name": "Missing 'TraceEnable Off' directive",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "check_absent": r"(?i)^\s*TraceEnable\s+Off\b",
        "description": "HTTP TRACE method may be enabled. Cross-Site Tracing (XST) attacks exploit TRACE combined with XSS.",
        "cwe": "CWE-16",
        "recommendation": "Add 'TraceEnable Off' to httpd.conf.",
    },
    {
        "id": "LAMP-APACHE-F04",
        "name": "Missing X-Content-Type-Options security header",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "check_absent": r"(?i)X-Content-Type-Options",
        "description": "X-Content-Type-Options header is not configured. Browsers may MIME-sniff responses and execute unexpected content.",
        "cwe": "CWE-693",
        "recommendation": "Add: 'Header always set X-Content-Type-Options \"nosniff\"'",
    },
    {
        "id": "LAMP-APACHE-F05",
        "name": "Missing X-Frame-Options security header",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "check_absent": r"(?i)X-Frame-Options",
        "description": "X-Frame-Options header is not configured, leaving the site vulnerable to clickjacking attacks.",
        "cwe": "CWE-693",
        "recommendation": "Add: 'Header always set X-Frame-Options \"SAMEORIGIN\"'",
    },
    {
        "id": "LAMP-APACHE-F06",
        "name": "Missing Strict-Transport-Security (HSTS) header",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "check_absent": r"(?i)Strict-Transport-Security",
        "description": "HSTS is not configured. Without HSTS, browsers may connect over HTTP first, enabling SSL stripping attacks.",
        "cwe": "CWE-319",
        "recommendation": "Add: 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"'",
    },
    {
        "id": "LAMP-APACHE-F07",
        "name": "Missing Content-Security-Policy header",
        "category": "Apache Misconfiguration",
        "severity": "MEDIUM",
        "check_absent": r"(?i)Content-Security-Policy",
        "description": "No Content-Security-Policy header found. Without CSP, reflected and stored XSS attacks are not mitigated.",
        "cwe": "CWE-693",
        "recommendation": "Add: 'Header always set Content-Security-Policy \"default-src \\'self\\'\"'",
    },
    {
        "id": "LAMP-APACHE-F08",
        "name": "Missing Referrer-Policy header",
        "category": "Apache Misconfiguration",
        "severity": "LOW",
        "check_absent": r"(?i)Referrer-Policy",
        "description": "No Referrer-Policy header found. Browsers may send the full URL as a referer header, leaking sensitive query parameters.",
        "cwe": "CWE-200",
        "recommendation": "Add: 'Header always set Referrer-Policy \"strict-origin-when-cross-origin\"'",
    },
    {
        "id": "LAMP-APACHE-F09",
        "name": "Missing Permissions-Policy header",
        "category": "Apache Misconfiguration",
        "severity": "LOW",
        "check_absent": r"(?i)Permissions-Policy",
        "description": "No Permissions-Policy header found. Browser features (camera, microphone, geolocation) are not explicitly restricted.",
        "cwe": "CWE-693",
        "recommendation": "Add: 'Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"'",
    },
]


# ============================================================
# LAMP STACK — MYSQL / MARIADB CONFIGURATION RULES
# ============================================================
LAMP_MYSQL_RULES = [
    {
        "id": "LAMP-MYSQL-001",
        "name": "skip-grant-tables – MySQL authentication completely disabled",
        "category": "MySQL Misconfiguration",
        "severity": "CRITICAL",
        "pattern": r"(?i)^\s*skip[_-]grant[_-]tables\b",
        "description": (
            "skip-grant-tables disables all authentication and grant table checks, "
            "allowing any user to connect to MySQL as root with no password. "
            "This provides complete unrestricted access to all databases."
        ),
        "cwe": "CWE-287",
        "recommendation": "Remove skip-grant-tables immediately. Only use for emergency recovery with network isolation.",
    },
    {
        "id": "LAMP-MYSQL-002",
        "name": "local-infile enabled – LOAD DATA LOCAL INFILE file read attack",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*local[_-]infile\s*=\s*(?:1|ON|true|yes)\b",
        "description": (
            "local-infile=ON enables LOAD DATA LOCAL INFILE, which allows a malicious MySQL "
            "server to read arbitrary files from the client filesystem. This is a known "
            "client-side attack vector (CVE-2018-20177 pattern) when clients connect to untrusted servers."
        ),
        "cwe": "CWE-200",
        "recommendation": "Set 'local-infile=0' in both [mysqld] and [mysql] sections of my.cnf.",
    },
    {
        "id": "LAMP-MYSQL-003",
        "name": "bind-address=0.0.0.0 – MySQL exposed on all network interfaces",
        "category": "MySQL Misconfiguration",
        "severity": "CRITICAL",
        "pattern": r"(?i)^\s*bind[_-]address\s*=\s*0\.0\.0\.0\b",
        "description": (
            "bind-address=0.0.0.0 exposes MySQL on all network interfaces, making the database "
            "accessible from external networks. Combined with weak credentials this enables "
            "remote brute force and unauthorized access."
        ),
        "cwe": "CWE-284",
        "recommendation": "Set 'bind-address=127.0.0.1' to restrict MySQL to localhost only.",
    },
    {
        "id": "LAMP-MYSQL-004",
        "name": "MySQL listening on all IPv6 interfaces",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*bind[_-]address\s*=\s*::\s*$",
        "description": (
            "bind-address=:: exposes MySQL on all IPv6 interfaces. "
            "This unnecessarily exposes the database service to external network access."
        ),
        "cwe": "CWE-284",
        "recommendation": "Restrict to 'bind-address=127.0.0.1' and use SSH tunnels for remote administration.",
    },
    {
        "id": "LAMP-MYSQL-005",
        "name": "secure-file-priv empty – unrestricted MySQL file read/write",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r'(?i)^\s*secure[_-]file[_-]priv\s*=\s*(?:""|\'\')\s*$',
        "description": (
            "secure-file-priv='' disables the restriction on LOAD DATA INFILE and "
            "SELECT INTO OUTFILE, allowing MySQL to read/write any file the mysql "
            "process has permission to access."
        ),
        "cwe": "CWE-200",
        "recommendation": "Set 'secure-file-priv=/var/lib/mysql-files' or a dedicated restricted directory.",
    },
    {
        "id": "LAMP-MYSQL-006",
        "name": "old_passwords=1 – insecure MySQL 4.x password hashing",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*old[_-]passwords\s*=\s*(?:1|ON|true)\b",
        "description": (
            "old_passwords=1 forces MySQL to use the old, insecure 16-byte password hash "
            "algorithm that can be cracked in seconds with modern hardware. "
            "This setting was removed in MySQL 5.7."
        ),
        "cwe": "CWE-916",
        "recommendation": "Remove old_passwords. Use caching_sha2_password or mysql_native_password authentication plugins.",
    },
    {
        "id": "LAMP-MYSQL-007",
        "name": "skip-show-database – database enumeration possible",
        "category": "MySQL Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)^\s*skip[_-]show[_-]database\s*=\s*(?:0|OFF|false|no)\b",
        "description": (
            "Without skip-show-database enabled, any MySQL user can run SHOW DATABASES and "
            "enumerate all database names regardless of individual database privileges."
        ),
        "cwe": "CWE-200",
        "recommendation": "Add 'skip-show-database' to [mysqld] section in my.cnf.",
    },
    {
        "id": "LAMP-MYSQL-008",
        "name": "symbolic-links=1 – MyISAM symlink attack risk",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*symbolic[_-]links\s*=\s*(?:1|ON|true)\b",
        "description": (
            "symbolic-links=1 allows MyISAM tables to use symbolic links, enabling database "
            "files to be placed anywhere. An attacker with file creation privileges could "
            "create symlinks to sensitive files."
        ),
        "cwe": "CWE-59",
        "recommendation": "Set 'symbolic-links=0' in my.cnf.",
    },
    {
        "id": "LAMP-MYSQL-009",
        "name": "log_bin_trust_function_creators=1 – stored function privilege escalation",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*log[_-]bin[_-]trust[_-]function[_-]creators\s*=\s*(?:1|ON|true)\b",
        "description": (
            "log_bin_trust_function_creators=1 allows users with CREATE ROUTINE privilege "
            "to create non-deterministic stored functions without SUPER privilege, potentially "
            "enabling privilege escalation via unsafe stored procedures."
        ),
        "cwe": "CWE-269",
        "recommendation": "Remove this setting or set to 0. Grant SUPER privilege only to DBAs.",
    },
    {
        "id": "LAMP-MYSQL-010",
        "name": "require_secure_transport=OFF – unencrypted MySQL connections allowed",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*require[_-]secure[_-]transport\s*=\s*(?:OFF|0|false|no)\b",
        "description": (
            "require_secure_transport=OFF allows unencrypted MySQL connections. "
            "Database credentials and query results can be intercepted in transit."
        ),
        "cwe": "CWE-319",
        "recommendation": "Set 'require_secure_transport=ON' and configure SSL/TLS for MySQL connections.",
    },
    {
        "id": "LAMP-MYSQL-011",
        "name": "MySQL running on default port 3306 – easily discoverable",
        "category": "MySQL Misconfiguration",
        "severity": "LOW",
        "pattern": r"(?i)^\s*port\s*=\s*3306\b",
        "description": (
            "Running MySQL on the default port 3306 makes it easily discoverable by automated "
            "vulnerability scanners and brute force tools."
        ),
        "cwe": "CWE-16",
        "recommendation": "Consider changing to a non-standard port and use firewall rules to restrict access.",
    },
    {
        "id": "LAMP-MYSQL-012",
        "name": "general-log=ON – all queries logged in plaintext",
        "category": "MySQL Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)^\s*general[_-]log\s*=\s*(?:1|ON|true)\b",
        "description": (
            "general-log=ON logs every SQL query including credentials in plaintext, "
            "authentication queries, and sensitive data. Log files may be accessible "
            "to unauthorized users and expose sensitive information."
        ),
        "cwe": "CWE-532",
        "recommendation": "Disable general-log in production. Use slow-query-log for performance analysis.",
    },
    {
        "id": "LAMP-MYSQL-013",
        "name": "sql_mode missing strict settings – silent data truncation",
        "category": "MySQL Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r'(?i)^\s*sql[_-]mode\s*=\s*["\']?(?!.*STRICT_TRANS_TABLES)[^"\'\n]+["\']?\s*$',
        "description": (
            "Without STRICT_TRANS_TABLES in sql_mode, MySQL silently truncates data that "
            "exceeds column width constraints, leading to data integrity issues and "
            "potentially exploitable behaviour."
        ),
        "cwe": "CWE-20",
        "recommendation": "Set sql_mode to include STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO.",
    },
    {
        "id": "LAMP-MYSQL-014",
        "name": "event_scheduler=ON – scheduled SQL code execution enabled",
        "category": "MySQL Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)^\s*event[_-]scheduler\s*=\s*(?:ON|1|true)\b",
        "description": (
            "The MySQL Event Scheduler allows scheduled SQL code execution. If an attacker "
            "can create events (requires EVENT privilege), this can be used for persistent "
            "backdoors or data exfiltration."
        ),
        "cwe": "CWE-269",
        "recommendation": "Disable the event scheduler if not required: 'event_scheduler=OFF'.",
    },
    {
        "id": "LAMP-MYSQL-015",
        "name": "Binary log enabled without encryption – sensitive data in binlog",
        "category": "MySQL Misconfiguration",
        "severity": "MEDIUM",
        "pattern": r"(?i)^\s*log[_-]bin\s*=\s*(?!OFF\b)[^\n#]+",
        "description": (
            "Binary logs record all data-modifying queries and may contain sensitive data "
            "including INSERT values with passwords or PII. Without binlog encryption, "
            "any OS user with file access to the MySQL data directory can read these logs."
        ),
        "cwe": "CWE-532",
        "recommendation": "Enable binlog encryption: 'binlog_encryption=ON' (MySQL 8.0+). Restrict file permissions on data directory.",
    },
    {
        "id": "LAMP-MYSQL-016",
        "name": "skip-name-resolve=OFF – DNS-based access control bypass risk",
        "category": "MySQL Misconfiguration",
        "severity": "LOW",
        "pattern": r"(?i)^\s*skip[_-]name[_-]resolve\s*=\s*(?:0|OFF|false|no)\b",
        "description": (
            "Without skip-name-resolve, MySQL performs DNS lookups for connecting clients. "
            "DNS cache poisoning could allow attackers to bypass hostname-based access controls."
        ),
        "cwe": "CWE-350",
        "recommendation": "Enable 'skip-name-resolve=1' and use IP addresses in GRANT statements.",
    },
    {
        "id": "LAMP-MYSQL-017",
        "name": "innodb_file_per_table=OFF – data isolation risk",
        "category": "MySQL Misconfiguration",
        "severity": "LOW",
        "pattern": r"(?i)^\s*innodb[_-]file[_-]per[_-]table\s*=\s*(?:0|OFF|false)\b",
        "description": (
            "innodb_file_per_table=OFF stores all tables in a single shared tablespace file. "
            "This prevents reclaiming disk space after DROP TABLE and complicates data isolation."
        ),
        "cwe": "CWE-664",
        "recommendation": "Enable 'innodb_file_per_table=1' for better data isolation and disk space management.",
    },
    {
        "id": "LAMP-MYSQL-018",
        "name": "MySQL default authentication plugin is weak (mysql_old_password)",
        "category": "MySQL Misconfiguration",
        "severity": "HIGH",
        "pattern": r"(?i)^\s*default[_-]authentication[_-]plugin\s*=\s*mysql[_-]old[_-]password\b",
        "description": (
            "mysql_old_password uses a deprecated and cryptographically weak hashing algorithm. "
            "Hashes can be cracked trivially with rainbow tables or GPU-accelerated brute force."
        ),
        "cwe": "CWE-916",
        "recommendation": "Use 'default-authentication-plugin=caching_sha2_password' (MySQL 8+) or 'mysql_native_password'.",
    },
    {
        "id": "LAMP-MYSQL-019",
        "name": "MySQL running as root OS user – privilege escalation risk",
        "category": "MySQL Misconfiguration",
        "severity": "CRITICAL",
        "pattern": r"(?i)^\s*user\s*=\s*root\b",
        "description": (
            "Running MySQL as the OS root user means any MySQL exploit or SQL injection leading "
            "to OS command execution has full root-level system access. This violates "
            "the principle of least privilege."
        ),
        "cwe": "CWE-250",
        "recommendation": "Run MySQL as a dedicated unprivileged user: 'user=mysql' in my.cnf.",
    },
    {
        "id": "LAMP-MYSQL-020",
        "name": "max_allowed_packet set excessively large – memory exhaustion DoS",
        "category": "MySQL Misconfiguration",
        "severity": "LOW",
        "pattern": r"(?i)^\s*max[_-]allowed[_-]packet\s*=\s*(?:[5-9]\d{8,}|[1-9]\d{9,})\b",
        "description": (
            "An excessively large max_allowed_packet (500MB+) allows clients to send "
            "very large packets, potentially enabling memory exhaustion and DoS attacks."
        ),
        "cwe": "CWE-400",
        "recommendation": "Set max_allowed_packet to 16M or 64M unless larger BLOBs are explicitly required.",
    },
]


# ============================================================
# LAMP STACK — APACHE VERSION CVEs
# ============================================================
APACHE_RANGE_CVES = [
    {
        "affected": "=2.4.49",
        "cve": "CVE-2021-41773",
        "severity": "CRITICAL",
        "description": (
            "Path traversal and RCE in Apache 2.4.49. A flaw in path normalization allows "
            "attackers to map URLs outside the document root. If mod_cgi is enabled, "
            "remote code execution is possible. Actively exploited in the wild."
        ),
        "fix": "2.4.51",
    },
    {
        "affected": "=2.4.50",
        "cve": "CVE-2021-42013",
        "severity": "CRITICAL",
        "description": (
            "Path traversal bypass in Apache 2.4.50. The fix for CVE-2021-41773 was "
            "incomplete. Double URL encoding (%2e%2e) still allows path traversal and RCE."
        ),
        "fix": "2.4.51",
    },
    {
        "affected": "<2.4.56",
        "cve": "CVE-2023-25690",
        "severity": "CRITICAL",
        "description": (
            "HTTP request smuggling via RewriteRule and ProxyPassMatch directives (CVSSv3: 9.8). "
            "Crafted HTTP/1.1 requests can bypass access controls and poison the proxy cache."
        ),
        "fix": "2.4.56",
    },
    {
        "affected": "<2.4.57",
        "cve": "CVE-2023-27522",
        "severity": "HIGH",
        "description": (
            "HTTP response splitting in mod_proxy_uwsgi (Apache 2.4.30-2.4.55). "
            "Specially crafted response headers from a uwsgi backend can cause response splitting."
        ),
        "fix": "2.4.57",
    },
    {
        "affected": "<2.4.57",
        "cve": "CVE-2023-31122",
        "severity": "MEDIUM",
        "description": (
            "Out-of-bounds read vulnerability in mod_macro when processing macros "
            "with certain argument lengths. Can cause server crash (DoS)."
        ),
        "fix": "2.4.57",
    },
    {
        "affected": "<2.4.58",
        "cve": "CVE-2023-45802",
        "severity": "HIGH",
        "description": (
            "HTTP/2 memory not reclaimed on stream reset. When a client resets an HTTP/2 "
            "stream during processing, memory is not properly reclaimed, enabling memory "
            "exhaustion DoS. Related to the Rapid Reset Attack (CVE-2023-44487)."
        ),
        "fix": "2.4.58",
    },
    {
        "affected": "<2.4.58",
        "cve": "CVE-2023-43622",
        "severity": "HIGH",
        "description": (
            "DoS via incomplete TLS handshake (Apache 2.4.11-2.4.57). An attacker initiating "
            "many TLS connections that are never completed can exhaust worker threads."
        ),
        "fix": "2.4.58",
    },
    {
        "affected": "<2.4.59",
        "cve": "CVE-2024-24795",
        "severity": "MEDIUM",
        "description": (
            "HTTP response splitting in multiple modules (Apache 2.4.0-2.4.58). "
            "Malicious response headers from backends can be used to inject content into responses."
        ),
        "fix": "2.4.59",
    },
    {
        "affected": "<2.4.59",
        "cve": "CVE-2024-27316",
        "severity": "HIGH",
        "description": (
            "HTTP/2 CONTINUATION frame flood DoS (CVSSv3: 7.5). An attacker sends "
            "an unlimited number of CONTINUATION frames, exhausting server memory. "
            "Affects Apache 2.4.17 through 2.4.58."
        ),
        "fix": "2.4.59",
    },
    {
        "affected": "<2.4.60",
        "cve": "CVE-2024-38474",
        "severity": "CRITICAL",
        "description": (
            "Encoding bypass leading to source code disclosure and potential RCE via "
            "mod_rewrite. Specially crafted requests can expose source code of CGI scripts "
            "or trigger server-side script execution."
        ),
        "fix": "2.4.60",
    },
    {
        "affected": "<2.4.60",
        "cve": "CVE-2024-38477",
        "severity": "HIGH",
        "description": (
            "NULL pointer dereference in mod_proxy. Crafted requests to a reverse proxy "
            "server with mod_proxy enabled can cause a server crash (DoS)."
        ),
        "fix": "2.4.60",
    },
    {
        "affected": "<2.4.60",
        "cve": "CVE-2024-39573",
        "severity": "HIGH",
        "description": (
            "mod_rewrite proxy handler substitution leading to SSRF. Certain RewriteRule "
            "patterns with substitution starting with an unescaped slash can unexpectedly "
            "set up as a proxy, enabling Server-Side Request Forgery."
        ),
        "fix": "2.4.60",
    },
    {
        "affected": "<2.4.62",
        "cve": "CVE-2024-40898",
        "severity": "HIGH",
        "description": (
            "SSRF with Windows UNC paths in mod_rewrite (Windows systems only). "
            "mod_rewrite rules can be exploited to generate SSRF via UNC path substitution, "
            "enabling NTLM hash capture attacks."
        ),
        "fix": "2.4.62",
    },
    {
        "affected": "<2.4.62",
        "cve": "CVE-2024-39884",
        "severity": "HIGH",
        "description": (
            "Source code disclosure via mod_rewrite substitution encoding issue (Apache 2.4.60). "
            "A regression in mod_rewrite 2.4.60 may cause source code of local content to be "
            "returned as plain text instead of being executed by the scripting handler."
        ),
        "fix": "2.4.62",
    },
]


# ============================================================
# LAMP STACK — MYSQL / MARIADB VERSION CVEs
# ============================================================
MYSQL_RANGE_CVES = [
    {
        "affected": "<=8.0.26",
        "cve": "CVE-2021-35604",
        "severity": "HIGH",
        "description": (
            "MySQL InnoDB component vulnerability (Oracle October 2021 CPU). "
            "An attacker with network access and low privileges can cause server hang or crash."
        ),
        "fix": "8.0.27",
    },
    {
        "affected": "<5.7.38",
        "cve": "CVE-2022-21589",
        "severity": "MEDIUM",
        "description": (
            "MySQL Server Security: Privileges vulnerability. Unauthenticated attacker with "
            "network access can cause partial DoS via multiple protocols."
        ),
        "fix": "5.7.38",
    },
    {
        "affected": "<8.0.30",
        "cve": "CVE-2022-21592",
        "severity": "MEDIUM",
        "description": (
            "MySQL Server C API vulnerability allowing a low-privileged attacker with network "
            "access to execute arbitrary code via the MySQL Client protocol."
        ),
        "fix": "8.0.30",
    },
    {
        "affected": "<10.9.3",
        "cve": "CVE-2022-38791",
        "severity": "HIGH",
        "description": (
            "MariaDB server crash via a prepared statement with certain INSERT operations. "
            "An authenticated attacker can cause a server assertion failure (DoS)."
        ),
        "fix": "10.9.3",
    },
    {
        "affected": "<10.9.3",
        "cve": "CVE-2022-47015",
        "severity": "HIGH",
        "description": (
            "MariaDB denial of service via crafted SQL statements. "
            "The spider storage engine is vulnerable to NULL pointer dereference."
        ),
        "fix": "10.9.3",
    },
    {
        "affected": "<10.11.6",
        "cve": "CVE-2023-5157",
        "severity": "HIGH",
        "description": (
            "MariaDB DoS via crafted JSON argument to certain functions. "
            "Unauthenticated attackers can cause server crashes via specially crafted queries."
        ),
        "fix": "10.11.6",
    },
    {
        "affected": "<8.0.35",
        "cve": "CVE-2023-22084",
        "severity": "MEDIUM",
        "description": (
            "MySQL InnoDB vulnerability allowing unauthenticated attacker with network access "
            "to read accessible data via multiple protocols (Oracle October 2023 CPU)."
        ),
        "fix": "8.0.35",
    },
    {
        "affected": "<8.0.37",
        "cve": "CVE-2024-20961",
        "severity": "HIGH",
        "description": (
            "MySQL Server EXPLAIN DoS vulnerability. An authenticated attacker with LOW "
            "privileges can cause a complete server denial of service via crafted EXPLAIN statements."
        ),
        "fix": "8.0.37",
    },
    {
        "affected": "<8.0.37",
        "cve": "CVE-2024-20973",
        "severity": "MEDIUM",
        "description": (
            "MySQL InnoDB vulnerability allowing an authenticated attacker with HIGH privileges "
            "to cause server hang or crash (DoS). Oracle April 2024 CPU."
        ),
        "fix": "8.0.37",
    },
    {
        "affected": "<8.3.0",
        "cve": "CVE-2024-21096",
        "severity": "MEDIUM",
        "description": (
            "MySQL mysqldump utility information disclosure. Requires human interaction and "
            "can result in unauthorized read access to a subset of MySQL Server accessible data."
        ),
        "fix": "8.3.0",
    },
]


# ============================================================
# LAMP STACK — ADDITIONAL PHP RULES (LAMP-specific patterns)
# ============================================================
LAMP_PHP_EXTRA_RULES = [
    {
        "id": "LAMP-PHP-001",
        "name": "mysqli_query() with variable interpolation – SQL injection",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "pattern": r"mysqli_query\s*\(\s*\$\w+\s*,\s*['\"]?\s*(?:SELECT|INSERT|UPDATE|DELETE|EXEC)\b[^;]*\$",
        "description": (
            "mysqli_query() called with a string containing variable interpolation. "
            "User-controlled variables in the query string enable SQL injection."
        ),
        "cwe": "CWE-89",
        "recommendation": "Use mysqli_prepare() with parameterized queries and mysqli_bind_param().",
    },
    {
        "id": "LAMP-PHP-002",
        "name": "Deprecated mysql_* functions used – no prepared statement support",
        "category": "SQL Injection",
        "severity": "HIGH",
        "pattern": r"\bmysql_(?:query|connect|real_escape_string|fetch_array|fetch_assoc|num_rows|select_db)\s*\(",
        "description": (
            "The mysql_* extension was removed in PHP 7 and deprecated since PHP 5.5. "
            "It lacks support for prepared statements and modern security features."
        ),
        "cwe": "CWE-89",
        "recommendation": "Migrate to PDO or mysqli with prepared statements.",
    },
    {
        "id": "LAMP-PHP-003",
        "name": "extract() with superglobal – variable injection attack",
        "category": "Variable Injection",
        "severity": "CRITICAL",
        "pattern": r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b",
        "description": (
            "extract() with superglobals injects user-supplied key-value pairs directly into "
            "the local symbol table, allowing attackers to overwrite any local variable including "
            "security-critical ones like $authenticated, $admin, or $config."
        ),
        "cwe": "CWE-473",
        "recommendation": "Never call extract() on superglobals. Access individual keys explicitly.",
    },
    {
        "id": "LAMP-PHP-004",
        "name": "parse_str() without output parameter – variable extraction to global scope",
        "category": "Variable Injection",
        "severity": "HIGH",
        "pattern": r"\bparse_str\s*\(\s*[^,)]+\s*\)",
        "description": (
            "parse_str() without a second argument extracts variables directly into the current "
            "scope, similar to register_globals. This enables variable injection attacks."
        ),
        "cwe": "CWE-473",
        "recommendation": "Always provide a second argument: parse_str($str, $output) and access $output.",
    },
    {
        "id": "LAMP-PHP-005",
        "name": "mail() with user-controlled arguments – email header injection",
        "category": "Email Header Injection",
        "severity": "HIGH",
        "pattern": r"\bmail\s*\(\s*\$_(?:GET|POST|REQUEST)\b",
        "description": (
            "Passing user input directly to mail() $to or $headers enables email header "
            "injection. Attackers can inject CRLF sequences to add arbitrary headers and "
            "send spam or phishing emails through the server."
        ),
        "cwe": "CWE-93",
        "recommendation": "Validate email addresses with filter_var(). Strip \\r and \\n from all mail() arguments.",
    },
    {
        "id": "LAMP-PHP-006",
        "name": "session_id() from user input – session fixation attack",
        "category": "Session Fixation",
        "severity": "HIGH",
        "pattern": r"\bsession_id\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
        "description": (
            "Setting the session ID from user-supplied input enables session fixation attacks. "
            "An attacker can pre-set a known session ID and trick a victim into authenticating "
            "with that ID, hijacking the authenticated session."
        ),
        "cwe": "CWE-384",
        "recommendation": "Never accept session IDs from user input. Call session_regenerate_id(true) after login.",
    },
    {
        "id": "LAMP-PHP-007",
        "name": "move_uploaded_file without visible validation – arbitrary file upload",
        "category": "Arbitrary File Upload",
        "severity": "HIGH",
        "pattern": r"\bmove_uploaded_file\s*\(\s*\$_FILES\b",
        "description": (
            "move_uploaded_file() used without visible extension/MIME validation nearby. "
            "Attackers may upload PHP scripts disguised as images, achieving remote code execution "
            "if the upload directory is web-accessible."
        ),
        "cwe": "CWE-434",
        "recommendation": (
            "Validate file extensions against an allowlist. Store uploads outside the webroot. "
            "Rename uploaded files. Set 'Options -ExecCGI' and 'php_flag engine off' on upload directories."
        ),
    },
    {
        "id": "LAMP-PHP-008",
        "name": "mt_rand() used for security tokens – predictable PRNG",
        "category": "Weak Randomness",
        "severity": "MEDIUM",
        "pattern": r"\bmt_rand\s*\(",
        "description": (
            "mt_rand() uses the Mersenne Twister algorithm which is not cryptographically secure. "
            "Using mt_rand() for password reset tokens, CSRF tokens, or session values allows "
            "predictable value attacks."
        ),
        "cwe": "CWE-338",
        "recommendation": "Use random_bytes() or random_int() for security tokens. Use bin2hex(random_bytes(32)) for tokens.",
    },
    {
        "id": "LAMP-PHP-009",
        "name": "unserialize() with cookie or request data – PHP object injection",
        "category": "PHP Object Injection",
        "severity": "CRITICAL",
        "pattern": r"\bunserialize\s*\(\s*\$_(?:COOKIE|GET|POST|REQUEST)\b",
        "description": (
            "PHP object injection via unserialize() with user-controlled data can trigger "
            "__wakeup() and __destruct() magic methods, potentially leading to RCE, "
            "file deletion, or SSRF through PHP Property Oriented Programming (POP) chains."
        ),
        "cwe": "CWE-502",
        "recommendation": "Never unserialize user input. Use JSON with json_decode() for data exchange.",
    },
    {
        "id": "LAMP-PHP-010",
        "name": "ldap_search() with unsanitized input – LDAP injection",
        "category": "LDAP Injection",
        "severity": "HIGH",
        "pattern": r"\bldap_search\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)\b",
        "description": (
            "User input passed to ldap_search() filter without escaping enables LDAP injection, "
            "allowing attackers to bypass authentication or read arbitrary LDAP directory entries."
        ),
        "cwe": "CWE-90",
        "recommendation": "Sanitize LDAP input with ldap_escape() using LDAP_ESCAPE_FILTER flag.",
    },
    {
        "id": "LAMP-PHP-011",
        "name": "XPath query with unsanitized user input – XPath injection",
        "category": "XPath Injection",
        "severity": "HIGH",
        "pattern": r"(?:xpath|->query\s*\(|->evaluate\s*\(|DOMXPath)[^;]*\$_(?:GET|POST|REQUEST)\b",
        "description": (
            "User input incorporated into XPath queries without escaping enables XPath injection, "
            "allowing attackers to extract arbitrary data from XML documents or bypass authentication."
        ),
        "cwe": "CWE-643",
        "recommendation": "Use parameterized XPath queries or escape special characters before interpolation.",
    },
    {
        "id": "LAMP-PHP-012",
        "name": "preg_replace() with /e modifier – arbitrary PHP code execution",
        "category": "Webshell / Backdoor Indicator",
        "severity": "CRITICAL",
        "pattern": r"\bpreg_replace\s*\(\s*['\"][^'\"]*\/e[imsgxADSUXJu]*['\"]",
        "description": (
            "preg_replace() with the /e modifier (removed in PHP 7) evaluates the replacement "
            "as PHP code. This is the classic PHP webshell technique allowing arbitrary code execution."
        ),
        "cwe": "CWE-95",
        "recommendation": "Remove /e modifier. Replace with preg_replace_callback(). Flag for security audit.",
    },
    {
        "id": "LAMP-PHP-013",
        "name": "File operation with user path input – path traversal and null byte injection",
        "category": "Path Traversal",
        "severity": "HIGH",
        "pattern": r"(?:fopen|file_get_contents|readfile|file_put_contents)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)\b",
        "description": (
            "File operation with user-controlled path may be vulnerable to path traversal "
            "(../../etc/passwd) or null byte injection (file.php%00.jpg) in PHP < 5.3.4."
        ),
        "cwe": "CWE-22",
        "recommendation": "Use basename() to strip directory components. Validate against an allowlist of allowed files.",
    },
    {
        "id": "LAMP-PHP-014",
        "name": "Loose comparison (==) for security checks – PHP type juggling",
        "category": "Type Juggling",
        "severity": "MEDIUM",
        "pattern": r'(?:if|while|return)\s*\([^)]*\$[^)]*==\s*(?:0|true|false|null|"0"|\'0\')\b',
        "description": (
            "PHP loose comparison (==) performs type coercion that can cause unexpected equality. "
            "'0e123' == '0e456' is true (magic hash), and 0 == 'non-numeric-string' is true in PHP 7. "
            "This can lead to authentication bypasses."
        ),
        "cwe": "CWE-697",
        "recommendation": "Always use strict equality (===) and strict inequality (!==) for security checks.",
    },
    {
        "id": "LAMP-PHP-015",
        "name": "phpinfo() call in production code – server information disclosure",
        "category": "Information Disclosure",
        "severity": "MEDIUM",
        "pattern": r"\bphpinfo\s*\(\s*\)",
        "description": (
            "phpinfo() outputs complete server configuration including PHP version, loaded extensions, "
            "environment variables, and file paths. This provides attackers with intelligence to "
            "identify exploitable vulnerabilities."
        ),
        "cwe": "CWE-200",
        "recommendation": "Remove all phpinfo() calls from production code. Restrict access if used in development.",
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
    SKIP_DIRS = {".git", "node_modules", "target", "build", ".gradle", ".idea", "__pycache__", ".next", "dist", "out"}

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
        elif suffix in (".py", ".pyw"):
            self._scan_python_source(filepath)
        elif name == "requirements.txt" or (name.startswith("requirements") and suffix == ".txt"):
            self._scan_requirements_txt(filepath)
        elif name == "pipfile":
            self._scan_pipfile(filepath)
        elif name == "pyproject.toml":
            self._scan_pyproject_toml(filepath)
        elif suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            self._scan_js_source(filepath)
        elif name == "package.json":
            self._scan_package_json(filepath)
        elif name == ".env" or name.startswith(".env."):
            self._scan_env_file(filepath)
        elif name in ("httpd.conf", "apache.conf", "apache2.conf", "httpd-ssl.conf", "httpd-vhosts.conf"):
            self._scan_apache_config(filepath)
        elif name == ".htaccess":
            self._scan_htaccess(filepath)
        elif suffix == ".conf" and any(tok in str(filepath).lower() for tok in (
                "apache", "httpd", "/sites-available/", "/sites-enabled/", "/conf.d/", "/vhosts/", "conf-available", "conf-enabled")):
            self._scan_apache_config(filepath)
        elif name in ("my.cnf", "my.ini", "mysqld.cnf", "mysql.conf") or (
                suffix == ".cnf" and any(tok in name.lower() for tok in ("mysql", "mariadb"))):
            self._scan_mysql_config(filepath)

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

        all_php_rules = PHP_SAST_RULES + LAMP_PHP_EXTRA_RULES
        compiled = [(rule, re.compile(rule["pattern"], re.IGNORECASE)) for rule in all_php_rules]
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
    # Python source SAST
    # ----------------------------------------------------------
    def _scan_python_source(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return

        self.scanned_files += 1
        self._vprint(f"  [py] {filepath}")

        compiled = [
            (rule, re.compile(rule["pattern"], re.MULTILINE))
            for rule in PYTHON_SAST_RULES
        ]

        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):          # skip comment-only lines
                continue
            for rule, rx in compiled:
                if rx.search(line):
                    self._add(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        file_path=str(filepath),
                        line_num=lineno,
                        line_content=line.rstrip(),
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                    ))

    # ----------------------------------------------------------
    # Python dependency scanning (requirements.txt)
    # ----------------------------------------------------------
    def _scan_requirements_txt(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return

        self.scanned_files += 1
        self._vprint(f"  [requirements.txt] {filepath}")

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", "-", "git+")):
                continue
            # normalise: "package==1.2.3" / "package>=1.0,<2.0" / "package[extra]==1.0"
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[.*?\])?\s*([=!<>~^,\s0-9.*]+)?", line)
            if not m:
                continue
            pkg_raw = m.group(1)
            ver_str = (m.group(2) or "").strip()
            # Extract pinned version from "==X.Y.Z"
            pin = re.search(r"==\s*([\d.]+)", ver_str)
            version = pin.group(1) if pin else ver_str
            self._check_python_dep(pkg_raw, version, str(filepath), lineno, raw)

    # ----------------------------------------------------------
    # Python dependency scanning (Pipfile)
    # ----------------------------------------------------------
    def _scan_pipfile(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return

        self.scanned_files += 1
        self._vprint(f"  [Pipfile] {filepath}")

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            # Match: package = "==1.2" or package = "*" or package = {version = "==1.2"}
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*["\'](?:==)?([\d.*]+)["\']', line)
            if m:
                self._check_python_dep(m.group(1), m.group(2), str(filepath), lineno, raw)

    # ----------------------------------------------------------
    # Python dependency scanning (pyproject.toml)
    # ----------------------------------------------------------
    def _scan_pyproject_toml(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return

        self.scanned_files += 1
        self._vprint(f"  [pyproject.toml] {filepath}")

        in_deps = False
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            # Track whether we are inside a dependencies array/table
            if re.match(r"^\[.*dependencies.*\]", line, re.IGNORECASE):
                in_deps = True
                continue
            if line.startswith("[") and not re.match(r"^\[.*dependencies.*\]", line, re.IGNORECASE):
                in_deps = False
            if not in_deps:
                continue
            # Match:  "package>=1.0,<2.0" or  package = ">=1.0"
            m = re.search(r'["\']?([A-Za-z0-9_.\-]+)["\']?\s*[=:><!~^,\s"\']*?([\d][.\d]*)', line)
            if m:
                self._check_python_dep(m.group(1), m.group(2), str(filepath), lineno, raw)

    # ----------------------------------------------------------
    # Python CVE / vulnerable-package check
    # ----------------------------------------------------------
    def _check_python_dep(self, pkg_raw, version, filepath, lineno, raw_line):
        """Normalise package name and compare version against known-vulnerable ranges."""
        pkg_key = re.sub(r"[-_.]", "-", pkg_raw).lower()
        # Also try underscore-normalised key
        for key in (pkg_key, pkg_key.replace("-", "_")):
            ranges = PYTHON_VULNERABLE_PACKAGES.get(key)
            if ranges:
                break
        else:
            return  # package not tracked

        for entry in ranges:
            if not version or self._version_in_range(version, entry["affected"]):
                cve = entry.get("cve", "")
                fix = entry.get("fix", "latest")
                rule_id = f"DEP-PY-{cve}" if cve else f"DEP-PY-{pkg_key.upper()}"
                pkg_name = pkg_raw if pkg_raw else pkg_key
                self._add(Finding(
                    rule_id=rule_id,
                    name=f"Vulnerable dependency: {pkg_name} {version} ({cve})" if cve else f"Vulnerable dependency: {pkg_name} {version}",
                    category="Vulnerable Dependency",
                    severity=entry["severity"],
                    file_path=filepath,
                    line_num=lineno,
                    line_content=raw_line.rstrip(),
                    description=entry["description"],
                    recommendation=f"Upgrade to {pkg_name} {fix} or later.",
                ))

    # ----------------------------------------------------------
    # JavaScript / TypeScript source SAST (MERN)
    # ----------------------------------------------------------
    def _scan_js_source(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [js/ts] {filepath}")

        compiled = [(rule, re.compile(rule["pattern"])) for rule in MERN_SAST_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                # Skip single-line comments
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
    # package.json — npm dependency CVE lookup
    # ----------------------------------------------------------
    def _scan_package_json(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
        except Exception as exc:
            self._warn(f"Cannot parse {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [package.json] {filepath}")

        # Combine dependencies and devDependencies
        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))

        for pkg_name, version_spec in all_deps.items():
            # Strip semver range operators (^, ~, >=, <=, etc.) to get the base version
            version = re.sub(r"^[^\d]*", "", str(version_spec)).strip()
            if not version or version in ("*", "latest", "next"):
                continue
            self._check_node_dep(pkg_name, version, str(filepath), 0, f'"{pkg_name}": "{version_spec}"')

    def _check_node_dep(self, pkg_name, version, filepath, lineno, raw_line):
        """Compare npm package version against known-vulnerable ranges."""
        pkg_key = pkg_name.lower()
        ranges = NODE_PACKAGE_CVES.get(pkg_key)
        if not ranges:
            return

        for entry in ranges:
            if not version or self._version_in_range(version, entry["affected"]):
                cve = entry.get("cve", "")
                fix = entry.get("fix", "latest")
                rule_id = f"DEP-NODE-{cve.replace('-', '')}" if cve else f"DEP-NODE-{pkg_key.upper()}"
                self._add(Finding(
                    rule_id=rule_id,
                    name=f"Vulnerable npm dependency: {pkg_name} {version} ({cve})" if cve else f"Vulnerable npm dependency: {pkg_name} {version}",
                    category="Vulnerable Dependency",
                    severity=entry["severity"],
                    file_path=filepath,
                    line_num=lineno,
                    line_content=raw_line.rstrip(),
                    description=entry["description"],
                    recommendation=f"Upgrade to {pkg_name} {fix} or later.",
                ))

    # ----------------------------------------------------------
    # .env file misconfiguration checks
    # ----------------------------------------------------------
    def _scan_env_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [.env] {filepath}")

        compiled = [(rule, re.compile(rule["pattern"], re.IGNORECASE)) for rule in ENV_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
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
    # Apache HTTP Server config SAST
    # ----------------------------------------------------------
    def _scan_apache_config(self, filepath):
        """Scan Apache httpd.conf / apache2.conf / VirtualHost config files."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [apache.conf] {filepath}")
        lines = content.splitlines(keepends=True)

        # Per-line SAST rules
        compiled = [(rule, re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)) for rule in LAMP_APACHE_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
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

        # Whole-file absence checks — flag missing security directives
        for check in LAMP_APACHE_FILE_CHECKS:
            rx = re.compile(check["check_absent"], re.IGNORECASE | re.MULTILINE)
            if not rx.search(content):
                self._add(Finding(
                    rule_id=check["id"],
                    name=check["name"],
                    category=check["category"],
                    severity=check["severity"],
                    file_path=filepath,
                    line_num=0,
                    line_content="",
                    description=check["description"],
                    recommendation=check["recommendation"],
                    cwe=check.get("cwe"),
                ))

        # Apache version directive comment check (e.g. "# Apache httpd version: 2.4.49")
        version_rx = re.compile(r"(?i)#\s*(?:Apache\s+)?(?:httpd\s+)?[Vv]ersion[:\s]+(\d+\.\d+\.\d+)\b")
        for m in version_rx.finditer(content):
            self._check_apache_version(str(filepath), m.group(1))

    # ----------------------------------------------------------
    # .htaccess SAST (subset of Apache rules)
    # ----------------------------------------------------------
    def _scan_htaccess(self, filepath):
        """Scan .htaccess files for security misconfigurations."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [.htaccess] {filepath}")

        # Apply the subset of Apache rules relevant to .htaccess context
        htaccess_rule_ids = {
            "LAMP-APACHE-004", "LAMP-APACHE-005", "LAMP-APACHE-006",
            "LAMP-APACHE-015", "LAMP-APACHE-016", "LAMP-APACHE-017",
            "LAMP-APACHE-018", "LAMP-APACHE-019", "LAMP-APACHE-024",
            "LAMP-APACHE-025", "LAMP-APACHE-029", "LAMP-APACHE-030",
        }
        compiled = [
            (rule, re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE))
            for rule in LAMP_APACHE_RULES
            if rule["id"] in htaccess_rule_ids
        ]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
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
    # MySQL / MariaDB config SAST
    # ----------------------------------------------------------
    def _scan_mysql_config(self, filepath):
        """Scan MySQL/MariaDB my.cnf / my.ini / mysqld.cnf files."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._warn(f"Cannot read {filepath}: {exc}")
            return

        self.scanned_files += 1
        self._vprint(f"  [mysql.cnf] {filepath}")

        compiled = [(rule, re.compile(rule["pattern"], re.IGNORECASE)) for rule in LAMP_MYSQL_RULES]
        for rule, rx in compiled:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith(";"):
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
    # Apache version CVE check
    # ----------------------------------------------------------
    def _check_apache_version(self, filepath, version):
        """Compare Apache version string against APACHE_RANGE_CVES."""
        for entry in APACHE_RANGE_CVES:
            if self._version_in_range(version, entry["affected"]):
                self._add(Finding(
                    rule_id=f"DEP-APACHE-{entry['cve'].replace('-', '')}",
                    name=f"Vulnerable Apache httpd {version} ({entry['cve']})",
                    category="Vulnerable Software Version",
                    severity=entry["severity"],
                    file_path=filepath,
                    line_num=0,
                    line_content=f"# Apache httpd version: {version}",
                    description=entry["description"],
                    recommendation=f"Upgrade Apache httpd to {entry['fix']} or later.",
                    cve=entry["cve"],
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
        print(f"{B}  Java, PHP, Python, MERN & LAMP Security Scanner v{VERSION}  —  Scan Report{R}")
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
            "scanner": f"Java, PHP, Python, MERN & LAMP Security Scanner v{VERSION}",
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
        description=f"Java, PHP, Python, MERN & LAMP Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 java_scanner.py /path/to/project
  python3 java_scanner.py /path/to/app.war --json report.json
  python3 java_scanner.py /var/www/html --severity HIGH
  python3 java_scanner.py pom.xml --verbose
  python3 java_scanner.py index.php --json report.json
  python3 java_scanner.py agent.py --json report.json
  python3 java_scanner.py requirements.txt --verbose
  python3 java_scanner.py /path/to/mern-app --json report.json
  python3 java_scanner.py server.js --severity CRITICAL
  python3 java_scanner.py package.json --verbose
  python3 java_scanner.py /var/www/lamp-app --json report.json
  python3 java_scanner.py httpd.conf --verbose
  python3 java_scanner.py my.cnf --severity HIGH
  python3 java_scanner.py /etc/apache2 --json report.json
""",
    )
    parser.add_argument("target", help=(
        "File or directory to scan. Supported: .java, .php, .py, .js, .ts, .jsx, .tsx, "
        "pom.xml, package.json, .env, requirements.txt, Pipfile, pyproject.toml, .gradle, "
        ".war, .jar, .ear, php.ini, httpd.conf, apache2.conf, .htaccess, my.cnf, my.ini, mysqld.cnf"
    ))
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Only report findings at this severity or above")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print(f"[*] Java, PHP, Python, MERN & LAMP Security Scanner v{VERSION}")
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
