#!/usr/bin/env python3
"""
PHP Security Scanner v4.0
Scans PHP applications for security vulnerabilities and misconfigurations.

Supported inputs:
  - Source files (.php, .phtml, .php5, .php7, .php8)
  - Runtime configuration (php.ini)
"""

import os
import re
import sys
import argparse
from pathlib import Path
from datetime import datetime
import json

VERSION = "4.0.0"

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
            "as PHP code \u2014 a well-known RCE vector removed in PHP 7."
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
        "name": "Reflected XSS \u2013 superglobal echoed without encoding",
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
        "name": "Potential stored XSS \u2013 variable echoed without encoding",
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
        "name": "session_id() set from user input \u2013 session fixation",
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
        "name": "base64_decode()+eval() \u2013 common webshell pattern",
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
        "name": "allow_url_include enabled \u2013 Remote File Inclusion risk",
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
        "name": "expose_php enabled \u2013 version disclosure",
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
        "name": "session.use_strict_mode disabled \u2013 session fixation risk",
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
class PHPScanner:
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
        if suffix in (".php", ".phtml", ".php5", ".php7", ".php8"):
            self._scan_php_source(filepath)
        elif name == "php.ini":
            self._scan_php_ini(filepath)

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
        print(f"{B}  PHP Security Scanner v{VERSION}  \u2014  Scan Report{R}")
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
            "scanner": f"PHP Security Scanner v{VERSION}",
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
        description=f"PHP Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 php_scanner.py /var/www/html
  python3 php_scanner.py index.php --json report.json
  python3 php_scanner.py /etc/php/8.2/apache2/php.ini --verbose
  python3 php_scanner.py /path/to/project --severity HIGH
""",
    )
    parser.add_argument("target", help="File or directory to scan (.php, .phtml, .php5, .php7, .php8, php.ini)")
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Only report findings at this severity or above")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print(f"[*] PHP Security Scanner v{VERSION}")
    print(f"[*] Target: {args.target}\n")

    scanner = PHPScanner(verbose=args.verbose)
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
