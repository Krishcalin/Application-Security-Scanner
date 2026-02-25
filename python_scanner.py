#!/usr/bin/env python3
"""
Python Security Scanner v4.0
Scans Python applications (including AI/agentic) for security vulnerabilities
and misconfigurations.

Supported inputs:
  - Source files (.py, .pyw)
  - Dependency manifests (requirements.txt, Pipfile, pyproject.toml)
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

VERSION = "4.0.0"

# ============================================================
# PYTHON SAST RULES  (Python source code patterns)
# ============================================================
PYTHON_SAST_RULES = [
    # --- Insecure Deserialization ---
    {
        "id": "PY-DESER-001",
        "category": "Insecure Deserialization",
        "name": "pickle.load/loads() \u2013 arbitrary code execution",
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
        "name": "yaml.load() without SafeLoader \u2013 code execution",
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
        "name": "marshal.loads() \u2013 unsafe deserialization",
        "severity": "CRITICAL",
        "pattern": r"\bmarshal\.loads?\s*\(",
        "description": "marshal is not safe against untrusted data and can crash the interpreter or execute code.",
        "cwe": "CWE-502",
        "recommendation": "Use JSON for data interchange. Never deserialize marshal data from untrusted sources.",
    },
    {
        "id": "PY-DESER-004",
        "category": "Insecure Deserialization",
        "name": "jsonpickle.decode() \u2013 arbitrary code execution",
        "severity": "CRITICAL",
        "pattern": r"\bjsonpickle\.decode\s*\(",
        "description": "jsonpickle.decode() instantiates arbitrary Python objects, enabling RCE via crafted JSON.",
        "cwe": "CWE-502",
        "recommendation": "Use json.loads() for untrusted input. Never use jsonpickle with untrusted data.",
    },
    {
        "id": "PY-DESER-005",
        "category": "Insecure Deserialization",
        "name": "torch.load() without weights_only=True \u2013 model file RCE",
        "severity": "CRITICAL",
        "pattern": r"\btorch\.load\s*\(",
        "description": (
            "torch.load() uses pickle by default; a malicious model file achieves RCE. "
            "CVE-2022-45907."
        ),
        "cwe": "CWE-502",
        "recommendation": "Use torch.load(f, weights_only=True) (PyTorch \u2265 2.0) to prevent arbitrary object loading.",
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
        "name": "LLM output passed to eval() or exec() \u2013 AI prompt injection \u2192 RCE",
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
        "name": "os.system() \u2013 shell command injection",
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
        "name": "os.popen() \u2013 shell execution",
        "severity": "HIGH",
        "pattern": r"\bos\.popen\s*\(",
        "description": "os.popen() executes a shell command. User-controlled input enables command injection.",
        "cwe": "CWE-78",
        "recommendation": "Replace with subprocess.run([...], shell=False, capture_output=True).",
    },
    {
        "id": "PY-CMDI-004",
        "category": "Command Injection",
        "name": "LLM/agent output passed to subprocess \u2013 AI prompt injection \u2192 RCE",
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
        "recommendation": "Use ORM filters or pass parameters: Model.objects.raw('SELECT \u2026 WHERE id=%s', [uid])",
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
        "name": "os.path.join() with user input \u2013 base-path bypass",
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
        "name": "httpx / aiohttp request \u2013 common in AI agent tooling",
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
        "description": "Rendering Jinja2 templates built from user strings enables SSTI \u2192 RCE via {{''.__class__.__mro__[1]...}}.",
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
        "name": "hashlib.md5() \u2013 broken hash",
        "severity": "MEDIUM",
        "pattern": r"\bhashlib\.md5\s*\(",
        "description": "MD5 is cryptographically broken. Do not use for passwords, HMAC, or integrity checks.",
        "cwe": "CWE-327",
        "recommendation": "Use hashlib.sha256() or better. For passwords use bcrypt, scrypt, or argon2-cffi.",
    },
    {
        "id": "PY-CRYPTO-002",
        "category": "Weak Cryptography",
        "name": "hashlib.sha1() \u2013 deprecated for security use",
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
        "name": "lxml etree imported \u2013 verify XXE hardening",
        "severity": "HIGH",
        "pattern": r"\blxml\.etree\b|from\s+lxml\s+import\s+etree",
        "description": "lxml resolves external entities and DTDs by default, enabling XXE attacks on untrusted XML.",
        "cwe": "CWE-611",
        "recommendation": "Use defusedxml, or configure: parser = etree.XMLParser(resolve_entities=False, no_network=True)",
    },
    {
        "id": "PY-XXE-002",
        "category": "XML External Entity (XXE)",
        "name": "xml.etree.ElementTree on untrusted data \u2013 DoS risk",
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
            "Flask debug=True enables the Werkzeug interactive debugger in the browser \u2014 "
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
        "name": "tempfile.mktemp() \u2013 TOCTOU race condition",
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
class PythonScanner:
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
        if suffix in (".py", ".pyw"):
            self._scan_python_source(filepath)
        elif name == "requirements.txt" or (name.startswith("requirements") and suffix == ".txt"):
            self._scan_requirements_txt(filepath)
        elif name == "pipfile":
            self._scan_pipfile(filepath)
        elif name == "pyproject.toml":
            self._scan_pyproject_toml(filepath)

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
                        cwe=rule.get("cwe"),
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
    # Version comparison helpers
    # ----------------------------------------------------------
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
        print(f"{B}  Python Security Scanner v{VERSION}  \u2014  Scan Report{R}")
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
            "scanner": f"Python Security Scanner v{VERSION}",
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
        description=f"Python Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 python_scanner.py /path/to/project
  python3 python_scanner.py agent.py --json report.json
  python3 python_scanner.py requirements.txt --verbose
  python3 python_scanner.py /path/to/django-app --severity HIGH
  python3 python_scanner.py pyproject.toml --verbose
""",
    )
    parser.add_argument("target", help="File or directory to scan (.py, .pyw, requirements.txt, Pipfile, pyproject.toml)")
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Only report findings at this severity or above")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print(f"[*] Python Security Scanner v{VERSION}")
    print(f"[*] Target: {args.target}\n")

    scanner = PythonScanner(verbose=args.verbose)
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
