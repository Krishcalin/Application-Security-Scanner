# Java, PHP & Python Security Scanner v3.0
# Application Security Scanner (ASS)

A static analysis tool that scans Java, PHP, and Python (including AI/agentic)
applications for security vulnerabilities and misconfigurations.

## What It Scans

| Input type | Language | Description |
|---|---|---|
| `.java` source files | Java | SAST rules — 20+ vulnerability patterns |
| `pom.xml` | Java | Maven dependency CVE lookup |
| `build.gradle` / `build.gradle.kts` | Java | Gradle dependency CVE lookup |
| `.war` / `.jar` / `.ear` archives | Java | Embedded configs, nested JARs, `pom.properties` |
| `web.xml` | Java | Servlet misconfiguration checks |
| `.properties` / `.yml` / `.yaml` | Java | Spring Boot misconfiguration checks |
| `.php` / `.phtml` / `.php5–8` | PHP | SAST rules — 15+ vulnerability patterns |
| `php.ini` | PHP | Runtime misconfiguration checks |
| `.py` / `.pyw` source files | Python | SAST rules — 50+ patterns incl. AI/agentic |
| `requirements.txt` | Python | Dependency CVE lookup (18 packages) |
| `Pipfile` | Python | Dependency CVE lookup |
| `pyproject.toml` | Python | Dependency CVE lookup |

---

## Vulnerability Categories

### Java SAST (source code patterns)

- **Insecure Deserialization** — `ObjectInputStream`, `XMLDecoder`, `XStream`, `SnakeYAML`
- **SQL Injection** — string-concatenated JDBC queries
- **Command Injection** — `Runtime.exec()`, `ProcessBuilder`
- **Path Traversal** — `new File(request.getParameter(...))`
- **Cross-Site Scripting (XSS)**
- **Hardcoded Credentials / API Keys**
- **Weak Cryptography** — MD5, SHA-1, DES, ECB mode, `java.util.Random`
- **XML External Entity (XXE)** — `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`
- **Server-Side Request Forgery (SSRF)**
- **Open Redirect**
- **Disabled SSL/TLS Certificate Validation**
- **Log Injection** (including Log4Shell trigger patterns)

### PHP SAST (source code patterns)

- **Remote Code Execution** — `eval()`, `preg_replace` with `/e` modifier
- **Command Injection** — `system()`, `exec()`, `shell_exec()`, `passthru()`, backtick operator
- **SQL Injection** — string-concatenated MySQL / MySQLi queries
- **Path Traversal / LFI / RFI** — `include`/`require` with user input, `file_get_contents`
- **Cross-Site Scripting (XSS)** — unescaped `echo $_GET/POST/REQUEST`
- **Unsafe Deserialization** — `unserialize()` with user-supplied data
- **File Upload Vulnerabilities** — no extension validation
- **Hardcoded Credentials**
- **Weak Cryptography** — `md5()`, `sha1()` for passwords
- **Open Redirect** — `header("Location: $_GET[...]")`
- **SSRF** — `curl_exec()` with user-controlled URL
- **Log Injection**

### Python SAST (source code patterns)

- **Insecure Deserialization** — `pickle.loads()`, `yaml.load()` (unsafe loader), `marshal.loads()`
- **Remote Code Execution** — `eval()`, `exec()` with user input; LLM output piped to `eval`/`exec`
- **Command Injection** — `os.system()`, `subprocess.call(shell=True)`, `os.popen()`;
  LLM output piped to `subprocess.run`
- **SQL Injection** — f-string / `%`-format / `.format()` queries; Django `raw()` with concatenation
- **Path Traversal** — `open()` with `request.args` / user-supplied path
- **SSRF** — `requests.get()`, `urllib.request.urlopen()` with user-controlled URL
- **Server-Side Template Injection (SSTI)** — `Jinja2.Template(user_input)`,
  `render_template_string(user_input)`
- **Open Redirect** — Flask `redirect(request.args[...])`
- **Weak Cryptography** — `hashlib.md5`, `hashlib.sha1`, `random` module for security tokens
- **XML External Entity (XXE)** — `lxml.etree.XMLParser(resolve_entities=True)`,
  `xml.etree.ElementTree` (not defused)
- **Hardcoded Credentials / AI API Keys** — passwords, `sk-*` (OpenAI), AWS keys,
  GCP keys, Django insecure `SECRET_KEY`
- **Log Injection** — `logging.info/warning/error` with `request.args` data
- **Insecure Temp Files** — predictable `/tmp/` paths
- **Flask Misconfigurations** — `app.run(debug=True)`, `SESSION_COOKIE_SECURE=False`
- **Django Misconfigurations** — `DEBUG=True`, insecure `SECRET_KEY`, `ALLOWED_HOSTS=["*"]`
- **AI/Agentic-Specific**
  - `LangChain allow_dangerous_deserialization=True` (arbitrary code execution via model files)
  - User input concatenated directly into LLM prompt (prompt injection)
  - `ShellTool` — gives LLM agent unrestricted OS command execution
  - `PythonREPLTool` — gives LLM agent unrestricted code execution
  - `load_chain()` without dangerous-deserialization flag (implicit risk)

---

## Dependency CVEs

### Java

| Library | CVE | Severity |
|---|---|---|
| commons-collections < 3.2.2 | CVE-2015-7501 | CRITICAL |
| log4j-core 2.0–2.14.x | CVE-2021-44228 (Log4Shell) | CRITICAL |
| spring-core < 5.3.18 | CVE-2022-22965 (Spring4Shell) | CRITICAL |
| struts2-core < 2.3.35 | CVE-2017-5638 | CRITICAL |
| jackson-databind < 2.9.10 | CVE-2019-14379 | CRITICAL |
| shiro-core < 1.2.5 | CVE-2016-4437 (Shiro-550) | CRITICAL |
| xstream < 1.4.18 | CVE-2021-39144 | CRITICAL |
| fastjson < 1.2.68 | CVE-2020-9547 | CRITICAL |
| h2 < 2.1.210 | CVE-2021-42392 | CRITICAL |

### Python

| Package | CVE | Severity |
|---|---|---|
| Django < 2.2.28 | CVE-2022-28347 | CRITICAL |
| torch < 2.0.1 | CVE-2022-45907 | CRITICAL |
| mlflow < 2.9.2 | CVE-2023-6977 | CRITICAL |
| Django < 3.2.21 | CVE-2023-43665 | HIGH |
| Flask < 2.3.2 | CVE-2023-30861 | HIGH |
| fastapi < 0.109.1 | CVE-2024-24762 | HIGH |
| urllib3 < 1.26.5 | CVE-2021-33503 | HIGH |
| aiohttp < 3.9.2 | CVE-2024-23334 | HIGH |
| cryptography < 41.0.6 | CVE-2023-49083 | HIGH |
| paramiko < 2.10.1 | CVE-2022-24302 | HIGH |
| Pillow < 10.2.0 | CVE-2023-50447 | HIGH |
| gradio < 4.11.0 | CVE-2024-0964 | HIGH |
| langchain < 0.0.312 | CVE-2023-46229 | HIGH |
| transformers < 4.36.0 | CVE-2023-7018 | HIGH |
| requests < 2.31.0 | CVE-2023-32681 | MEDIUM |
| urllib3 < 2.0.7 | CVE-2023-45803 | MEDIUM |
| aiohttp < 3.9.4 | CVE-2024-27306 | MEDIUM |
| Jinja2 < 3.1.3 | CVE-2024-22195 | MEDIUM |
| PyYAML < 6.0.1 | CVE-2022-1769 | MEDIUM |
| celery < 4.4.0 | CVE-2021-23727 | HIGH |
| SQLAlchemy < 1.4.0 | CVE-2019-7548 | HIGH |

### PHP Misconfiguration Checks (`php.ini`)

| Setting | Risk | Severity |
|---|---|---|
| `display_errors = On` | Stack traces exposed to users | HIGH |
| `allow_url_include = On` | Remote File Inclusion (RFI) | CRITICAL |
| `allow_url_fopen = On` | Increased SSRF attack surface | LOW |
| `expose_php = On` | Version disclosure | LOW |
| `register_globals = On` | Variable injection / auth bypass | CRITICAL |
| `session.cookie_httponly` not set | Session hijacking via XSS | HIGH |
| `session.cookie_secure` not set | Cookie transmitted over HTTP | HIGH |
| `disable_functions` empty | Dangerous functions accessible | LOW |

---

## Usage

```
python3 java_scanner.py <target> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `target` | File or directory to scan |
| `--json FILE` | Write findings to a JSON report file |
| `--severity LEVEL` | Show only CRITICAL / HIGH / MEDIUM / LOW / INFO (and above) |
| `--verbose`, `-v` | Print each file as it is scanned |

### Examples

```bash
# Scan a Maven Java project
python3 java_scanner.py /path/to/project

# Scan a WAR file and save JSON report
python3 java_scanner.py /path/to/app.war --json report.json

# Scan a PHP web root
python3 java_scanner.py /var/www/html --severity HIGH

# Scan a Python AI agent and its dependencies
python3 java_scanner.py agent.py --json report.json
python3 java_scanner.py requirements.txt --verbose

# Only show CRITICAL findings across a full project
python3 java_scanner.py /src --severity CRITICAL

# Scan a single pom.xml verbosely
python3 java_scanner.py pom.xml --verbose
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings |
| `1` | One or more CRITICAL or HIGH findings detected |

---

## Quick Demo

```bash
python3 java_scanner.py tests/samples/
```

Expected output (abridged):

```
[CRITICAL]  SQLI-001         String concatenation in JDBC query
[CRITICAL]  CMDI-001         Runtime.exec() – potential command injection
[CRITICAL]  DESER-001        Unsafe ObjectInputStream usage
[CRITICAL]  DEP-CVE202144228 Vulnerable dependency: log4j-core 2.14.1
[CRITICAL]  PHPINI-002       allow_url_include enabled – Remote File Inclusion risk
[CRITICAL]  PHP-RCE-001      eval() with user-controlled input – RCE
[CRITICAL]  PY-DESER-001     pickle.loads() with user-supplied data – RCE
[CRITICAL]  PY-RCE-001       eval() with user-controlled input – RCE
[CRITICAL]  PY-AI-001        LangChain allow_dangerous_deserialization=True
[HIGH]      CRED-001         Hardcoded password / secret in source code
[HIGH]      PY-CMDI-001      os.system() with string concatenation – command injection
[HIGH]      PY-CRED-001      Hardcoded password / secret in Python source
...

SUMMARY
CRITICAL  46
HIGH      72
MEDIUM    29
LOW        3
```

---

## Requirements

- Python 3.6+
- No third-party dependencies (standard library only)

---

## Test Samples

The `tests/samples/` directory contains intentionally vulnerable files that exercise
every scanner rule:

| File | Language | What it tests |
|---|---|---|
| `VulnerableApp.java` | Java | SQLI, CMDI, DESER, XXE, XSS, CRED, CRYPTO, SSRF, Log4Shell |
| `pom.xml` | Java | Maven CVEs: Log4Shell, Spring4Shell, Commons-Collections, XStream, Shiro, etc. |
| `application.properties` | Java | Spring Boot misconfigs: H2 console, actuators, debug mode, weak passwords |
| `vulnerable.php` | PHP | RCE, CMDI, SQLI, XSS, LFI, unserialize, open redirect |
| `php.ini` | PHP | All `php.ini` misconfiguration rules |
| `vulnerable_agent.py` | Python | All 50+ Python SAST rules incl. AI/agentic patterns |
| `requirements.txt` | Python | 18 known-vulnerable Python packages |

---

## Reference CVEs Demonstrated

The deserialization exploit scripts in this repository correspond to real-world CVEs
that the scanner detects:

| File | CVE | Attack vector |
|---|---|---|
| `Oracle WebLogic Exploit` | CVE-2015-8103 | Jenkins CLI RMI deserialization |
| `Java Deserialization Exploits` | CVE-2016-1291 | Cisco Prime HTTP deserialization |
| `WebSphere Remote Code Execution` | CVE-2015-7450 | IBM WebSphere SOAP deserialization |
