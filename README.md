# Static Application Security Testing (SAST)

A collection of self-contained Python SAST scanners for source code vulnerability detection
across **Java**, **PHP**, **Python**, **MERN/Node.js**, and **AI/LLM applications**, plus
**SaaS Security Posture Management (SSPM)** scanners for **Microsoft 365**, **ServiceNow**,
and more.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/SAST_scanners-5-ef4444?style=flat-square"/>
  <img src="https://img.shields.io/badge/SSPM_scanners-2-f59e0b?style=flat-square"/>
  <img src="https://img.shields.io/badge/languages-Java%20%7C%20PHP%20%7C%20Python%20%7C%20JS%2FTS%20%7C%20AI%2FLLM-22c55e?style=flat-square"/>
</p>

---

## Scanners at a Glance

| Scanner | Type | Target | Version | Lines |
|---------|------|--------|:-------:|:-----:|
| `java_scanner.py` | SAST | Java source, Maven/Gradle, WAR/JAR, Spring Boot | 4.0.0 | 3,696 |
| `php_scanner.py` | SAST | PHP source, `php.ini` | 4.0.0 | 848 |
| `python_scanner.py` | SAST | Python source, requirements/Pipfile/pyproject.toml | 4.0.0 | 1,231 |
| `mern_scanner.py` | SAST | JS/TS source, package.json, `.env` | 4.0.0 | 1,181 |
| `owasp_llm_scanner.py` | SAST | Python/JS AI & LLM applications (OWASP LLM Top 10) | 1.0.0 | 1,998 |
| `m365_scanner.py` | SSPM | Microsoft 365 + Entra ID (Microsoft Graph API) | 1.0.0 | 2,258 |
| `servicenow_scanner.py` | SSPM | ServiceNow live instance (REST Table API) | 1.0.0 | 1,696 |

> **Other scanners** (AWS IaC, Cisco, Palo Alto, SAP SuccessFactors, Fortinet, Kubernetes, etc.)
> have been moved to their own dedicated repositories. See [Related Projects](#related-projects).

---

## SAST Scanners

### Java Scanner (`java_scanner.py`)

**What it scans**

| Input type | Description |
|---|---|
| `.java` source files | SAST rules — 20+ vulnerability patterns |
| `pom.xml` | Maven dependency CVE lookup |
| `build.gradle` / `build.gradle.kts` | Gradle dependency CVE lookup |
| `.war` / `.jar` / `.ear` archives | Embedded configs, nested JARs, `pom.properties` |
| `web.xml` | Servlet misconfiguration checks |
| `.properties` / `.yml` / `.yaml` | Spring Boot misconfiguration checks |

**Vulnerability categories**

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

**Java dependency CVEs**

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

```bash
python3 java_scanner.py /path/to/project [--json report.json] [--severity HIGH] [-v]
python3 java_scanner.py app.war --json report.json
python3 java_scanner.py pom.xml --verbose
```

---

### PHP Scanner (`php_scanner.py`)

**What it scans**

| Input type | Description |
|---|---|
| `.php` / `.phtml` / `.php5–8` | SAST rules — 15+ vulnerability patterns |
| `php.ini` | Runtime misconfiguration checks |

**Vulnerability categories**

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

**`php.ini` misconfiguration checks**

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

```bash
python3 php_scanner.py /var/www/html [--json report.json] [--severity HIGH] [-v]
python3 php_scanner.py php.ini --verbose
```

---

### Python Scanner (`python_scanner.py`)

**What it scans**

| Input type | Description |
|---|---|
| `.py` / `.pyw` source files | SAST rules — 50+ patterns incl. AI/agentic |
| `requirements.txt` | Dependency CVE lookup (18+ packages) |
| `Pipfile` | Dependency CVE lookup |
| `pyproject.toml` | Dependency CVE lookup |

**Vulnerability categories**

- **Insecure Deserialization** — `pickle.loads()`, `yaml.load()` (unsafe loader), `marshal.loads()`
- **Remote Code Execution** — `eval()`, `exec()` with user input; LLM output piped to `eval`/`exec`
- **Command Injection** — `os.system()`, `subprocess.call(shell=True)`, `os.popen()`
- **SQL Injection** — f-string / `%`-format / `.format()` queries; Django `raw()` with concatenation
- **Path Traversal** — `open()` with `request.args` / user-supplied path
- **SSRF** — `requests.get()`, `urllib.request.urlopen()` with user-controlled URL
- **Server-Side Template Injection (SSTI)** — `Jinja2.Template(user_input)`, `render_template_string(user_input)`
- **Open Redirect** — Flask `redirect(request.args[...])`
- **Weak Cryptography** — `hashlib.md5`, `hashlib.sha1`, `random` module for security tokens
- **XML External Entity (XXE)** — `lxml.etree.XMLParser(resolve_entities=True)`
- **Hardcoded Credentials / AI API Keys** — `sk-*` (OpenAI), AWS keys, GCP keys, Django `SECRET_KEY`
- **Flask / Django Misconfigurations** — `DEBUG=True`, `SESSION_COOKIE_SECURE=False`, `ALLOWED_HOSTS=["*"]`
- **AI/Agentic-specific** — `LangChain allow_dangerous_deserialization=True`, `ShellTool`, `PythonREPLTool`, prompt injection

**Python dependency CVEs** — 18+ packages including Django, Flask, FastAPI, LangChain, transformers, torch, mlflow, gradio, cryptography, paramiko, Pillow, aiohttp, urllib3, Jinja2, requests, PyYAML.

```bash
python3 python_scanner.py /path/to/project [--json report.json] [--severity HIGH] [-v]
python3 python_scanner.py requirements.txt --verbose
```

---

### MERN Stack Scanner (`mern_scanner.py`)

**What it scans**

| Input type | Description |
|---|---|
| `.js` / `.jsx` / `.ts` / `.tsx` / `.mjs` / `.cjs` | SAST rules — 25+ vulnerability patterns |
| `package.json` | npm dependency CVE lookup (20+ packages) |
| `.env` / `.env.*` | Environment misconfiguration checks |

**Vulnerability categories**

- **NoSQL Injection** — `req.body`/`req.query` passed to Mongoose `find()`; `$where`; mass assignment
- **Command Injection** — `child_process.exec()` / `execSync()` with user-controlled args; `eval()`
- **Path Traversal** — `fs.readFile()` / `fs.writeFile()` / `path.join()` with `req.params`
- **Cross-Site Scripting (XSS)** — `dangerouslySetInnerHTML`, `innerHTML`, `document.write()`
- **SQL Injection** — Sequelize `.query()` / Knex `.raw()` with template-literal interpolation
- **SSRF** — `axios.get()` / `fetch()` with user-controlled URL
- **Broken Authentication / JWT** — weak/hardcoded secret; `algorithms: ['none']` bypass
- **Prototype Pollution** — `_.merge()` / `_.defaultsDeep()` with `req.body`
- **Hardcoded Credentials** — JWT/session secrets, MongoDB URIs, API keys
- **Insecure Deserialization** — `node-serialize.unserialize()`
- **Security Misconfiguration** — CORS wildcard; missing `helmet()`; insecure cookies
- **ReDoS** — `new RegExp(userInput)` with untrusted pattern

**npm dependency CVEs** — 20+ packages including minimist, ejs, lodash, jsonwebtoken, axios, mongoose, express, next, socket.io, ws, cross-spawn, and more.

```bash
python3 mern_scanner.py /path/to/mern-app [--json report.json] [--severity HIGH] [-v]
python3 mern_scanner.py package.json --verbose
python3 mern_scanner.py .env --severity HIGH
```

---

### OWASP LLM Top 10 Scanner (`owasp_llm_scanner.py`)

Targets AI and LLM-powered applications — checks Python code, JavaScript/TypeScript code,
environment files, YAML configs, and dependency manifests against the
[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**What it scans**

| Input type | Description |
|---|---|
| `.py` / `.pyw` | 36 Python SAST rules for LLM/AI patterns |
| `.js` / `.jsx` / `.ts` / `.tsx` / `.mjs` / `.cjs` | 16 JS/TS SAST rules for LLM/AI patterns |
| `.env` / `.env.*` | 4 environment rules (API key exposure, debug prompts) |
| `.yaml` / `.yml` | 4 YAML rules (LLM agent configs, unsafe tool definitions) |
| `requirements.txt` | 13 vulnerable Python LLM package CVEs |
| `package.json` | 3 vulnerable npm LLM package CVEs |

**OWASP LLM categories covered**

| Category | Key Checks |
|---|---|
| **LLM01** Prompt Injection | User input concatenated into prompts, unsanitized tool outputs fed back to LLM |
| **LLM02** Sensitive Info Disclosure | PII in prompts, training data leakage, system prompt exposure |
| **LLM03** Supply Chain | Vulnerable LLM packages (LangChain, transformers, mlflow, etc.) |
| **LLM04** Data & Model Poisoning | Unvalidated training data inputs, `allow_dangerous_deserialization` |
| **LLM05** Improper Output Handling | LLM output piped to `eval()`, `exec()`, `subprocess`, `render_template_string` |
| **LLM06** Excessive Agency | `ShellTool`, `PythonREPLTool`, broad tool permissions, unguarded agentic loops |
| **LLM07** System Prompt Leakage | System prompt logged, reflected in responses, or stored insecurely |
| **LLM08** Vector & Embedding Weaknesses | Unvalidated RAG inputs, embedding injection |
| **LLM09** Misinformation | Missing output validation, unchecked model confidence scores |
| **LLM10** Unbounded Consumption | Missing token limits, rate limiting, cost controls |

```bash
python3 owasp_llm_scanner.py /path/to/ai-project [--json report.json] [--severity HIGH] [-v]
python3 owasp_llm_scanner.py agent.py --verbose
python3 owasp_llm_scanner.py requirements.txt
```

---

## SSPM Scanners

Unlike the SAST scanners, the SSPM scanners make **live API calls** to running
SaaS instances and evaluate the actual configuration state against security best practices.

> **Prerequisite**: `pip install requests`

---

### Microsoft 365 + Entra ID SSPM Scanner (`m365_scanner.py`)

Makes live Microsoft Graph API calls using OAuth 2.0 Client Credentials flow to audit the
security posture of a Microsoft 365 tenant and Entra ID across **50+ checks**.

**Check categories**: Security Defaults, Conditional Access (MFA, legacy auth, risky sign-in), MFA Registration, Privileged Access (Global Admin count, PIM, break-glass), Password Policy, App Registrations (high-risk permissions, secret/cert hygiene), Guest & External Access, Exchange Online, SharePoint Online, Microsoft Teams, Audit Logging, Identity Protection.

```bash
python3 m365_scanner.py \
  --tenant-id <tenant-id> \
  --client-id <app-client-id> \
  --client-secret <secret> \
  [--severity HIGH] [--json report.json] [--html report.html] [-v]
```

---

### ServiceNow SSPM Scanner (`servicenow_scanner.py`)

Makes live REST Table API calls to a ServiceNow instance and audits security configuration
across **40+ checks**.

**Check categories**: XSS Prevention, CSRF Protection, Session Management, Authentication, Password Policy, File Attachments, Transport Security, Script Security, Audit & Logging, Users, OAuth Applications, Access Control Lists, Email Security.

```bash
python3 servicenow_scanner.py \
  --instance <instance-name-or-url> \
  --username <user> \
  --password <pass> \
  [--severity HIGH] [--json report.json] [--html report.html] [-v]
```

---

## Common Options

All scanners share these CLI options:

| Option | Description |
|---|---|
| `--severity LEVEL` | Show only findings at or above this level (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) |
| `--json FILE` | Save findings to a JSON report file |
| `--html FILE` | Save a self-contained HTML report (SSPM scanners) |
| `--verbose`, `-v` | Print each file/check as it is processed |
| `--version` | Print scanner name and version |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings |
| `1` | One or more CRITICAL or HIGH findings detected |

---

## Requirements

### SAST scanners

- Python 3.8+
- No third-party dependencies (standard library only)

### SSPM scanners (`m365_scanner.py`, `servicenow_scanner.py`)

- Python 3.8+
- `pip install requests`

---

## Test Samples

The `tests/samples/` directory contains intentionally vulnerable files that exercise scanner rules:

| File | Scanner | What it tests |
|---|---|---|
| `VulnerableApp.java` | `java_scanner.py` | SQLI, CMDI, DESER, XXE, XSS, CRED, CRYPTO, SSRF, Log4Shell |
| `pom.xml` | `java_scanner.py` | Maven CVEs: Log4Shell, Spring4Shell, Commons-Collections, XStream, Shiro |
| `application.properties` | `java_scanner.py` | Spring Boot misconfigs: H2 console, actuators, debug mode |
| `vulnerable.php` | `php_scanner.py` | RCE, CMDI, SQLI, XSS, LFI, unserialize, open redirect |
| `php.ini` | `php_scanner.py` | All `php.ini` misconfiguration rules |
| `vulnerable_agent.py` | `python_scanner.py` / `owasp_llm_scanner.py` | 50+ Python SAST rules incl. AI/agentic patterns |
| `requirements.txt` | `python_scanner.py` / `owasp_llm_scanner.py` | Known-vulnerable Python packages |
| `vulnerable_mern.js` | `mern_scanner.py` | NoSQL injection, CMDI, JWT bypass, prototype pollution, SSRF, XSS, DESER |
| `package.json` | `mern_scanner.py` | 20 known-vulnerable npm packages |
| `.env` | `mern_scanner.py` | Weak secrets, DEBUG wildcard, CORS wildcard, embedded DB credentials |

```bash
# Run all SAST test samples
python3 java_scanner.py tests/samples/
python3 php_scanner.py tests/samples/
python3 python_scanner.py tests/samples/
python3 mern_scanner.py tests/samples/
python3 owasp_llm_scanner.py tests/samples/
```

---

## Report Formats

### Console (all scanners)
Colour-coded severity output with file/line references and remediation advice.

### JSON (`--json report.json`)
Machine-readable format. Schema includes scanner metadata, target, findings array (rule_id, name, category, severity, file, line, description, recommendation, cwe, cve), and summary counts.

### HTML (`--html report.html`)
Self-contained dark-themed HTML report with severity chips, filterable findings table, and inline remediation guidance. Available on SSPM scanners.

---

## Related Projects

Scanners that were previously in this repository have been moved to dedicated repos:

| Scanner | Repo |
|---------|------|
| AWS CloudFormation + Terraform IaC | [AWS-Security-Scanner](https://github.com/Krishcalin/AWS-Security-Scanner) |
| Cisco IOS/IOS-XE Network Security | [Cisco-Network-Security](https://github.com/Krishcalin/Cisco-Network-Security) |
| Palo Alto PAN-OS Firewall Security | [PaloAlto-Network-Security](https://github.com/Krishcalin/PaloAlto-Network-Security) |
| Fortinet FortiGate Firewall Security | [Fortinet-Network-Security](https://github.com/Krishcalin/Fortinet-Network-Security) |
| SAP SuccessFactors SSPM | [SAP-SuccessFactors](https://github.com/Krishcalin/SAP-SuccessFactors) |
| Kubernetes KSPM | [Kubernetes-KSPM](https://github.com/Krishcalin/Kubernetes-Security-Posture-Management) |
| AI Security Posture Management | [AI-Secure-Posture-Management](https://github.com/Krishcalin/AI-Secure-Posture-Management) |
| OWASP API Security | [API-Security](https://github.com/Krishcalin/API-Security) |
| Cloud Detection & Response | [Cloud-Detection-Response](https://github.com/Krishcalin/Cloud-Detection-Response) |
| DAST Scanner | [Dynamic-Application-Security-Testing](https://github.com/Krishcalin/Dynamic-Application-Security-Testing) |
| Windows Red Teaming (MITRE ATT&CK) | [Windows-Red-Teaming](https://github.com/Krishcalin/Windows-Red-Teaming) |

---

## License

[MIT License](LICENSE)
