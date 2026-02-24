# Java, PHP, Python & MERN Security Scanner v4.0
# Application Security Scanner (ASS)

A static analysis tool that scans Java, PHP, Python (including AI/agentic),
and MERN stack (MongoDB / Express / React / Node.js) applications for security
vulnerabilities and misconfigurations.

## What It Scans

| Input type | Language / Stack | Description |
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
| `.js` / `.jsx` / `.ts` / `.tsx` / `.mjs` / `.cjs` | MERN / Node.js | SAST rules — 25+ vulnerability patterns |
| `package.json` | MERN / Node.js | npm dependency CVE lookup (20 packages) |
| `.env` / `.env.*` | MERN / Node.js | Environment misconfiguration checks |

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

### MERN Stack SAST (JavaScript / TypeScript source code patterns)

- **NoSQL Injection** — `req.body`/`req.query` passed directly to Mongoose `find()`/`findOne()`;
  `$where` with user input; Mongoose model constructed from `req.body` (mass assignment / CWE-943)
- **Command Injection** — `child_process.exec()` / `execSync()` with user-controlled args;
  `eval()` / `vm.runInNewContext()` with request data (CWE-78, CWE-95)
- **Path Traversal** — `fs.readFile()` / `fs.writeFile()` / `path.join()` with `req.params`
  or `req.query` (CWE-22)
- **Cross-Site Scripting (XSS)** — `dangerouslySetInnerHTML` with user data; `innerHTML` assignment;
  `document.write()`; `res.send()` with unsanitized request input (CWE-79)
- **SQL Injection** — Sequelize `.query()` / Knex `.raw()` with template-literal interpolation (CWE-89)
- **Server-Side Request Forgery (SSRF)** — `axios.get()` / `fetch()` with user-controlled URL (CWE-918)
- **Open Redirect** — `res.redirect()` with `req.query.url` (CWE-601)
- **Broken Authentication / JWT** — JWT signed with weak/hardcoded secret; `algorithms: ['none']`
  bypass; `jwt.verify()` without expiry enforcement (CWE-330, CWE-347, CWE-613)
- **Prototype Pollution** — `_.merge()` / `_.defaultsDeep()` with `req.body`;
  `Object.assign({}, req.body)` (CWE-1321)
- **Hardcoded Credentials** — JWT/session secrets, MongoDB URIs with credentials,
  API keys / access tokens in source (CWE-798)
- **Insecure Deserialization** — `node-serialize.unserialize()` (IIFE RCE, CVE-2017-5941);
  `js-yaml YAML.load()` without SafeLoader (CWE-502)
- **Security Misconfiguration** — CORS wildcard `*`; missing `helmet()`; cookies without
  `httpOnly`/`secure` flags (CWE-16, CWE-614, CWE-942)
- **ReDoS** — `new RegExp(userInput)` with untrusted pattern (CWE-1333)

### .env File Misconfiguration Checks

| Setting | Risk | Severity |
|---|---|---|
| `NODE_ENV=development` | Verbose errors / debug info in production | MEDIUM |
| `JWT_SECRET=secret` (weak/default) | JWT token forgery | CRITICAL |
| `SESSION_SECRET=changeme` (weak/default) | Session cookie forgery | CRITICAL |
| `DEBUG=*` | Credentials / internals leaked to logs | MEDIUM |
| `MONGODB_URI=mongodb://user:pass@…` | Database credentials in plaintext | HIGH |
| Plaintext `DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, etc. | Credential exposure | HIGH |
| `CORS_ORIGIN=*` | All-origin cross-site requests allowed | MEDIUM |

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

### npm / Node.js (MERN)

| Package | CVE | Severity |
|---|---|---|
| minimist < 1.2.6 | CVE-2021-44906 | CRITICAL |
| ejs < 3.1.7 | CVE-2022-29078 (SSTI → RCE) | CRITICAL |
| lodash < 4.17.21 | CVE-2021-23337 (Command Injection) | HIGH |
| lodash < 4.17.19 | CVE-2020-8203 (Prototype Pollution) | HIGH |
| express < 4.19.2 | CVE-2024-29041 (Open Redirect) | MEDIUM |
| mongoose < 7.6.3 | CVE-2023-3696 (Prototype Pollution) | HIGH |
| jsonwebtoken < 9.0.0 | CVE-2022-23529 (Insecure Default Algorithm) | HIGH |
| jsonwebtoken < 9.0.0 | CVE-2022-23540 (ReDoS) | MEDIUM |
| axios < 0.21.2 | CVE-2021-3749 (ReDoS) | HIGH |
| axios < 1.6.0 | CVE-2023-45857 (CSRF Token Exposure) | MEDIUM |
| node-fetch < 2.6.7 | CVE-2022-0235 (Header Leakage on Redirect) | HIGH |
| ejs < 3.1.10 | CVE-2024-33883 (Prototype Pollution → XSS) | HIGH |
| multer < 1.4.5-lts.1 | CVE-2022-24434 (DoS) | HIGH |
| socket.io < 4.6.2 | CVE-2023-31125 (DoS) | HIGH |
| json5 < 2.2.2 | CVE-2022-46175 (Prototype Pollution) | HIGH |
| body-parser < 1.20.3 | CVE-2024-45590 (DoS) | HIGH |
| cross-spawn < 7.0.5 | CVE-2024-21538 (ReDoS) | HIGH |
| path-to-regexp < 0.1.12 | CVE-2024-45296 (ReDoS) | HIGH |
| tough-cookie < 4.1.3 | CVE-2023-26136 (Prototype Pollution) | HIGH |
| ws < 8.17.1 | CVE-2024-37890 (DoS) | HIGH |
| next < 14.1.1 | CVE-2024-34351 (SSRF) | HIGH |
| next < 13.5.1 | CVE-2023-46298 (DoS) | HIGH |
| passport < 0.6.0 | CVE-2022-25896 (Session Fixation) | MEDIUM |
| serialize-javascript < 6.0.1 | CVE-2022-25878 (ReDoS) | MEDIUM |
| semver < 7.5.2 | CVE-2022-25883 (ReDoS) | MEDIUM |

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

# Scan a MERN stack application (auto-detects .js/.ts, package.json, .env)
python3 java_scanner.py /path/to/mern-app --json report.json

# Scan a single Express/Node.js file
python3 java_scanner.py server.js --severity CRITICAL

# Scan npm dependencies for CVEs
python3 java_scanner.py package.json --verbose

# Scan .env file for secrets and misconfigurations
python3 java_scanner.py .env --severity HIGH

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
[CRITICAL]  SQLI-001              String concatenation in JDBC query
[CRITICAL]  CMDI-001              Runtime.exec() – potential command injection
[CRITICAL]  DESER-001             Unsafe ObjectInputStream usage
[CRITICAL]  DEP-CVE202144228      Vulnerable dependency: log4j-core 2.14.1
[CRITICAL]  PHPINI-002            allow_url_include enabled – Remote File Inclusion risk
[CRITICAL]  PHP-RCE-001           eval() with user-controlled input – RCE
[CRITICAL]  PY-DESER-001          pickle.loads() with user-supplied data – RCE
[CRITICAL]  PY-RCE-001            eval() with user-controlled input – RCE
[CRITICAL]  PY-AI-001             LangChain allow_dangerous_deserialization=True
[CRITICAL]  MERN-NOSQL-001        req.body passed directly to MongoDB/Mongoose query
[CRITICAL]  MERN-CMDI-001         child_process.exec() with user-controlled input
[CRITICAL]  MERN-JWT-001          JWT signed with hardcoded or weak secret
[CRITICAL]  MERN-JWT-002          JWT verification with algorithms: ['none']
[CRITICAL]  MERN-DESER-001        node-serialize unserialize() with user input – RCE
[CRITICAL]  ENV-002               JWT_SECRET with weak or default value
[CRITICAL]  DEP-NODE-CVE202144906 Vulnerable npm dependency: minimist 1.2.5
[HIGH]      MERN-SEC-002          MongoDB connection string with embedded credentials
[HIGH]      MERN-NOSQL-003        Mongoose model spread from req.body (mass assignment)
[HIGH]      MERN-PATH-001         fs.readFile with user-controlled path
[HIGH]      MERN-SSRF-001         axios/fetch/node-fetch with user-controlled URL
[HIGH]      DEP-NODE-CVE202123337 Vulnerable npm dependency: lodash 4.17.15
...

SUMMARY
CRITICAL  59
HIGH      105
MEDIUM    44
LOW        4
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
| `vulnerable_mern.js` | MERN / Node.js | NoSQL injection, CMDI, JWT bypass, prototype pollution, SSRF, XSS, DESER, path traversal |
| `package.json` | MERN / Node.js | 20 known-vulnerable npm packages (20+ CVEs) |
| `.env` | MERN / Node.js | Weak secrets, DEBUG wildcard, CORS wildcard, embedded DB credentials |

---

## Reference CVEs Demonstrated

The deserialization exploit scripts in this repository correspond to real-world CVEs
that the scanner detects:

| File | CVE | Attack vector |
|---|---|---|
| `Oracle WebLogic Exploit` | CVE-2015-8103 | Jenkins CLI RMI deserialization |
| `Java Deserialization Exploits` | CVE-2016-1291 | Cisco Prime HTTP deserialization |
| `WebSphere Remote Code Execution` | CVE-2015-7450 | IBM WebSphere SOAP deserialization |
