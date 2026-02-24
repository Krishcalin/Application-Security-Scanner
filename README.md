# Application Security Scanner (ASS)

A static analysis tool that scans Java applications for common security vulnerabilities and misconfigurations.

## What It Scans

| Input type | Description |
|---|---|
| `.java` source files | SAST rules — 20+ vulnerability patterns |
| `pom.xml` | Maven dependency CVE lookup |
| `build.gradle` / `build.gradle.kts` | Gradle dependency CVE lookup |
| `.war` / `.jar` / `.ear` archives | Scans embedded configs, nested JARs, and `pom.properties` |
| `web.xml` | Servlet misconfiguration checks |
| `.properties` / `.yml` / `.yaml` | Spring Boot misconfiguration checks |

## Vulnerability Categories

**SAST (source code patterns)**
- Insecure Deserialization — `ObjectInputStream`, `XMLDecoder`, `XStream`, `SnakeYAML`
- SQL Injection — string-concatenated JDBC queries
- Command Injection — `Runtime.exec()`, `ProcessBuilder`
- Path Traversal — `new File(request.getParameter(...))`
- Cross-Site Scripting (XSS)
- Hardcoded Credentials / API Keys
- Weak Cryptography — MD5, SHA-1, DES, ECB mode, `java.util.Random`
- XML External Entity (XXE) — `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`
- Server-Side Request Forgery (SSRF)
- Open Redirect
- Disabled SSL/TLS Certificate Validation
- Log Injection (including Log4Shell trigger patterns)

**Dependency CVEs (selected)**
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

**Misconfiguration checks**
- `web.xml` — directory listing, missing HttpOnly/Secure cookie flags, no security constraints, no error pages
- Spring Boot — exposed actuator endpoints, H2 console, debug mode, plaintext passwords, SSL disabled, wildcard CORS

## Usage

```
python3 java_scanner.py <target> [options]
```

**Arguments**

| Argument | Description |
|---|---|
| `target` | File or directory to scan |
| `--json FILE` | Write findings to a JSON report file |
| `--severity LEVEL` | Show only CRITICAL / HIGH / MEDIUM / LOW / INFO (and above) |
| `--verbose`, `-v` | Print each file as it is scanned |

**Examples**

```bash
# Scan a Maven project
python3 java_scanner.py /path/to/project

# Scan a WAR file and save JSON report
python3 java_scanner.py /path/to/app.war --json report.json

# Only show CRITICAL and HIGH findings
python3 java_scanner.py /src --severity HIGH

# Scan a single pom.xml verbosely
python3 java_scanner.py pom.xml --verbose
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings |
| `1` | One or more CRITICAL or HIGH findings detected |

## Quick Demo

```bash
python3 java_scanner.py tests/samples/
```

Expected output (abridged):

```
[CRITICAL]  SQLI-001   String concatenation in JDBC query
[CRITICAL]  CMDI-001   Runtime.exec() – potential command injection
[CRITICAL]  DESER-001  Unsafe ObjectInputStream usage
[CRITICAL]  DEP-CVE202144228  Vulnerable dependency: log4j-core 2.14.1
[HIGH]      CRED-001   Hardcoded password / secret in source code
...
SUMMARY
CRITICAL  9
HIGH      16
MEDIUM    8
```

## Requirements

- Python 3.6+
- No third-party dependencies (standard library only)

## Reference CVEs Demonstrated

The `tests/samples/` directory contains an intentionally vulnerable Java class and configuration files that exercise every scanner rule, including the deserialization CVEs documented in the exploit scripts in this repository:

| File | CVE | Attack vector |
|---|---|---|
| `Oracle WebLogic Exploit` | CVE-2015-8103 | Jenkins CLI RMI deserialization |
| `Java Deserialization Exploits` | CVE-2016-1291 | Cisco Prime HTTP deserialization |
| `WebSphere Remote Code Execution` | CVE-2015-7450 | IBM WebSphere SOAP deserialization |
