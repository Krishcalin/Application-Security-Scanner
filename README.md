# Application Security Scanner (ASS)

A collection of self-contained security scanners covering **Static Application Security Testing (SAST)**
for source code, **Infrastructure-as-Code (IaC) security analysis**, and **SaaS Security Posture
Management (SSPM)** for cloud SaaS platforms.

---

## Scanners at a Glance

| Scanner | Type | Target | Version |
|---------|------|--------|---------|
| `java_scanner.py` | SAST | Java source, Maven/Gradle, WAR/JAR, Spring Boot | 4.0.0 |
| `php_scanner.py` | SAST | PHP source, `php.ini` | 4.0.0 |
| `python_scanner.py` | SAST | Python source, requirements/Pipfile/pyproject.toml | 4.0.0 |
| `mern_scanner.py` | SAST | JS/TS source, package.json, `.env` | 4.0.0 |
| `owasp_llm_scanner.py` | SAST | Python/JS AI & LLM applications (OWASP LLM Top 10) | 1.0.0 |
| `aws_scanner.py` | IaC | CloudFormation (YAML/JSON) + Terraform (`.tf`) | 1.1.0 |
| `servicenow_scanner.py` | SSPM | ServiceNow live instance (REST Table API) | 1.0.0 |
| `successfactors_scanner.py` | SSPM | SAP SuccessFactors live instance (OData v2 API) | 1.0.0 |
| `m365_scanner.py` | SSPM | Microsoft 365 + Entra ID (Microsoft Graph API) | 1.0.0 |

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

**Python dependency CVEs**

| Package | CVE | Severity |
|---|---|---|
| Django < 2.2.28 | CVE-2022-28347 | CRITICAL |
| torch < 2.0.1 | CVE-2022-45907 | CRITICAL |
| mlflow < 2.9.2 | CVE-2023-6977 | CRITICAL |
| Flask < 2.3.2 | CVE-2023-30861 | HIGH |
| fastapi < 0.109.1 | CVE-2024-24762 | HIGH |
| langchain < 0.0.312 | CVE-2023-46229 | HIGH |
| transformers < 4.36.0 | CVE-2023-7018 | HIGH |
| gradio < 4.11.0 | CVE-2024-0964 | HIGH |
| cryptography < 41.0.6 | CVE-2023-49083 | HIGH |
| paramiko < 2.10.1 | CVE-2022-24302 | HIGH |
| Pillow < 10.2.0 | CVE-2023-50447 | HIGH |
| aiohttp < 3.9.2 | CVE-2024-23334 | HIGH |
| urllib3 < 1.26.5 | CVE-2021-33503 | HIGH |
| Jinja2 < 3.1.3 | CVE-2024-22195 | MEDIUM |
| requests < 2.31.0 | CVE-2023-32681 | MEDIUM |
| PyYAML < 6.0.1 | CVE-2022-1769 | MEDIUM |

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

- **NoSQL Injection** — `req.body`/`req.query` passed to Mongoose `find()`/`findOne()`; `$where` with user input; mass assignment via `req.body`
- **Command Injection** — `child_process.exec()` / `execSync()` with user-controlled args; `eval()` / `vm.runInNewContext()` with request data
- **Path Traversal** — `fs.readFile()` / `fs.writeFile()` / `path.join()` with `req.params` or `req.query`
- **Cross-Site Scripting (XSS)** — `dangerouslySetInnerHTML`, `innerHTML`, `document.write()`, `res.send()` with unsanitized input
- **SQL Injection** — Sequelize `.query()` / Knex `.raw()` with template-literal interpolation
- **SSRF** — `axios.get()` / `fetch()` with user-controlled URL
- **Open Redirect** — `res.redirect()` with `req.query.url`
- **Broken Authentication / JWT** — JWT signed with weak/hardcoded secret; `algorithms: ['none']` bypass; `jwt.verify()` without expiry
- **Prototype Pollution** — `_.merge()` / `_.defaultsDeep()` with `req.body`; `Object.assign({}, req.body)`
- **Hardcoded Credentials** — JWT/session secrets, MongoDB URIs with credentials, API keys in source
- **Insecure Deserialization** — `node-serialize.unserialize()` (IIFE RCE, CVE-2017-5941)
- **Security Misconfiguration** — CORS wildcard `*`; missing `helmet()`; cookies without `httpOnly`/`secure`
- **ReDoS** — `new RegExp(userInput)` with untrusted pattern

**`.env` misconfiguration checks**

| Setting | Risk | Severity |
|---|---|---|
| `NODE_ENV=development` | Verbose errors in production | MEDIUM |
| `JWT_SECRET=secret` (weak/default) | JWT token forgery | CRITICAL |
| `SESSION_SECRET=changeme` (weak/default) | Session cookie forgery | CRITICAL |
| `DEBUG=*` | Credentials / internals leaked to logs | MEDIUM |
| `MONGODB_URI=mongodb://user:pass@…` | Database credentials in plaintext | HIGH |
| Plaintext `DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, etc. | Credential exposure | HIGH |
| `CORS_ORIGIN=*` | All-origin cross-site requests allowed | MEDIUM |

**npm / Node.js dependency CVEs**

| Package | CVE | Severity |
|---|---|---|
| minimist < 1.2.6 | CVE-2021-44906 | CRITICAL |
| ejs < 3.1.7 | CVE-2022-29078 (SSTI → RCE) | CRITICAL |
| lodash < 4.17.21 | CVE-2021-23337 (Command Injection) | HIGH |
| jsonwebtoken < 9.0.0 | CVE-2022-23529 (Insecure Default Algorithm) | HIGH |
| axios < 0.21.2 | CVE-2021-3749 (ReDoS) | HIGH |
| mongoose < 7.6.3 | CVE-2023-3696 (Prototype Pollution) | HIGH |
| node-fetch < 2.6.7 | CVE-2022-0235 (Header Leakage on Redirect) | HIGH |
| multer < 1.4.5-lts.1 | CVE-2022-24434 (DoS) | HIGH |
| socket.io < 4.6.2 | CVE-2023-31125 (DoS) | HIGH |
| next < 14.1.1 | CVE-2024-34351 (SSRF) | HIGH |
| body-parser < 1.20.3 | CVE-2024-45590 (DoS) | HIGH |
| cross-spawn < 7.0.5 | CVE-2024-21538 (ReDoS) | HIGH |
| path-to-regexp < 0.1.12 | CVE-2024-45296 (ReDoS) | HIGH |
| ws < 8.17.1 | CVE-2024-37890 (DoS) | HIGH |
| tough-cookie < 4.1.3 | CVE-2023-26136 (Prototype Pollution) | HIGH |
| express < 4.19.2 | CVE-2024-29041 (Open Redirect) | MEDIUM |
| passport < 0.6.0 | CVE-2022-25896 (Session Fixation) | MEDIUM |

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

## Infrastructure-as-Code Scanner

### AWS IaC Scanner (`aws_scanner.py`) — v1.1.0

Scans AWS **CloudFormation** templates (YAML/JSON) and **Terraform** (`.tf`) files for
security misconfigurations across 40+ AWS service types.

**What it scans**

| Input type | Description |
|---|---|
| `.yaml` / `.yml` / `.json` | CloudFormation structural analysis (CF_DISPATCH → 42 resource handlers) |
| `.tf` | Terraform SAST regex rules (60+ rules) |

**Services covered**

| Service | Key Checks |
|---|---|
| **S3** | Public ACLs, missing encryption, no versioning, no MFA delete, public access block |
| **IAM** | Wildcard actions/resources, AdministratorAccess, root API keys, no MFA, inline policies |
| **EC2 / Security Groups** | SSH/RDP open to 0.0.0.0/0, unrestricted egress, IMDSv2 not required |
| **RDS** | Public accessibility, no encryption, no backup, no deletion protection, default port |
| **CloudTrail** | Not enabled, no log validation, no S3 encryption, no CloudWatch integration |
| **KMS** | Key rotation disabled |
| **CloudFront** | HTTP allowed (no HTTPS redirect), old TLS minimum, geo restriction absent |
| **ElastiCache** | No transit/at-rest encryption, no auth token |
| **ECS** | Privileged containers, host PID/network mode, no readonly root filesystem |
| **OpenSearch** | Public access, no encryption, node-to-node not encrypted, no audit logging |
| **Redshift** | Publicly accessible, no encryption, no enhanced VPC routing |
| **ECR** | Image scan on push disabled, policy allows `*` principal |
| **DynamoDB** | No KMS encryption, no point-in-time recovery |
| **Lambda** | No reserved concurrency, no dead letter queue, wildcard resource permissions |
| **API Gateway** | No authentication, logging disabled, no TLS client cert, default endpoint not disabled |
| **Secrets Manager** | No KMS encryption, auto-rotate disabled |
| **CloudWatch Alarms** | No alarm actions configured |
| **CloudWatch Log Groups** | No retention policy, no KMS encryption |
| **VPC** | DNS hostnames disabled; subnets auto-assigning public IPs; Flow Logs capturing ACCEPT-only |
| **WAFv2** | Default action ALLOW with no rules, metrics/sampling disabled |
| **GuardDuty** | Detector disabled |
| **AWS Config** | Not recording all supported types, global resource types excluded |
| **Elastic Beanstalk** | HTTP listener, managed updates off, basic health reporting |
| **SageMaker Notebooks** | Direct internet access, no KMS, no VPC subnet |
| **SageMaker Domains** | Public internet access, missing default execution role |
| **Bedrock Agents** | No guardrail attached, session TTL > 1 hour |
| **EBS Volumes** | Encryption disabled |
| **Step Functions** | Logging OFF, X-Ray tracing disabled |

```bash
python3 aws_scanner.py /path/to/cloudformation/ [--json report.json] [--html report.html] [--severity HIGH] [-v]
python3 aws_scanner.py template.yaml --verbose
python3 aws_scanner.py /path/to/terraform/
```

---

## SSPM Scanners

Unlike the SAST and IaC scanners, the SSPM scanners make **live API calls** to running
SaaS instances and evaluate the actual configuration state against security best practices.

> **Prerequisite**: `pip install requests` (all three SSPM scanners require it)

---

### ServiceNow SSPM Scanner (`servicenow_scanner.py`) — v1.0.0

Makes live REST Table API calls to a ServiceNow instance and audits its security
configuration across 40+ checks.

**Authentication**

```bash
python3 servicenow_scanner.py \
  --instance <instance-name-or-full-url> \
  --username <user> \
  --password <pass> \
  [--severity HIGH] [--json report.json] [--html report.html] [-v]
```

Environment variable fallback: `SNOW_INSTANCE`, `SNOW_USERNAME`, `SNOW_PASSWORD`

**Check categories**

| Category | Rule IDs | Key Checks |
|---|---|---|
| XSS Prevention | SN-XSS-001 to 004 | `glide.ui.escape_text`, `escape_html_text_area`, Anti-Samy, CSP active |
| CSRF Protection | SN-CSRF-001 | CSRF token enforcement |
| Session Management | SN-SESS-001 to 005 | Session timeout ≤ 30 min, guest timeout ≤ 15 min, session rotation, concurrency |
| Authentication | SN-AUTH-001 to 005 | Max failed attempts ≤ 10, no blank passwords, basic auth scripts, SSO required, MFA |
| Password Policy | SN-PWD-001 to 007 | Min length ≥ 8, upper/lower/special/digit requirements, lockout count, history |
| File Attachments | SN-FILE-001 | MIME type validation, dangerous extension blocking (17 extensions) |
| Transport Security | SN-TLS-001 to 002 | HTTPS redirect, SameSite cookie attribute |
| Script Security | SN-SCRIPT-001 to 002 | Script sandbox, dynamic forms |
| Audit & Logging | SN-LOG-001 to 003 | Audit enabled, syslog/SIEM probe, log retention |
| Users | SN-USER-001 to 006 | Default admin active, stale accounts (>90d), maint role, sec_admin count, MFA on admins, service accounts with admin |
| OAuth Applications | SN-OAUTH-001 to 004 | Admin scope, stale clients, client sprawl (>10), token lifetime > 1 hr |
| Access Control Lists | SN-ACL-001 to 003 | Public read on `sys_user`, public write on `sys_*`, public log read |
| Email Security | SN-EMAIL-001 to 002 | Email allow/deny list, antivirus scanning on attachments |

**ServiceNow tables queried**: `sys_properties`, `sys_user`, `sys_user_has_role`, `oauth_entity`, `sys_acl`, `sys_syslog_config`, `syslog_transaction`

---

### SAP SuccessFactors SSPM Scanner (`successfactors_scanner.py`) — v1.0.0

Makes live OData v2 REST API calls to an SAP SuccessFactors HCM tenant and audits its
security posture across 30+ checks aligned with SAP Security Best Practices and CIS guidance.

**Authentication**

```bash
python3 successfactors_scanner.py \
  --api-host <api4.successfactors.com> \
  --company-id <COMPANY_ID> \
  --username <user> \
  --password <pass> \
  [--severity HIGH] [--json report.json] [--html report.html] [-v]
```

Environment variable fallback: `SF_API_HOST`, `SF_COMPANY_ID`, `SF_USERNAME`, `SF_PASSWORD`

**Check categories**

| Category | Rule IDs | Key Checks |
|---|---|---|
| Password Policy | SF-PWD-001 to 010 | Min length ≥ 8, complexity (upper/lower/digit/special), max age ≤ 90d, lockout ≤ 10, history ≥ 5, temp password TTL ≤ 24h |
| Users | SF-USER-001 to 005 | Super-admin count > 5, never-logged-in admins, stale accounts (>90d), service accounts with super-admin, unclassified super-admins |
| Permission Roles | SF-ROLE-001 to 002 | Broad-scoped roles (access all employees), role count sprawl (>50) |
| SSO & Authentication | SF-AUTH-001 to 004 | SSO not enabled, MFA not enforced, self-registration open, no IP restrictions |
| Session Management | SF-SESS-001 to 002 | Session timeout > 30 min, concurrent sessions unlimited |
| Audit Logging | SF-LOG-001 to 004 | Audit logging enabled, retention < 90d, admin action audit, data access audit |
| Data Privacy | SF-PRIV-001 to 003 | GDPR data purge jobs, sensitive field masking, consent management config |
| Integration Security | SF-INT-001 to 004 | OAuth client sprawl (>10), admin-scope OAuth clients, token lifetime > 1 hr, HTTP (non-HTTPS) integration flows |

**OData entities queried**: `PasswordPolicy`, `User`, `CompanyInfo`, `PermissionRole`, `AuditConfiguration`, `OAuthClient`, `PersonalDataPurgeJob`, `ConsentManagementConfig`, `IntegrationFlowDesign`

---

### Microsoft 365 + Entra ID SSPM Scanner (`m365_scanner.py`) — v1.0.0

Makes live Microsoft Graph API (v1.0 + beta) calls using OAuth 2.0 Client Credentials
flow to audit the security posture of a Microsoft 365 tenant and its Entra ID identity
provider across 50+ checks.

**Authentication setup (Entra ID App Registration)**

1. Register an app in Entra ID (Azure Portal → App registrations → New registration)
2. Grant the following **Application** permissions (no user sign-in required):
   - `Policy.Read.All`, `Directory.Read.All`, `User.Read.All`
   - `AuditLog.Read.All`, `Reports.Read.All`, `IdentityRiskyUser.Read.All`
   - `RoleManagement.Read.Directory`, `Application.Read.All`
   - `SecurityEvents.Read.All`
3. Grant admin consent
4. Create a client secret

```bash
python3 m365_scanner.py \
  --tenant-id <tenant-id> \
  --client-id <app-client-id> \
  --client-secret <secret> \
  [--severity HIGH] [--json report.json] [--html report.html] [-v]
```

Environment variable fallback: `M365_TENANT_ID`, `M365_CLIENT_ID`, `M365_CLIENT_SECRET`

**Check categories**

| Category | Rule IDs | Key Checks |
|---|---|---|
| Security Defaults | M365-SEC-001 to 002 | Security defaults enabled/disabled, conflicts with Conditional Access |
| Conditional Access | M365-CA-001 to 008 | MFA for all users, MFA for admins, block legacy auth, risky sign-in remediation, device compliance, named location gaps, app-specific policies |
| MFA Registration | M365-MFA-001 to 004 | Users without any MFA, admins without MFA, SMS/voice-only MFA (no phishing-resistant), SSPR configured without MFA |
| Privileged Access | M365-PRIV-001 to 005 | Too many Global Admins (>5), guest users in admin roles, service principals as privileged role owners, permanent PIM assignments (no time-bound), no break-glass account |
| Password Policy | M365-PWD-001 to 003 | Password expiry enabled, custom banned password list, smart lockout configuration |
| App Registrations | M365-APP-001 to 005 | High-risk API permissions (Directory.ReadWrite, RoleManagement.ReadWrite, etc.), expired client secrets, secrets expiring within 30 days, secrets instead of certificates, application sprawl |
| Guest & External Access | M365-GUEST-001 to 004 | Anyone-can-invite guest policy, B2B collaboration restrictions, cross-tenant access settings, external Teams federation |
| Exchange Online | M365-EXO-001 to 004 | Admin email notifications, auto-forwarding to external addresses, legacy protocols (POP/IMAP/MAPI), SMTP AUTH enabled globally |
| SharePoint Online | M365-SPO-001 to 004 | Sharing capability (Anyone links), anonymous link expiry, default link sharing type, legacy authentication |
| Microsoft Teams | M365-TEAMS-001 to 003 | Anonymous meeting join, unrestricted external federation, uncontrolled guest access |
| Audit Logging | M365-AUDIT-001 to 003 | Unified Audit Log enabled, audit log export policy, per-mailbox audit enabled |
| Identity Protection | M365-IDP-001 to 005 | High-risk users unaddressed, medium-risk user accumulation, sign-in risk policy absent, user risk policy absent, risky service principals |

**Privileged Entra ID roles monitored**: Global Administrator, User Administrator, Application Administrator, Cloud Application Administrator, Authentication Administrator, Privileged Authentication Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator, Teams Administrator, Compliance Administrator, Billing Administrator, Global Reader

**High-risk Graph API permissions flagged**: `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Group.ReadWrite.All`, `User.ReadWrite.All`, `Mail.ReadWrite` (All), `Files.ReadWrite.All`, `Sites.ReadWrite.All`, `DeviceManagementApps.ReadWrite.All`, `Organization.ReadWrite.All`

---

## Common Options

All scanners share these CLI options:

| Option | Description |
|---|---|
| `--severity LEVEL` | Show only findings at or above this level (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) |
| `--json FILE` | Save findings to a JSON report file |
| `--html FILE` | Save a self-contained HTML report (SSPM and AWS scanners) |
| `--verbose`, `-v` | Print each file/check as it is processed |
| `--version` | Print scanner name and version |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings (or all filtered below threshold) |
| `1` | One or more CRITICAL or HIGH findings detected |

---

## Requirements

### SAST and IaC scanners (`java_scanner.py`, `php_scanner.py`, `python_scanner.py`, `mern_scanner.py`, `owasp_llm_scanner.py`, `aws_scanner.py`)

- Python 3.8+
- No third-party dependencies (standard library only)
- `PyYAML` is used by `aws_scanner.py` — install with `pip install pyyaml`

### SSPM scanners (`servicenow_scanner.py`, `successfactors_scanner.py`, `m365_scanner.py`)

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
| `vulnerable_agent.py` | `python_scanner.py` / `owasp_llm_scanner.py` | 50+ Python SAST rules incl. AI/agentic patterns, all LLM Top 10 categories |
| `requirements.txt` | `python_scanner.py` / `owasp_llm_scanner.py` | Known-vulnerable Python packages |
| `vulnerable_mern.js` | `mern_scanner.py` | NoSQL injection, CMDI, JWT bypass, prototype pollution, SSRF, XSS, DESER |
| `package.json` | `mern_scanner.py` | 20 known-vulnerable npm packages |
| `.env` | `mern_scanner.py` | Weak secrets, DEBUG wildcard, CORS wildcard, embedded DB credentials |
| `gap_services_bad.yaml` | `aws_scanner.py` | CloudFormation template exercising all v1.1.0 gap-service checks: CloudWatch, Logs, VPC, Subnet, FlowLog, WAFv2, GuardDuty, Config, Beanstalk, SageMaker, Bedrock, EBS, StepFunctions |

```bash
# Run all SAST/IaC test samples
python3 java_scanner.py tests/samples/
python3 aws_scanner.py tests/samples/gap_services_bad.yaml --severity LOW
```

---

## Report Formats

### Console (all scanners)
Colour-coded severity output with file/line references and remediation advice.

### JSON (`--json report.json`)
Machine-readable format compatible with all scanners. Schema:

```json
{
  "scanner": "m365_scanner v1.0.0",
  "generated": "2026-02-26T12:00:00",
  "target": "contoso.onmicrosoft.com",
  "findings": [
    {
      "id": "M365-CA-003",
      "name": "Legacy Authentication Not Blocked",
      "category": "Conditional Access",
      "severity": "HIGH",
      "file": "conditionalAccessPolicies",
      "line": null,
      "code": "No CA policy blocks legacy auth protocols",
      "description": "...",
      "recommendation": "...",
      "cwe": "CWE-287",
      "cve": null
    }
  ],
  "summary": { "CRITICAL": 2, "HIGH": 8, "MEDIUM": 5, "LOW": 1, "INFO": 0 }
}
```

### HTML (`--html report.html`)
Self-contained dark-themed HTML report with severity chips, filterable findings table,
and inline remediation guidance. No external dependencies.
