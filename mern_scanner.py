#!/usr/bin/env python3
"""
MERN Stack Security Scanner v4.0
Scans MongoDB / Express / React / Node.js applications for security
vulnerabilities and misconfigurations.

Supported inputs:
  - JavaScript / TypeScript source files (.js, .jsx, .ts, .tsx, .mjs, .cjs)
  - npm dependency manifests (package.json)
  - Environment configuration (.env)
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
        "pattern": r"""\$where\s*[=:]\s*[`'"].*?(?:req\.|params\.|query\.|body\.)""",
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
            "arguments\u2014never a shell string. Validate and allowlist all user-supplied values."
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
        "pattern": r"\.innerHTML\s*=\s*(?!['\"\s]*['\"])[^;]*(?:req\.|params\.|query\.|body\.|location\.|document\.)",
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
            "Store it in an environment variable\u2014never hardcode it."
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
            "or validate input against a strict schema. Upgrade lodash \u2265 4.17.21."
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
        "name": "node-serialize unserialize() with user input \u2013 RCE",
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
        "recommendation": "Use YAML.safeLoad() (js-yaml \u2264 3.x) or yaml.load() with { schema: FAILSAFE_SCHEMA } (js-yaml 4+).",
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
            "Cookies without httpOnly are accessible to JavaScript (XSS \u2192 session theft). "
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
class MERNScanner:
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
        if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            self._scan_js_source(filepath)
        elif name == "package.json":
            self._scan_package_json(filepath)
        elif name == ".env" or name.startswith(".env."):
            self._scan_env_file(filepath)

    # ----------------------------------------------------------
    # JavaScript / TypeScript source SAST
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
    # package.json \u2014 npm dependency CVE lookup
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
        print(f"{B}  MERN Stack Security Scanner v{VERSION}  \u2014  Scan Report{R}")
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
            "scanner": f"MERN Stack Security Scanner v{VERSION}",
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
        description=f"MERN Stack Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mern_scanner.py /path/to/mern-app
  python3 mern_scanner.py server.js --severity CRITICAL
  python3 mern_scanner.py package.json --verbose
  python3 mern_scanner.py /path/to/project --json report.json
  python3 mern_scanner.py .env --verbose
""",
    )
    parser.add_argument("target", help="File or directory to scan (.js, .jsx, .ts, .tsx, .mjs, .cjs, package.json, .env)")
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Only report findings at this severity or above")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print(f"[*] MERN Stack Security Scanner v{VERSION}")
    print(f"[*] Target: {args.target}\n")

    scanner = MERNScanner(verbose=args.verbose)
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
