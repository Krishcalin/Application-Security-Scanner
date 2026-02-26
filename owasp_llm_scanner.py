#!/usr/bin/env python3
"""
OWASP LLM Top 10 Security Scanner v1.0.0
Scans AI/LLM application code for vulnerabilities mapped to the
OWASP LLM Top 10 (2025) categories.

Supported inputs:
  - Python source files (.py, .pyw)
  - JavaScript / TypeScript (.js, .jsx, .ts, .tsx, .mjs, .cjs)
  - Environment files (.env)
  - YAML configuration files (.yaml, .yml)
  - Python dependency manifests (requirements.txt, Pipfile, pyproject.toml)
  - Node dependency manifests (package.json)
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

VERSION = "1.0.0"

# ============================================================
# LLM SAST RULES — Python source files
# ============================================================
LLM_PYTHON_SAST_RULES = [

    # ── LLM01: Prompt Injection ──────────────────────────────
    {
        "id": "LLM01-001",
        "category": "LLM01: Prompt Injection",
        "name": "User input directly interpolated into LLM prompt via f-string",
        "severity": "HIGH",
        "pattern": r'(?:messages|prompt|content|system)\s*[=:]\s*f["\'][^"\']*(?:request\.|args\.|kwargs\.|user_input|user_message|input\s*\(|params\[)',
        "description": (
            "User-controlled data interpolated directly into an LLM prompt via f-string "
            "enables prompt injection attacks where an attacker can override system instructions."
        ),
        "cwe": "CWE-74",
        "recommendation": (
            "Sanitize user input before including in prompts. Apply input length limits, "
            "strip control characters, and use a separate system role message to establish guardrails."
        ),
    },
    {
        "id": "LLM01-002",
        "category": "LLM01: Prompt Injection",
        "name": "User input concatenated into LLM message content",
        "severity": "HIGH",
        "pattern": r'(?:content|prompt)\s*[=:]\s*["\'][^"\']*["\'\s]*\+\s*(?:request\.|user_input|user_message|query|args|kwargs)',
        "description": (
            "String concatenation of user input into LLM message content enables prompt injection. "
            "Attackers can inject instructions to override system behavior."
        ),
        "cwe": "CWE-74",
        "recommendation": (
            "Use structured prompt templates with parameterization. "
            "Never directly concatenate user data into prompt strings."
        ),
    },
    {
        "id": "LLM01-003",
        "category": "LLM01: Prompt Injection",
        "name": "LLM prompt constructed with .format() from user input",
        "severity": "HIGH",
        "pattern": r'(?:prompt|content|template|message)\s*=\s*[^=\n]+\.format\s*\([^)]*(?:request\.|user_|input_|query|args\.|kwargs\.)',
        "description": (
            "Using .format() with user-controlled values to build LLM prompts enables prompt injection. "
            "An attacker can craft input that breaks out of intended prompt structure."
        ),
        "cwe": "CWE-74",
        "recommendation": (
            "Validate and sanitize all user inputs before including in prompts. "
            "Use allowlists for permitted content and separate user input from system instructions."
        ),
    },
    {
        "id": "LLM01-004",
        "category": "LLM01: Prompt Injection",
        "name": "LangChain PromptTemplate built from user-controlled string",
        "severity": "HIGH",
        "pattern": r'PromptTemplate\.from_template\s*\([^)]*(?:request\.|user_|input_|args\.|kwargs\.|\+\s*\w)',
        "description": (
            "Constructing a LangChain PromptTemplate directly from user-controlled strings "
            "enables prompt injection. The template structure itself becomes attacker-controlled."
        ),
        "cwe": "CWE-74",
        "recommendation": (
            "Define PromptTemplates statically with fixed structure. "
            "Pass user data only as input_variables, never as the template string."
        ),
    },
    {
        "id": "LLM01-005",
        "category": "LLM01: Prompt Injection",
        "name": "ChatPromptTemplate from_messages with user-controlled input",
        "severity": "MEDIUM",
        "pattern": r'ChatPromptTemplate\.from_messages\s*\([^)]*(?:user_input|request\.|args\.|kwargs\.)',
        "description": (
            "Building chat prompt templates with unvalidated user input in the messages list "
            "allows injection of additional role directives."
        ),
        "cwe": "CWE-1427",
        "recommendation": (
            "Use fixed templates and pass user input only as input_variables. "
            "Validate input against expected patterns before template rendering."
        ),
    },
    {
        "id": "LLM01-006",
        "category": "LLM01: Prompt Injection",
        "name": "LangChain agent run() / invoke() with unvalidated user input",
        "severity": "HIGH",
        "pattern": r'(?:agent(?:_chain)?|chain|executor)\.(?:run|invoke|arun|ainvoke)\s*\(\s*(?:request\.|user_input|user_message|query|args|kwargs)',
        "description": (
            "Passing unvalidated user input directly to a LangChain agent's run/invoke method "
            "enables prompt injection attacks that can compromise agent tool usage."
        ),
        "cwe": "CWE-20",
        "recommendation": (
            "Validate and sanitize user input before passing to agents. "
            "Implement input length limits and content filtering."
        ),
    },

    # ── LLM02: Sensitive Information Disclosure ──────────────
    {
        "id": "LLM02-001",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "Hardcoded OpenAI API key",
        "severity": "CRITICAL",
        "pattern": r'(?:api_key|openai\.api_key|OPENAI_API_KEY)\s*=\s*["\']sk-[A-Za-z0-9_\-]{20,}["\']',
        "description": (
            "Hardcoded OpenAI API key detected. Exposed keys allow unauthorized API usage "
            "and can result in significant financial charges and data exposure."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Store API keys in environment variables or a secrets manager. "
            "Use os.environ.get('OPENAI_API_KEY') and inject via CI/CD secrets. "
            "Rotate any exposed keys immediately."
        ),
    },
    {
        "id": "LLM02-002",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "Hardcoded Anthropic API key",
        "severity": "CRITICAL",
        "pattern": r'(?:api_key|anthropic\.api_key|ANTHROPIC_API_KEY)\s*=\s*["\']sk-ant-[A-Za-z0-9_\-]{20,}["\']',
        "description": (
            "Hardcoded Anthropic API key detected. Exposed keys allow unauthorized access "
            "to Claude models and may result in significant API costs."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Store API keys in environment variables. "
            "Use os.environ.get('ANTHROPIC_API_KEY'). Rotate any exposed keys immediately."
        ),
    },
    {
        "id": "LLM02-003",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "Hardcoded Hugging Face access token",
        "severity": "CRITICAL",
        "pattern": r'(?:token|hf_token|HUGGING_FACE_TOKEN|HF_TOKEN)\s*=\s*["\']hf_[A-Za-z0-9]{20,}["\']',
        "description": (
            "Hardcoded Hugging Face access token detected. Exposed tokens allow unauthorized "
            "access to private models, datasets, and Inference API quota."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Use environment variables for HF tokens. "
            "Use huggingface_hub.login() with externally-sourced tokens. Rotate immediately if exposed."
        ),
    },
    {
        "id": "LLM02-004",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "PII field names passed directly to LLM API call",
        "severity": "HIGH",
        "pattern": r'(?:invoke|predict|generate|create|run)\s*\([^)]*(?:ssn|social_security|credit_card|card_number|dob|date_of_birth|passport_number|drivers_license)',
        "description": (
            "Personally Identifiable Information (PII) field names detected in LLM API call arguments. "
            "Sending PII to external LLM APIs may violate GDPR, HIPAA, and other data protection regulations."
        ),
        "cwe": "CWE-200",
        "recommendation": (
            "Anonymize or pseudonymize PII before passing to LLM APIs. "
            "Implement data minimization principles and data processing agreements with LLM providers."
        ),
    },
    {
        "id": "LLM02-005",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "LLM response object logged at INFO or DEBUG level",
        "severity": "MEDIUM",
        "pattern": r'logging\.(?:info|debug)\s*\([^)]*(?:response|completion|result|output|choices)',
        "description": (
            "Logging LLM API response objects at INFO/DEBUG level may expose sensitive "
            "generated content or user data in log files and log aggregation systems."
        ),
        "cwe": "CWE-532",
        "recommendation": (
            "Log only metadata (tokens used, latency, model ID) at INFO level. "
            "Log full responses only at DEBUG level and ensure log files are access-controlled."
        ),
    },
    {
        "id": "LLM02-006",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "Raw LLM response printed to stdout",
        "severity": "LOW",
        "pattern": r'\bprint\s*\([^)]*(?:response|completion|result|llm_output|model_output)',
        "description": (
            "Printing raw LLM API responses to stdout may expose sensitive information "
            "in production logs, terminals, or log aggregation systems."
        ),
        "cwe": "CWE-209",
        "recommendation": (
            "In production, use structured logging and log only necessary metadata. "
            "Avoid printing raw model outputs."
        ),
    },

    # ── LLM03: Supply Chain ──────────────────────────────────
    {
        "id": "LLM03-001",
        "category": "LLM03: Supply Chain",
        "name": "torch.load() without weights_only=True — arbitrary code execution risk",
        "severity": "CRITICAL",
        "pattern": r'\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)[^)]*\)',
        "description": (
            "torch.load() deserializes Python objects via pickle by default. "
            "A malicious model file can execute arbitrary code during loading. "
            "CVE-2022-45907."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Use torch.load(..., weights_only=True) for PyTorch >= 1.13. "
            "For older versions, only load model files from trusted, integrity-verified sources. "
            "Prefer safetensors format for model weights."
        ),
    },
    {
        "id": "LLM03-002",
        "category": "LLM03: Supply Chain",
        "name": "allow_dangerous_deserialization=True in LangChain",
        "severity": "CRITICAL",
        "pattern": r'allow_dangerous_deserialization\s*=\s*True',
        "description": (
            "Setting allow_dangerous_deserialization=True in LangChain enables pickle-based "
            "deserialization of chain files, allowing arbitrary code execution from malicious files."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Remove this flag. Define chains using LCEL (LangChain Expression Language) "
            "instead of serialized chain files."
        ),
    },
    {
        "id": "LLM03-003",
        "category": "LLM03: Supply Chain",
        "name": "LangChain chain loaded from file (pickle deserialization)",
        "severity": "HIGH",
        "pattern": r'(?:load_chain|Chain\.load|BaseChain\.load)\s*\(',
        "description": (
            "Loading LangChain chains from files uses pickle deserialization, "
            "which can execute arbitrary code from malicious chain files."
        ),
        "cwe": "CWE-502",
        "recommendation": (
            "Prefer LCEL chain definitions over serialized chains. "
            "If loading from file is required, only load from integrity-verified sources."
        ),
    },
    {
        "id": "LLM03-004",
        "category": "LLM03: Supply Chain",
        "name": "Model weights downloaded via HTTP without integrity verification",
        "severity": "MEDIUM",
        "pattern": r'(?:requests\.get|urllib\.request\.urlretrieve|urllib\.request\.urlopen)\s*\([^)]*(?:model|weights|checkpoint|gguf|safetensor|\.bin["\'])',
        "description": (
            "Downloading model files over HTTP without verifying a cryptographic hash "
            "allows man-in-the-middle attacks to substitute malicious model weights."
        ),
        "cwe": "CWE-494",
        "recommendation": (
            "After download, verify the file SHA256 hash against a known-good value. "
            "Use HTTPS and pin the server certificate. Prefer huggingface_hub for managed downloads."
        ),
    },
    {
        "id": "LLM03-005",
        "category": "LLM03: Supply Chain",
        "name": "trust_remote_code=True in from_pretrained() — remote code execution",
        "severity": "CRITICAL",
        "pattern": r'from_pretrained\s*\([^)]*trust_remote_code\s*=\s*True',
        "description": (
            "trust_remote_code=True allows the Hugging Face Hub to execute arbitrary Python code "
            "from the model repository during loading. A compromised or malicious model achieves full RCE."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Never use trust_remote_code=True with public or unreviewed models. "
            "Audit model repository code before enabling. Pin to a specific verified commit hash."
        ),
    },
    {
        "id": "LLM03-006",
        "category": "LLM03: Supply Chain",
        "name": "Hugging Face model loaded without revision pin",
        "severity": "MEDIUM",
        "pattern": r'from_pretrained\s*\(\s*["\'][A-Za-z0-9_\-/]+["\']\s*\)',
        "description": (
            "Loading a Hugging Face model without specifying a revision (commit hash) "
            "means model weights may change without notice, enabling silent supply chain substitution."
        ),
        "cwe": "CWE-829",
        "recommendation": (
            "Pin model loading to a specific commit: "
            "from_pretrained('org/model', revision='abc123...'). "
            "Store the pinned hash in version control."
        ),
    },

    # ── LLM04: Data and Model Poisoning ─────────────────────
    {
        "id": "LLM04-001",
        "category": "LLM04: Data and Model Poisoning",
        "name": "trust_remote_code=True in load_dataset() — remote code execution",
        "severity": "CRITICAL",
        "pattern": r'load_dataset\s*\([^)]*trust_remote_code\s*=\s*True',
        "description": (
            "Using trust_remote_code=True with load_dataset() allows the dataset repository "
            "to execute arbitrary Python code, enabling data poisoning and RCE."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Avoid trust_remote_code=True for datasets from untrusted sources. "
            "Review dataset scripts before enabling. Use local, verified datasets where possible."
        ),
    },
    {
        "id": "LLM04-002",
        "category": "LLM04: Data and Model Poisoning",
        "name": "Training data path taken from command-line arguments without validation",
        "severity": "MEDIUM",
        "pattern": r'(?:train|dataset|data_path|data_dir|train_file)\s*=\s*(?:args\.|parser\.|sys\.argv)',
        "description": (
            "Accepting training data paths directly from command-line arguments without validation "
            "allows an attacker to redirect training to poisoned or malicious datasets."
        ),
        "cwe": "CWE-20",
        "recommendation": (
            "Validate data paths against an allowlist of permitted directories. "
            "Verify data integrity using checksums (SHA256) before training."
        ),
    },
    {
        "id": "LLM04-003",
        "category": "LLM04: Data and Model Poisoning",
        "name": "User-supplied feedback written to training corpus without sanitization",
        "severity": "HIGH",
        "pattern": r'(?:open|write|json\.dump|csv\.writer)\s*\([^)]*(?:feedback|reward|rating|annotation|label|rlhf)',
        "description": (
            "Writing user-supplied feedback or labels to training/fine-tuning data without "
            "sanitization enables data poisoning attacks that can corrupt model behavior over time."
        ),
        "cwe": "CWE-20",
        "recommendation": (
            "Validate and sanitize all feedback data. Implement anomaly detection. "
            "Use human review pipelines for RLHF feedback before adding to training sets."
        ),
    },
    {
        "id": "LLM04-004",
        "category": "LLM04: Data and Model Poisoning",
        "name": "Training dataset loaded from remote URL without integrity check",
        "severity": "HIGH",
        "pattern": r'(?:load_dataset|pd\.read_csv|pd\.read_json|pd\.read_parquet)\s*\(\s*(?:f["\']|["\']https?://)',
        "description": (
            "Loading training data directly from remote URLs without integrity verification "
            "enables data poisoning via malicious or compromised remote data sources."
        ),
        "cwe": "CWE-494",
        "recommendation": (
            "Download data to local storage, verify SHA256 hash against a known-good value, "
            "then load from the local verified path."
        ),
    },

    # ── LLM05: Improper Output Handling ─────────────────────
    {
        "id": "LLM05-001",
        "category": "LLM05: Improper Output Handling",
        "name": "eval() / exec() receiving LLM-generated output — code injection",
        "severity": "CRITICAL",
        "pattern": r'\b(?:eval|exec)\s*\([^)]*(?:response|completion|output|result|generated|llm_|model_)',
        "description": (
            "Passing LLM-generated output directly to eval() or exec() enables code injection. "
            "An attacker can craft prompts that cause the LLM to generate and execute malicious code."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Never execute LLM-generated code without sandboxing. "
            "Use ast.literal_eval() for safe value parsing. "
            "Run generated code in an isolated subprocess with resource limits and no network access."
        ),
    },
    {
        "id": "LLM05-002",
        "category": "LLM05: Improper Output Handling",
        "name": "LLM output interpolated into SQL query — SQL injection",
        "severity": "CRITICAL",
        "pattern": r'(?:execute|cursor\.execute)\s*\([^)]*(?:response|completion|output|result|generated)[^)]*\)',
        "description": (
            "Using LLM-generated text in SQL queries without parameterization enables SQL injection. "
            "Adversarial prompts can cause the LLM to generate malicious SQL payloads."
        ),
        "cwe": "CWE-89",
        "recommendation": (
            "Use parameterized queries or an ORM for all database operations. "
            "Never interpolate LLM output directly into SQL strings."
        ),
    },
    {
        "id": "LLM05-003",
        "category": "LLM05: Improper Output Handling",
        "name": "LLM output passed to subprocess — OS command injection",
        "severity": "CRITICAL",
        "pattern": r'subprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*(?:response|completion|output|result|generated|llm_)',
        "description": (
            "Using LLM-generated text as shell commands enables OS command injection. "
            "Adversarial prompts can make the LLM generate malicious shell payloads."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Never pass LLM output to shell commands. "
            "If command execution is required, map LLM output to a predefined allowlist of safe commands."
        ),
    },
    {
        "id": "LLM05-004",
        "category": "LLM05: Improper Output Handling",
        "name": "Jinja2 '| safe' filter applied to LLM-generated content — XSS",
        "severity": "HIGH",
        "pattern": r'(?:response|completion|output|result|generated|llm_)[^|\n]*\|\s*safe',
        "description": (
            "Marking LLM-generated content as safe in Jinja2 templates disables HTML escaping, "
            "enabling XSS attacks. Adversarial prompts can generate malicious HTML/JavaScript."
        ),
        "cwe": "CWE-79",
        "recommendation": (
            "Never apply the '| safe' filter to LLM-generated content. "
            "Use Jinja2's auto-escaping and escape all dynamic content with Markup.escape()."
        ),
    },
    {
        "id": "LLM05-005",
        "category": "LLM05: Improper Output Handling",
        "name": "LLM output written to file without sanitization",
        "severity": "MEDIUM",
        "pattern": r'(?:\.write|\.writelines)\s*\([^)]*(?:response|completion|output|result|generated|llm_)',
        "description": (
            "Writing raw LLM output to files without sanitization can lead to log injection, "
            "path traversal, or malicious file content that affects downstream processing."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Validate and sanitize LLM output before writing to files. "
            "Use safe file-writing patterns with path validation and content filtering."
        ),
    },
    {
        "id": "LLM05-006",
        "category": "LLM05: Improper Output Handling",
        "name": "LLM output used in os.system() — OS command injection",
        "severity": "CRITICAL",
        "pattern": r'os\.system\s*\([^)]*(?:response|completion|output|result|generated|llm_)',
        "description": (
            "Using LLM-generated output in os.system() calls enables OS command injection. "
            "Adversarial prompts can generate malicious shell commands."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Never use os.system() with LLM output. "
            "Use subprocess with a fixed command list (no shell=True) and validate all inputs."
        ),
    },

    # ── LLM06: Excessive Agency ──────────────────────────────
    {
        "id": "LLM06-001",
        "category": "LLM06: Excessive Agency",
        "name": "ShellTool / BashTool exposed to LLM agent — arbitrary command execution",
        "severity": "CRITICAL",
        "pattern": r'(?:ShellTool|BashTool|SystemCommandTool|TerminalTool|shell_tool|bash_tool)\s*\(\s*\)',
        "description": (
            "Exposing shell/bash execution tools to an LLM agent grants the agent the ability "
            "to execute arbitrary OS commands, enabling full system compromise via prompt injection."
        ),
        "cwe": "CWE-78",
        "recommendation": (
            "Do not expose shell tools to agents handling untrusted input. "
            "Use purpose-specific, sandboxed tools with defined input/output schemas."
        ),
    },
    {
        "id": "LLM06-002",
        "category": "LLM06: Excessive Agency",
        "name": "PythonREPLTool / CodeInterpreter exposed to LLM agent",
        "severity": "CRITICAL",
        "pattern": r'(?:PythonREPLTool|PythonAstREPLTool|CodeInterpreterTool|python_repl)\s*\(',
        "description": (
            "Exposing a Python REPL or code interpreter to an LLM agent allows execution of "
            "arbitrary Python code, enabling full system compromise via adversarial prompts."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Run code interpreters in isolated containers with resource limits, "
            "no network access, and a restricted filesystem."
        ),
    },
    {
        "id": "LLM06-003",
        "category": "LLM06: Excessive Agency",
        "name": "AgentExecutor without max_iterations — unbounded agent loop",
        "severity": "HIGH",
        "pattern": r'AgentExecutor\s*\((?![^)]*max_iterations)[^)]*\)',
        "description": (
            "Creating an AgentExecutor without setting max_iterations allows runaway agent loops "
            "with uncontrolled tool execution, resource exhaustion, and potential system impact."
        ),
        "cwe": "CWE-400",
        "recommendation": (
            "Always set max_iterations (e.g., max_iterations=10) and max_execution_time "
            "on AgentExecutor to prevent infinite loops and unbounded tool calls."
        ),
    },
    {
        "id": "LLM06-004",
        "category": "LLM06: Excessive Agency",
        "name": "allow_dangerous_tools=True grants unrestricted tool access to agent",
        "severity": "HIGH",
        "pattern": r'allow_dangerous_tools\s*=\s*True',
        "description": (
            "Setting allow_dangerous_tools=True grants the LLM agent access to high-risk tools "
            "without additional validation, significantly expanding the attack surface."
        ),
        "cwe": "CWE-269",
        "recommendation": (
            "Remove this flag. Explicitly list only the specific tools required. "
            "Apply least-privilege principles to agent tool access."
        ),
    },
    {
        "id": "LLM06-005",
        "category": "LLM06: Excessive Agency",
        "name": "FileManagementTool with write capabilities in agent toolkit",
        "severity": "HIGH",
        "pattern": r'FileManagementTool\s*\([^)]*(?:write|delete|create|selected_tools)',
        "description": (
            "Granting an LLM agent file write/delete capabilities without human confirmation "
            "enables attackers to exfiltrate data or corrupt files via prompt injection."
        ),
        "cwe": "CWE-250",
        "recommendation": (
            "Implement human-in-the-loop confirmation for file write operations. "
            "Restrict agents to read-only access where possible."
        ),
    },

    # ── LLM07: System Prompt Leakage ─────────────────────────
    {
        "id": "LLM07-001",
        "category": "LLM07: System Prompt Leakage",
        "name": "Agent verbose=True leaks system prompt and chain details to logs",
        "severity": "MEDIUM",
        "pattern": r'\b(?:AgentExecutor|initialize_agent|Agent)\s*\([^)]*verbose\s*=\s*True',
        "description": (
            "Setting verbose=True on LangChain agents logs the full chain execution, "
            "including the system prompt, to stdout/logs, leaking confidential instructions."
        ),
        "cwe": "CWE-200",
        "recommendation": (
            "Disable verbose mode in production. "
            "Use structured logging for operational metrics without exposing prompt contents."
        ),
    },
    {
        "id": "LLM07-002",
        "category": "LLM07: System Prompt Leakage",
        "name": "System prompt value returned in HTTP API response",
        "severity": "HIGH",
        "pattern": r'(?:return|jsonify|Response)\s*\([^)]*(?:system_prompt|SYSTEM_PROMPT|sys_prompt)',
        "description": (
            "Returning the system prompt in API responses exposes confidential instructions "
            "to end users or API consumers, enabling prompt reverse-engineering."
        ),
        "cwe": "CWE-497",
        "recommendation": (
            "Never include system prompt content in API responses. "
            "Return only the user-facing LLM output."
        ),
    },
    {
        "id": "LLM07-003",
        "category": "LLM07: System Prompt Leakage",
        "name": "System prompt logged to application logs",
        "severity": "MEDIUM",
        "pattern": r'logging\.(?:info|debug|warning)\s*\([^)]*(?:system_prompt|SYSTEM_PROMPT|sys_prompt)',
        "description": (
            "Logging the system prompt exposes confidential instructions in log files "
            "accessible to operators, log aggregation systems, or attackers."
        ),
        "cwe": "CWE-532",
        "recommendation": (
            "Do not log system prompts. "
            "Log only operational metadata such as request IDs, token counts, and latency."
        ),
    },

    # ── LLM08: Vector and Embedding Weaknesses ───────────────
    {
        "id": "LLM08-001",
        "category": "LLM08: Vector and Embedding Weaknesses",
        "name": "ChromaDB client created without authentication",
        "severity": "HIGH",
        "pattern": r'chromadb\.(?:Client|HttpClient|PersistentClient)\s*\([^)]*\)',
        "description": (
            "Creating a ChromaDB client without authentication settings allows any user "
            "on the network to read, modify, or poison the vector store contents."
        ),
        "cwe": "CWE-284",
        "recommendation": (
            "Enable ChromaDB authentication (basic auth or token auth). "
            "Restrict network access to the vector store using firewall rules or VPC isolation."
        ),
    },
    {
        "id": "LLM08-002",
        "category": "LLM08: Vector and Embedding Weaknesses",
        "name": "Unsanitized user input stored directly in vector database",
        "severity": "HIGH",
        "pattern": r'(?:add_texts|add_documents|upsert|add)\s*\([^)]*(?:request\.|user_input|user_message|query|args\.|kwargs\.)',
        "description": (
            "Storing unsanitized user input in a vector database enables indirect prompt injection. "
            "Malicious content retrieved from the vector store can hijack LLM behavior."
        ),
        "cwe": "CWE-284",
        "recommendation": (
            "Validate and sanitize content before storing in vector databases. "
            "Implement content filtering to detect and reject prompt injection payloads."
        ),
    },
    {
        "id": "LLM08-003",
        "category": "LLM08: Vector and Embedding Weaknesses",
        "name": "Vector similarity search results used directly in LLM prompt",
        "severity": "MEDIUM",
        "pattern": r'similarity_search(?:_with_score)?\s*\(',
        "description": (
            "Using vector search results directly in prompts without relevance threshold or "
            "content validation allows adversarial retrieved content to influence LLM behavior."
        ),
        "cwe": "CWE-285",
        "recommendation": (
            "Set minimum similarity score thresholds for retrieved documents. "
            "Validate retrieved content for prompt injection patterns before including in prompts."
        ),
    },

    # ── LLM09: Misinformation ────────────────────────────────
    {
        "id": "LLM09-001",
        "category": "LLM09: Misinformation",
        "name": "High temperature setting significantly increases hallucination risk",
        "severity": "MEDIUM",
        "pattern": r'\btemperature\s*=\s*(?:0\.9[1-9]|[1-9](?:\.\d+)?)\b',
        "description": (
            "Temperature values above 0.9 significantly increase LLM hallucination rates "
            "and unpredictability, raising the risk of generating false or misleading information."
        ),
        "cwe": "CWE-1254",
        "recommendation": (
            "Use temperature <= 0.7 for factual use cases. "
            "Implement output validation and grounding with RAG for accuracy-critical applications."
        ),
    },
    {
        "id": "LLM09-002",
        "category": "LLM09: Misinformation",
        "name": "Streaming LLM response processed without validation",
        "severity": "LOW",
        "pattern": r'stream\s*=\s*True',
        "description": (
            "Streaming LLM responses without buffering or validation may expose partial, "
            "incoherent, or hallucinated content to downstream processing or users."
        ),
        "cwe": "CWE-1254",
        "recommendation": (
            "Buffer complete responses before downstream processing. "
            "Validate generated content for factual accuracy in accuracy-critical applications."
        ),
    },

    # ── LLM10: Unbounded Consumption ─────────────────────────
    {
        "id": "LLM10-001",
        "category": "LLM10: Unbounded Consumption",
        "name": "LLM client instantiated without max_tokens limit",
        "severity": "HIGH",
        "pattern": r'(?:ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|AzureChatOpenAI|ChatCohere|ChatMistralAI|ChatBedrock)\s*\((?![^)]*max_tokens)[^)]*\)',
        "description": (
            "Instantiating LLM clients without setting max_tokens allows unbounded token generation, "
            "leading to excessive API costs and potential denial-of-service via token exhaustion."
        ),
        "cwe": "CWE-400",
        "recommendation": (
            "Always set max_tokens when instantiating LLM clients. "
            "Implement cost monitoring, budgeting alerts, and hard spending limits on API accounts."
        ),
    },
    {
        "id": "LLM10-002",
        "category": "LLM10: Unbounded Consumption",
        "name": "OpenAI ChatCompletion.create() without request timeout",
        "severity": "MEDIUM",
        "pattern": r'openai\.(?:ChatCompletion|Completion)\.create\s*\((?![^)]*timeout)[^)]*\)',
        "description": (
            "Making OpenAI API calls without a timeout allows requests to hang indefinitely, "
            "blocking application threads and causing resource exhaustion."
        ),
        "cwe": "CWE-799",
        "recommendation": (
            "Set request_timeout parameter on all API calls. "
            "Use httpx timeout configuration for the OpenAI client: "
            "OpenAI(timeout=httpx.Timeout(30.0))."
        ),
    },
    {
        "id": "LLM10-003",
        "category": "LLM10: Unbounded Consumption",
        "name": "LLM API call inside unbounded loop without termination guard",
        "severity": "MEDIUM",
        "pattern": r'while\s+True\s*:[^}]*(?:invoke|predict|generate|create|run)\s*\(',
        "description": (
            "Calling LLM APIs in an infinite loop (while True) without a termination condition "
            "enables runaway API consumption and significant unexpected costs."
        ),
        "cwe": "CWE-400",
        "recommendation": (
            "Implement explicit loop termination conditions, token budget tracking, "
            "and circuit breakers for LLM API calls."
        ),
    },
    {
        "id": "LLM10-004",
        "category": "LLM10: Unbounded Consumption",
        "name": "Anthropic client.messages.create() without timeout",
        "severity": "MEDIUM",
        "pattern": r'client\.messages\.create\s*\((?![^)]*timeout)[^)]*\)',
        "description": (
            "Making Anthropic API calls without a timeout allows requests to hang indefinitely, "
            "blocking application threads and potentially causing resource exhaustion."
        ),
        "cwe": "CWE-799",
        "recommendation": (
            "Configure timeouts on the Anthropic client: "
            "anthropic.Anthropic(timeout=30.0). "
            "Set per-request timeouts for all API calls."
        ),
    },
]


# ============================================================
# LLM SAST RULES — JavaScript / TypeScript source files
# ============================================================
LLM_JS_SAST_RULES = [

    # ── LLM01: Prompt Injection ──────────────────────────────
    {
        "id": "LLM01-JS-001",
        "category": "LLM01: Prompt Injection",
        "name": "User input in LLM prompt via template literal (JS/TS)",
        "severity": "HIGH",
        "pattern": r'(?:content|prompt|message)\s*[:=]\s*`[^`]*\$\{[^}]*(?:req\.|request\.|body\.|params\.|query\.|userInput|user_input|inputText)',
        "description": (
            "User-controlled data interpolated into LLM prompts via JavaScript template literals "
            "enables prompt injection attacks."
        ),
        "cwe": "CWE-74",
        "recommendation": (
            "Sanitize user input before including in prompts. "
            "Use structured message formats with system role separation."
        ),
    },
    {
        "id": "LLM01-JS-002",
        "category": "LLM01: Prompt Injection",
        "name": "User input concatenated into LLM prompt string (JS/TS)",
        "severity": "HIGH",
        "pattern": r'(?:content|prompt|message)\s*[:=]\s*["\'][^"\']*["\'\s]*\+\s*(?:req\.|request\.|body\.|params\.|query\.|userInput)',
        "description": (
            "String concatenation of user input into LLM message content enables prompt injection "
            "in JavaScript/TypeScript applications."
        ),
        "cwe": "CWE-74",
        "recommendation": (
            "Use parameterized prompts. Validate and sanitize all user inputs "
            "before including in LLM API calls."
        ),
    },
    {
        "id": "LLM01-JS-003",
        "category": "LLM01: Prompt Injection",
        "name": "LangChain JS agent invoked with raw user request (JS/TS)",
        "severity": "HIGH",
        "pattern": r'(?:agent|chain|executor)\.(?:invoke|call|run)\s*\(\s*(?:req\.|request\.|body\.|params\.|userInput)',
        "description": (
            "Passing unvalidated user request data directly to a LangChain.js agent "
            "enables prompt injection attacks compromising agent tool usage."
        ),
        "cwe": "CWE-20",
        "recommendation": (
            "Validate and sanitize user input before passing to agents. "
            "Implement input length limits and content filtering."
        ),
    },

    # ── LLM02: Sensitive Information Disclosure ──────────────
    {
        "id": "LLM02-JS-001",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "Hardcoded OpenAI / Anthropic / Gemini API key (JS/TS)",
        "severity": "CRITICAL",
        "pattern": r'(?:apiKey|api_key|OPENAI_API_KEY|ANTHROPIC_API_KEY|openaiKey)\s*[:=]\s*["\'](?:sk-|sk-ant-|AIza)[A-Za-z0-9_\-]{20,}["\']',
        "description": (
            "Hardcoded LLM API key detected in JavaScript/TypeScript source. "
            "Exposed keys allow unauthorized API usage and financial abuse."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Load API keys from environment variables (process.env.OPENAI_API_KEY). "
            "Never hardcode credentials in client-side or source code. Rotate exposed keys immediately."
        ),
    },
    {
        "id": "LLM02-JS-002",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "LLM API response logged to console (JS/TS)",
        "severity": "LOW",
        "pattern": r'console\.(?:log|info|debug)\s*\([^)]*(?:response|completion|result|output|choices)',
        "description": (
            "Logging raw LLM API responses to the console may expose sensitive generated "
            "content or user data in production browser or server logs."
        ),
        "cwe": "CWE-209",
        "recommendation": (
            "Log only metadata (token counts, request IDs) in production. "
            "Avoid logging full LLM response objects."
        ),
    },

    # ── LLM05: Improper Output Handling ─────────────────────
    {
        "id": "LLM05-JS-001",
        "category": "LLM05: Improper Output Handling",
        "name": "LLM output assigned to innerHTML — XSS",
        "severity": "HIGH",
        "pattern": r'\.innerHTML\s*[+]?=\s*[^;]*(?:response|completion|result|output|content|choices)',
        "description": (
            "Assigning LLM-generated content to innerHTML enables XSS attacks. "
            "Adversarial prompts can cause the LLM to generate malicious HTML/JavaScript."
        ),
        "cwe": "CWE-79",
        "recommendation": (
            "Use textContent instead of innerHTML for LLM output. "
            "If HTML rendering is required, sanitize with DOMPurify before DOM insertion."
        ),
    },
    {
        "id": "LLM05-JS-002",
        "category": "LLM05: Improper Output Handling",
        "name": "document.write() with LLM-generated content — XSS",
        "severity": "HIGH",
        "pattern": r'document\.write\s*\([^)]*(?:response|completion|result|output|content)',
        "description": (
            "Using document.write() with LLM-generated content enables XSS and HTML injection. "
            "Adversarial prompts can generate malicious markup."
        ),
        "cwe": "CWE-79",
        "recommendation": (
            "Never use document.write() with dynamic content. "
            "Use DOM manipulation methods and sanitize content with DOMPurify."
        ),
    },
    {
        "id": "LLM05-JS-003",
        "category": "LLM05: Improper Output Handling",
        "name": "eval() / Function() with LLM-generated output (JS/TS)",
        "severity": "CRITICAL",
        "pattern": r'(?:\beval\s*\(|new\s+Function\s*\()[^)]*(?:response|completion|result|output|content|choices)',
        "description": (
            "Evaluating LLM-generated JavaScript code via eval() or Function() enables "
            "arbitrary code execution. Adversarial prompts can generate malicious code."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Never execute LLM-generated code with eval() or Function(). "
            "Use sandboxed environments (e.g., vm2, isolated-vm) if code execution is required."
        ),
    },
    {
        "id": "LLM05-JS-004",
        "category": "LLM05: Improper Output Handling",
        "name": "LLM output used in dangerouslySetInnerHTML (React)",
        "severity": "HIGH",
        "pattern": r'dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*(?:response|completion|result|output|content)',
        "description": (
            "Using LLM-generated content in React's dangerouslySetInnerHTML bypasses "
            "React's XSS protection, enabling cross-site scripting via adversarial prompts."
        ),
        "cwe": "CWE-79",
        "recommendation": (
            "Sanitize LLM output with DOMPurify before using dangerouslySetInnerHTML. "
            "Prefer rendering as plain text where possible."
        ),
    },

    # ── LLM06: Excessive Agency ──────────────────────────────
    {
        "id": "LLM06-JS-001",
        "category": "LLM06: Excessive Agency",
        "name": "AutoGen / multi-agent human_input_mode=NEVER removes human oversight",
        "severity": "HIGH",
        "pattern": r'human_input_mode\s*[:=]\s*["\']NEVER["\']',
        "description": (
            "Setting human_input_mode to NEVER in AutoGen or similar multi-agent frameworks "
            "removes all human oversight, allowing agents to take uncontrolled actions."
        ),
        "cwe": "CWE-269",
        "recommendation": (
            "Use human_input_mode='ALWAYS' or 'TERMINATE' to maintain human oversight "
            "for critical operations."
        ),
    },
    {
        "id": "LLM06-JS-002",
        "category": "LLM06: Excessive Agency",
        "name": "LangChain.js agent created without maxIterations (JS/TS)",
        "severity": "HIGH",
        "pattern": r'(?:initializeAgentExecutorWithOptions|AgentExecutor\.fromAgentAndTools)\s*\((?![^)]*maxIterations)[^)]*\)',
        "description": (
            "Creating LangChain.js agent executors without maxIterations allows runaway "
            "agent loops with unbounded tool execution and API consumption."
        ),
        "cwe": "CWE-400",
        "recommendation": (
            "Always set maxIterations when creating agent executors: "
            "{ maxIterations: 10, ... }."
        ),
    },

    # ── LLM07: System Prompt Leakage ─────────────────────────
    {
        "id": "LLM07-JS-001",
        "category": "LLM07: System Prompt Leakage",
        "name": "System prompt hardcoded in client-side JavaScript / TypeScript",
        "severity": "HIGH",
        "pattern": r'(?:systemPrompt|system_prompt|SYSTEM_PROMPT)\s*[:=]\s*["\'][^"\']{20,}["\']',
        "description": (
            "Hardcoding the system prompt in client-side JavaScript exposes confidential "
            "instructions to any user who inspects the page source or JS bundle."
        ),
        "cwe": "CWE-200",
        "recommendation": (
            "Keep system prompts server-side. "
            "Never expose system prompt content in client-side code or API responses."
        ),
    },
    {
        "id": "LLM07-JS-002",
        "category": "LLM07: System Prompt Leakage",
        "name": "System prompt included in server API response (JS/TS)",
        "severity": "HIGH",
        "pattern": r'res\.(?:json|send)\s*\([^)]*(?:systemPrompt|system_prompt|SYSTEM_PROMPT)',
        "description": (
            "Including the system prompt in HTTP API responses exposes confidential "
            "LLM instructions to API consumers."
        ),
        "cwe": "CWE-497",
        "recommendation": (
            "Return only the user-facing LLM output in API responses. "
            "Keep system prompts server-side and out of all response payloads."
        ),
    },

    # ── LLM09: Misinformation ────────────────────────────────
    {
        "id": "LLM09-JS-001",
        "category": "LLM09: Misinformation",
        "name": "High temperature in LLM API call increases hallucination risk (JS/TS)",
        "severity": "MEDIUM",
        "pattern": r'\btemperature\s*:\s*(?:0\.9[1-9]|[1-9](?:\.\d+)?)\b',
        "description": (
            "Temperature values above 0.9 significantly increase LLM hallucination rates "
            "in JavaScript/TypeScript LLM applications."
        ),
        "cwe": "CWE-1254",
        "recommendation": (
            "Use temperature <= 0.7 for factual use cases. "
            "Implement output grounding with RAG for accuracy-critical applications."
        ),
    },

    # ── LLM10: Unbounded Consumption ─────────────────────────
    {
        "id": "LLM10-JS-001",
        "category": "LLM10: Unbounded Consumption",
        "name": "OpenAI / Anthropic API call without maxTokens limit (JS/TS)",
        "severity": "HIGH",
        "pattern": r'(?:openai|anthropic|client)\.(?:chat\.completions\.create|messages\.create)\s*\((?![^)]*max_tokens)[^)]*\)',
        "description": (
            "Making LLM API calls without a max_tokens parameter allows unbounded token generation "
            "and excessive API costs in JavaScript/TypeScript applications."
        ),
        "cwe": "CWE-400",
        "recommendation": (
            "Always specify max_tokens in API calls: { max_tokens: 1000, ... }. "
            "Implement cost monitoring and hard spending limits on API accounts."
        ),
    },
    {
        "id": "LLM10-JS-002",
        "category": "LLM10: Unbounded Consumption",
        "name": "LLM API call in setInterval / recursive setTimeout without guard (JS/TS)",
        "severity": "MEDIUM",
        "pattern": r'setInterval\s*\([^)]*(?:invoke|generate|create|chat)\s*\(',
        "description": (
            "Calling LLM APIs inside setInterval without rate limiting or token budget tracking "
            "enables runaway API consumption."
        ),
        "cwe": "CWE-770",
        "recommendation": (
            "Implement rate limiting, token budget tracking, and circuit breakers "
            "for all scheduled LLM API calls."
        ),
    },
]


# ============================================================
# LLM RULES — .env files
# ============================================================
LLM_ENV_RULES = [
    {
        "id": "LLM02-ENV-001",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "LLM API key stored in .env file",
        "severity": "HIGH",
        "pattern": r'(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY|HUGGINGFACE_TOKEN|HF_TOKEN|GEMINI_API_KEY|REPLICATE_API_KEY|TOGETHER_API_KEY|GROQ_API_KEY|MISTRAL_API_KEY|PERPLEXITY_API_KEY)\s*=\s*\S+',
        "description": (
            "LLM API keys stored in .env files may be accidentally committed to version control, "
            "exposing credentials and enabling unauthorized API usage."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Add .env to .gitignore. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) "
            "or CI/CD environment variable injection for production deployments."
        ),
    },
    {
        "id": "LLM07-ENV-001",
        "category": "LLM07: System Prompt Leakage",
        "name": "System prompt stored in .env file",
        "severity": "MEDIUM",
        "pattern": r'(?:SYSTEM_PROMPT|SYS_PROMPT|LLM_SYSTEM|AGENT_INSTRUCTIONS|LLM_INSTRUCTIONS)\s*=\s*\S+',
        "description": (
            "Storing system prompts in .env files risks exposure through version control commits "
            "or environment variable dumps accessible to application code."
        ),
        "cwe": "CWE-497",
        "recommendation": (
            "Store system prompts in a dedicated secrets manager or config service with access controls. "
            "Do not commit .env files to version control."
        ),
    },
    {
        "id": "LLM03-ENV-001",
        "category": "LLM03: Supply Chain",
        "name": "ML experiment tracking credentials in .env file",
        "severity": "HIGH",
        "pattern": r'(?:MLFLOW_TRACKING_URI|WANDB_API_KEY|NEPTUNE_API_KEY|COMET_API_KEY|DAGSHUB_TOKEN)\s*=\s*\S+',
        "description": (
            "ML experiment tracking platform credentials stored in .env files risk exposure "
            "through accidental version control commits, enabling unauthorized model access."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Add .env to .gitignore. Use a secrets manager for all ML platform credentials. "
            "Implement pre-commit hooks to detect secret exposure."
        ),
    },
    {
        "id": "LLM02-ENV-002",
        "category": "LLM02: Sensitive Information Disclosure",
        "name": "Database credentials in .env may reach LLM context",
        "severity": "MEDIUM",
        "pattern": r'(?:DATABASE_URL|DB_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|MONGO_URI)\s*=\s*\S+',
        "description": (
            "Database credentials in .env files may inadvertently be included in LLM context "
            "or exposed through environment variable logging."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Use a secrets manager for all database credentials. "
            "Implement environment variable access controls and audit logging."
        ),
    },
]


# ============================================================
# LLM RULES — YAML / YML configuration files
# ============================================================
LLM_YAML_RULES = [
    {
        "id": "LLM07-YAML-001",
        "category": "LLM07: System Prompt Leakage",
        "name": "System prompt stored in YAML configuration file",
        "severity": "MEDIUM",
        "pattern": r'(?:system_prompt|system_message|agent_instructions|llm_system|initial_prompt)\s*:\s*["\']?.{10,}',
        "description": (
            "System prompts stored in YAML configuration files may be exposed if the config "
            "is committed to version control or accessible to unauthorized users."
        ),
        "cwe": "CWE-497",
        "recommendation": (
            "Store system prompts in a secrets manager with access controls. "
            "If using YAML configs, restrict file access and exclude from version control."
        ),
    },
    {
        "id": "LLM03-YAML-001",
        "category": "LLM03: Supply Chain",
        "name": "LLM API key hardcoded in YAML configuration",
        "severity": "CRITICAL",
        "pattern": r'(?:api_key|apiKey|openai_key|anthropic_key|llm_key)\s*:\s*["\']?(?:sk-|sk-ant-|hf_)[A-Za-z0-9_\-]{20,}',
        "description": (
            "Hardcoded LLM API credentials detected in YAML configuration files. "
            "These are easily exposed through version control or configuration dumps."
        ),
        "cwe": "CWE-312",
        "recommendation": (
            "Use environment variable references (e.g., ${OPENAI_API_KEY}) in YAML configs "
            "instead of hardcoded values. Use a secrets manager for production deployments."
        ),
    },
    {
        "id": "LLM10-YAML-001",
        "category": "LLM10: Unbounded Consumption",
        "name": "No max_tokens or token limit configured in YAML LLM config",
        "severity": "MEDIUM",
        "pattern": r'(?:model|llm|openai|anthropic)\s*:\s*\n(?:\s+\w+\s*:.*\n)*(?!\s+max_tokens\s*:)',
        "description": (
            "LLM configuration in YAML without max_tokens settings allows unbounded "
            "token consumption when the configuration is used at runtime."
        ),
        "cwe": "CWE-400",
        "recommendation": (
            "Add max_tokens configuration to all LLM YAML configurations. "
            "Implement API cost monitoring and alerting."
        ),
    },
    {
        "id": "LLM04-YAML-001",
        "category": "LLM04: Data and Model Poisoning",
        "name": "trust_remote_code: true in model configuration YAML",
        "severity": "CRITICAL",
        "pattern": r'trust_remote_code\s*:\s*true',
        "description": (
            "trust_remote_code: true in YAML model configuration enables execution of arbitrary "
            "Python code from model repositories during runtime, enabling supply chain attacks."
        ),
        "cwe": "CWE-94",
        "recommendation": (
            "Remove trust_remote_code: true from configuration. "
            "Audit model repository code before enabling this setting."
        ),
    },
]


# ============================================================
# LLM VULNERABLE PACKAGES — CVE database
# ============================================================
LLM_VULNERABLE_PACKAGES = {
    # ── Python LLM frameworks ─────────────────────────────
    "langchain": [
        {
            "affected": "<0.0.247",
            "cve": "CVE-2023-38858",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via PALChain. Attacker-controlled math expressions are executed unsandboxed.",
            "fix": "0.0.247",
        },
        {
            "affected": "<0.0.312",
            "cve": "CVE-2023-34541",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via LLMMathChain and SerpAPIWrapper due to unsanitized LLM output passed to eval().",
            "fix": "0.0.312",
        },
        {
            "affected": "<0.0.312",
            "cve": "CVE-2023-46229",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via unsafe pickle deserialization of chain and tool files.",
            "fix": "0.0.312",
        },
        {
            "affected": "<0.1.17",
            "cve": "CVE-2024-28088",
            "severity": "HIGH",
            "description": "Path traversal in LocalFileStore allows reading arbitrary files outside the store directory.",
            "fix": "0.1.17",
        },
        {
            "affected": "<0.1.17",
            "cve": "CVE-2024-2965",
            "severity": "HIGH",
            "description": "Path traversal in JSONLoader allows reading arbitrary files from the filesystem.",
            "fix": "0.1.17",
        },
    ],
    "langchain-core": [
        {
            "affected": "<0.1.52",
            "cve": "CVE-2024-3571",
            "severity": "HIGH",
            "description": "ReDoS vulnerability via crafted JSON schema input in prompt template validation.",
            "fix": "0.1.52",
        },
    ],
    "langchain-community": [
        {
            "affected": "<0.2.5",
            "cve": "CVE-2024-5565",
            "severity": "HIGH",
            "description": "SSRF via GraphCypherQAChain when attacker controls database URI configuration.",
            "fix": "0.2.5",
        },
    ],
    "openai": [
        {
            "affected": "<1.0.0",
            "cve": "CVE-2023-37901",
            "severity": "MEDIUM",
            "description": "Sensitive data logged in debug mode in the deprecated openai SDK (<1.0.0).",
            "fix": "1.0.0",
        },
    ],
    "anthropic": [
        {
            "affected": "<0.28.0",
            "cve": "CVE-2024-24787",
            "severity": "MEDIUM",
            "description": "Improper certificate validation in older SDK versions may allow MITM attacks on API calls.",
            "fix": "0.28.0",
        },
    ],
    "transformers": [
        {
            "affected": "<4.36.0",
            "cve": "CVE-2023-6730",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via unsafe pickle deserialization when loading model files.",
            "fix": "4.36.0",
        },
        {
            "affected": "<4.38.0",
            "cve": "CVE-2024-7393",
            "severity": "HIGH",
            "description": "Arbitrary code execution via malicious model card Python code blocks.",
            "fix": "4.38.0",
        },
    ],
    "torch": [
        {
            "affected": "<2.0.1",
            "cve": "CVE-2022-45907",
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via torch.load() with malicious model files (pickle deserialization).",
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
        {
            "affected": "<4.11.0",
            "cve": "CVE-2024-2206",
            "severity": "CRITICAL",
            "description": "SSRF and path traversal via crafted file path in Gradio file serving endpoint.",
            "fix": "4.11.0",
        },
        {
            "affected": "<4.19.2",
            "cve": "CVE-2024-1561",
            "severity": "HIGH",
            "description": "Arbitrary file read via crafted file path in the Gradio API.",
            "fix": "4.19.2",
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
        {
            "affected": "<2.9.2",
            "cve": "CVE-2023-6014",
            "severity": "CRITICAL",
            "description": "Authentication bypass in MLflow tracking server allows unauthorized model access.",
            "fix": "2.9.2",
        },
        {
            "affected": "<2.12.1",
            "cve": "CVE-2024-37054",
            "severity": "HIGH",
            "description": "Path traversal in artifact serving allows reading arbitrary files.",
            "fix": "2.12.1",
        },
    ],
    "litellm": [
        {
            "affected": "<1.35.4",
            "cve": "CVE-2024-5751",
            "severity": "CRITICAL",
            "description": "SSRF via crafted model name allows requests to internal network endpoints.",
            "fix": "1.35.4",
        },
    ],
    "llama-index": [
        {
            "affected": "<0.10.24",
            "cve": "CVE-2024-3095",
            "severity": "HIGH",
            "description": "Arbitrary code execution via malicious document loader plugin.",
            "fix": "0.10.24",
        },
    ],
    "llama-cpp-python": [
        {
            "affected": "<0.2.58",
            "cve": "CVE-2024-34359",
            "severity": "CRITICAL",
            "description": "SSRF vulnerability via crafted model URL in llama-cpp-python server.",
            "fix": "0.2.58",
        },
    ],
    "ollama": [
        {
            "affected": "<0.1.34",
            "cve": "CVE-2024-39722",
            "severity": "HIGH",
            "description": "Path traversal vulnerability allows reading arbitrary files from the server.",
            "fix": "0.1.34",
        },
    ],
    "requests": [
        {
            "affected": "<2.31.0",
            "cve": "CVE-2023-32681",
            "severity": "MEDIUM",
            "description": "Proxy-Authorization header leaked to destination servers on redirect — affects LLM API calls through proxies.",
            "fix": "2.31.0",
        },
    ],
}

# Node.js / npm LLM vulnerable packages
LLM_NPM_VULNERABLE_PACKAGES = {
    "langchain": [
        {
            "affected": "<0.1.17",
            "cve": "CVE-2024-28088",
            "severity": "HIGH",
            "description": "Path traversal in LangChain.js file system operations.",
            "fix": "0.1.17",
        },
    ],
    "@langchain/core": [
        {
            "affected": "<0.1.52",
            "cve": "CVE-2024-3571",
            "severity": "HIGH",
            "description": "ReDoS via crafted JSON schema input in prompt template validation.",
            "fix": "0.1.52",
        },
    ],
    "openai": [
        {
            "affected": "<4.0.0",
            "cve": "CVE-2023-37901",
            "severity": "MEDIUM",
            "description": "Sensitive data logged in debug mode in legacy openai npm package.",
            "fix": "4.0.0",
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
class LLMScanner:
    SKIP_DIRS = {
        ".git", "node_modules", "target", "build", ".gradle",
        ".idea", "__pycache__", ".next", "dist", "out", ".venv",
        "venv", "env", ".env", "site-packages",
    }

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
            self._scan_python(filepath)
        elif suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            self._scan_js(filepath)
        elif name == ".env" or name.startswith(".env."):
            self._scan_env(filepath)
        elif suffix in (".yaml", ".yml"):
            self._scan_yaml(filepath)
        elif name in ("requirements.txt",) or (name.startswith("requirements") and suffix == ".txt"):
            self._scan_requirements(filepath)
        elif name == "pipfile":
            self._scan_pipfile(filepath)
        elif name == "pyproject.toml":
            self._scan_pyproject_toml(filepath)
        elif name == "package.json":
            self._scan_package_json(filepath)

    # ----------------------------------------------------------
    # Shared SAST scanning loop
    # ----------------------------------------------------------
    def _sast_scan(self, text, rules, filepath, file_label):
        """Apply a list of SAST rules line-by-line against text content."""
        compiled = [
            (rule, re.compile(rule["pattern"], re.MULTILINE))
            for rule in rules
        ]
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.lstrip()
            # Skip pure comment lines
            if stripped.startswith(("#", "//", "*", "/*")):
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
    # Python source scanning
    # ----------------------------------------------------------
    def _scan_python(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        self._vprint(f"  [py] {filepath}")
        self._sast_scan(text, LLM_PYTHON_SAST_RULES, filepath, "py")

    # ----------------------------------------------------------
    # JavaScript / TypeScript source scanning
    # ----------------------------------------------------------
    def _scan_js(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        self._vprint(f"  [js/ts] {filepath}")
        self._sast_scan(text, LLM_JS_SAST_RULES, filepath, "js")

    # ----------------------------------------------------------
    # .env file scanning
    # ----------------------------------------------------------
    def _scan_env(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        self._vprint(f"  [.env] {filepath}")
        self._sast_scan(text, LLM_ENV_RULES, filepath, "env")

    # ----------------------------------------------------------
    # YAML configuration scanning
    # ----------------------------------------------------------
    def _scan_yaml(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        self._vprint(f"  [yaml] {filepath}")
        self._sast_scan(text, LLM_YAML_RULES, filepath, "yaml")

    # ----------------------------------------------------------
    # Python dependency scanning — requirements.txt
    # ----------------------------------------------------------
    def _scan_requirements(self, filepath):
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
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[.*?\])?\s*([=!<>~^,\s0-9.*]+)?", line)
            if not m:
                continue
            pkg_raw = m.group(1)
            ver_str = (m.group(2) or "").strip()
            pin = re.search(r"==\s*([\d.]+)", ver_str)
            version = pin.group(1) if pin else ver_str
            self._check_python_dep(pkg_raw, version, str(filepath), lineno, raw)
            # Flag unpinned LLM packages
            if not pin and self._is_llm_package(pkg_raw) and ver_str:
                self._add(Finding(
                    rule_id="LLM03-REQ-001",
                    name=f"Unpinned LLM package: {pkg_raw}",
                    category="LLM03: Supply Chain",
                    severity="MEDIUM",
                    file_path=str(filepath),
                    line_num=lineno,
                    line_content=raw.rstrip(),
                    description=(
                        f"LLM framework package '{pkg_raw}' is not pinned to an exact version. "
                        "Unpinned dependencies may silently upgrade to versions with new vulnerabilities or breaking changes."
                    ),
                    recommendation=(
                        f"Pin to a specific version: {pkg_raw}==<exact_version>. "
                        "Use pip-compile or similar tools to generate locked dependency files."
                    ),
                    cwe="CWE-829",
                ))

    # ----------------------------------------------------------
    # Python dependency scanning — Pipfile
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
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*["\'](?:==)?([\d.*]+)["\']', line)
            if m:
                self._check_python_dep(m.group(1), m.group(2), str(filepath), lineno, raw)

    # ----------------------------------------------------------
    # Python dependency scanning — pyproject.toml
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
            if re.match(r"^\[.*dependencies.*\]", line, re.IGNORECASE):
                in_deps = True
                continue
            if line.startswith("[") and not re.match(r"^\[.*dependencies.*\]", line, re.IGNORECASE):
                in_deps = False
            if not in_deps:
                continue
            m = re.search(r'["\']?([A-Za-z0-9_.\-]+)["\']?\s*[=:><!~^,\s"\']*?([\d][.\d]*)', line)
            if m:
                self._check_python_dep(m.group(1), m.group(2), str(filepath), lineno, raw)

    # ----------------------------------------------------------
    # Node.js dependency scanning — package.json
    # ----------------------------------------------------------
    def _scan_package_json(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        self._vprint(f"  [package.json] {filepath}")

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            self._warn(f"Could not parse JSON: {filepath}")
            return

        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))

        # Find line numbers for each package in the raw text
        lines = text.splitlines()
        for pkg, ver_spec in all_deps.items():
            version = re.sub(r"[^0-9.]", "", ver_spec)
            # Find the line number
            lineno = 1
            for i, l in enumerate(lines, 1):
                if f'"{pkg}"' in l or f"'{pkg}'" in l:
                    lineno = i
                    break
            self._check_npm_dep(pkg, version, str(filepath), lineno,
                                 f'  "{pkg}": "{ver_spec}"')

    # ----------------------------------------------------------
    # CVE / vulnerable-package checks
    # ----------------------------------------------------------
    def _check_python_dep(self, pkg_raw, version, filepath, lineno, raw_line):
        pkg_key = re.sub(r"[-_.]", "-", pkg_raw).lower()
        for key in (pkg_key, pkg_key.replace("-", "_")):
            ranges = LLM_VULNERABLE_PACKAGES.get(key)
            if ranges:
                break
        else:
            return

        for entry in ranges:
            if not version or self._version_in_range(version, entry["affected"]):
                cve = entry.get("cve", "")
                fix = entry.get("fix", "latest")
                rule_id = f"DEP-LLM-{cve}" if cve else f"DEP-LLM-{pkg_key.upper()}"
                self._add(Finding(
                    rule_id=rule_id,
                    name=(
                        f"Vulnerable LLM dependency: {pkg_raw} {version} ({cve})"
                        if cve else f"Vulnerable LLM dependency: {pkg_raw} {version}"
                    ),
                    category="LLM03: Supply Chain",
                    severity=entry["severity"],
                    file_path=filepath,
                    line_num=lineno,
                    line_content=raw_line.rstrip(),
                    description=entry["description"],
                    recommendation=f"Upgrade {pkg_raw} to version {fix} or later.",
                    cve=cve,
                    cwe="CWE-1104",
                ))

    def _check_npm_dep(self, pkg_raw, version, filepath, lineno, raw_line):
        pkg_key = pkg_raw.lower()
        ranges = LLM_NPM_VULNERABLE_PACKAGES.get(pkg_key)
        if not ranges:
            return

        for entry in ranges:
            if not version or self._version_in_range(version, entry["affected"]):
                cve = entry.get("cve", "")
                fix = entry.get("fix", "latest")
                rule_id = f"DEP-NPM-{cve}" if cve else f"DEP-NPM-{pkg_key.upper()}"
                self._add(Finding(
                    rule_id=rule_id,
                    name=(
                        f"Vulnerable npm LLM package: {pkg_raw} {version} ({cve})"
                        if cve else f"Vulnerable npm LLM package: {pkg_raw} {version}"
                    ),
                    category="LLM03: Supply Chain",
                    severity=entry["severity"],
                    file_path=filepath,
                    line_num=lineno,
                    line_content=raw_line.rstrip(),
                    description=entry["description"],
                    recommendation=f"Upgrade {pkg_raw} to version {fix} or later.",
                    cve=cve,
                    cwe="CWE-1104",
                ))

    @staticmethod
    def _is_llm_package(pkg_name):
        """Return True if the package is a known LLM framework."""
        llm_packages = {
            "langchain", "langchain-core", "langchain-community", "langchain-openai",
            "langchain-anthropic", "openai", "anthropic", "transformers", "torch",
            "gradio", "mlflow", "litellm", "llama-index", "llama-cpp-python",
            "ollama", "autogen", "pyautogen", "crewai", "dspy-ai", "haystack-ai",
            "semantic-kernel", "instructor", "guidance", "outlines",
        }
        return re.sub(r"[-_.]", "-", pkg_name).lower() in llm_packages

    # ----------------------------------------------------------
    # Version comparison helpers
    # ----------------------------------------------------------
    @staticmethod
    def _parse_ver(s):
        """Parse a version string into a comparable tuple of ints."""
        s = re.sub(
            r"[-.]?(RELEASE|FINAL|GA|SNAPSHOT|alpha\d*|beta\d*|rc\d*).*$",
            "", s, flags=re.IGNORECASE
        )
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
        print(f"{B}  OWASP LLM Top 10 Security Scanner v{VERSION}  \u2014  Scan Report{R}")
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
            "scanner": f"OWASP LLM Top 10 Security Scanner v{VERSION}",
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
        description=f"OWASP LLM Top 10 Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
OWASP LLM Top 10 (2025) categories covered:
  LLM01  Prompt Injection
  LLM02  Sensitive Information Disclosure
  LLM03  Supply Chain (vulnerable/unpinned LLM packages, model loading)
  LLM04  Data and Model Poisoning
  LLM05  Improper Output Handling (eval, SQL, XSS, command injection)
  LLM06  Excessive Agency (shell tools, code interpreters, unbounded agents)
  LLM07  System Prompt Leakage
  LLM08  Vector and Embedding Weaknesses
  LLM09  Misinformation (high temperature, unvalidated streaming)
  LLM10  Unbounded Consumption (missing token limits, timeouts, iteration caps)

Supported file types:
  .py .pyw               Python source
  .js .jsx .ts .tsx      JavaScript / TypeScript
  .mjs .cjs              ES modules / CommonJS
  .env                   Environment configuration
  .yaml .yml             YAML configuration
  requirements.txt       Python dependencies
  Pipfile                Pipenv dependencies
  pyproject.toml         PEP 517/518 dependencies
  package.json           Node.js dependencies

Examples:
  python3 owasp_llm_scanner.py /path/to/llm-project
  python3 owasp_llm_scanner.py agent.py --json report.json
  python3 owasp_llm_scanner.py requirements.txt --verbose
  python3 owasp_llm_scanner.py /path/to/project --severity HIGH
  python3 owasp_llm_scanner.py . --severity LOW --json full_report.json
""",
    )
    parser.add_argument(
        "target",
        help=(
            "File or directory to scan. Supports .py, .pyw, .js, .jsx, .ts, .tsx, "
            ".mjs, .cjs, .env, .yaml, .yml, requirements.txt, Pipfile, pyproject.toml, package.json"
        ),
    )
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Only report findings at this severity or above (default: all)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"owasp_llm_scanner v{VERSION}")
    args = parser.parse_args()

    print(f"[*] OWASP LLM Top 10 Security Scanner v{VERSION}")
    print(f"[*] Target: {args.target}\n")

    scanner = LLMScanner(verbose=args.verbose)
    scanner.scan_path(args.target)

    if args.severity:
        scanner.filter_severity(args.severity)

    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)

    counts = scanner.summary()
    sys.exit(1 if (counts.get("CRITICAL", 0) or counts.get("HIGH", 0)) else 0)


if __name__ == "__main__":
    main()
