"""
Intentionally vulnerable Python / AI-agent file used to verify scanner detection.
DO NOT use any of these patterns in production code.
"""

import os
import subprocess
import pickle
import yaml
import marshal
import random
import hashlib
import requests
import urllib.request
from flask import Flask, render_template_string, redirect, request

# =============================================================================
# PY-CRED-001 / PY-CRED-002 / PY-CRED-003 / PY-CRED-004 – Hardcoded secrets
# =============================================================================
DB_PASSWORD = "s3cr3tP@ssw0rd!"
OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SECRET_KEY = "django-insecure-hardcoded-secret-key-do-not-use"
GCP_API_KEY = "AIzaSyD-FAKE-KEY-12345"

# =============================================================================
# PY-DESER-001 – pickle.loads() with user-supplied data
# =============================================================================
def load_session(cookie_data: bytes):
    obj = pickle.loads(cookie_data)          # PY-DESER-001
    return obj

# =============================================================================
# PY-DESER-002 – yaml.load() without safe loader
# =============================================================================
def parse_config(yaml_str: str):
    cfg = yaml.load(yaml_str, Loader=yaml.Loader)  # PY-DESER-002
    return cfg

# =============================================================================
# PY-DESER-003 – marshal.loads() with untrusted bytes
# =============================================================================
def restore_code(blob: bytes):
    return marshal.loads(blob)               # PY-DESER-003

# =============================================================================
# PY-RCE-001 / PY-RCE-002 – eval() / exec() with user input
# =============================================================================
def calculate(expr: str):
    return eval(request.args.get("expr", ""))   # PY-RCE-001

def run_script(code: str):
    exec(request.args.get("code", ""))          # PY-RCE-002

# =============================================================================
# PY-RCE-003 – LLM output executed via eval/exec (AI prompt-injection → RCE)
# =============================================================================
def run_llm_response(response: str):
    # Simulates calling an LLM and blindly executing the result
    exec(response)                              # PY-RCE-003 (exec + response var)
    result = eval(response)                     # PY-RCE-003 (eval + response var)
    return result

# =============================================================================
# PY-CMDI-001 / PY-CMDI-002 / PY-CMDI-003 – Command injection
# =============================================================================
def ping_host(host: str):
    os.system("ping -c 1 " + host)                       # PY-CMDI-001
    subprocess.call("nslookup " + host, shell=True)      # PY-CMDI-002
    result = os.popen("traceroute " + host).read()       # PY-CMDI-003
    return result

# =============================================================================
# PY-CMDI-004 – LLM output → subprocess (AI prompt-injection → OS command)
# =============================================================================
def execute_ai_command(completion: str):
    subprocess.run(completion, shell=True)               # PY-CMDI-004

# =============================================================================
# PY-SQLI-001 / PY-SQLI-002 / PY-SQLI-003 – SQL injection
# =============================================================================
def get_user_fstring(conn, user_id: str):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # PY-SQLI-001
    conn.execute(query)

def get_user_percent(conn, username: str):
    query = "SELECT * FROM users WHERE name = '%s'" % username  # PY-SQLI-002
    conn.execute(query)

# PY-SQLI-003 would appear in a Django view; shown as comment for reference:
# User.objects.raw("SELECT * FROM users WHERE id = " + user_id)

# =============================================================================
# PY-PATH-001 – Path traversal via open() with user-supplied path
# =============================================================================
def read_file(filename: str):
    with open(request.args.get("file", ""), "r") as fh:  # PY-PATH-001
        return fh.read()

# =============================================================================
# PY-SSRF-001 / PY-SSRF-002 / PY-SSRF-003 – SSRF
# =============================================================================
def fetch_url_requests(url: str):
    resp = requests.get(request.args.get("url", ""))     # PY-SSRF-001
    return resp.text

def fetch_url_urllib(url: str):
    return urllib.request.urlopen(                        # PY-SSRF-002
        request.args.get("endpoint", "")
    ).read()

# =============================================================================
# PY-SSTI-001 / PY-SSTI-002 – Server-Side Template Injection
# =============================================================================
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # PY-SSTI-002: render_template_string with user data concatenated
    return render_template_string("<h1>Hello " + name + "</h1>")

# PY-SSTI-001: direct Jinja2 Template with user-controlled string
from jinja2 import Template
def render_custom(tmpl_str: str):
    t = Template(request.args.get("template", ""))       # PY-SSTI-001
    return t.render()

# =============================================================================
# PY-REDIR-001 – Open redirect
# =============================================================================
@app.route("/redirect")
def unsafe_redirect():
    target = request.args.get("next", "/")
    return redirect(target)                               # PY-REDIR-001

# =============================================================================
# PY-CRYPTO-001 / PY-CRYPTO-002 / PY-CRYPTO-003 – Weak cryptography
# =============================================================================
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()     # PY-CRYPTO-001

def generate_token(email: str) -> str:
    return hashlib.sha1(email.encode()).hexdigest()       # PY-CRYPTO-002

def weak_nonce() -> int:
    return random.randint(100000, 999999)                 # PY-CRYPTO-003

# =============================================================================
# PY-XXE-001 / PY-XXE-002 – XML External Entity injection
# =============================================================================
from lxml import etree

def parse_xml_lxml(xml_bytes: bytes):
    parser = etree.XMLParser(resolve_entities=True)       # PY-XXE-001
    return etree.fromstring(xml_bytes, parser)

import xml.etree.ElementTree as ET
def parse_xml_stdlib(xml_str: str):
    return ET.fromstring(xml_str)                         # PY-XXE-002

# =============================================================================
# PY-FLASK-001 / PY-FLASK-002 – Flask misconfigurations
# =============================================================================
app.run(debug=True)                                       # PY-FLASK-001

# =============================================================================
# PY-AI-001 – LangChain allow_dangerous_deserialization
# =============================================================================
from langchain.chains import load_chain

def load_agent_chain(path: str):
    chain = load_chain(path, allow_dangerous_deserialization=True)  # PY-AI-001
    return chain

# =============================================================================
# PY-AI-002 – User input injected directly into LLM prompt (prompt injection)
# =============================================================================
import openai

def ask_ai(user_message: str):
    # PY-AI-002: user_input concatenated directly into prompt without sanitisation
    user_input = request.args.get("q", "")
    prompt = "Summarise this: " + user_input
    resp = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return resp.choices[0].message.content

# =============================================================================
# PY-AI-003 – LangChain ShellTool (unrestricted OS command execution by agent)
# =============================================================================
from langchain.tools import ShellTool           # PY-AI-003

shell_tool = ShellTool()

# =============================================================================
# PY-AI-004 – LangChain PythonREPLTool (unrestricted code execution by agent)
# =============================================================================
from langchain_experimental.tools import PythonREPLTool  # PY-AI-004

python_repl = PythonREPLTool()

# =============================================================================
# PY-AI-005 – LangChain load_chain() without dangerous deserialization flag
# =============================================================================
def restore_chain(saved_path: str):
    return load_chain(saved_path)                         # PY-AI-005

# =============================================================================
# PY-LOG-001 – Log injection with user-controlled data
# =============================================================================
import logging
logger = logging.getLogger(__name__)

def log_request(req_param: str):
    logger.info("Received request: %s", request.args.get("input"))  # PY-LOG-001

# =============================================================================
# PY-TMPFILE-001 – Insecure use of /tmp (predictable path)
# =============================================================================
def save_upload(data: bytes):
    with open("/tmp/upload.bin", "wb") as fh:             # PY-TMPFILE-001
        fh.write(data)

# =============================================================================
# PY-DJANGO-001 / PY-DJANGO-002 / PY-DJANGO-003 – Django misconfigurations
# (shown as plain assignments that match the scanner patterns)
# =============================================================================
DEBUG = True                                              # PY-DJANGO-001
SECRET_KEY = "django-insecure-hardcoded-key-for-scanner-demo"  # PY-DJANGO-002
ALLOWED_HOSTS = ["*"]                                     # PY-DJANGO-003
