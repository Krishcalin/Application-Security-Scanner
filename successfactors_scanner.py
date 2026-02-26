#!/usr/bin/env python3
"""
SAP SuccessFactors SSPM Scanner v1.0.0
SaaS Security Posture Management scanner for SAP SuccessFactors HCM instances.

Performs live OData REST API checks against a SAP SuccessFactors instance to
identify security misconfigurations aligned with:
  - Palo Alto Networks SSPM for SAP SuccessFactors
  - SAP SuccessFactors Security Hardening Guide
  - CIS HR SaaS Security Best Practices
  - OWASP, GDPR, and NIST SP 800-63B guidelines

No agent or plugin installation required — uses the standard SAP SuccessFactors
OData v2 REST API with read-only credentials.

Usage:
  python successfactors_scanner.py \\
      --api-host api4.successfactors.com \\
      --company-id MYCOMPANY \\
      --username admin.ro \\
      --password secret

Env var fallback:
  SF_API_HOST   SF_COMPANY_ID   SF_USERNAME   SF_PASSWORD

Data-center API hosts:
  DC1 (US)   : api4.successfactors.com
  DC2 (EU)   : apisalesdemo2.successfactors.eu
  DC4 (US2)  : api8.successfactors.com
  DC10 (APAC): api10.successfactors.com
  DC12 (Canada): api12.successfactors.com
  (Use the host shown in your instance URL — api{N}.successfactors.com)
"""

import os
import re
import sys
import json
import html as html_mod
import argparse
from datetime import datetime, timezone, timedelta

try:
    import requests
    from requests.auth import HTTPBasicAuth
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "1.0.0"

# ============================================================
# PASSWORD POLICY RULES
# Applied to fields returned from the PasswordPolicy OData entity.
#
# Operators:
#   gte_int     int(value) >= threshold  (fail if below)
#   lte_int     int(value) <= threshold  (fail if above)
#   eq_true     value in (True, "true", "yes", "1")
#   eq_false    value in (False, "false", "no", "0")
#   non_zero    int(value) != 0          (fail if zero — means "disabled")
#   lte_days    int(value) <= N and > 0  (0 = never expires → also a fail)
# ============================================================
PASSWORD_POLICY_RULES = [
    {
        "id": "SF-PWD-001",
        "category": "Password Policy",
        "name": "Minimum password length below 8 characters",
        "severity": "HIGH",
        "field": "minimumPasswordLength",
        "operator": "gte_int",
        "threshold": 8,
        "description": (
            "NIST SP 800-63B recommends a minimum of 8 characters. Short passwords "
            "are trivially brute-forced, especially for accounts with API or bulk data "
            "access. SAP SuccessFactors stores sensitive employee PII and compensation data."
        ),
        "recommendation": "Set minimumPasswordLength to at least 12 in the Password Policy.",
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-002",
        "category": "Password Policy",
        "name": "Uppercase characters not required in passwords",
        "severity": "MEDIUM",
        "field": "requireUpperCase",
        "operator": "eq_true",
        "description": "Requiring uppercase characters increases password entropy.",
        "recommendation": "Enable requireUpperCase in the Password Policy configuration.",
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-003",
        "category": "Password Policy",
        "name": "Lowercase characters not required in passwords",
        "severity": "MEDIUM",
        "field": "requireLowerCase",
        "operator": "eq_true",
        "description": "Requiring lowercase characters adds to password complexity.",
        "recommendation": "Enable requireLowerCase in the Password Policy configuration.",
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-004",
        "category": "Password Policy",
        "name": "Numeric digits not required in passwords",
        "severity": "MEDIUM",
        "field": "requireNumber",
        "operator": "eq_true",
        "description": "Numeric digits are a basic component of a strong password policy.",
        "recommendation": "Enable requireNumber in the Password Policy configuration.",
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-005",
        "category": "Password Policy",
        "name": "Special characters not required in passwords",
        "severity": "MEDIUM",
        "field": "requireSymbol",
        "operator": "eq_true",
        "description": (
            "Special characters significantly increase password entropy. "
            "Without them, dictionary and brute-force attacks are faster."
        ),
        "recommendation": "Enable requireSymbol in the Password Policy configuration.",
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-006",
        "category": "Password Policy",
        "name": "Password expiration disabled (passwordExpiration = 0)",
        "severity": "MEDIUM",
        "field": "passwordExpiration",
        "operator": "non_zero",
        "description": (
            "Passwords that never expire allow compromised credentials to remain valid "
            "indefinitely. While NIST no longer recommends periodic rotation for "
            "end users, rotation is still best practice for service and admin accounts."
        ),
        "recommendation": (
            "Set passwordExpiration to 90 days for privileged/admin accounts. "
            "For regular users, combine no-expiry with breach detection and MFA."
        ),
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-007",
        "category": "Password Policy",
        "name": "Password expiration set to more than 90 days",
        "severity": "LOW",
        "field": "passwordExpiration",
        "operator": "lte_days",
        "threshold": 90,
        "description": (
            "Password rotation periods longer than 90 days extend the exposure window "
            "for a compromised credential. For privileged accounts, 90 days or fewer "
            "is recommended."
        ),
        "recommendation": "Reduce passwordExpiration to 90 days or less for privileged accounts.",
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-008",
        "category": "Password Policy",
        "name": "Login lockout threshold too high (>10 attempts)",
        "severity": "HIGH",
        "field": "lockoutThreshold",
        "operator": "lte_int",
        "threshold": 10,
        "description": (
            "A high lockout threshold allows excessive brute-force attempts before an "
            "account is locked, enabling credential-stuffing and password-spray attacks "
            "against SuccessFactors accounts that may hold payroll and personal data."
        ),
        "recommendation": "Set lockoutThreshold to 5 or fewer failed attempts.",
        "cwe": "CWE-307",
    },
    {
        "id": "SF-PWD-009",
        "category": "Password Policy",
        "name": "Password history policy too short (<5 previous passwords)",
        "severity": "LOW",
        "field": "passwordHistory",
        "operator": "gte_int",
        "threshold": 5,
        "description": (
            "A short password history allows users to cycle through a small set of "
            "passwords, negating the security benefit of forced rotation."
        ),
        "recommendation": "Set passwordHistory to at least 10.",
        "cwe": "CWE-521",
    },
    {
        "id": "SF-PWD-010",
        "category": "Password Policy",
        "name": "Temporary password expiration too long (>24 hours)",
        "severity": "MEDIUM",
        "field": "temporaryPasswordExpiration",
        "operator": "lte_int",
        "threshold": 24,
        "description": (
            "Temporary passwords (sent during onboarding or reset) that are valid for "
            "more than 24 hours give attackers a long window to intercept and use them "
            "before the legitimate user does."
        ),
        "recommendation": "Set temporaryPasswordExpiration to 24 hours or less.",
        "cwe": "CWE-640",
    },
]

# ============================================================
# Finding data class  (identical schema to all other scanners)
# ============================================================
class Finding:
    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = file_path        # repurposed: OData entity name
        self.line_num = line_num          # always None for API checks
        self.line_content = line_content  # repurposed: "field = current_value"
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe or ""
        self.cve = cve or ""

    def to_dict(self):
        return {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_num,
            "code": self.line_content,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "cve": self.cve,
        }


# ============================================================
# SAP SuccessFactors SSPM Scanner
# ============================================================
class SuccessFactorsScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    # OData entity names for reference in findings
    ENTITY_PASSWORD_POLICY = "PasswordPolicy"
    ENTITY_USER            = "User"
    ENTITY_COMPANY_INFO    = "CompanyInfo"
    ENTITY_PERMISSION_ROLE = "PermissionRole"
    ENTITY_ROLE_ASSIGNMENT = "RoleAssignment"
    ENTITY_AUDIT           = "AuditConfiguration"
    ENTITY_OAUTH_CLIENT    = "OAuthClient"

    def __init__(self, api_host: str, company_id: str,
                 username: str, password: str, verbose: bool = False):
        # Normalise host — strip protocol if provided
        api_host = re.sub(r"^https?://", "", api_host).rstrip("/")
        self.api_host = api_host
        self.company_id = company_id
        self.base_url = f"https://{api_host}/odata/v2"
        # SAP SF Basic Auth: username@companyId:password
        self.auth = HTTPBasicAuth(f"{username}@{company_id}", password)
        self.verbose = verbose
        self.findings: list[Finding] = []

    # ----------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------
    def scan(self):
        """Run all SSPM check groups against the instance."""
        print(f"[*] SAP SuccessFactors SSPM Scanner v{VERSION}")
        print(f"[*] Target : https://{self.api_host}")
        print(f"[*] Company: {self.company_id}")
        print("[*] Running checks …")

        self._check_password_policy()
        self._check_users()
        self._check_permission_roles()
        self._check_sso_and_auth()
        self._check_audit_logging()
        self._check_data_privacy()
        self._check_integration_security()
        self._check_session_management()

    # ----------------------------------------------------------
    # OData REST API helper
    # ----------------------------------------------------------
    def _api_get(self, entity: str, params: dict = None) -> list[dict]:
        """
        Fetch records from a SAP SuccessFactors OData v2 entity.
        Handles pagination with $top/$skip.
        Returns list of record dicts, or [] on error.
        """
        url = f"{self.base_url}/{entity}"
        base_params = {
            "$format": "json",
            "$top": 200,
            "$skip": 0,
        }
        if params:
            base_params.update(params)

        results = []
        while True:
            try:
                resp = requests.get(
                    url, auth=self.auth, params=base_params,
                    timeout=30,
                    headers={"Accept": "application/json"},
                )
            except requests.exceptions.ConnectionError as e:
                self._warn(f"Cannot connect to {self.api_host}: {e}")
                return []
            except requests.exceptions.Timeout:
                self._warn(f"Timeout fetching {entity}")
                return []

            if resp.status_code == 401:
                self._warn("Authentication failed — check username, company ID, and password.")
                return []
            if resp.status_code == 403:
                self._warn(
                    f"Access denied to '{entity}' — ensure the service user has "
                    "the required OData API Permission in Manage Permission Roles."
                )
                return []
            if resp.status_code == 404:
                self._vprint(f"  [skip] Entity '{entity}' not found (module may not be enabled).")
                return []
            if resp.status_code != 200:
                self._warn(f"Unexpected {resp.status_code} for '{entity}': {resp.text[:200]}")
                return []

            try:
                body = resp.json()
            except ValueError:
                self._warn(f"Non-JSON response from '{entity}'")
                return []

            # OData v2 wraps results in d.results or d
            d = body.get("d", {})
            if isinstance(d, dict):
                page = d.get("results", [])
                # If single record (no results array), wrap it
                if not isinstance(page, list):
                    page = [d]
            elif isinstance(d, list):
                page = d
            else:
                page = []

            results.extend(page)

            # SAP OData pagination: __next link signals more pages
            if "__next" not in body.get("d", {}) and len(page) < base_params["$top"]:
                break
            if len(page) < base_params["$top"]:
                break
            base_params["$skip"] += base_params["$top"]

        self._vprint(f"  [api] {entity}: {len(results)} record(s)")
        return results

    def _api_get_single(self, entity: str, params: dict = None) -> dict:
        """Fetch a single record (first result) from an OData entity."""
        results = self._api_get(entity, params)
        return results[0] if results else {}

    # ----------------------------------------------------------
    # Password Policy Checks
    # ----------------------------------------------------------
    def _check_password_policy(self):
        self._vprint("  [check] Password policy …")
        policy = self._api_get_single(self.ENTITY_PASSWORD_POLICY)
        if not policy:
            self._add(Finding(
                rule_id="SF-PWD-000",
                name="Password Policy entity not accessible",
                category="Password Policy",
                severity="MEDIUM",
                file_path=self.ENTITY_PASSWORD_POLICY,
                line_num=None,
                line_content="GET /odata/v2/PasswordPolicy → no data",
                description=(
                    "The PasswordPolicy OData entity could not be retrieved. "
                    "This may indicate missing OData API permissions for the scanning "
                    "account, or that password policy is not configured."
                ),
                recommendation=(
                    "Grant the scanning user 'OData API Access' under Manage Permission Roles "
                    "> Administrator Permissions > Manage Security."
                ),
                cwe="CWE-16",
            ))
            return

        for rule in PASSWORD_POLICY_RULES:
            field = rule["field"]
            raw = policy.get(field)
            if raw is None:
                continue  # Field not present in response — skip
            if not self._evaluate_pw_rule(rule, raw):
                display = f"{field} = {raw!r}"
                self._add(Finding(
                    rule_id=rule["id"],
                    name=rule["name"],
                    category=rule["category"],
                    severity=rule["severity"],
                    file_path=self.ENTITY_PASSWORD_POLICY,
                    line_num=None,
                    line_content=display,
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                    cwe=rule.get("cwe", ""),
                ))

    def _evaluate_pw_rule(self, rule: dict, raw_value) -> bool:
        """Return True if value passes the rule (no finding). False → finding needed."""
        op = rule["operator"]
        try:
            v_int = int(raw_value)
        except (ValueError, TypeError):
            v_int = None
        v_bool = str(raw_value).lower() in ("true", "yes", "1")

        if op == "eq_true":
            return v_bool
        if op == "eq_false":
            return str(raw_value).lower() in ("false", "no", "0")
        if op == "gte_int":
            return v_int is not None and v_int >= rule["threshold"]
        if op == "lte_int":
            return v_int is not None and v_int <= rule["threshold"]
        if op == "non_zero":
            return v_int is not None and v_int != 0
        if op == "lte_days":
            # 0 = never expires (already caught by non_zero) → pass here
            if v_int == 0:
                return True
            return v_int is not None and v_int <= rule["threshold"]
        return True  # unknown operator → pass

    # ----------------------------------------------------------
    # User Management Checks
    # ----------------------------------------------------------
    def _check_users(self):
        self._vprint("  [check] User accounts …")

        # 1. Super-admin user count
        super_admins = self._api_get(self.ENTITY_USER, {
            "$filter": "isSuperAdmin eq 'true' and status eq 'active'",
            "$select": "userId,username,email,lastLoginDate,isSuperAdmin",
            "$top": 500,
        })
        if len(super_admins) > 5:
            sample = ", ".join(u.get("username", u.get("userId", "?")) for u in super_admins[:5])
            suffix = f" (+{len(super_admins)-5} more)" if len(super_admins) > 5 else ""
            self._add(Finding(
                rule_id="SF-USER-001",
                name=f"Too many active super-admin users ({len(super_admins)})",
                category="User Management",
                severity="HIGH",
                file_path=self.ENTITY_USER,
                line_num=None,
                line_content=f"Super admins: {sample}{suffix}",
                description=(
                    f"{len(super_admins)} active user accounts have super-admin privileges. "
                    "Super admins can access all employee data (including payroll, national IDs, "
                    "and performance reviews) and modify any system configuration. Excessive "
                    "super-admin accounts significantly increase the blast radius of a compromise."
                ),
                recommendation=(
                    "Reduce super-admin count to 3-5 named individuals with documented "
                    "business justification. Use Manage Permission Roles to grant granular "
                    "permissions instead of super-admin for day-to-day tasks."
                ),
                cwe="CWE-269",
            ))

        # 2. Super admins who have never logged in
        never_logged_in_admins = [
            u for u in super_admins
            if not u.get("lastLoginDate") or u.get("lastLoginDate") == "null"
        ]
        if never_logged_in_admins:
            sample = ", ".join(
                u.get("username", u.get("userId", "?")) for u in never_logged_in_admins[:5]
            )
            self._add(Finding(
                rule_id="SF-USER-002",
                name=f"Super-admin accounts that have never logged in ({len(never_logged_in_admins)})",
                category="User Management",
                severity="HIGH",
                file_path=self.ENTITY_USER,
                line_num=None,
                line_content=f"Never-logged-in super admins: {sample}",
                description=(
                    "Super-admin accounts that have never been used may be stale provisioning "
                    "artefacts, test accounts, or orphaned service accounts. They represent "
                    "dormant high-privilege access vectors that may be compromised without detection."
                ),
                recommendation=(
                    "Disable or delete super-admin accounts that have never logged in. "
                    "If they are integration accounts, replace super-admin with least-privilege roles."
                ),
                cwe="CWE-269",
            ))

        # 3. Active users inactive > 90 days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S")
        stale_users = self._api_get(self.ENTITY_USER, {
            "$filter": f"status eq 'active' and lastLoginDate lt datetimeoffset'{cutoff}'",
            "$select": "userId,username,lastLoginDate,department",
            "$top": 500,
        })
        if stale_users:
            sample = ", ".join(u.get("username", u.get("userId", "?")) for u in stale_users[:5])
            suffix = f" (+{len(stale_users)-5} more)" if len(stale_users) > 5 else ""
            self._add(Finding(
                rule_id="SF-USER-003",
                name=f"Active accounts inactive for >90 days ({len(stale_users)} found)",
                category="User Management",
                severity="MEDIUM",
                file_path=self.ENTITY_USER,
                line_num=None,
                line_content=f"Stale users: {sample}{suffix}",
                description=(
                    f"{len(stale_users)} active accounts have not logged in for over 90 days. "
                    "These may belong to former employees, contractors, or seasonal workers "
                    "who still have access to HR records, payroll data, and personal information."
                ),
                recommendation=(
                    "Implement an automated lifecycle management process: deactivate accounts "
                    "inactive for 90 days and terminate employment records. Integrate with your "
                    "HRIS to trigger deactivation on contract end or resignation."
                ),
                cwe="CWE-613",
            ))

        # 4. Integration / service users with super-admin
        service_user_patterns = re.compile(
            r"(svc|service|api|int|integration|system|bot|auto|sftp|mulesoft|boomi|workato|middleware)",
            re.IGNORECASE,
        )
        svc_super_admins = [
            u for u in super_admins
            if service_user_patterns.search(u.get("username", "") or u.get("userId", ""))
        ]
        if svc_super_admins:
            sample = ", ".join(
                u.get("username", u.get("userId", "?")) for u in svc_super_admins[:5]
            )
            self._add(Finding(
                rule_id="SF-USER-004",
                name=f"Integration/service accounts with super-admin role ({len(svc_super_admins)})",
                category="User Management",
                severity="CRITICAL",
                file_path=self.ENTITY_USER,
                line_num=None,
                line_content=f"Service super-admins: {sample}",
                description=(
                    "Integration and service accounts should never hold super-admin privileges. "
                    "A leaked API key or credential for a super-admin service account gives "
                    "unrestricted access to all SuccessFactors data and configuration — including "
                    "payroll, bank details, and national IDs for all employees."
                ),
                recommendation=(
                    "Replace super-admin with the minimum required OData entity permissions "
                    "for each integration. Use dedicated Permission Roles with only the "
                    "entities and operations (read/write) needed by the integration."
                ),
                cwe="CWE-269",
            ))

        # 5. Users with isSuperAdmin and no division/department (orphan accounts)
        orphan_admins = [
            u for u in super_admins
            if not u.get("division") and not u.get("department")
            and not service_user_patterns.search(u.get("username", "") or u.get("userId", ""))
        ]
        if orphan_admins:
            sample = ", ".join(
                u.get("username", u.get("userId", "?")) for u in orphan_admins[:5]
            )
            self._add(Finding(
                rule_id="SF-USER-005",
                name=f"Super-admin accounts with no division/department ({len(orphan_admins)})",
                category="User Management",
                severity="MEDIUM",
                file_path=self.ENTITY_USER,
                line_num=None,
                line_content=f"Unclassified super admins: {sample}",
                description=(
                    "Super-admin accounts not assigned to any division or department are "
                    "difficult to trace to a business owner, making access reviews harder "
                    "and orphaned accounts more likely to remain undetected."
                ),
                recommendation=(
                    "Assign every super-admin account to a department and primary manager. "
                    "This enables quarterly access reviews and automated offboarding."
                ),
                cwe="CWE-269",
            ))

    # ----------------------------------------------------------
    # Permission Role Checks
    # ----------------------------------------------------------
    def _check_permission_roles(self):
        self._vprint("  [check] Permission roles …")

        roles = self._api_get(self.ENTITY_PERMISSION_ROLE, {
            "$select": "roleName,roleDesc,permissionCategory",
            "$top": 200,
        })
        if not roles:
            return

        # SF-ROLE-001: Roles named "All Employees" or with universal access patterns
        broad_roles = [
            r for r in roles
            if re.search(r"\ball\b|\beveryone\b|\bunrestricted\b|\bglobal\b",
                         (r.get("roleName") or ""), re.IGNORECASE)
        ]
        if broad_roles:
            sample = ", ".join(r.get("roleName", "?") for r in broad_roles[:5])
            self._add(Finding(
                rule_id="SF-ROLE-001",
                name=f"Broadly-scoped permission roles detected ({len(broad_roles)})",
                category="Permission Roles",
                severity="MEDIUM",
                file_path=self.ENTITY_PERMISSION_ROLE,
                line_num=None,
                line_content=f"Broad roles: {sample}",
                description=(
                    "Permission roles with names suggesting universal access (e.g., 'All', "
                    "'Everyone', 'Global') may grant more access than intended, violating "
                    "the principle of least privilege and enabling excessive data access."
                ),
                recommendation=(
                    "Review these roles in Manage Permission Roles. Ensure they grant only "
                    "the minimum permissions required and use role-based target populations "
                    "rather than 'All' employee populations."
                ),
                cwe="CWE-269",
            ))

        # SF-ROLE-002: Too many permission roles overall (complexity = governance risk)
        if len(roles) > 50:
            self._add(Finding(
                rule_id="SF-ROLE-002",
                name=f"High number of permission roles ({len(roles)}) — governance risk",
                category="Permission Roles",
                severity="LOW",
                file_path=self.ENTITY_PERMISSION_ROLE,
                line_num=None,
                line_content=f"Total permission roles = {len(roles)}",
                description=(
                    f"{len(roles)} permission roles are defined. A large number of roles "
                    "makes it very difficult to perform access reviews, detect role "
                    "creep, and understand who has access to what data."
                ),
                recommendation=(
                    "Audit and consolidate permission roles. Aim for role definitions based "
                    "on job functions rather than individuals. Use the 'Who Can Access What' "
                    "report in SuccessFactors to identify overlapping or redundant roles."
                ),
                cwe="CWE-269",
            ))

    # ----------------------------------------------------------
    # SSO and Authentication Checks
    # ----------------------------------------------------------
    def _check_sso_and_auth(self):
        self._vprint("  [check] SSO and authentication …")

        company_info = self._api_get_single(self.ENTITY_COMPANY_INFO, {
            "$select": (
                "company,ssoEnabled,mfaEnabled,passwordlessEnabled,"
                "sessionTimeout,concurrentLoginEnabled,ipRestrictionEnabled,"
                "selfRegistrationEnabled"
            ),
        })
        if not company_info:
            self._vprint("  [skip] CompanyInfo entity not accessible — skipping SSO checks.")
            return

        # SF-AUTH-001: SSO not enabled
        sso_enabled = str(company_info.get("ssoEnabled", "false")).lower()
        if sso_enabled not in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-AUTH-001",
                name="SSO (Single Sign-On) not enabled",
                category="Authentication: SSO",
                severity="HIGH",
                file_path=self.ENTITY_COMPANY_INFO,
                line_num=None,
                line_content="ssoEnabled = false",
                description=(
                    "Without SSO, SuccessFactors users authenticate with local passwords "
                    "that bypass your organisation's MFA policies, conditional access rules, "
                    "and identity governance controls. HR data including payroll and "
                    "personal records is accessible without enterprise-grade authentication."
                ),
                recommendation=(
                    "Configure SAML 2.0 or OIDC SSO via your Identity Provider (Okta, "
                    "Azure AD, PingFederate, etc.) in Provisioning > Security Settings. "
                    "Enforce SSO and disable fallback local authentication for non-admin accounts."
                ),
                cwe="CWE-287",
            ))

        # SF-AUTH-002: MFA not enabled
        mfa_enabled = str(company_info.get("mfaEnabled", "false")).lower()
        if mfa_enabled not in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-AUTH-002",
                name="Multi-factor authentication (MFA) not enabled",
                category="Authentication: MFA",
                severity="HIGH",
                file_path=self.ENTITY_COMPANY_INFO,
                line_num=None,
                line_content="mfaEnabled = false",
                description=(
                    "Without MFA, a stolen or phished password alone grants full access to "
                    "employee HR records, payroll data, national IDs, performance reviews, "
                    "and compensation information for potentially thousands of employees."
                ),
                recommendation=(
                    "Enable MFA for all users, prioritising administrators and HR staff. "
                    "Configure MFA via your IdP (preferred) or SAP SuccessFactors native MFA. "
                    "Enforce step-up authentication for payroll and sensitive data exports."
                ),
                cwe="CWE-308",
            ))

        # SF-AUTH-003: Self-registration enabled (users can create their own accounts)
        self_reg = str(company_info.get("selfRegistrationEnabled", "false")).lower()
        if self_reg in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-AUTH-003",
                name="Self-registration of user accounts is enabled",
                category="Authentication: Account Creation",
                severity="HIGH",
                file_path=self.ENTITY_COMPANY_INFO,
                line_num=None,
                line_content="selfRegistrationEnabled = true",
                description=(
                    "When self-registration is enabled, anyone with internet access can "
                    "create an account in your SuccessFactors instance. This could expose "
                    "the system to unauthorized access, phishing campaigns, or social "
                    "engineering against HR staff."
                ),
                recommendation=(
                    "Disable self-registration unless it is required for a specific onboarding "
                    "workflow. Use HR-driven provisioning linked to your HRIS system instead."
                ),
                cwe="CWE-287",
            ))

        # SF-AUTH-004: IP restriction not enabled
        ip_restrict = str(company_info.get("ipRestrictionEnabled", "false")).lower()
        if ip_restrict not in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-AUTH-004",
                name="IP-based access restriction not enabled",
                category="Authentication: Network Controls",
                severity="MEDIUM",
                file_path=self.ENTITY_COMPANY_INFO,
                line_num=None,
                line_content="ipRestrictionEnabled = false",
                description=(
                    "Without IP allowlisting, SuccessFactors is accessible from any internet "
                    "address. This makes credential-stuffing attacks and access from "
                    "unexpected geographies (indicators of compromise) harder to block."
                ),
                recommendation=(
                    "Enable IP allowlisting via Admin Center > Security Center > Login Options "
                    "and restrict access to your corporate IP ranges and VPN egress IPs. "
                    "For admin users, enforce VPN usage before accessing SuccessFactors."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # Session Management Checks
    # ----------------------------------------------------------
    def _check_session_management(self):
        self._vprint("  [check] Session management …")

        company_info = self._api_get_single(self.ENTITY_COMPANY_INFO, {
            "$select": "sessionTimeout,concurrentLoginEnabled",
        })
        if not company_info:
            return

        # SF-SESS-001: Session timeout > 30 minutes or not set
        session_timeout = company_info.get("sessionTimeout")
        if session_timeout is not None:
            try:
                st = int(session_timeout)
                if st == 0 or st > 30:
                    label = "not set (unlimited)" if st == 0 else f"{st} minutes"
                    self._add(Finding(
                        rule_id="SF-SESS-001",
                        name=f"Session timeout too long or disabled ({label})",
                        category="Session Management",
                        severity="HIGH",
                        file_path=self.ENTITY_COMPANY_INFO,
                        line_num=None,
                        line_content=f"sessionTimeout = {session_timeout}",
                        description=(
                            f"A session timeout of {label} keeps authenticated sessions "
                            "alive too long, increasing risk of session hijacking from "
                            "unattended workstations and stolen session tokens."
                        ),
                        recommendation=(
                            "Set sessionTimeout to 30 minutes or less via "
                            "Admin Center > Security Center > Login Options. "
                            "For HR admin accounts, consider 15 minutes."
                        ),
                        cwe="CWE-613",
                    ))
            except (ValueError, TypeError):
                pass
        else:
            self._add(Finding(
                rule_id="SF-SESS-001",
                name="Session timeout not configured",
                category="Session Management",
                severity="HIGH",
                file_path=self.ENTITY_COMPANY_INFO,
                line_num=None,
                line_content="sessionTimeout = <not set>",
                description=(
                    "No session timeout is configured, meaning authenticated sessions "
                    "remain valid indefinitely until the user explicitly logs out."
                ),
                recommendation="Set sessionTimeout to 30 minutes in Admin Center > Security Center > Login Options.",
                cwe="CWE-613",
            ))

        # SF-SESS-002: Concurrent logins allowed
        concurrent = str(company_info.get("concurrentLoginEnabled", "true")).lower()
        if concurrent in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-SESS-002",
                name="Concurrent logins from multiple sessions are permitted",
                category="Session Management",
                severity="LOW",
                file_path=self.ENTITY_COMPANY_INFO,
                line_num=None,
                line_content="concurrentLoginEnabled = true",
                description=(
                    "Allowing concurrent sessions means the same account can be logged in "
                    "from multiple locations simultaneously. This makes it harder to detect "
                    "account sharing or a compromised session being used in parallel with "
                    "a legitimate one."
                ),
                recommendation=(
                    "Disable concurrent logins and terminate the previous session when a "
                    "new login occurs. Configure alerts for simultaneous login attempts "
                    "from different IP addresses."
                ),
                cwe="CWE-613",
            ))

    # ----------------------------------------------------------
    # Audit Logging Checks
    # ----------------------------------------------------------
    def _check_audit_logging(self):
        self._vprint("  [check] Audit logging …")

        # SF-LOG-001: Check if audit is enabled via AuditConfiguration entity
        audit_config = self._api_get_single(self.ENTITY_AUDIT, {
            "$select": "auditEnabled,retentionPeriod,auditForAdmin,auditForData",
        })

        if not audit_config:
            self._add(Finding(
                rule_id="SF-LOG-001",
                name="Audit configuration not accessible or not configured",
                category="Audit Logging",
                severity="HIGH",
                file_path=self.ENTITY_AUDIT,
                line_num=None,
                line_content="GET /odata/v2/AuditConfiguration → no data",
                description=(
                    "The AuditConfiguration entity could not be retrieved. "
                    "Without audit logging, there is no record of who accessed "
                    "sensitive HR data, what changes were made, or when. "
                    "This prevents incident investigation and compliance reporting."
                ),
                recommendation=(
                    "Enable audit logging via Admin Center > Audit Logging. "
                    "Ensure admin actions, data access, and configuration changes are all audited. "
                    "Configure a minimum retention period of 365 days for compliance."
                ),
                cwe="CWE-778",
            ))
            return

        audit_enabled = str(audit_config.get("auditEnabled", "false")).lower()
        if audit_enabled not in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-LOG-001",
                name="Audit logging is disabled",
                category="Audit Logging",
                severity="HIGH",
                file_path=self.ENTITY_AUDIT,
                line_num=None,
                line_content="auditEnabled = false",
                description=(
                    "Audit logging is disabled. There is no record of who accessed "
                    "sensitive HR data, what configuration changes were made, or when. "
                    "This eliminates the ability to detect breaches, investigate incidents, "
                    "or demonstrate compliance with GDPR, SOX, and HIPAA."
                ),
                recommendation=(
                    "Enable audit logging in Admin Center > Audit Logging. "
                    "Ensure at minimum: admin actions, personal data access, and "
                    "configuration changes are captured."
                ),
                cwe="CWE-778",
            ))

        # SF-LOG-002: Retention period < 90 days
        retention = audit_config.get("retentionPeriod")
        if retention is not None:
            try:
                days = int(retention)
                if days < 90:
                    self._add(Finding(
                        rule_id="SF-LOG-002",
                        name=f"Audit log retention too short ({days} days)",
                        category="Audit Logging",
                        severity="MEDIUM",
                        file_path=self.ENTITY_AUDIT,
                        line_num=None,
                        line_content=f"retentionPeriod = {days} days",
                        description=(
                            f"Audit logs are retained for only {days} day(s). "
                            "Security incidents are often discovered weeks or months after "
                            "they occur. Short retention periods limit forensic investigations "
                            "and violate data retention requirements under GDPR and SOX."
                        ),
                        recommendation=(
                            "Set retentionPeriod to at least 365 days. "
                            "For regulated industries, consider 7 years (SOX). "
                            "Export logs to an immutable SIEM or cold storage for long-term retention."
                        ),
                        cwe="CWE-778",
                    ))
            except (ValueError, TypeError):
                pass

        # SF-LOG-003: Admin action auditing not enabled
        admin_audit = str(audit_config.get("auditForAdmin", "false")).lower()
        if admin_audit not in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-LOG-003",
                name="Admin action auditing not enabled",
                category="Audit Logging",
                severity="HIGH",
                file_path=self.ENTITY_AUDIT,
                line_num=None,
                line_content="auditForAdmin = false",
                description=(
                    "Administrator actions (configuration changes, role assignments, "
                    "data exports) are not being audited. Admin-level changes are the "
                    "highest-risk actions in the system and should always be logged."
                ),
                recommendation=(
                    "Enable auditForAdmin in Audit Logging settings. "
                    "Configure real-time alerts for critical admin actions such as "
                    "permission changes and bulk data exports."
                ),
                cwe="CWE-778",
            ))

        # SF-LOG-004: Data access auditing not enabled
        data_audit = str(audit_config.get("auditForData", "false")).lower()
        if data_audit not in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SF-LOG-004",
                name="Personal data access auditing not enabled",
                category="Audit Logging",
                severity="MEDIUM",
                file_path=self.ENTITY_AUDIT,
                line_num=None,
                line_content="auditForData = false",
                description=(
                    "Access to personal data (names, salaries, national IDs, bank details) "
                    "is not being audited. Without data access logs, it is impossible to "
                    "detect insider threats, identify over-privileged access, or respond "
                    "to GDPR Subject Access Requests with full access history."
                ),
                recommendation=(
                    "Enable auditForData in Audit Logging settings. "
                    "Configure alerts for bulk data access (e.g., downloading >50 records) "
                    "and access to sensitive fields from unexpected roles."
                ),
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # Data Privacy / GDPR Checks
    # ----------------------------------------------------------
    def _check_data_privacy(self):
        self._vprint("  [check] Data privacy and GDPR …")

        # SF-PRIV-001: Check for data purge/retention jobs
        # SAP SF exposes purge jobs via Admin Center — check via ConfigurationCenter entity
        purge_jobs = self._api_get("PersonalDataPurgeJob", {
            "$filter": "isEnabled eq 'true'",
            "$select": "jobName,isEnabled,retentionPeriod",
            "$top": 50,
        })
        if not purge_jobs:
            self._add(Finding(
                rule_id="SF-PRIV-001",
                name="No active GDPR personal data purge job configured",
                category="Data Privacy: GDPR",
                severity="MEDIUM",
                file_path="PersonalDataPurgeJob",
                line_num=None,
                line_content="active purge jobs = 0",
                description=(
                    "No personal data purge jobs are active. Under GDPR Article 17 "
                    "(Right to Erasure), organisations must be able to delete personal "
                    "data on request and must not retain it beyond its lawful purpose. "
                    "Without purge jobs, terminated employee data accumulates indefinitely."
                ),
                recommendation=(
                    "Configure Personal Data Purge Jobs in Admin Center > Data Retention "
                    "Management. Define retention periods per data category aligned with "
                    "your organisation's GDPR data retention policy."
                ),
                cwe="CWE-212",
            ))

        # SF-PRIV-002: Sensitive field masking — check if National ID is masked
        # Approximate check via PicklistValue or field definitions
        # This is a best-effort check; full field masking config requires UI access
        self._add(Finding(
            rule_id="SF-PRIV-002",
            name="Verify: National ID / Tax ID field masking configuration",
            category="Data Privacy: Sensitive Fields",
            severity="MEDIUM",
            file_path="FieldDefinition",
            line_num=None,
            line_content="Field: nationalId / taxId — masking status: manual verification required",
            description=(
                "National IDs, Tax IDs, and Social Security Numbers stored in SuccessFactors "
                "should be masked so that only authorised HR roles can see the full value. "
                "This check requires manual verification in Admin Center > Manage Business "
                "Configuration > Personal Information as automated API access to field masking "
                "settings is limited."
            ),
            recommendation=(
                "In Admin Center > Configure Object Definitions, enable field-level masking "
                "for nationalId, taxId, bankAccountNumber, and iban fields. "
                "Restrict full-value access to payroll and HR admin roles only. "
                "Enable 'Who Can Access What' reporting to audit who has seen these fields."
            ),
            cwe="CWE-312",
        ))

        # SF-PRIV-003: Check for consent management configuration
        consent_config = self._api_get("ConsentManagementConfig", {
            "$select": "isEnabled,consentType",
            "$top": 10,
        })
        if not consent_config:
            self._add(Finding(
                rule_id="SF-PRIV-003",
                name="Consent management not configured",
                category="Data Privacy: GDPR",
                severity="LOW",
                file_path="ConsentManagementConfig",
                line_num=None,
                line_content="active consent configurations = 0",
                description=(
                    "SuccessFactors Consent Management is not configured. GDPR requires "
                    "explicit consent for processing personal data where no other legal "
                    "basis applies (e.g., for optional data like photos, personal email). "
                    "Without consent management, you cannot demonstrate lawful processing."
                ),
                recommendation=(
                    "Configure Consent Management via Admin Center > Consent Management "
                    "for optional personal data fields. Track and audit consent withdrawal."
                ),
                cwe="CWE-359",
            ))

    # ----------------------------------------------------------
    # Integration Security Checks
    # ----------------------------------------------------------
    def _check_integration_security(self):
        self._vprint("  [check] Integration and API security …")

        # SF-INT-001: OAuth clients with super-admin or broad access
        oauth_clients = self._api_get(self.ENTITY_OAUTH_CLIENT, {
            "$select": "clientId,clientName,enabled,tokenExpiration,allowedScopes",
            "$top": 200,
        })
        if oauth_clients:
            active_clients = [c for c in oauth_clients if str(c.get("enabled", "true")).lower() in ("true", "yes", "1")]

            # Count active clients
            if len(active_clients) > 10:
                self._add(Finding(
                    rule_id="SF-INT-001",
                    name=f"High number of active OAuth API clients ({len(active_clients)})",
                    category="Integration Security",
                    severity="LOW",
                    file_path=self.ENTITY_OAUTH_CLIENT,
                    line_num=None,
                    line_content=f"active OAuth clients = {len(active_clients)}",
                    description=(
                        f"{len(active_clients)} active OAuth clients are registered. "
                        "OAuth client sprawl makes it difficult to track all integrations, "
                        "identify stale or over-privileged clients, and respond quickly "
                        "to a compromised credential."
                    ),
                    recommendation=(
                        "Audit all OAuth clients in Admin Center > OAuth 2.0 Client Management. "
                        "Remove unused or stale clients. Maintain a register of approved integrations."
                    ),
                    cwe="CWE-284",
                ))

            # Check for super-admin scope in clients
            for client in active_clients:
                name = client.get("clientName") or client.get("clientId", "unknown")
                scopes = client.get("allowedScopes", "") or ""
                if re.search(r"admin|super|\*|all", scopes, re.IGNORECASE):
                    self._add(Finding(
                        rule_id="SF-INT-002",
                        name=f"OAuth client '{name}' has admin/wildcard scope",
                        category="Integration Security",
                        severity="HIGH",
                        file_path=self.ENTITY_OAUTH_CLIENT,
                        line_num=None,
                        line_content=f"client = {name}, scopes = {scopes!r}",
                        description=(
                            f"OAuth client '{name}' has admin or wildcard scopes, granting "
                            "it super-admin level access to all SuccessFactors data. "
                            "If the client secret is leaked, an attacker gains unrestricted "
                            "access to all employee records."
                        ),
                        recommendation=(
                            "Reduce scopes to the minimum OData entities required by the "
                            "integration. Rotate the client secret immediately if it may "
                            "have been exposed."
                        ),
                        cwe="CWE-269",
                    ))

                # Check token expiration > 1 hour
                token_exp = client.get("tokenExpiration")
                if token_exp:
                    try:
                        if int(token_exp) > 3600:
                            self._add(Finding(
                                rule_id="SF-INT-003",
                                name=f"OAuth client '{name}' token lifetime exceeds 1 hour",
                                category="Integration Security",
                                severity="MEDIUM",
                                file_path=self.ENTITY_OAUTH_CLIENT,
                                line_num=None,
                                line_content=f"client = {name}, tokenExpiration = {token_exp}s",
                                description=(
                                    f"Access tokens for '{name}' are valid for "
                                    f"{int(token_exp)//3600}h {(int(token_exp)%3600)//60}m. "
                                    "Long-lived tokens extend the window for a stolen token "
                                    "to be replayed."
                                ),
                                recommendation=(
                                    "Set tokenExpiration to 3600 seconds (1 hour) or less. "
                                    "Use refresh tokens with rotation for long-running integrations."
                                ),
                                cwe="CWE-613",
                            ))
                    except (ValueError, TypeError):
                        pass

        # SF-INT-004: Integration Center — check for outbound http (non-https) integrations
        int_flows = self._api_get("IntegrationFlowDesign", {
            "$filter": "type eq 'Outbound'",
            "$select": "flowName,targetEndpoint,isActive",
            "$top": 100,
        })
        http_flows = [
            f for f in int_flows
            if str(f.get("targetEndpoint", "")).startswith("http://")
            and str(f.get("isActive", "false")).lower() in ("true", "yes", "1")
        ]
        if http_flows:
            sample = ", ".join(f.get("flowName", "?") for f in http_flows[:5])
            self._add(Finding(
                rule_id="SF-INT-004",
                name=f"Integration flows using plain HTTP endpoints ({len(http_flows)})",
                category="Integration Security",
                severity="HIGH",
                file_path="IntegrationFlowDesign",
                line_num=None,
                line_content=f"HTTP outbound flows: {sample}",
                description=(
                    f"{len(http_flows)} active outbound integration flows transmit data "
                    "to endpoints over plain HTTP (not HTTPS). Employee data sent to "
                    "partner systems (payroll, benefits, directories) is transmitted "
                    "in cleartext, vulnerable to network interception."
                ),
                recommendation=(
                    "Update all integration target endpoints to HTTPS. "
                    "Validate TLS certificate of target endpoints. "
                    "Enable mTLS (mutual TLS) for highly sensitive payroll integrations."
                ),
                cwe="CWE-319",
            ))

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _add(self, finding: Finding):
        self.findings.append(finding)

    def _vprint(self, msg: str):
        if self.verbose:
            print(msg)

    def _warn(self, msg: str):
        print(f"  [!] {msg}", file=sys.stderr)

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    def summary(self) -> dict:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str):
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'='*72}{R}")
        print(f"{B}  SAP SuccessFactors SSPM Scanner v{VERSION}  --  Scan Report{R}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Instance  : https://{self.api_host}")
        print(f"  Company   : {self.company_id}")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        for f in sorted_findings:
            sev_color = self.SEVERITY_COLOR.get(f.severity, "")
            print(f"{sev_color}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Entity   : {f.file_path}")
            print(f"  Context  : {f.line_content}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 72)
        for sev, _ in sorted(self.SEVERITY_ORDER.items(), key=lambda x: x[1]):
            color = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 72)

    def save_json(self, path: str):
        report = {
            "scanner": "successfactors_scanner",
            "version": VERSION,
            "generated": datetime.now().isoformat(),
            "instance": f"https://{self.api_host}",
            "company_id": self.company_id,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report saved to: {os.path.abspath(path)}")

    def save_html(self, path: str):
        esc = html_mod.escape
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = self.summary()

        sev_style = {
            "CRITICAL": "background:#c0392b;color:#fff",
            "HIGH":     "background:#e67e22;color:#fff",
            "MEDIUM":   "background:#2980b9;color:#fff",
            "LOW":      "background:#27ae60;color:#fff",
        }
        row_style = {
            "CRITICAL": "border-left:4px solid #c0392b",
            "HIGH":     "border-left:4px solid #e67e22",
            "MEDIUM":   "border-left:4px solid #2980b9",
            "LOW":      "border-left:4px solid #27ae60",
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        rows_html = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rs = row_style.get(f.severity, "")
            st = sev_style.get(f.severity, "")
            rows_html += (
                f'<tr style="background:{bg};{rs}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px">'
                f'<span style="{st};padding:3px 10px;border-radius:10px;font-size:0.8em;font-weight:bold">'
                f'{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.9em">'
                f'{esc(f.rule_id)}</td>'
                f'<td style="padding:10px 14px;color:#a9b1d6">{esc(f.category)}</td>'
                f'<td style="padding:10px 14px;font-weight:bold;color:#cdd6f4">{esc(f.name)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.85em;color:#89b4fa">'
                f'{esc(f.file_path)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.82em;color:#a6e3a1">'
                f'{esc(f.line_content or "")}</td>'
                f'<td style="padding:10px 14px;color:#cdd6f4">{esc(f.cwe)}</td>'
                f'</tr>'
                f'<tr style="background:{bg}" data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td colspan="7" style="padding:6px 14px 14px 14px">'
                f'<div style="color:#bac2de;font-size:0.88em;margin-bottom:4px">'
                f'<b>Issue:</b> {esc(f.description)}</div>'
                f'<div style="color:#89dceb;font-size:0.88em">'
                f'<b>Fix:</b> {esc(f.recommendation)}</div>'
                f'</td></tr>'
            )

        categories = sorted({f.category for f in self.findings})
        cat_options = "".join(
            f'<option value="{esc(c)}">{esc(c)}</option>' for c in categories
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP SuccessFactors SSPM Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1b2e; color: #cdd6f4; min-height: 100vh; }}
  header {{ background: linear-gradient(135deg,#1a3a5c,#2d4a1e); padding: 28px 36px; border-bottom: 2px solid #313244; }}
  header h1 {{ font-size: 1.7em; font-weight: 700; color: #89dceb; margin-bottom: 8px; }}
  header p {{ color: #a6adc8; font-size: 0.95em; margin: 2px 0; }}
  .chips {{ padding: 20px 36px; background: #181825; border-bottom: 1px solid #313244; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .chips label {{ color: #a6adc8; font-size: 0.9em; margin-right: 6px; }}
  .filters {{ padding: 16px 36px; background: #1e1e2e; display: flex; gap: 12px; flex-wrap: wrap; border-bottom: 1px solid #313244; }}
  .filters select, .filters input {{ background: #313244; color: #cdd6f4; border: 1px solid #45475a; border-radius: 6px; padding: 6px 12px; font-size: 0.9em; }}
  .container {{ padding: 20px 36px 40px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  th {{ background: #313244; color: #89dceb; padding: 12px 14px; text-align: left; font-weight: 600; position: sticky; top: 0; }}
  tr:hover td {{ filter: brightness(1.12); }}
  td {{ vertical-align: top; }}
  .no-findings {{ text-align: center; padding: 60px; color: #a6e3a1; font-size: 1.2em; }}
</style>
</head>
<body>
<header>
  <h1>SAP SuccessFactors SSPM Scan Report</h1>
  <p>Scanner: SAP SuccessFactors SSPM Scanner v{esc(VERSION)}</p>
  <p>Instance: https://{esc(self.api_host)}</p>
  <p>Company ID: {esc(self.company_id)}</p>
  <p>Generated: {esc(now)}</p>
  <p>Total Findings: <strong>{len(self.findings)}</strong></p>
</header>
<div class="chips">
  <label>Severity:</label>
  {chip_html}
</div>
<div class="filters">
  <select id="sevFilter" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option value="CRITICAL">CRITICAL</option>
    <option value="HIGH">HIGH</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="LOW">LOW</option>
  </select>
  <select id="catFilter" onchange="applyFilters()">
    <option value="">All Categories</option>
    {cat_options}
  </select>
  <input type="text" id="textFilter" placeholder="Search name / rule ID …" oninput="applyFilters()" style="flex:1;min-width:200px">
</div>
<div class="container">
{f'<div class="no-findings">No findings — instance is clean!</div>' if not self.findings else f"""
<table id="findings-table">
<thead><tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th><th>Name</th>
  <th>Entity</th><th>Context</th><th>CWE</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>"""}
</div>
<script>
function applyFilters() {{
  var sev = document.getElementById('sevFilter').value.toUpperCase();
  var cat = document.getElementById('catFilter').value.toLowerCase();
  var txt = document.getElementById('textFilter').value.toLowerCase();
  var rows = document.querySelectorAll('#findings-table tbody tr');
  rows.forEach(function(row) {{
    var rs = (row.getAttribute('data-severity') || '').toUpperCase();
    var rc = (row.getAttribute('data-category') || '').toLowerCase();
    var rt = row.textContent.toLowerCase();
    var show = (!sev || rs === sev) && (!cat || rc.includes(cat)) && (!txt || rt.includes(txt));
    row.style.display = show ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] HTML report saved to: {os.path.abspath(path)}")


# ============================================================
# CLI entry point
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        prog="successfactors_scanner",
        description=(
            f"SAP SuccessFactors SSPM Scanner v{VERSION} — "
            "SaaS Security Posture Management checks via OData REST API"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Data-center API hosts:\n"
            "  US (DC1)     : api4.successfactors.com\n"
            "  EU (DC2)     : apisalesdemo2.successfactors.eu\n"
            "  US2 (DC4)    : api8.successfactors.com\n"
            "  APAC (DC10)  : api10.successfactors.com\n"
            "  Canada (DC12): api12.successfactors.com\n\n"
            "Environment variables: SF_API_HOST  SF_COMPANY_ID  SF_USERNAME  SF_PASSWORD"
        ),
    )
    parser.add_argument(
        "--api-host",
        default=os.environ.get("SF_API_HOST", ""),
        metavar="HOST",
        help=(
            "SAP SuccessFactors API host (e.g. api4.successfactors.com). "
            "Env: SF_API_HOST"
        ),
    )
    parser.add_argument(
        "--company-id",
        default=os.environ.get("SF_COMPANY_ID", ""),
        metavar="COMPANY_ID",
        help="SAP SuccessFactors company/tenant ID. Env: SF_COMPANY_ID",
    )
    parser.add_argument(
        "--username", "-u",
        default=os.environ.get("SF_USERNAME", ""),
        metavar="USERNAME",
        help=(
            "Service user username (will be combined with company ID as "
            "username@companyId for Basic Auth). Env: SF_USERNAME"
        ),
    )
    parser.add_argument(
        "--password", "-p",
        default=os.environ.get("SF_PASSWORD", ""),
        metavar="PASSWORD",
        help="Service user password. Env: SF_PASSWORD",
    )
    parser.add_argument(
        "--severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save findings as JSON to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save findings as a self-contained HTML report to FILE",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (API calls, skipped entities, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"successfactors_scanner v{VERSION}",
    )

    args = parser.parse_args()

    # Requests check after parse_args so --version/--help work without requests
    if not HAS_REQUESTS:
        parser.error(
            "The 'requests' library is required.\n"
            "  Install with:  pip install requests"
        )

    # Validate required credentials
    missing = []
    if not args.api_host:
        missing.append("--api-host (or SF_API_HOST env var)")
    if not args.company_id:
        missing.append("--company-id (or SF_COMPANY_ID env var)")
    if not args.username:
        missing.append("--username (or SF_USERNAME env var)")
    if not args.password:
        missing.append("--password (or SF_PASSWORD env var)")
    if missing:
        parser.error("Missing required arguments:\n  " + "\n  ".join(missing))

    scanner = SuccessFactorsScanner(
        api_host=args.api_host,
        company_id=args.company_id,
        username=args.username,
        password=args.password,
        verbose=args.verbose,
    )

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()
