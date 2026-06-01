"""Vendor vulnerability standard matcher.
Maps VulnForge findings to vendor-specific tier standards.
Prevents submitting findings that the vendor won't accept.

NOTE: All vendor names are anonymized. Real vendor mapping is done
by the user at report-submission time via the --vendor flag.
"""

# Vendor tier definitions - low severity criteria
# Keys are arbitrary identifiers, not real vendor names.
VENDOR_STANDARDS = {
    "default": {
        "desc": "通用标准",
        "low_accepted": [
            "info_leak_limited",
            "reflected_xss",
            "open_redirect",
            "security_header_missing",
            "cookie_insecure",
            "subdomain_leak",
            "api_route_leak",
        ],
        "medium_accepted": [
            "info_leak_limited",
            "json_hijacking",
            "stored_xss",
            "csrf_sensitive",
            "logic_flaw",
            "design_flaw",
        ],
        "high_accepted": [
            "system_access",
            "severe_info_leak",
            "sql_injection",
            "critical_logic",
            "mobile_app_rce",
            "auth_bypass",
            "local_code_exec",
        ],
    },
    "tier_a": {
        "desc": "A类厂商（严格：低危仅收反射XSS/URL跳转/信息泄露）",
        "low_accepted": [
            "phpinfo_leak",
            "local_sql_injection",
            "log_leak",
            "config_leak",
            "reflected_xss",
            "sms_bomb",
            "open_redirect",
            "credential_stuffing",
        ],
        "medium_accepted": [
            "info_leak_limited",
            "json_hijacking",
            "stored_xss",
            "csrf_sensitive",
            "logic_flaw",
            "design_flaw",
        ],
        "high_accepted": [
            "system_access",
            "severe_info_leak",
            "sql_injection",
            "critical_logic",
            "mobile_app_rce",
            "auth_bypass",
            "local_code_exec",
        ],
    },
    "tier_b": {
        "desc": "B类厂商（宽松：低危收录范围较广）",
        "low_accepted": [
            "info_leak_limited",
            "reflected_xss",
            "open_redirect",
            "security_header_missing",
            "cookie_insecure",
            "subdomain_leak",
            "api_route_leak",
        ],
        "medium_accepted": [
            "stored_xss",
            "csrf",
            "idor",
            "auth_bypass_limited",
        ],
        "high_accepted": [
            "rce",
            "sql_injection",
            "command_injection",
            "arbitrary_file_read",
            "auth_bypass",
        ],
    },
}

# VulnForge category -> vendor-neutral category mapping
CATEGORY_MAP = {
    "api_leak": "api_route_leak",
    "secret_leak": "info_leak_limited",
    "subdomain_leak": "subdomain_leak",
    "security_header": "security_header_missing",
    "cookie_security": "cookie_insecure",
    "cors_misconfig": "config_leak",
    "endpoint_exposure": "info_leak_limited",
    "info_leak": "info_leak_limited",
    "xss_reflected": "reflected_xss",
    "xss_stored": "stored_xss",
    "sql_injection": "sql_injection",
    "command_injection": "command_injection",
    "rce": "rce",
    "deserialization": "system_access",
    "auth_bypass": "auth_bypass",
    "idor": "idor",
    "csrf": "csrf",
    "open_redirect": "open_redirect",
    "sms_bomb": "sms_bomb",
}


def check_submittable(finding: dict, tier: str, severity: str) -> tuple[bool, str]:
    """Check if a finding is submittable based on anonymous tier rules.
    
    Args:
        finding: VulnForge finding dict with 'category' field
        tier: Tier identifier ('default', 'tier_a', 'tier_b')
        severity: Severity level ('high', 'medium', 'low')
    
    Returns:
        (is_submittable: bool, reason: str)
    """
    if tier not in VENDOR_STANDARDS:
        tier = "default"
    
    standard = VENDOR_STANDARDS[tier]
    category = finding.get("category", "")
    
    # Map VulnForge category to vendor-neutral category
    vendor_cat = CATEGORY_MAP.get(category, category)
    
    # Check severity tier
    tier_key = f"{severity}_accepted"
    accepted = standard.get(tier_key, [])
    
    if vendor_cat in accepted:
        return (True, f"Accepted: [{tier}] {severity} tier")
    
    return (False, f"Not accepted: [{tier}] {severity} tier does not cover this category")


def filter_submittable(findings: list[dict], tier: str = "default") -> tuple[list[dict], list[dict]]:
    """Filter findings to only those submittable under the given tier rules.
    
    Returns:
        (submittable: list[dict], rejected: list[dict])
    """
    submittable = []
    rejected = []
    for f in findings:
        sev = f.get("severity", "low")
        ok, reason = check_submittable(f, tier, sev)
        f["vendor_check"] = reason
        if ok:
            submittable.append(f)
        else:
            rejected.append(f)
    return submittable, rejected
