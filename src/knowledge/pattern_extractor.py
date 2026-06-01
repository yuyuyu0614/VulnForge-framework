"""Extract vulnerability patterns from confirmed findings for the knowledge base.

Takes a confirmed finding (+ its hook context) and distills it into a reusable
vulnerability_patterns row that can later be retrieved for similar code.
"""

import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import get_db, Database


def _derive_code_signature(cwe_id: str, snippet: str, language: str) -> str:
    """Generate a regex code signature from the vulnerable snippet and CWE."""
    # Escape for regex but keep structural patterns
    escaped = re.escape(snippet.strip()[:200])
    # Generalize specific variable names to capture groups
    for placeholder in [r"username", r"password", r"user_input", r"query",
                        r"cmd", r"command", r"filepath", r"filename",
                        r"user_id", r"uid", r"id", r"name", r"data"]:
        escaped = escaped.replace(re.escape(placeholder), r"\w+")
    return escaped


def _derive_detection_rule(cwe_id: str, language: str) -> str:
    """Return an AST-level or regex detection rule based on CWE and language."""
    rules = {
        "CWE-89": {
            "python": r'(cursor\.execute|\.raw|\.execute_many)\s*\(\s*(?:f["\']|[^)]*\%[^)]*|[^)]*\+[^)]*)',
            "go":     r'db\.(Query|Exec|QueryRow)\s*\(\s*[^)]*\+[^)]*',
            "default": r'(execute|query|raw)\s*\(\s*(?:f["\']|["\'].*\%|["\'].*\+)',
        },
        "CWE-79": {
            "python": r'(return\s+(?:render_template|HttpResponse|Response)\s*\([^)]*request\.(?:args|form|GET|POST)[^)]*\)|innerHTML\s*=)',
            "default": r'(innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()',
        },
        "CWE-78": {
            "python": r'(os\.(?:system|popen)|subprocess\.(?:call|run|Popen)|commands\.getoutput)\s*\([^)]*',
            "go":     r'exec\.Command\s*\([^)]*',
            "default": r'(system|exec|popen|subprocess)\s*\([^)]*',
        },
        "CWE-22": {
            "python": r'(open|read|write)\s*\([^)]*\+[^)]*(?:request|input|args|form)',
            "default": r'(file|open|read)\s*\([^)]*\.\.\/[^)]*',
        },
        "CWE-862": {
            "python": r'@(?:app|router|blueprint)\.(?:route|get|post)\s*\([^)]*\)\s*\n\s*def\s+\w+',
            "default": r'@(?:route|RequestMapping|Get|Post)(?!.*@Auth)',
        },
    }
    cwe_rules = rules.get(cwe_id, {})
    return cwe_rules.get(language, cwe_rules.get("default", ""))


def extract_pattern(finding: dict, hook: dict | None = None,
                    db: Database | None = None) -> dict | None:
    """Extract a vulnerability pattern from a confirmed finding.

    Args:
        finding: A finding dict with at least: cwe_id, title, description, poc_code
        hook: Optional hook dict with snippet, file_path, func_name, language
        db: Optional database instance (used to look up hook if not provided)

    Returns:
        Pattern dict ready for insert_pattern(), or None if extraction fails.
    """
    db = db or get_db()

    cwe_id = finding.get("cwe_id", finding.get("cwe", ""))
    if not cwe_id or not cwe_id.startswith("CWE-"):
        return None

    # Resolve hook if not provided
    if hook is None:
        hook_id = finding.get("hook_id", "")
        if hook_id:
            hooks = db.list_hooks()
            hook = next((h for h in hooks if h.get("hook_id") == hook_id), None)

    snippet = ""
    language = "unknown"
    if hook:
        snippet = hook.get("snippet", "")
        language = hook.get("language", "unknown")

    if not snippet:
        snippet = finding.get("description", "")[:500]

    pattern_type = _cwe_to_pattern_type(cwe_id)
    code_signature = _derive_code_signature(cwe_id, snippet, language)
    detection_rule = _derive_detection_rule(cwe_id, language)
    fix_snippet = finding.get("description", "")[:800]

    return {
        "pattern_type": pattern_type,
        "cwe_id": cwe_id,
        "code_signature": code_signature,
        "vulnerable_snippet": snippet[:1000],
        "fix_snippet": fix_snippet,
        "detection_rule": detection_rule,
        "source_project": "audit_pipeline",
    }


def store_pattern(finding: dict, hook: dict | None = None,
                  db: Database | None = None) -> int | None:
    """Extract and store a pattern from a finding. Returns pattern id or None."""
    pattern = extract_pattern(finding, hook, db)
    if pattern is None:
        return None
    return (db or get_db()).insert_pattern(**pattern)


def _cwe_to_pattern_type(cwe_id: str) -> str:
    mapping = {
        "CWE-89": "sql_injection",
        "CWE-79": "xss",
        "CWE-78": "command_injection",
        "CWE-77": "command_injection",
        "CWE-22": "path_traversal",
        "CWE-862": "auth_bypass",
        "CWE-306": "auth_bypass",
        "CWE-918": "ssrf",
        "CWE-502": "deserialization",
        "CWE-200": "info_leak",
        "CWE-352": "csrf",
        "CWE-434": "file_upload",
    }
    return mapping.get(cwe_id, cwe_id.replace("CWE-", "").lower())


def extract_patterns_from_findings(db, findings: list[dict]) -> int:
    """Extract vulnerability patterns from a list of findings and insert into DB.

    Returns the number of new patterns added.
    """
    count = 0
    for f in findings:
        if f.get("verdict") != "true_positive":
            continue
        pattern_type = f.get("cwe", f.get("cwe_id", ""))
        if not pattern_type:
            continue
        # Map CWE to pattern_type
        cwe_map = {
            "CWE-89": "sql_injection",
            "CWE-79": "xss",
            "CWE-78": "command_injection",
            "CWE-22": "path_traversal",
            "CWE-502": "deserialization",
            "CWE-798": "hardcoded_credentials",
            "CWE-862": "auth_bypass",
            "CWE-306": "auth_bypass",
            "CWE-200": "info_leak",
            "CWE-352": "csrf",
            "CWE-918": "ssrf",
            "CWE-434": "unrestricted_upload",
        }
        pt = cwe_map.get(pattern_type, "unknown")
        desc = f.get("description", f.get("reason", ""))[:500]
        title = f.get("title", "Untitled")[:120]

        try:
            db.insert_pattern(
                pattern_type=pt,
                cwe_id=pattern_type,
                code_signature="",
                vulnerable_snippet=desc,
                fix_snippet="",
                detection_rule="",
                source_project="VulnForge auto-extract",
            )
            count += 1
        except Exception:
            pass

    return count
