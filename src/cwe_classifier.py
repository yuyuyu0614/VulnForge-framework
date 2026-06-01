
"""CWE Classifier — Maps AST hooks to precise CWE identifiers.

Replaces the generic 'dangerous_call' with specific CWE numbers
required by SRC platforms (补天, HackerOne, Bugcrowd).
"""

import re
from typing import Optional

# CWE mapping table
# Format: (function_pattern, module_context) -> (CWE_ID, CWE_TITLE, severity_override)
CWE_RULES = {
    "python": [
        # SQL Injection
        (r'\.(execute|executemany|executescript)\(', None, "CWE-89", "SQL Injection", "critical"),
        # Command Injection
        (r'(os\.system|subprocess\.(call|check_output|run|Popen)|os\.popen)', None, "CWE-78", "OS Command Injection", "critical"),
        # Code Injection
        (r'(exec|eval|compile)\(', None, "CWE-94", "Code Injection", "critical"),
        # Deserialization
        (r'(pickle\.(loads?|dumps?)|yaml\.load|marshal\.loads?|Unpickler)', None, "CWE-502", "Deserialization of Untrusted Data", "high"),
        # Path Traversal
        (r'(open|read|write)\(.*(?:path|file|name|dir)', None, "CWE-22", "Path Traversal", "high"),
        # SSRF
        (r'(requests|urllib|httpx)\.(get|post|put|delete)\(', None, "CWE-918", "Server-Side Request Forgery", "high"),
        # XSS (Flask/Jinja2)
        (r'(render_template_string|Markup)\(', None, "CWE-79", "Cross-Site Scripting", "high"),
        # Hardcoded Secrets (redirect to secrets scanner)
        (r'(password|secret|key|token|api_key)', None, "CWE-798", "Hardcoded Credentials", "high"),
        # XXE
        (r'(etree\.parse|lxml\.etree\.parse|xml\.sax)', None, "CWE-611", "XML External Entity", "high"),
        # Open Redirect
        (r'redirect\(', None, "CWE-601", "Open Redirect", "medium"),
        # Insecure Deserialization (JSON)
        (r'json\.loads\(.*request', None, "CWE-502", "Deserialization of Untrusted Data", "medium"),
    ],
    "java": [
        (r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder', None, "CWE-78", "OS Command Injection", "critical"),
        (r'Statement\.execute|PreparedStatement\.execute|executeQuery|executeUpdate', None, "CWE-89", "SQL Injection", "critical"),
        (r'readObject|readUnshared|ObjectInputStream', None, "CWE-502", "Deserialization of Untrusted Data", "critical"),
        (r'InitialContext|lookup\(', None, "CWE-917", "JNDI Injection", "critical"),
        (r'ScriptEngine\.eval|ScriptEngineManager', None, "CWE-94", "Code Injection", "critical"),
        (r'FileInputStream|FileReader|RandomAccessFile', None, "CWE-22", "Path Traversal", "high"),
        (r'HttpURLConnection|openConnection', None, "CWE-918", "SSRF", "high"),
        (r'DocumentBuilderFactory|SAXParserFactory|XMLReader', None, "CWE-611", "XXE", "high"),
        (r'Method\.invoke|Field\.setAccessible', None, "CWE-470", "Unsafe Reflection", "high"),
    ],
    "javascript": [
        (r'eval\(', None, "CWE-94", "Code Injection", "critical"),
        (r'(child_process|cross_spawn)\.(exec|spawn)', None, "CWE-78", "OS Command Injection", "critical"),
        (r'innerHTML|outerHTML|document\.write', None, "CWE-79", "Cross-Site Scripting", "high"),
        (r'(fetch|axios|request)\(', None, "CWE-918", "SSRF", "high"),
        (r'JSON\.parse\(', None, "CWE-502", "Deserialization", "medium"),
    ],
    "php": [
        (r'(mysql_query|mysqli_query|pg_query|sqlite_query)', None, "CWE-89", "SQL Injection", "critical"),
        (r'(exec|system|passthru|shell_exec|popen|proc_open)', None, "CWE-78", "OS Command Injection", "critical"),
        (r'(eval|assert|preg_replace.*\/e)', None, "CWE-94", "Code Injection", "critical"),
        (r'(unserialize)', None, "CWE-502", "Deserialization", "critical"),
        (r'(include|require|file_get_contents|fopen)', None, "CWE-98", "File Inclusion", "high"),
    ],
    "go": [
        (r'(exec\.Command|exec\.CommandContext)', None, "CWE-78", "OS Command Injection", "critical"),
        (r'(template\.Execute|template\.ExecuteTemplate)', None, "CWE-94", "Server-Side Template Injection", "high"),
        (r'(database/sql.*Query|database/sql.*Exec)', None, "CWE-89", "SQL Injection", "critical"),
        (r'(http\.Get|http\.Post|http\.NewRequest)', None, "CWE-918", "SSRF", "high"),
    ],
}

# CWE remediation guidance
REMEDIATION = {
    "CWE-89": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "CWE-78": "Use subprocess with shell=False and a list of arguments. Avoid os.system().",
    "CWE-94": "Never pass user-controlled data to eval/exec. Use ast.literal_eval() if needed.",
    "CWE-502": "Never unpickle/unmarshal untrusted data. Use JSON or a safe serialization format.",
    "CWE-22": "Use os.path.abspath + os.path.commonpath to validate paths. Never concatenate user input into file paths.",
    "CWE-918": "Whitelist allowed URLs/hosts. Never let users control the full URL.",
    "CWE-79": "Use template auto-escaping. Sanitize user input with bleach or similar.",
    "CWE-798": "Use environment variables or a secrets manager. Never commit credentials to source code.",
    "CWE-611": "Disable external entity processing in XML parsers. Set resolve_entities=False.",
    "CWE-601": "Use django.utils.http.url_has_allowed_host_and_scheme() or equivalent.",
    "CWE-917": "Avoid JNDI lookups with user-controlled names.",
    "CWE-98": "Use a whitelist of allowed files. Never include files based on user input.",
}


def classify_cwe(hook: dict, language: str = "python") -> dict:
    """Classify a hook with precise CWE identifier.
    
    If hook already has cwe_id (from grep scanner), use it directly.
    """
    # If CWE already set by grep scanner, just fill remediation
    if hook.get('cwe_id') and hook.get('cwe_id') != 'CWE-0':
        hook['hook_type'] = hook['cwe_id']
        hook['remediation'] = REMEDIATION.get(hook['cwe_id'], "Review and fix the vulnerability.")
        return hook
    
    called = hook.get('called_function', hook.get('metadata', {}).get('called_function', ''))
    snippet = hook.get('snippet', '')
    
    rules = CWE_RULES.get(language, [])
    for pattern, _ctx, cwe_id, cwe_title, severity in rules:
        if re.search(pattern, snippet, re.IGNORECASE):
            hook['cwe_id'] = cwe_id
            hook['cwe_title'] = cwe_title
            hook['severity'] = severity
            hook['remediation'] = REMEDIATION.get(cwe_id, "Review and fix the vulnerability.")
            hook['hook_type'] = cwe_id  # Replace generic type
            return hook
    
    # Fallback: keep original but mark as unclassified
    hook['cwe_id'] = 'CWE-0'
    hook['cwe_title'] = 'Unclassified dangerous call'
    return hook


def batch_classify(hooks: list[dict], language: str = "python") -> list[dict]:
    """Classify all hooks with CWE identifiers."""
    return [classify_cwe(h, language) for h in hooks]


def get_cwe_stats(hooks: list[dict]) -> dict:
    """Generate CWE statistics from classified hooks."""
    stats = {}
    for h in hooks:
        cwe = h.get('cwe_id', 'CWE-0')
        if cwe not in stats:
            stats[cwe] = {'count': 0, 'title': h.get('cwe_title', ''), 'findings': []}
        stats[cwe]['count'] += 1
        stats[cwe]['findings'].append({
            'file': h.get('file_path', ''),
            'line': h.get('line_start', 0),
            'function': h.get('func_name', ''),
        })
    return stats
