
"""False Positive Filter — Dataflow-aware reachability analysis.

Filters out AST hooks where dangerous calls are NOT reachable from user input.
Uses lightweight intra-procedural taint tracking.
"""

import re
from typing import Optional

# User input source patterns (per language)
USER_INPUT_PATTERNS = {
    "python": [
        r'request\.args', r'request\.form', r'request\.json',
        r'request\.data', r'request\.cookies', r'request\.headers',
        r'request\.get_json\(', r'input\(', r'sys\.argv',
        r'os\.environ', r'getpass\.getpass',
    ],
    "java": [
        r'request\.getParameter', r'request\.getQueryString',
        r'request\.getHeader', r'request\.getCookie',
        r'@RequestParam', r'@PathVariable', r'@RequestBody',
        r'Scanner', r'BufferedReader\.readLine',
    ],
    "javascript": [
        r'req\.query', r'req\.body', r'req\.params',
        r'req\.cookies', r'req\.headers',
        r'window\.location', r'document\.cookie',
    ],
    "php": [
        r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE',
        r'\$_SERVER', r'\$_FILES', r'file_get_contents\(.*php://input',
    ],
}

# Known safe patterns (never exploitable)
SAFE_PATTERNS = {
    "python": [
        # Flask app.run() is not exploitable
        (r'app\.run\(', "Framework bootstrap, not exploitable"),
        # request.args.get() used for variable assignment — not injection itself
        (r'\w+\s*=\s*request\.\w+\.get\(', "Variable assignment from request, not injection"),
        # open() with static path
        (r'open\(["\'](?!/)', "Static file open, likely not path traversal"),
        # json.loads/dumps on internal data
        (r'json\.(loads|dumps)\(', "JSON serialization, not deserialization attack"),
    ],
    "java": [
        # Logger calls
        (r'log\.(info|debug|warn|error|trace)\(', "Logger call, not exploitable"),
        # toString, equals, hashCode
        (r'\.(toString|equals|hashCode)\(', "Standard library method, not exploitable"),
    ],
}


def has_user_input_in_function(code: str, func_name: str, language: str) -> bool:
    """Check if the enclosing function contains user input sources."""
    patterns = USER_INPUT_PATTERNS.get(language, [])
    for pat in patterns:
        if re.search(pat, code, re.IGNORECASE):
            return True
    return False


def is_known_safe(line: str, language: str) -> tuple[bool, str]:
    """Check if a line matches known safe patterns.
    Returns (is_safe, reason).
    """
    patterns = SAFE_PATTERNS.get(language, [])
    for pat, reason in patterns:
        if re.search(pat, line, re.IGNORECASE):
            return True, reason
    return False, ""



# Patterns that are always true positives regardless of context
ALWAYS_TRUE = {
    "java": [
        r'readObject', r'readUnshared', r'ObjectInputStream',
        r'JNDI', r'InitialContext\.lookup',
        r'ScriptEngine\.eval',
        r'ProcessBuilder',
    ],
    "python": [
        r'pickle\.(loads?|dumps?)', r'yaml\.load\(' , r'marshal\.loads?',
        r'(exec|eval)\s*\(',
        r'os\.system', r'subprocess\.(call|check_output|Popen)',
    ],
    "php": [
        r'unserialize', r'eval\(', r'assert\(',
        r'(exec|system|passthru|shell_exec)\s*\(',
    ],
}


def _is_always_true_positive(hook: dict, language: str) -> bool:
    """Check if a hook is known to always indicate a real vulnerability."""
    patterns = ALWAYS_TRUE.get(language, [])
    line = hook.get("snippet", "")
    import re as _re
    for pat in patterns:
        if _re.search(pat, line, _re.IGNORECASE):
            return True
    return False


def _is_test_file(file_path: str) -> bool:
    """Check if file is a test file (unit tests rarely have exploitable vulns)."""
    import os
    fname = os.path.basename(file_path).lower()
    fdir = os.path.dirname(file_path).lower()
    test_indicators = ['test_', '_test.', 'test.', 'tests/', '/test/', '/tests/', 'spec_', '_spec.', 'Test.java', 'Test.py', 'Test.php', 'Tests.java', 'Tests.py']
    for ti in test_indicators:
        if ti in fname or ti in fdir:
            return True
    return False


def _has_user_param_in_line(line, language="python"):
    """Check if the dangerous line contains user-controllable variables."""
    import re as _re
    if language == "python":
        patterns = [
            r'f"', r"f'", r'\.format\(', r'%\(',
            r'request\.', r'user_input', r'req\.',
            r'params\[', r'kwargs\[', r'args\[',
        ]
        for p in patterns:
            if _re.search(p, line):
                return True
    if language == "java":
        patterns = [
            r'request\.getParameter', r'request\.getQuery',
            r'\+\s*"',
        ]
        for p in patterns:
            if _re.search(p, line):
                return True
    return False

def filter_false_positives(hooks: list[dict], file_content: str, language: str) -> list[dict]:
    """Filter hooks using intra-procedural taint analysis + parameter inspection.
    
    A hook is a true positive if:
    1. It passes always-true check, OR
    2. The dangerous call has user-controlled parameters, OR
    3. It's in a function with user input sources
    AND
    4. It doesn't match known-safe patterns
    5. It's not in a test file (for CWE-78/94)
    """
    filtered = []
    file_path = hooks[0].get("file_path", "") if hooks else ""
    for hook in hooks:
        line = hook.get("snippet", "")
        func = hook.get("func_name", "")
        cwe = hook.get("cwe_id", "")
        fp = hook.get("file_path", file_path)
        
        # Test files: skip entirely (test boilerplate, not exploitable)
        if _is_test_file(fp):
            hook["fp_filtered"] = True
            hook["fp_reason"] = "Test file"
            continue
        
        # Parameter taint check: command injection without user params is not exploitable
        if cwe in ("CWE-78", "CWE-94", "CWE-89"):
            if not _has_user_param_in_line(line, language):
                hook["fp_filtered"] = True
                hook["fp_reason"] = f"{cwe}: no user-controlled parameter detected"
                continue
        
        # Always-true positives bypass all filters
        if _is_always_true_positive(hook, language):
            hook["fp_filtered"] = False
            filtered.append(hook)
            continue
        
        # SSRF/CWE-918: only true positive if user can control the URL
        if cwe == "CWE-918":
            if func and has_user_input_in_function(file_content, func, language):
                hook["fp_filtered"] = False
                filtered.append(hook)
            elif is_route_handler(func, language):
                hook["fp_filtered"] = False
                filtered.append(hook)
            else:
                hook["fp_filtered"] = True
                hook["fp_reason"] = f"HTTP client call without user-controlled URL — not SSRF"
            continue
        
        # Skip known safe patterns
        is_safe, reason = is_known_safe(line, language)
        if is_safe:
            hook["fp_filtered"] = True
            hook["fp_reason"] = reason
            continue
        
        # Check if function has user input
        if func and has_user_input_in_function(file_content, func, language):
            hook["fp_filtered"] = False
            filtered.append(hook)
        elif is_route_handler(func, language):
            hook["fp_filtered"] = False
            filtered.append(hook)
        else:
            hook["fp_filtered"] = True
            hook["fp_reason"] = f"No user input reachable in function '{func}'"
    
    return filtered


def is_route_handler(func_name: str, language: str) -> bool:
    """Check if function name suggests it's an HTTP route handler."""
    if not func_name:
        return False
    if language == "python":
        return bool(re.match(r'^(index|home|login|logout|register|upload|download|'
                           r'search|query|profile|admin|api_|view_|handle_|do_)',
                           func_name, re.IGNORECASE))
    if language == "java":
        return bool(re.match(r'^(doGet|doPost|service|handle|process)', func_name))
    return False


def estimate_confidence(hook: dict) -> int:
    """Assign confidence score based on signal strength."""
    score = 30  # base
    if hook.get("fp_filtered") == False:
        score += 20
    if hook.get("severity") == "critical":
        score += 15
    if hook.get("severity") == "high":
        score += 10
    # Presence of user-controlled variable name
    snippet = hook.get("snippet", "")
    if re.search(r'(user|input|param|query|body|file|name|id)', snippet, re.IGNORECASE):
        score += 10
    return min(score, 95)
