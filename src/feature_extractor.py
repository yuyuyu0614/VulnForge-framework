import re
"""AST-based feature extraction — identifies dangerous calls, sinks, and attack surfaces.

Supports: Python, JavaScript, Java, Go, C/C++
Outputs: standardized hook dicts ready for db.insert_hook()
"""

import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# Language grammar imports (lazy loaded)
_grammars: dict[str, object] = {}

EXT_TO_LANG: dict[str, str] = {
    ".py": "python", ".pyi": "python", ".pyx": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".jsx": "javascript",
    ".java": "java", ".kt": "java",
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php", ".php5": "php",
    ".go": "go",
    ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hpp": "cpp", ".hxx": "cpp",
}

# ---- Language-Specific Pattern Definitions ----

# Each pattern: (hook_type, severity, description, query_or_function_names)
# For now, we target specific function call names via AST walking.
# In production, tree-sitter queries would be more precise.

DANGEROUS_CALLS: dict[str, list[tuple[str, str, str, str, list[str]]]] = {
    "python": [
        # (hook_type, severity, cwe_id, description, function_names)
        ("CWE-94", "critical", "CWE-94", "Code execution via exec/eval", ["exec", "eval", "compile"]),
        ("CWE-78", "high", "CWE-78", "Command injection via os.system/subprocess", ["system", "popen", "call", "check_output", "run"]),
        ("CWE-918", "high", "CWE-918", "SSRF via user-controlled URL", ["urlopen"]),
        ("CWE-502", "high", "CWE-502", "Deserialization via pickle/yaml", ["load", "loads", "Unpickler"]),
        ("CWE-22", "medium", "CWE-22", "File/path operations", ["open", "__import__"]),
        ("CWE-89", "high", "CWE-89", "SQL injection via cursor.execute", ["execute", "executemany", "executescript"]),
        ("CWE-913", "medium", "CWE-913", "Dynamic attribute access", ["__getattribute__", "__setattr__", "getattr", "setattr"]),
        ("input_source", "medium", "CWE-20", "Web request input source", ["args", "form", "json", "cookies"]),
        ("input_source", "medium", "CWE-20", "User input source", ["input", "getpass"]),
    ],
    "javascript": [
        ("CWE-94", "critical", "CWE-94", "Code execution via eval/Function", ["eval", "Function"]),
        ("CWE-78", "high", "CWE-78", "Command injection via child_process", ["exec", "execSync", "spawn", "fork"]),
        ("CWE-79", "medium", "CWE-79", "DOM XSS injection", ["innerHTML", "outerHTML", "document.write"]),
        ("CWE-913", "medium", "CWE-913", "Dynamic import/require", ["import", "require"]),
        ("input_source", "medium", "CWE-20", "HTTP request handling", ["app.get", "app.post", "router.get", "router.post"]),
    ],
    "java": [
        ("CWE-78", "high", "CWE-78", "Command execution via Runtime.exec", ["exec"]),
        ("CWE-470", "high", "CWE-470", "Reflection-based invocation", ["invoke", "newInstance"]),
        ("CWE-502", "critical", "CWE-502", "Deserialization", ["readObject", "readUnshared"]),
        ("CWE-917", "medium", "CWE-917", "JNDI lookup", ["lookup"]),
        ("CWE-94", "medium", "CWE-94", "Script engine eval", ["eval", "compile"]),
        ("route_entry", "medium", "CWE-20", "Spring MVC endpoint", ["GetMapping", "PostMapping", "RequestMapping"]),
    ],
    "go": [
        ("dangerous_call", "critical", "Command execution via os/exec", ["Command", "CommandContext"]),
        ("dangerous_call", "high", "Template injection", ["Execute", "ExecuteTemplate"]),
        ("dangerous_call", "medium", "Reflect-based operations", ["ValueOf", "Set", "Call"]),
        ("route_entry", "medium", "HTTP handler registration", ["HandleFunc", "Handle", "NewServeMux"]),
        ("input_source", "medium", "HTTP request parsing", ["ParseForm", "FormValue", "PostFormValue"]),
    ],
    "php": [
        ("dangerous_call", "critical", "Command injection via exec/system", ["exec", "system", "passthru", "shell_exec", "popen", "proc_open"]),
        ("dangerous_call", "critical", "Code injection via eval/assert", ["eval", "assert", "create_function"]),
        ("dangerous_call", "critical", "SQL injection via mysql_query", ["mysql_query", "mysqli_query", "pg_query", "mssql_query"]),
        ("dangerous_call", "high", "File inclusion", ["include", "include_once", "require", "require_once"]),
        ("dangerous_call", "high", "Deserialization", ["unserialize"]),
        ("dangerous_call", "high", "File operations", ["fopen", "file_get_contents", "file_put_contents", "move_uploaded_file"]),
        ("dangerous_call", "medium", "XXE via simplexml", ["simplexml_load_string", "simplexml_load_file"]),
        ("input_source", "medium", "User input superglobals", ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"]),
    ],
    "cpp": [
        ("dangerous_call", "critical", "Command execution via system/popen", ["system", "popen", "execve", "execvp"]),
        ("dangerous_call", "high", "Memory manipulation", ["memcpy", "strcpy", "strcat", "sprintf", "gets"]),
        ("dangerous_call", "high", "Process creation", ["fork", "CreateProcess"]),
        ("dangerous_call", "medium", "Dynamic library loading", ["dlopen", "LoadLibrary"]),
    ],
}

# — Fast regex patterns for languages where tree-sitter parsing is weak —
GREP_PATTERNS: dict[str, list[tuple[str, str, str, str, str, str]]] = {
    "java": [
        # (hook_type, severity, cwe_id, cwe_title, description, regex_pattern)
        ("CWE-78", "critical", "CWE-78", "OS Command Injection", "Command injection via Runtime.exec/ProcessBuilder", r'Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder'),
        ("CWE-89", "critical", "CWE-89", "SQL Injection", "SQL injection via JDBC Statement.execute", r'(Statement|PreparedStatement)\.(execute|executeQuery|executeUpdate)'),
        ("CWE-502", "critical", "CWE-502", "Deserialization", "Deserialization via readObject", r'(ObjectInputStream|readObject|readUnshared)'),
        ("CWE-917", "critical", "CWE-917", "JNDI Injection", "JNDI injection via InitialContext.lookup", r'(InitialContext|lookup)\('),
        ("CWE-94", "high", "CWE-94", "Code Injection", "Code injection via ScriptEngine.eval", r'(ScriptEngine|ScriptEngineManager)\.eval'),
        ("CWE-918", "high", "CWE-918", "SSRF", "SSRF via HttpURLConnection", r'(HttpURLConnection|URL\().*openConnection'),
        ("CWE-611", "high", "CWE-611", "XXE", "XXE via DocumentBuilderFactory", r'(DocumentBuilderFactory|SAXParserFactory|XMLReader)'),
        ("CWE-22", "medium", "CWE-22", "Path Traversal", "Path traversal via FileInputStream", r'new\s+(FileInputStream|FileReader|FileWriter|RandomAccessFile)\('),
        ("CWE-470", "high", "CWE-470", "Unsafe Reflection", "Unsafe reflection via Method.invoke", r'(Method|Field)\.(invoke|setAccessible)'),
    ],
    "php": [
        ("CWE-78", "critical", "CWE-78", "OS Command Injection", "Command injection", r'(exec|system|passthru|shell_exec|popen|proc_open)\s*\('),
        ("CWE-89", "critical", "CWE-89", "SQL Injection", "SQL injection", r'(mysql_query|mysqli_query|pg_query|mssql_query|sqlite_query)\s*\('),
        ("CWE-94", "critical", "CWE-94", "Code Injection", "Code injection via eval/assert", r'(eval|assert|create_function)\s*\('),
        ("CWE-98", "high", "CWE-98", "File Inclusion", "Local/Remote file inclusion", r'(include|include_once|require|require_once)\s*["\'$]'),
        ("CWE-502", "high", "CWE-502", "Deserialization", "PHP deserialization via unserialize", r'unserialize\s*\('),
        ("CWE-434", "high", "CWE-434", "Unrestricted File Upload", "File write/upload", r'(fopen|file_put_contents|move_uploaded_file|copy)\s*\('),
        ("CWE-611", "medium", "CWE-611", "XXE", "XXE via simplexml", r'simplexml_load_(string|file)\s*\('),
        ("input_source", "medium", "CWE-20", "Improper Input Validation", "User input from superglobals", r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\['),
    ],
}


def _grep_scan(file_path: Path, language: str) -> list[dict]:
    """Fast regex-based hook extraction for languages with weak tree-sitter support."""
    patterns = GREP_PATTERNS.get(language, [])
    if not patterns:
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return []
    
    hooks = []
    for hook_type, severity, cwe_id, cwe_title, description, pattern in patterns:
        for line_no, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                hooks.append({
                    'hook_id': hashlib.sha256(
                        f"{file_path}:{line_no}:{pattern}".encode()
                    ).hexdigest()[:16],
                    'file_path': str(file_path),
                    'func_name': '',
                    'hook_type': hook_type,
                    'language': language,
                    'severity': severity,
                    'cwe_id': cwe_id,
                    'cwe_title': cwe_title,
                    'line_start': line_no,
                    'line_end': line_no,
                    'snippet': line.rstrip()[:300],
                    'metadata': {
                        'description': description,
                        'pattern': pattern,
                        'called_function': '',
                    },
                })
    return hooks




def _detect_language(file_path: str | Path) -> str | None:
    ext = Path(file_path).suffix.lower()
    return EXT_TO_LANG.get(ext)


def _load_grammar(lang: str) -> object | None:
    if lang in _grammars:
        return _grammars[lang]
    try:
        import importlib
        mod = importlib.import_module(f"tree_sitter_{lang}")
        _grammars[lang] = mod
        return mod
    except ImportError:
        return None


def _find_func_name(node, source: bytes) -> tuple[str | None, int, int]:
    """Walk up from a node to find the enclosing function/method name and line range."""
    cursor = node.walk()
    current = cursor.node
    while current:
        if current.type in ("function_definition", "method_definition",
                            "function_declaration", "function",
                            "method_declaration", "constructor_declaration",
                            "func_literal", "lambda_expression"):
            # Find the name child
            for child in current.children:
                if child.type in ("identifier", "name", "property_identifier"):
                    return (
                        source[child.start_byte:child.end_byte].decode(),
                        current.start_point[0] + 1,  # 1-indexed
                        current.end_point[0] + 1,
                    )
            # anonymous function
            return ("<anonymous>", current.start_point[0] + 1, current.end_point[0] + 1)
        current = current.parent
    return (None, 0, 0)


def _node_snippet(node, source: bytes, context_lines: int = 2) -> str:
    """Extract a snippet around the given node with surrounding context lines."""
    lines = source.decode(errors="replace").split("\n")
    start = max(node.start_point[0] - context_lines, 0)
    end = min(node.end_point[0] + context_lines + 1, len(lines))
    snippet_lines = lines[start:end]
    # Mark the target line
    result = []
    for i, line in enumerate(snippet_lines, start=start + 1):
        prefix = ">>>" if i == node.start_point[0] + 1 else "   "
        result.append(f"{prefix}{i:4d}  {line}")
    return "\n".join(result)


@dataclass
class ExtractionResult:
    file_path: str
    language: str
    hooks: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def extract_hooks(file_path: str | Path, db=None) -> ExtractionResult:
    """Parse a source file and extract all dangerous hooks.

    Args:
        file_path: path to source file
        db: optional Database instance to auto-insert hooks (for pipeline mode)

    Returns:
        ExtractionResult with all hooks found
    """
    file_path = Path(file_path)
    result = ExtractionResult(file_path=str(file_path), language="unknown")

    lang = _detect_language(file_path)
    if lang is None:
        result.errors.append(f"Unsupported file type: {file_path.suffix}")
        return result

    result.language = lang
    grammar = _load_grammar(lang)
    if grammar is None:
        result.errors.append(f"Tree-sitter grammar not installed for: {lang}")
        return result

    patterns = DANGEROUS_CALLS.get(lang, [])
    if not patterns:
        result.errors.append(f"No patterns defined for: {lang}")
        return result

    # Build a flat set of target function names for efficient lookup
    name_to_meta: dict[str, list[tuple[str, str, str]]] = {}
    for hook_type, severity, cwe_id, desc, names in patterns:
        for n in names:
            name_to_meta.setdefault(n, []).append((hook_type, severity, cwe_id, desc))

    try:
        source_bytes = file_path.read_bytes()
    except Exception as e:
        result.errors.append(f"Failed to read file: {e}")
        return result

    try:
        from tree_sitter import Parser, Language
        lang_obj = Language(grammar.language())
        parser = Parser(lang_obj)
        tree = parser.parse(source_bytes)
    except Exception as e:
        result.errors.append(f"Parse error: {e}")
        return result

    # Walk the AST looking for function call identifiers matching dangerous names
    _walk_node(
        tree.root_node, source_bytes, name_to_meta, result, file_path,
        lang, db
    )
    return result


def _walk_node(
    node, source: bytes, name_to_meta: dict,
    result: ExtractionResult, file_path: Path, lang: str, db
):
    """Recursively walk AST, collect call_expression nodes with dangerous target names."""
    if node.type in ("call_expression", "call", "method_invocation"):
        # Try to find the function name being called
        name_node = _get_call_name_node(node, lang)
        if name_node:
            called_name = source[name_node.start_byte:name_node.end_byte].decode()
            if called_name in name_to_meta:
                for hook_type, severity, cwe_id, desc in name_to_meta[called_name]:
                    func_name, line_s, line_e = _find_func_name(node, source)
                    snippet = _node_snippet(node, source)
                    hook = {
                        "hook_id": hashlib.sha256(
                            f"{file_path}:{func_name}:{line_s}:{hook_type}:{called_name}".encode()
                        ).hexdigest()[:16],
                        "file_path": str(file_path),
                        "func_name": func_name or called_name,
                        "hook_type": hook_type,
                        "cwe_id": cwe_id,
                        "cwe_title": desc,
                        "language": lang,
                        "severity": severity,
                        "line_start": node.start_point[0] + 1,
                        "line_end": node.end_point[0] + 1,
                        "snippet": snippet,
                        "metadata": {
                            "called_function": called_name,
                            "description": desc,
                            "enclosing_func": func_name,
                            "line_range": [node.start_point[0] + 1, node.end_point[0] + 1],
                        },
                    }
                    result.hooks.append(hook)
                    if db:
                        db.insert_hook(**hook)

    # Recurse children
    for child in node.children:
        _walk_node(child, source, name_to_meta, result, file_path, lang, db)


def _get_call_name_node(node, lang: str):
    """Extract the identifier node representing the function name being called.

    Handles cross-language AST node type differences:
    - Python: call > attribute > identifier (last)
    - Go:     call_expression > selector_expression > field_identifier (last)
    - JS:     call_expression > member_expression > property_identifier (last)
    - Java:   method_invocation > ... > identifier (last)
    """
    # Direct calls: eval(), system(), require()
    for child in node.children:
        if child.type in ("identifier", "name", "function", "variable_name"):
            return child

    # Qualified calls: os.system(), exec.Command(), document.write()
    qualifier_types = ("attribute", "selector_expression", "member_expression",
                       "method_invocation", "field_access")
    for child in node.children:
        if child.type in qualifier_types:
            return _get_last_identifier(child)

    # Nested call: e.g. router.post(...) in JS
    for child in node.children:
        if child.type in ("call_expression", "call"):
            inner = _get_call_name_node(child, lang)
            if inner:
                return inner

    return None


def _get_last_identifier(node):
    """Recursively find the last (rightmost) identifier in a qualified expression chain."""
    last_id = None
    for child in node.children:
        if child.type in ("identifier", "name", "field_identifier",
                          "property_identifier", "type_identifier"):
            last_id = child
        # Handle nested qualification: os.path.system
        for nested_type in ("attribute", "selector_expression", "member_expression"):
            if child.type == nested_type:
                inner = _get_last_identifier(child)
                if inner:
                    last_id = inner
    return last_id


# --- Convenience: batch extraction ---

def extract_directory(root_dir: str | Path, db=None, extensions: set[str] | None = None,
                        exclude_dirs: set[str] | None = None,
                        max_file_kb: int = 500) -> list[ExtractionResult]:
    """Walk a directory tree and extract hooks from all supported files.
    
    Args:
        root_dir: Root directory to scan
        db: Database instance for storing results
        extensions: Only scan these extensions (None = all supported)
        exclude_dirs: Directory names to skip (e.g., node_modules, vendor, lib)
        max_file_kb: Skip files larger than this (minified libs)
    """
    if exclude_dirs is None:
        exclude_dirs = {
            'node_modules', 'vendor', 'lib', 'libs', 'dist', 'build',
            '.git', '__pycache__', '.venv', 'venv', 'env',
            'bower_components', 'external', 'third_party', 'thirdparty',
            'jquery', 'bootstrap', 'ace', 'codemirror',
        }
    root_dir = Path(root_dir)
    results = []
    
    def _is_excluded(path: Path) -> bool:
        parts = set(p.name.lower() for p in path.parents if p != root_dir)
        return bool(parts & exclude_dirs)
    
    for file_path in root_dir.rglob("*"):
        if not file_path.is_file():
            continue
        ext = file_path.suffix.lower()
        if extensions and ext not in extensions:
            continue
        if ext not in EXT_TO_LANG:
            continue
        # Skip large files (minified libs, bundles)
        try:
            if file_path.stat().st_size > max_file_kb * 1024:
                continue
        except OSError:
            continue
        # Skip excluded directories
        if _is_excluded(file_path):
            continue
        # Skip files with .min. in name (minified)
        if '.min.' in file_path.name.lower():
            continue
        lang = _detect_language(file_path)
        r = extract_hooks(file_path, db=db)
        # If tree-sitter found nothing, try grep fallback
        if not r.hooks:
            grep_lang = r.language or lang
            if grep_lang:
                grep_hooks = _grep_scan(file_path, grep_lang)
                if grep_hooks:
                    r.hooks = grep_hooks
                    r.language = grep_lang
        if r.hooks or r.errors:
            results.append(r)
    return results


def summary(results: list[ExtractionResult]) -> dict:
    """Generate a summary of extraction results."""
    total_hooks = 0
    total_errors = 0
    files_with_hooks = 0
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_type: dict[str, int] = {}

    for r in results:
        if r.hooks:
            files_with_hooks += 1
        total_hooks += len(r.hooks)
        total_errors += len(r.errors)
        for h in r.hooks:
            by_severity[h["severity"]] = by_severity.get(h["severity"], 0) + 1
            by_type[h["hook_type"]] = by_type.get(h["hook_type"], 0) + 1

    return {
        "files_scanned": len(results),
        "files_with_hooks": files_with_hooks,
        "total_hooks": total_hooks,
        "total_errors": total_errors,
        "by_severity": by_severity,
        "by_type": by_type,
    }
