"""Hallucination checker — AST-based verification of AI-generated findings.

Detects 4 hallucination types defined by CodeHalu (AAAI 2025):
  1. Mapping hallucination — function signatures don't match reality
  2. Naming hallucination — fabricated variables, classes, filenames
  3. Resource hallucination — non-existent libraries, APIs, dependencies
  4. Logic hallucination — semantically impossible claims

Used by the confidence scoring system: L5 (HalluJudge) + L7 (deterministic rules).
Successful verification grants +15 confidence points toward the 60-point threshold.

Usage:
    checker = HallucinationChecker()
    report = checker.check(finding, project_path)
    if report.passed:
        score += 15  # confidence boost
"""

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from feature_extractor import (
    _detect_language, _load_grammar, EXT_TO_LANG,
)
from code_chunker import chunk_directory, chunk_file, to_context_json


@dataclass
class HallucinationReport:
    """Result of a hallucination check run."""
    passed: bool = True
    issues: list[dict] = field(default_factory=list)
    checks_run: int = 0
    checks_passed: int = 0
    confidence_penalty: float = 0.0

    def add_issue(self, htype: str, detail: str, severity: str = "warning"):
        self.issues.append({
            "type": htype,
            "detail": detail,
            "severity": severity,
        })
        if severity == "error":
            self.passed = False
            self.confidence_penalty += 5.0
        elif severity == "warning":
            self.confidence_penalty += 2.0


class HallucinationChecker:
    def _cache_valid(self) -> bool:
        """Check if cached index is still valid by comparing file mtimes."""
        try:
            for f in self.project_path.rglob("*"):
                if f.is_file():
                    cached = self._mtime_cache.get(str(f))
                    if cached is None or cached != f.stat().st_mtime:
                        return False
            return True
        except Exception:
            return False

    """Verifies AI-generated security findings against the actual codebase."""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        self._file_index: dict[str, Path] = {}
        self._func_index: dict[str, list[dict]] = {}
        self._var_index: dict[str, set[str]] = {}
        self._import_index: dict[str, set[str]] = {}
        self._class_index: dict[str, list[dict]] = {}
        self._built = False

    # ── Index Building ───────────────────────────────────────────

    def build_index(self, force: bool = False) -> "HallucinationChecker":
        """Scan the entire project and build lookup indexes.

        Uses file mtime cache to skip unchanged files on subsequent calls.
        Set force=True to rebuild everything.
        Call once before running multiple checks.
        """
        # Check cache: skip if already built and no files changed
        if self._built and not force:
            if self._cache_valid():
                return self

        self._mtime_cache: dict[str, float] = {}
        # File index
        self._mtime_cache = {}
        for f in self.project_path.rglob("*"):
            if f.is_file():
                self._file_index[f.name] = f
                self._file_index[str(f.relative_to(self.project_path))] = f
                try:
                    self._mtime_cache[str(f)] = f.stat().st_mtime
                except Exception:
                    pass

        # Chunk all supported files for function/class indexes
        chunk_results = chunk_directory(self.project_path)

        for cr in chunk_results:
            contexts = to_context_json(cr)
            for ctx in contexts:
                name = ctx.get("name", "")
                if not name or name == "<unknown>":
                    continue

                entry = {
                    "name": name,
                    "file": ctx.get("file", ""),
                    "signature": ctx.get("signature", ""),
                    "type": ctx.get("type", ""),
                    "lines": ctx.get("lines", ""),
                    "parent": ctx.get("parent"),
                }

                if ctx.get("type") == "class":
                    self._class_index.setdefault(name, []).append(entry)
                else:
                    self._func_index.setdefault(name, []).append(entry)

            # Build variable index from source
            self._build_var_index(cr.file_path, cr.full_source)
            # Build import index
            self._build_import_index(cr.file_path, cr.full_source)

        self._built = True
        return self

    def _build_var_index(self, file_path: str, source: str):
        """Extract variable names using tree-sitter when possible, regex fallback."""
        lang = _detect_language(file_path)
        grammar = _load_grammar(lang) if lang else None

        if grammar and source:
            try:
                from tree_sitter import Parser, Language
                lang_obj = Language(grammar.language())
                parser = Parser(lang_obj)
                tree = parser.parse(source.encode())
                vars_found = set()
                self._collect_variables(tree.root_node, source.encode(), vars_found)
                self._var_index[file_path] = vars_found
            except Exception:
                self._var_index[file_path] = self._regex_extract_vars(source)
        else:
            self._var_index[file_path] = self._regex_extract_vars(source)

    def _collect_variables(self, node, source_bytes: bytes, vars_found: set):
        """Recursively collect variable/parameter names from AST."""
        if node.type in ("assignment", "variable_declaration", "variable_declarator",
                         "let_declaration", "const_declaration", "var_declaration"):
            for child in node.children:
                if child.type in ("identifier", "variable_name", "name",
                                  "property_identifier"):
                    vars_found.add(source_bytes[child.start_byte:child.end_byte].decode())

        if node.type in ("parameters", "formal_parameters", "parameter_list",
                         "argument_list"):
            for child in node.children:
                if child.type in ("identifier", "variable_name", "name",
                                  "property_identifier"):
                    vars_found.add(source_bytes[child.start_byte:child.end_byte].decode())

        for child in node.children:
            self._collect_variables(child, source_bytes, vars_found)

    @staticmethod
    def _regex_extract_vars(source: str) -> set[str]:
        """Fallback: regex extraction of variable assignments."""
        patterns = [
            r'(?:var|let|const)\s+(\w+)',      # JS
            r'(\w+)\s*[:=]\s*',                 # assignment
            r'def\s+\w+\(([^)]*)\)',            # Python params
            r'function\s+\w+\(([^)]*)\)',       # JS params
            r'func\s+\w+\(([^)]*)\)',           # Go params
            r'(\w+)\s+\w+\s*=',                 # typed assignment
        ]
        vars_found = set()
        for pat in patterns:
            for m in re.finditer(pat, source):
                if m.lastindex and m.lastindex >= 1:
                    group = m.group(1)
                    for var in re.findall(r'\w+', group):
                        if len(var) > 1:
                            vars_found.add(var)
        return vars_found

    def _build_import_index(self, file_path: str, source: str):
        """Index imported modules and packages."""
        lang = _detect_language(file_path)
        imports = set()

        if lang == "python":
            for m in re.finditer(r'(?:import\s+(\w+)|from\s+(\w+))', source):
                imp = m.group(1) or m.group(2)
                if imp:
                    imports.add(imp)
        elif lang == "javascript":
            for m in re.finditer(r'(?:require\s*\(\s*["\']([^"\']+)["\']|import\s+.*?\s+from\s+["\']([^"\']+)["\'])', source):
                imp = m.group(1) or m.group(2)
                if imp:
                    imports.add(imp)
        elif lang == "go":
            for m in re.finditer(r'"([^"]+)"', source):
                imports.add(m.group(1))
        elif lang == "java":
            for m in re.finditer(r'import\s+([\w.]+)', source):
                imports.add(m.group(1))

        self._import_index[file_path] = imports

    # ── Hallucination Checks ─────────────────────────────────────

    def check(self, finding: dict, hook: dict | None = None) -> HallucinationReport:
        """Run all hallucination checks against a finding.

        Args:
            finding: A finding dict with at least description, title, poc_code.
            hook: Optional hook dict for file/function context.

        Returns:
            HallucinationReport with detailed results.
        """
        if not self._built:
            self.build_index()

        report = HallucinationReport()
        desc = finding.get("description", "") or finding.get("reason", "")
        poc = finding.get("poc_code", "") or finding.get("poc", "")
        title = finding.get("title", "")
        combined_text = f"{title}\n{desc}\n{poc}"

        # Resolve file context
        target_file = None
        if hook:
            raw_path = hook.get("file_path", "")
            if raw_path:
                if Path(raw_path).is_absolute():
                    target_file = Path(raw_path)
                else:
                    target_file = self.project_path / raw_path
                    if not target_file.exists():
                        target_file = None

        target_file_str = str(target_file) if target_file else ""

        # ── Check 1: Naming hallucination — fabricated filenames ──
        report.checks_run += 1
        file_issues = self._check_file_references(combined_text)
        for issue in file_issues:
            report.add_issue("naming_hallucination", issue)
        if not file_issues:
            report.checks_passed += 1

        # ── Check 2: Naming hallucination — fabricated function names ──
        report.checks_run += 1
        func_issues = self._check_function_references(combined_text, target_file_str)
        for issue in func_issues:
            report.add_issue("naming_hallucination", issue)
        if not func_issues:
            report.checks_passed += 1

        # ── Check 3: Mapping hallucination — wrong signatures ──
        report.checks_run += 1
        sig_issues = self._check_signature_claims(combined_text, target_file_str)
        for issue in sig_issues:
            report.add_issue("mapping_hallucination", issue, severity="error")
        if not sig_issues:
            report.checks_passed += 1

        # ── Check 4: Resource hallucination — non-existent imports ──
        report.checks_run += 1
        res_issues = self._check_resource_claims(combined_text, target_file_str)
        for issue in res_issues:
            report.add_issue("resource_hallucination", issue)
        if not res_issues:
            report.checks_passed += 1

        # ── Check 5: Logic hallucination — impossible claims ──
        report.checks_run += 1
        logic_issues = self._check_logic_claims(combined_text, target_file_str)
        for issue in logic_issues:
            report.add_issue("logic_hallucination", issue, severity="error")
        if not logic_issues:
            report.checks_passed += 1

        return report

    def _check_file_references(self, text: str) -> list[str]:
        """Check if AI mentions files that don't exist in the project."""
        issues = []
        # Find quoted file paths or dotted module references
        file_patterns = [
            r'["\']([^"\']+\.[a-z]{2,6})["\']',       # quoted filenames
            r'(?:file|File|path|Path)\s*["\']([^"\']+)["\']',  # file/path references
            r'(?:in|from)\s+["\']?([\w/.-]+\.[a-z]{2,6})["\']?',  # in/from references
        ]

        for pat in file_patterns:
            for m in re.finditer(pat, text):
                ref = m.group(1).strip()
                if not ref or ref.startswith(("http://", "https://", "/tmp", "/var")):
                    continue
                # Skip known library names
                if any(ref.startswith(p) for p in ("os.", "sys.", "re.", "json.",
                                                     "flask.", "django.", "sqlalchemy.",
                                                     "express", "react", "lodash")):
                    continue
                if ref not in self._file_index:
                    # Only flag if it looks like a real filename (has extension)
                    if re.search(r'\.[a-z]{2,6}$', ref):
                        issues.append(
                            f"Referenced file '{ref}' not found in project — possible naming hallucination"
                        )
        return issues

    def _check_function_references(self, text: str, target_file: str) -> list[str]:
        """Check if AI mentions functions that don't exist."""
        issues = []
        # Look for patterns like: "the X() function", "calls Y()", "Z() in"
        func_refs = re.findall(r'\b([a-z_]\w{2,40})\s*\(\)', text)

        # Build a merged index of all known names
        known_funcs = set(self._func_index.keys())
        known_classes = set(self._class_index.keys())

        for ref in func_refs:
            if ref in known_funcs or ref in known_classes:
                continue
            # Skip known builtins
            if ref in _BUILTINS:
                continue
            # Skip common English words that look like function calls
            if ref in _COMMON_WORDS:
                continue
            # Only flag if it appears multiple times (more likely a claim)
            count = len(re.findall(rf'\b{re.escape(ref)}\s*\(\)', text))
            if count >= 2:
                issues.append(
                    f"Function '{ref}()' referenced but not found in codebase — "
                    f"possible naming hallucination"
                )

        return issues

    def _check_signature_claims(self, text: str, target_file: str) -> list[str]:
        """Check if AI claims specific parameter names or return types that don't match."""
        issues = []
        # Look for claims like "X() takes Y parameter" or "returns Z"
        sig_claims = re.findall(
            r'(?:takes|accepts|receives|expects)\s+(?:a\s+|an\s+)?["\']?(\w+)["\']?\s+(?:parameter|argument|input)',
            text, re.IGNORECASE
        )

        if sig_claims and target_file and target_file in self._var_index:
            known_vars = self._var_index[target_file]
            for claimed_param in sig_claims:
                if len(claimed_param) > 2 and claimed_param not in known_vars:
                    issues.append(
                        f"AI claims parameter '{claimed_param}' exists in function, "
                        f"but it is not found in {target_file} — mapping hallucination"
                    )
        return issues

    def _check_resource_claims(self, text: str, target_file: str) -> list[str]:
        """Check if AI references libraries/modules not imported in the target file."""
        issues = []
        # Extract library references
        lib_refs = re.findall(
            r'(?:imports?|uses?|depends?\s+on|requires?|from)\s+["\']?(\w+(?:\.\w+)*)["\']?',
            text, re.IGNORECASE
        )

        if target_file and target_file in self._import_index:
            known_imports = self._import_index[target_file]
            for lib in lib_refs:
                if lib.lower() in _KNOWN_STDLIB:
                    continue
                # Check if the library root name is imported
                root = lib.split(".")[0]
                if root not in known_imports and not any(
                        i.startswith(root) for i in known_imports):
                    issues.append(
                        f"AI references library '{lib}' but it is not imported in "
                        f"{target_file} — possible resource hallucination"
                    )
        return issues

    def _check_logic_claims(self, text: str, target_file: str) -> list[str]:
        """Detect semantically impossible or contradictory claims."""
        issues = []

        # Pattern 1: "always" + "never" in same paragraph (contradiction)
        paragraphs = text.split("\n\n")
        for para in paragraphs:
            has_always = "always" in para.lower()
            has_never = "never" in para.lower()
            if has_always and has_never:
                issues.append(
                    "Paragraph contains both 'always' and 'never' — possible contradiction: "
                    f"'{para[:120]}...'"
                )
                break  # one is enough

        # Pattern 2: Claims about "return value" but PoC shows void/None
        if "return" in text.lower() or "returns" in text.lower():
            poc = ""
            poc_match = re.search(r'(?:PoC|poc|POC|exploit)[:\s]*```[^`]*```', text)
            if poc_match:
                poc = poc_match.group(0)
                if "return" not in poc and "print" not in poc:
                    issues.append(
                        "AI describes return behavior but PoC shows no return/print — "
                        "possible logic hallucination"
                    )

        # Pattern 3: Severity doesn't match CWE
        severity = ""
        cwe = ""
        sev_match = re.search(r'(?:severity|Severity)[:\s]*(critical|high|medium|low)', text)
        cwe_match = re.search(r'(CWE-\d+)', text)
        if sev_match:
            severity = sev_match.group(1)
        if cwe_match:
            cwe = cwe_match.group(1)
        if severity and cwe:
            expected = _CWE_SEVERITY_MAP.get(cwe)
            if expected and severity != expected:
                issues.append(
                    f"Severity '{severity}' inconsistent with {cwe} (expected '{expected}')"
                )

        return issues

    # ── Confidence Integration ────────────────────────────────────

    def compute_confidence_boost(self, finding: dict, hook: dict | None = None) -> float:
        """Run check and return the confidence boost (0 to +15).

        This is the L5+L7 scoring hook for the confidence scoring system.
        """
        report = self.check(finding, hook)
        if report.checks_run == 0:
            return 0.0
        ratio = report.checks_passed / report.checks_run
        # Scale: all pass → +15, half pass → +7.5, none → 0
        return round(ratio * 15.0, 1)


# ── Constants ────────────────────────────────────────────────────

_BUILTINS = {
    "print", "len", "range", "int", "str", "float", "bool", "list",
    "dict", "set", "tuple", "type", "isinstance", "hasattr", "getattr",
    "setattr", "delattr", "open", "input", "raw_input", "eval", "exec",
    "compile", "globals", "locals", "vars", "dir", "id", "hash", "repr",
    "format", "map", "filter", "reduce", "zip", "enumerate", "sorted",
    "reversed", "any", "all", "sum", "min", "max", "abs", "round",
    "console.log", "setTimeout", "setInterval", "fetch", "require",
    "module.exports", "exports", "define", "alert", "confirm",
    "fmt.Println", "fmt.Printf", "make", "append", "delete", "close",
    "System.out.println", "toString", "equals", "hashCode",
}

_COMMON_WORDS = {
    "this", "that", "then", "when", "where", "which", "while",
    "would", "could", "should", "about", "above", "after", "before",
    "during", "without", "within", "through", "between", "because",
    "first", "second", "third", "other", "another", "example",
    "following", "previous", "current", "original", "modified",
    "additional", "different", "similar", "specific", "general",
}

_KNOWN_STDLIB = {
    "os", "sys", "re", "json", "time", "datetime", "math", "random",
    "collections", "itertools", "functools", "typing", "io", "pathlib",
    "subprocess", "threading", "multiprocessing", "asyncio", "socket",
    "ssl", "hashlib", "base64", "struct", "pickle", "sqlite3",
    "logging", "argparse", "unittest", "http", "urllib", "xml",
    "csv", "configparser", "tempfile", "shutil", "glob", "fnmatch",
    "flask", "django", "fastapi", "requests", "numpy", "pandas",
    "express", "react", "vue", "angular", "jquery", "lodash",
    "fmt", "net/http", "encoding/json", "database/sql", "context",
    "bufio", "strings", "strconv", "sync", "errors", "io/ioutil",
}

_CWE_SEVERITY_MAP = {
    "CWE-89": "high",    # SQL Injection
    "CWE-78": "high",    # Command Injection
    "CWE-79": "medium",  # XSS
    "CWE-22": "high",    # Path Traversal
    "CWE-502": "high",   # Deserialization
    "CWE-798": "high",   # Hardcoded Credentials
    "CWE-862": "medium", # Missing Authorization
    "CWE-306": "high",   # Missing Authentication
    "CWE-200": "medium", # Information Leak
    "CWE-352": "medium", # CSRF
    "CWE-918": "high",   # SSRF
    "CWE-434": "high",   # Unrestricted File Upload
    "CWE-787": "critical", # Out-of-bounds Write
    "CWE-125": "high",   # Out-of-bounds Read
    "CWE-416": "high",   # Use After Free
    "CWE-476": "medium", # NULL Pointer Dereference
    "CWE-20":  "medium", # Improper Input Validation
}
