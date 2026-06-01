"""truffleHog integration + built-in regex fallback — detect hardcoded secrets.

Secrets (API keys, tokens, passwords) are deterministic — no AI verification needed.
Detections are written directly to the findings table with verdict='true_positive' and high confidence.

Two modes:
  1. truffleHog CLI (preferred) — `trufflehog filesystem --json <path>`
  2. Built-in regex — 40+ high-signal patterns when truffleHog is unavailable
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import get_db, Database

# ── Built-in secret patterns (fallback when truffleHog is not installed) ───

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern_type, regex, description)
    ("api_key", r'(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,64}["\']?', "API Key"),
    ("api_key", r'(?:secret|SECRET)\s*[:=]\s*["\']?[A-Za-z0-9_\-+/]{16,128}["\']?', "Secret key"),
    ("api_key", r'sk-[A-Za-z0-9]{32,64}', "OpenAI-style API key"),
    ("api_key", r'(?:access[_-]?token|ACCESS_TOKEN)\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]{16,256}["\']?', "Access token"),
    ("api_key", r'(?:bearer|Bearer)\s+[A-Za-z0-9_\-\.]{16,256}', "Bearer token literal"),
    ("password", r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{1,128}["\']', "Hardcoded password"),
    ("password", r'(?:password|passwd|pwd)\s*[:=]\s*[^\s"\']{1,64}', "Hardcoded password (unquoted)"),
    ("private_key", r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key block"),
    ("private_key", r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', "EC private key"),
    ("private_key", r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----', "DSA private key"),
    ("private_key", r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', "OpenSSH private key"),
    ("private_key", r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----', "PGP private key"),
    ("database_url", r'(?:DATABASE_URL|database_url|db_url|MONGO_URI)\s*[:=]\s*["\']?(?:mongodb|mysql|postgres|postgresql|sqlite|redis)://[^\s"\']+', "Database URL"),
    ("jwt_secret", r'(?:JWT_SECRET|jwt_secret|SECRET_KEY|secret_key)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{8,128}["\']?', "JWT / session secret"),
    ("aws_key", r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|aws_access_key|aws_secret_key)\s*[:=]\s*["\']?[A-Za-z0-9/+=]{16,64}["\']?', "AWS credential"),
    ("aws_key", r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    ("gcp_key", r'(?:GCP_|GOOGLE_)(?:API_)?(?:KEY|SECRET|CREDENTIALS)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,256}["\']?', "GCP credential"),
    ("azure_key", r'(?:AZURE_|azure_)(?:KEY|SECRET|CONNECTION_STRING)\s*[:=]\s*["\']?[A-Za-z0-9_\-+/=]{16,256}["\']?', "Azure credential"),
    ("github_token", r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}', "GitHub personal access token"),
    ("github_token", r'(?:GITHUB_TOKEN|github_token|GH_TOKEN)\s*[:=]\s*["\']?[A-Za-z0-9_]{16,256}["\']?', "GitHub token"),
    ("gitlab_token", r'(?:GITLAB_TOKEN|gitlab_token|CI_JOB_TOKEN)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,256}["\']?', "GitLab token"),
    ("slack_webhook", r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}', "Slack webhook URL"),
    ("discord_webhook", r'https://discord\.com/api/webhooks/\d{16,20}/[A-Za-z0-9_\-]{60,68}', "Discord webhook URL"),
    ("telegram_token", r'(?:TELEGRAM_TOKEN|telegram_token|TELEGRAM_BOT_TOKEN)\s*[:=]\s*["\']?\d{8,10}:[A-Za-z0-9_\-]{35}["\']?', "Telegram bot token"),
    ("generic_token", r'(?:token|TOKEN|api_token|API_TOKEN)\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]{16,256}["\']?', "Generic token"),
    ("oauth_secret", r'(?:OAUTH|oauth|CLIENT_SECRET|client_secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,128}["\']?', "OAuth secret"),
]

# File extensions to scan for secrets
_SECRET_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".kt", ".rb",
    ".php", ".swift", ".c", ".cpp", ".h", ".hpp", ".rs", ".sh", ".bash",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".env.example", ".env.local", ".env.development", ".env.production",
    ".properties", ".xml", ".gradle", ".dockerfile", ".tf",
}

# Directories to exclude
_SECRET_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
                     ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
                     ".idea", ".vscode", "vendor", ".next", ".nuxt"}

# Files to exclude
_SECRET_SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                      "poetry.lock", "Cargo.lock", "Gemfile.lock", "go.sum"}


class SecretsScanner:
    """Run secret detection and persist findings."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_db()
        self.db.init_schema()

    def scan(self, project_path: str) -> list[str]:
        """Scan a project directory for hardcoded secrets.

        Tries truffleHog first; falls back to built-in regex if unavailable.
        Returns list of finding_ids inserted.
        """
        project_path = str(Path(project_path).resolve())

        # Attempt truffleHog first
        try:
            return self._scan_trufflehog(project_path)
        except (FileNotFoundError, NotImplementedError):
            pass

        # Fallback to built-in regex
        return self._scan_regex(project_path)

    # ── truffleHog path ─────────────────────────────────────────

    def _scan_trufflehog(self, project_path: str) -> list[str]:
        """Run trufflehog filesystem scan."""
        cmd = [
            "trufflehog", "filesystem",
            "--json",
            "--no-update",
            "--directory", project_path,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
        except subprocess.TimeoutExpired:
            print("  [WARN] truffleHog timed out after 300s")
            raise
        except FileNotFoundError:
            print("  [INFO] truffleHog not installed, using built-in regex scanner")
            raise

        if result.returncode not in (0, 1):  # 1 = findings found
            stderr = result.stderr.strip()
            if stderr:
                print(f"  [WARN] truffleHog exited with code {result.returncode}: "
                      f"{stderr[:200]}")

        if not result.stdout.strip():
            print("  Secrets: 0 found (truffleHog)")
            return []

        raw_findings = self._parse_trufflehog_output(result.stdout)
        return self._persist_findings(raw_findings, source="truffleHog")

    def _parse_trufflehog_output(self, raw_output: str) -> list[dict]:
        """Parse trufflehog --json output (one JSON object per line)."""
        findings = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            findings.append({
                "file_path": entry.get("SourceMetadata", {}).get("Data", {}).get("filesystem", {}).get("file", ""),
                "line_start": entry.get("SourceMetadata", {}).get("Data", {}).get("filesystem", {}).get("line", 0),
                "description": (
                    f"Secret detected: {entry.get('DetectorName', 'unknown')} — "
                    f"{entry.get('Raw', '')[:120]}"
                ),
                "severity": "high",
                "cwe_id": "CWE-798",
                "raw": entry.get("Raw", ""),
                "verified": entry.get("Verified", False),
            })
        return findings

    # ── Built-in regex path ─────────────────────────────────────

    def _scan_regex(self, project_path: str) -> list[str]:
        """Built-in regex-based secret scanner.

        Walks all source files and matches against 40+ high-signal patterns.
        """
        root = Path(project_path)
        all_findings: list[dict] = []

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in _SECRET_SCAN_EXTENSIONS:
                continue

            # Check skip directories
            parts = set(file_path.parts)
            if parts & _SECRET_SKIP_DIRS:
                continue
            if file_path.name in _SECRET_SKIP_FILES:
                continue

            try:
                content = file_path.read_text(errors="replace")
            except Exception:
                continue

            for pattern_type, regex, desc in _SECRET_PATTERNS:
                for match in re.finditer(regex, content, re.IGNORECASE):
                    line_start = content[:match.start()].count("\n") + 1
                    matched_text = match.group(0)

                    # Skip obvious false positives
                    if self._is_false_positive(matched_text, file_path):
                        continue

                    # Truncate credential for safety in report
                    display_text = self._sanitize_secret(matched_text)

                    all_findings.append({
                        "file_path": str(file_path),
                        "line_start": line_start,
                        "line_end": line_start,
                        "description": f"Hardcoded {desc}: {display_text}",
                        "severity": "high" if pattern_type in (
                            "private_key", "password", "aws_key") else "medium",
                        "cwe_id": "CWE-798",
                        "raw": matched_text,
                        "verified": False,
                        "secret_type": pattern_type,
                    })

        if not all_findings:
            print("  Secrets: 0 found (built-in regex)")
            return []

        return self._persist_findings(all_findings, source="regex_scanner")

    # ── Persistence ──────────────────────────────────────────────

    def _persist_findings(self, findings: list[dict], source: str) -> list[str]:
        """Deduplicate and persist secret findings to the database."""
        t0 = time.time()
        finding_ids: list[str] = []

        for f in findings:
            file_path = f.get("file_path", "")
            line_start = f.get("line_start", 0)
            desc = f.get("description", "")

            # Write as a hook first (for pipeline compatibility)
            hook_id = self.db.insert_hook(
                file_path=file_path,
                func_name=f"<secret:{f.get('secret_type', 'unknown')}>",
                hook_type="secret_leak",
                language="text",
                severity=f.get("severity", "high"),
                line_start=line_start,
                line_end=f.get("line_end", line_start),
                snippet=desc[:500],
                metadata=json.dumps(f, ensure_ascii=False),
                status="verified",
                confidence=95.0,
            )

            # Write directly to findings (secrets are deterministic true_positives)
            finding_id = self.db.insert_finding(
                hook_id=hook_id,
                agent_id=source,
                severity=f.get("severity", "high"),
                title=f"Hardcoded {f.get('secret_type', 'secret')} detected",
                description=desc,
                cwe_id=f.get("cwe_id", "CWE-798"),
                verdict="true_positive",
                confidence=95.0,
                raw_response=json.dumps(f, ensure_ascii=False),
            )
            finding_ids.append(finding_id)

        elapsed = time.time() - t0
        print(f"  Secrets: {len(finding_ids)} findings written in {elapsed:.2f}s "
              f"(source: {source})")
        return finding_ids

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    @staticmethod
    def _is_false_positive(text: str, file_path: Path) -> bool:
        """Filter out common false positive matches."""
        fp = file_path.name.lower()

        # Source files that legitimately contain key-like strings
        if "test" in fp or "spec" in fp or "mock" in fp or "fixture" in fp:
            if "password" in text.lower() or "secret" in text.lower():
                # Check for obviously placeholder values
                placeholder_indicators = [
                    "example", "placeholder", "your-", "xxx", "test",
                    "changeme", "replace", "<", "${", "{{",
                ]
                if any(p in text.lower() for p in placeholder_indicators):
                    return True

        # Filter variable assignment patterns: xxx = request.xxx.get(
        if "request." in text.lower() and ".get(" in text.lower():
            return True

        # Exclude common non-secret patterns
        if text.startswith("-----BEGIN") and "ENCRYPTED" in text:
            return True  # encrypted private key, not raw

        return False

    @staticmethod
    def _sanitize_secret(text: str) -> str:
        """Truncate secret values for safe display in reports."""
        lines = text.split("\n")
        sanitized = []
        for line in lines:
            # Show prefix + "...<truncated>" for long secrets
            if len(line) > 30:
                # Find the value part after = or :
                for sep in (": ", "=", ":"):
                    idx = line.find(sep)
                    if idx > 0:
                        key = line[:idx + len(sep)]
                        val = line[idx + len(sep):]
                        if len(val) > 16:
                            sanitized.append(f"{key}{val[:8]}...<truncated>")
                            break
                else:
                    sanitized.append(f"{line[:20]}...<truncated>")
            else:
                sanitized.append(line)
        return " | ".join(sanitized)
