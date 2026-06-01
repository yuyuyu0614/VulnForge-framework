"""Semgrep integration — scan target project and write findings to hooks table.

Usage:
    runner = SemgrepRunner(db=get_db())
    hooks_written = runner.scan(project_path)

Each Semgrep finding becomes a hook with hook_type='semgrep'.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import get_db, Database


def _extract_func_name(check_id: str) -> str:
    """Extract a short func_name from the Semgrep check_id.

    e.g. 'python.sqlalchemy.security.sqlalchemy-execute-raw-query' → 'sqlalchemy-execute-raw-query'
    """
    return check_id.rsplit(".", 1)[-1]


def _make_dedup_key(finding: dict) -> tuple:
    """Create a deduplication key: (file_path, line_start, line_end, check_id)."""
    return (
        finding.get("path", ""),
        finding.get("start", {}).get("line", 0),
        finding.get("end", {}).get("line", 0),
        finding.get("check_id", ""),
    )


class SemgrepRunner:
    """Run Semgrep SAST on a project directory and ingest results."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_db()
        self.db.init_schema()

    def scan(self, project_path: str, config: str = "auto") -> list[str]:
        """Run semgrep scan and persist findings as hooks.

        Args:
            project_path: Path to the target project directory or file.
            config: Semgrep config (default 'auto' uses community rulesets).

        Returns:
            List of hook_ids inserted into the database.
        """
        project_path = str(Path(project_path).resolve())
        cmd = [
            "semgrep", "--config", config, "--json", "--quiet",
            "--no-git-ignore",
            project_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            print(f"  [WARN] Semgrep timed out after 300s on {project_path}")
            return []
        except FileNotFoundError:
            print("  [WARN] Semgrep CLI not found — install with: pip install semgrep")
            return []

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                print(f"  [WARN] Semgrep exited with code {result.returncode}: {stderr[:200]}")
            else:
                print(f"  [WARN] Semgrep exited with code {result.returncode} (no stderr)")

        if not result.stdout.strip():
            print("  Semgrep: no output returned")
            return []

        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"  [WARN] Semgrep JSON parse error: {e}")
            return []

        hook_dicts = self._parse_semgrep_output(raw)
        if not hook_dicts:
            print("  Semgrep: 0 findings after dedup")
            return []

        t0 = time.time()
        hook_ids = []
        for hd in hook_dicts:
            hid = self.db.insert_hook(**hd)
            hook_ids.append(hid)

        elapsed = time.time() - t0
        print(f"  Semgrep: {len(hook_ids)} hooks written in {elapsed:.2f}s "
              f"(deduped from {len(raw.get('results', []))} raw results)")
        return hook_ids

    def _parse_semgrep_output(self, raw: dict) -> list[dict]:
        """Parse semgrep --json output into a list of hook-compatible dicts.

        Deduplicates by (file_path, line_start, line_end, check_id).
        """
        results = raw.get("results", [])
        if not results:
            return []

        seen = set()
        hooks = []

        for finding in results:
            dedup_key = _make_dedup_key(finding)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            hook = self._to_hook(finding)
            if hook:
                hooks.append(hook)

        return hooks

    def _to_hook(self, finding: dict) -> dict | None:
        """Convert a single Semgrep finding to a hook dict for insert_hook()."""
        check_id = finding.get("check_id", "unknown")
        file_path = finding.get("path", "")
        start = finding.get("start", {})
        end = finding.get("end", {})
        extra = finding.get("extra", {})

        line_start = start.get("line")
        line_end = end.get("line")

        severity_map = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low",
        }
        severity = severity_map.get(extra.get("severity", "").upper(), "info")

        code_lines = extra.get("lines", "")
        message = extra.get("message", "")

        metadata = {
            "check_id": check_id,
            "risk_reason": message,
            "semgrep_severity": extra.get("severity", ""),
            "cwe": extra.get("metadata", {}).get("cwe", []),
            "owasp": extra.get("metadata", {}).get("owasp", []),
            "source_rule": extra.get("metadata", {}).get("source", ""),
        }

        return {
            "file_path": file_path,
            "func_name": _extract_func_name(check_id),
            "hook_type": "semgrep",
            "language": "python",
            "severity": severity,
            "line_start": line_start,
            "line_end": line_end,
            "snippet": code_lines if code_lines else message[:500],
            "metadata": json.dumps(metadata, ensure_ascii=False),
            "status": "pending",
            "confidence": 30.0,
        }
