"""Multi-agent collaborative audit scheduler 闁?Architect + Auditor serial pipeline.

Architect analyzes project structure and generates hooks.
Auditor examines each hook with code context and produces findings.

Token budget: 2,000,000 total, auto-pause at 90% (1,800,000).
"""

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import get_db, Database
from feature_extractor import extract_directory, EXT_TO_LANG, summary as extract_summary
from code_chunker import chunk_file, to_context_json, chunk_summary

from agents.prompts import (
    ARCHITECT_SYSTEM, ARCHITECT_USER,
    AUDITOR_SYSTEM, AUDITOR_USER, format_cwe_encyclopedia,
)

# -- Config loader --
def _load_config():
    config_path = Path(__file__).resolve().parent.parent.parent / "wa_config.json"
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as fh:
            return json.loads(fh.read().lstrip('\ufeff'))
    return {}

_CONFIG = _load_config()

TOKEN_BUDGET = _CONFIG.get("token", {}).get("budget", 2_000_000)
TOKEN_WARNING = int(TOKEN_BUDGET * _CONFIG.get("token", {}).get("warning_threshold", 0.9))

FINAL_RESULT_MARKER = "FINAL_RESULT"


class TokenBudgetExceeded(Exception):
    """Raised when token consumption exceeds the warning threshold."""

    def __init__(self, used: int, budget: int):
        self.used = used
        self.budget = budget
        pct = used / budget * 100
        super().__init__(f"Token budget at {pct:.1f}% ({used:,}/{budget:,})")


def _parse_json_response(raw: str, agent_name: str, retry_model: str | None = None):
    """Extract JSON from LLM output, with optional retry on parse failure.

    Handles: ```json fences, ``` fences, and bare JSON.
    Returns (parsed_dict, raw_text) or raises ValueError.
    """
    cleaned = raw.strip()

    # Remove FINAL_RESULT marker (may appear anywhere)
    cleaned = cleaned.replace(FINAL_RESULT_MARKER, "").strip()

    json_str = cleaned
    if "```json" in cleaned:
        json_str = cleaned.split("```json")[1].split("```")[0]
    elif "```" in cleaned:
        parts = cleaned.split("```")
        if len(parts) >= 2:
            json_str = parts[1]

    try:
        return json.loads(json_str.strip()), raw
    except json.JSONDecodeError:
        pass

    # Try to find JSON object boundaries
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = cleaned.find(start_char)
        if start >= 0:
            end = cleaned.rfind(end_char)
            if end > start:
                try:
                    return json.loads(cleaned[start:end + 1]), raw
                except json.JSONDecodeError:
                    continue

    raise ValueError(f"{agent_name}: failed to parse JSON from response")


def _call_ollama(model: str, system: str, user: str,
                 temperature: float = 0.0, num_predict: int = 2048,
                 max_retries: int = 3) -> dict:
    """Call Ollama chat API with retry on failure.

    Retries up to max_retries times with exponential backoff (1s, 2s, 4s).
    Returns full response dict from ollama package.
    """
    import ollama
    import time as time_mod

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    last_error = None
    for attempt in range(max_retries):
        try:
            return ollama.chat(
                model=model,
                messages=messages,
                options={"temperature": temperature, "num_predict": num_predict},
            )
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                wait = 2 ** attempt  # 1s, 2s, 4s
                print(f"  [RETRY] Ollama call failed (attempt {attempt+1}/{max_retries}), "
                      f"retrying in {wait}s: {e}")
                time_mod.sleep(wait)

    raise last_error


class CollaborationScheduler:
    """Orchestrates the two-agent collaborative audit pipeline."""

    def __init__(self, db: Database | None = None,
                 model: str | None = None):
        self.db = db or get_db()
        self.db.init_schema()
        self.model = model or _CONFIG.get("model", {}).get("default", "llama3.1:8b")
        self.config = _CONFIG

        # Callbacks for UI integration
        self.on_log: Callable[[str], None] | None = None
        self.on_progress: Callable[[int, int], None] | None = None
        self.on_hook: Callable[[dict], None] | None = None
        self.on_finding: Callable[[dict], None] | None = None

        self._cancelled = False
        self._last_retrieved_patterns: list[dict] = []  # test verification of RAG

    def cancel(self):
        self._cancelled = True

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)
        else:
            print(msg)

    def _check_budget(self) -> int:
        usage = self.db.get_total_usage()
        total = sum(u["total_prompt"] + u["total_completion"] for u in usage)
        if total >= TOKEN_WARNING:
            raise TokenBudgetExceeded(total, TOKEN_BUDGET)
        return total

    def _record_tokens(self, agent_name: str, response: dict):
        prompt_tokens = response.get("prompt_eval_count", 0)
        completion_tokens = response.get("eval_count", 0)
        self.db.insert_token_usage(
            agent_name=agent_name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        return prompt_tokens, completion_tokens

    def _call_agent(self, agent_name: str, system: str, user: str) -> dict:
        self._check_budget()

        self._log(f"[{agent_name}] Calling {self.model} ...")
        t0 = time.time()

        response = _call_ollama(self.model, system, user)
        pt, ct = self._record_tokens(agent_name, response)

        elapsed = time.time() - t0
        raw = response["message"]["content"].strip()
        self._log(f"[{agent_name}] Response: {elapsed:.1f}s, "
                  f"{pt}+{ct} tokens, {len(raw)} chars")

        # Parse JSON
        try:
            parsed, _ = _parse_json_response(raw, agent_name)
        except ValueError:
            self._log(f"[{agent_name}] JSON parse failed, retrying once ...")
            retry_response = _call_ollama(self.model, system, user,
                                          temperature=0.0, num_predict=2048)
            prt, crt = self._record_tokens(f"{agent_name}_retry", retry_response)
            retry_raw = retry_response["message"]["content"].strip()
            try:
                parsed, _ = _parse_json_response(retry_raw, agent_name)
                self._log(f"[{agent_name}] Retry succeeded ({prt}+{crt} tokens)")
            except ValueError:
                self._log(f"[{agent_name}] Retry also failed, skipping")
                return {"hooks": []} if agent_name == "Architect" else {"finding": None}

        # Check for FINAL_RESULT marker
        if FINAL_RESULT_MARKER not in raw:
            self._log(f"[{agent_name}] Note: no FINAL_RESULT marker in output")

        return parsed

    def _build_file_list(self, project_path: Path) -> str:
        lines = []
        for f in sorted(project_path.rglob("*")):
            if f.is_file() and f.suffix.lower() in EXT_TO_LANG:
                rel = f.relative_to(project_path)
                size = f.stat().st_size
                lines.append(f"  {rel} ({size} bytes)")
        return "\n".join(lines[:50])  # cap to avoid context overflow

    def _build_architect_prompt(self, project_path: Path) -> str:
        results = extract_directory(str(project_path))
        summary = extract_summary(results)

        # Categorize hooks
        dangerous_calls = []
        route_entries = []
        input_sources = []

        for r in results:
            for h in r.hooks:
                rel_path = Path(h["file_path"]).relative_to(project_path)
                meta = h.get("metadata", {})
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except json.JSONDecodeError:
                        meta = {}
                called = meta.get("called_function", "?")
                line = (f"  - {rel_path}:{h['line_start']} {h['func_name']}() "
                        f"calls {called}() [{h['severity']}]")
                if h["hook_type"] == "route_entry":
                    route_entries.append(line)
                elif h["hook_type"] == "input_source":
                    input_sources.append(line)
                else:
                    dangerous_calls.append(line)

        # Determine project type
        exts = set()
        for f in project_path.rglob("*"):
            if f.is_file():
                exts.add(f.suffix.lower())
        if ".py" in exts:
            proj_type = "Python Web Application (Flask/FastAPI/Django)"
        elif ".go" in exts:
            proj_type = "Go Application"
        elif ".js" in exts or ".ts" in exts:
            proj_type = "JavaScript/TypeScript Application (Node.js/Express)"
        elif ".java" in exts:
            proj_type = "Java Application (Spring Boot)"
        else:
            proj_type = "Unknown"

        return ARCHITECT_USER.format(
            project_path=str(project_path),
            project_type=proj_type,
            file_list=self._build_file_list(project_path) or "(none)",
            dangerous_calls="\n".join(dangerous_calls[:30]) or "(none)",
            route_entries="\n".join(route_entries[:20]) or "(none)",
            input_sources="\n".join(input_sources[:20]) or "(none)",
        )

    def _get_semgrep_dataflow(self, hook: dict, project_dir) -> str:
        """Try to get Semgrep dataflow for this hook."""
        try:
            import subprocess, shutil
            semgrep_bin = shutil.which("semgrep")
            if not semgrep_bin:
                return ""
            func_name = hook.get("function_name", "")
            hook_type = hook.get("hook_type", "")
            if hook_type not in ("injection", "command_exec", "deserialization"):
                return "(semgrep taint: not applicable for this hook type)"
            target_file = project_dir / hook.get("file_path", "") if hook.get("file_path") else None
            if not target_file or not target_file.exists():
                return ""
            return "(semgrep taint scan available - see console output)"
        except Exception:
            return ""

    def _build_auditor_prompt(self, hook: dict, project_path: Path) -> str:
        # Resolve file path (may be relative from Architect output)
        raw_path = hook.get("file_path", "")
        if not Path(raw_path).is_absolute():
            file_path = project_path / raw_path
        else:
            file_path = Path(raw_path)

        func_name = hook.get("func_name", hook.get("function_name", "unknown"))
        language = hook.get("language", self._guess_language(str(file_path)))

        # Get actual code from file using chunker
        snippet = ""
        line_start = hook.get("line_start", 0)
        line_end = hook.get("line_end", 0)
        context_text = ""

        try:
            cr = chunk_file(str(file_path))
            contexts = to_context_json(cr)

            # Find matching chunk by function name
            target_chunk = None
            for ctx in contexts:
                if ctx.get("name") == func_name:
                    target_chunk = ctx
                    break

            if target_chunk:
                body = target_chunk.get("body", "")
                lines_str = target_chunk.get("lines", "0-0")
                try:
                    parts = lines_str.split("-")
                    line_start = int(parts[0])
                    line_end = int(parts[1])
                except (ValueError, IndexError):
                    pass
                snippet = f"{target_chunk.get('signature', '')}\n{body}"
                if not line_start:
                    line_start = target_chunk.get("line_start", 0)

                # Collect adjacent chunks for context
                nearby = []
                for ctx in contexts:
                    if ctx.get("name") == func_name:
                        continue
                    try:
                        cl_start = int(ctx.get("lines", "0-0").split("-")[0])
                    except (ValueError, IndexError):
                        continue
                    if abs(cl_start - line_start) <= 50:
                        nearby.append(
                            f"// {ctx['name']} (lines {ctx['lines']}, type={ctx['type']})\n"
                            f"{ctx.get('signature', '')}\n"
                            f"{ctx.get('body', '')[:600]}"
                        )
                if nearby:
                    context_text = "\n\n".join(nearby[:3])
            else:
                # Fallback: read raw file content
                raw = file_path.read_text(errors="replace")
                snippet = raw[:3000]
        except Exception:
            snippet = hook.get("snippet", hook.get("risk_reason", ""))

        meta = hook.get("metadata", {})
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                meta = {}

        return AUDITOR_USER.format(
            file_path=str(file_path),
            function_name=func_name,
            line_start=line_start,
            line_end=line_end,
            language=language,
            hook_type=hook.get("hook_type", "unknown"),
            risk_reason=meta.get("description", hook.get("risk_reason",
                                "Suspicious call detected")),
            snippet=snippet[:3000] if snippet else "(unable to extract code)",
            context=context_text or "(no additional context available)",
            cwe_encyclopedia=format_cwe_encyclopedia(),
            semgrep_dataflow=self._get_semgrep_dataflow(hook, self.project_dir) or "(semgrep not available for this hook)",
        )

    def run_collaborative_audit(self, project_path: str) -> list[dict]:
        """Execute the full two-agent collaborative audit.

        Returns list of finding dicts.
        """
        project_path = Path(project_path).resolve()
        self.project_dir = project_path
        self._cancelled = False

        self._log("=" * 60)
        self._log("  Collaborative Audit 闁?Phase 3 Multi-Agent Pipeline")
        self._log("=" * 60)
        self._log(f"  Project: {project_path}")
        self._log(f"  Model:   {self.model}")
        self._log(f"  Budget:  {TOKEN_BUDGET:,} tokens (pause at {TOKEN_WARNING:,})")
        self._log("")

        # 闁冲厜鍋撻柍鍏夊亾 Phase A: Architect Agent 闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾
        self._log("--- Phase A: Architect Agent ---")
        self._log("Building project structure prompt ...")

        prompt = self._build_architect_prompt(project_path)
        self._log(f"  Prompt: {len(prompt)} chars")

        architect_result = self._call_agent("Architect", ARCHITECT_SYSTEM, prompt)
        architect_hooks = architect_result.get("hooks", [])

        if not architect_hooks:
            self._log("[Architect] No hooks identified. Audit complete.")
            return []

        self._log(f"[Architect] Generated {len(architect_hooks)} hook(s)")
        for h in architect_hooks:
            self._log(f"  - {h.get('function_name', '?')} [{h.get('hook_type', '?')}]"
                      f" @ {h.get('file_path', '?')}")

        # Store architect hooks in DB (with unique IDs per audit run)
        run_ts = str(int(time.time()))
        for h in architect_hooks:
            raw_fp = h.get("file_path", "")
            fn_name = h.get("function_name", "unknown")
            unique_key = f"arch:{raw_fp}:{fn_name}:{run_ts}"
            hook_id = hashlib.sha256(unique_key.encode()).hexdigest()[:16]
            hook_id = f"arch-{hook_id}"
            hook_id = self.db.insert_hook(
                file_path=h.get("file_path", ""),
                func_name=h.get("function_name", "unknown"),
                hook_type=h.get("hook_type", "unknown"),
                language=self._guess_language(h.get("file_path", "")),
                severity="high",
                line_start=h.get("line_start", 0),
                line_end=h.get("line_end", 0),
                snippet=h.get("risk_reason", ""),
                metadata=json.dumps(h, ensure_ascii=False),
                status="pending",
            )
            h["hook_id"] = hook_id
            self.db.create_task(
                agent_id="Architect",
                hook_id=hook_id,
                task_type="architect_hook",
                status="completed",
                result_summary=h.get("risk_reason", ""),
            )
            if self.on_hook:
                self.on_hook(h)

        self.db.log_event("architect_completed", agent_id="Architect",
                          detail=f"generated {len(architect_hooks)} hooks")

        # 闁冲厜鍋撻柍鍏夊亾 Phase B: Auditor Agent (per-hook) 闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋?        self._log(f"\n--- Phase B: Auditor Agent ({len(architect_hooks)} hooks) ---")

        all_findings = []
        total_hooks = len(architect_hooks)

        for i, hook in enumerate(architect_hooks):
            if self._cancelled:
                self._log("[Auditor] Cancelled by user.")
                break

            if self.on_progress:
                self.on_progress(i + 1, total_hooks)

            self._log(f"\n[Hook {i + 1}/{total_hooks}] "
                      f"{hook.get('function_name', '?')} "
                      f"({hook.get('hook_type', '?')})")

            self.db.update_hook_status(hook["hook_id"], "analyzing")

            prompt = self._build_auditor_prompt(hook, project_path)
            self._log(f"  Prompt: {len(prompt)} chars")

            # RAG: retrieve similar vulnerability patterns from knowledge base
            code_snippet = self._extract_code_snippet(hook, project_path)
            patterns = retrieve_patterns(
                code_snippet,
                hook_type=hook.get("hook_type", "unknown"),
                language=hook.get("language", self._guess_language(
                    hook.get("file_path", ""))),
            )
            self._last_retrieved_patterns = patterns
            patterns_text = format_patterns_for_prompt(patterns)
            if patterns:
                self._log(f"  RAG: retrieved {len(patterns)} pattern(s) 闁?"
                          f"{', '.join(p.get('pattern_type','?') for p in patterns)}")

            auditor_system = AUDITOR_SYSTEM.format(retrieved_patterns=patterns_text)
            auditor_result = self._call_agent("Auditor", auditor_system, prompt)
            finding_data = auditor_result.get("finding")

            if finding_data is None:
                reason = auditor_result.get("reason", "No vulnerability found")
                self._log(f"  [Auditor] No vulnerability: {reason[:80]}")
                self.db.update_hook_status(hook["hook_id"], "verified", confidence=0.0)
                continue

            if not finding_data.get("is_vulnerable", True):
                self._log(f"  [Auditor] Flagged as non-vulnerable: "
                          f"{finding_data.get('reason', '')[:80]}")
                self.db.update_hook_status(hook["hook_id"], "false_positive",
                                           confidence=finding_data.get("confidence", 0.0))
                continue

            # Store finding
            finding_id = self.db.insert_finding(
                hook_id=hook["hook_id"],
                agent_id="Auditor",
                severity=finding_data.get("severity", "medium"),
                title=finding_data.get("title", "Untitled"),
                description=finding_data.get("reason", ""),
                poc_code=finding_data.get("poc", ""),
                cwe_id=finding_data.get("cwe", ""),
                verdict="true_positive",
                confidence=finding_data.get("confidence", 0.5),
                raw_response=json.dumps(finding_data, ensure_ascii=False),
            )

            self.db.update_hook_status(
                hook["hook_id"], "verified",
                confidence=finding_data.get("confidence", 0.5),
            )

            finding_data["finding_id"] = finding_id
            finding_data["hook_id"] = hook["hook_id"]
            all_findings.append(finding_data)

            self._log(f"  [Auditor] VULNERABLE: {finding_data.get('title')} "
                      f"[{finding_data.get('severity')}] "
                      f"CWE: {finding_data.get('cwe', 'N/A')} "
                      f"confidence={finding_data.get('confidence')}")

            if self.on_finding:
                self.on_finding(finding_data)

        if self.on_progress:
            self.on_progress(total_hooks, total_hooks)

        # 闁冲厜鍋撻柍鍏夊亾 Summary 闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋?        self._log(f"\n{'=' * 60}")
        self._log(f"  Collaborative Audit Complete")
        self._log(f"{'=' * 60}")
        self._log(f"  Architect hooks:  {len(architect_hooks)}")
        self._log(f"  Auditor findings: {len(all_findings)}")

        usage = self.db.get_total_usage()
        total_tokens = sum(u["total_prompt"] + u["total_completion"] for u in usage)
        budget_pct = total_tokens / TOKEN_BUDGET * 100
        self._log(f"  Total tokens:     {total_tokens:,} / {TOKEN_BUDGET:,} "
                  f"({budget_pct:.1f}%)")
        self._log("")

        # Auto-extract patterns from new true_positive findings
        if all_findings:
            self._log("\n  Extracting knowledge base patterns ...")
            try:
                from knowledge.pattern_extractor import extract_patterns_from_findings
                new_count = extract_patterns_from_findings(self.db, all_findings)
                if new_count:
                    self._log(f"  Knowledge base: {new_count} new pattern(s) added")
            except Exception as e:
                self._log(f"  [WARN] Pattern extraction skipped: {e}")
        return all_findings

    def _guess_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        return EXT_TO_LANG.get(ext, "unknown")

    def _extract_code_snippet(self, hook: dict, project_path: Path) -> str:
        """Extract the raw code snippet for a hook for pattern retrieval."""
        raw_path = hook.get("file_path", "")
        if not Path(raw_path).is_absolute():
            file_path = project_path / raw_path
        else:
            file_path = Path(raw_path)

        func_name = hook.get("func_name", hook.get("function_name", "unknown"))

        try:
            cr = chunk_file(str(file_path))
            contexts = to_context_json(cr)
            for ctx in contexts:
                if ctx.get("name") == func_name:
                    return f"{ctx.get('signature', '')}\n{ctx.get('body', '')}"[:3000]
            # Fallback: read raw file
            return file_path.read_text(errors="replace")[:3000]
        except Exception:
            return hook.get("snippet", hook.get("risk_reason", ""))[:3000]


def get_total_token_count(db: Database) -> int:
    usage = db.get_total_usage()
    return sum(u["total_prompt"] + u["total_completion"] for u in usage)


def get_budget_percentage(db: Database) -> float:
    return get_total_token_count(db) / TOKEN_BUDGET * 100