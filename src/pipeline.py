"""End-to-end pipeline — ties together extraction, chunking, DB, and LLM analysis.

Usage:
    D:/python/python.exe src/pipeline.py scan tests/fixtures       # scan directory
    D:/python/python.exe src/pipeline.py analyze                   # analyze pending hooks
    D:/python/python.exe src/pipeline.py run tests/fixtures        # full pipeline
    D:/python/python.exe src/pipeline.py stats                     # show DB stats

This script is the "verifiable minimum unit" for the complete Phase 1 pipeline.
"""

import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import get_db, Database
from feature_extractor import extract_hooks, extract_directory, summary as extract_summary
from code_chunker import chunk_file, to_context_json, chunk_summary
from preprocess.semgrep_runner import SemgrepRunner
from agents.scheduler import CollaborationScheduler, TokenBudgetExceeded


# --- LLM Integration (Ollama) ---

ANALYZE_HOOK_PROMPT = """You are a security code auditor. Analyze the following code for vulnerabilities.

## Code Context
File: {file_path}
Function: {func_name} (lines {line_start}-{line_end})
Language: {language}
Hook Type: {hook_type}
Trigger: suspicious call to `{called_function}()`

### Code Snippet
```
{snippet}
```

### Instructions
1. Determine if the suspicious call is a REAL vulnerability or a false positive
2. If real:
   - Describe the vulnerability type
   - Explain the attack vector
   - Rate severity: critical/high/medium/low/info
   - Assign a CWE ID if applicable
   - Explain how to fix it
3. If false positive:
   - Explain why it's not exploitable
4. Output your analysis in JSON format with keys:
   - verdict: "true_positive" | "false_positive" | "needs_review"
   - severity: "critical" | "high" | "medium" | "low" | "info"
   - title: short vulnerability title
   - description: detailed analysis
   - cwe_id: CWE identifier or null
   - confidence: 0.0 to 1.0

Output ONLY valid JSON, no other text."""


def analyze_hook_with_llm(hook: dict, model: str = "llama3.1:8b") -> dict | None:
    """[DEPRECATED] Use CollaborationScheduler.run_collaborative_audit() instead.

    Kept for backward compatibility. Delegates to the full pipeline.
    """
    print("  [INFO] analyze_hook_with_llm is deprecated. Use `pipeline.py run` instead.")
    return None

def cmd_scan(target_dir: str, db: Database | None = None, use_semgrep: bool = False):
    """Phase 1a: Scan directory, extract hooks + chunks, store in DB."""
    target = Path(target_dir)
    if not target.exists():
        print(f"ERROR: directory not found: {target_dir}")
        return

    print(f"Scanning: {target.resolve()}")
    t0 = time.time()

    # Step 0 (optional): Run Semgrep SAST before AST extraction
    semgrep_hook_ids: list[str] = []
    if use_semgrep:
        print("\n--- Semgrep SAST ---")
        runner = SemgrepRunner(db=db)
        semgrep_hook_ids = runner.scan(str(target))
        if semgrep_hook_ids:
            # Create tasks for Semgrep hooks so they enter the AI audit queue
            for hid in semgrep_hook_ids:
                db.create_task(
                    agent_id="code_auditor",
                    hook_id=hid,
                    task_type="analyze_hook",
                    status="queued",
                )
            print(f"  Semgrep hooks queued for AI audit: {len(semgrep_hook_ids)}")

    # Step 1: Extract hooks
    hook_results = extract_directory(target)
    h_summary = extract_summary(hook_results)
    print(f"  Hooks: {h_summary['total_hooks']} found in {h_summary['files_with_hooks']} files")

    # Step 2: Chunk files
    chunk_results = []
    for r in hook_results:
        if r.hooks:
            cr = chunk_file(r.file_path)
            chunk_results.append(cr)
    c_summary = chunk_summary(chunk_results)
    print(f"  Chunks: {c_summary['total_chunks']} generated from {c_summary['files_with_chunks']} files")

    # Step 3: Store in DB
    if db:
        for r in hook_results:
            for h in r.hooks:
                db.insert_hook(**h)
                db.create_task(
                    agent_id="code_auditor",
                    hook_id=h["hook_id"],
                    task_type="analyze_hook",
                    status="queued",
                )

        for cr in chunk_results:
            contexts = to_context_json(cr)
            for ctx in contexts:
                # Store context summary as a finding's raw_response for now
                # In production, this goes to a dedicated chunks table
                pass

        db.log_event("scan_completed", agent_id="pipeline",
                      detail=f"scanned {target_dir}: {h_summary['total_hooks']} hooks, "
                             f"{c_summary['total_chunks']} chunks")

    elapsed = time.time() - t0
    print(f"\nScan complete in {elapsed:.1f}s")
    print(f"  Severity breakdown: {h_summary['by_severity']}")
    print(f"  Hook type breakdown: {h_summary['by_type']}")

    return hook_results, chunk_results


def cmd_analyze(db: Database | None = None, model: str = "llama3.1:8b",
                 limit: int | None = None):
    """Analyze pending hooks using the full CollaborationScheduler pipeline.

    This now delegates to the Architect→Auditor two-agent pipeline,
    replacing the old single-model analyze. RAG knowledge base is
    automatically injected.
    """
    if db is None:
        db = get_db()
    db.init_schema()

    print("=" * 50)
    print("  VulnForge — Collaborative Analysis (Architect + Auditor)")
    print("=" * 50)

    pending = [h for h in db.list_hooks() if h["status"] == "pending"]
    if not pending:
        print("  No pending hooks to analyze.")
        return

    if limit:
        pending = pending[:limit]

    print(f"  Pending hooks: {len(pending)} (limit={limit or 'all'})")

    scheduler = CollaborationScheduler(db=db, model=model)

    # We need a project path — use the first hook's file_path to guess
    first_hook = pending[0]
    from pathlib import Path
    hook_path = Path(first_hook["file_path"])
    # Find project root: walk up until __init__.py found, then take parent.
    # Fallback to the scan target directory itself if no package structure detected.
    project_path = str(hook_path.parent)
    max_walk = 5
    for _ in range(max_walk):
        parent = str(Path(project_path).parent)
        if parent == project_path:
            break
        if (Path(parent) / "__init__.py").exists() or (Path(parent) / "setup.py").exists():
            project_path = parent
        else:
            break
    # Safety: if project_path walked too far, use the benchmarks dir
    if len(project_path) < 10 or project_path == str(Path.home()):
        project_path = str(hook_path.parent)

    print(f"  Project path: {project_path}")

    try:
        findings = scheduler.run_collaborative_audit(project_path)
        print(f"\n  Complete: {len(findings)} finding(s) generated.")
    except TokenBudgetExceeded as e:
        print(f"\n  [WARN] Token budget exceeded: {e}")
    except Exception as e:
        print(f"\n  [ERROR] Analysis failed: {type(e).__name__}: {e}")

def cmd_stats(db: Database | None = None):
    """Show current database statistics."""
    if db is None:
        db = get_db()
    s = db.stats()
    print("=" * 50)
    print("  VulnForge — Database Statistics")
    print("=" * 50)
    print(f"  Hooks total:       {s['hooks_total']}")
    print(f"  Hooks pending:     {s['hooks_pending']}")
    print(f"  Findings total:    {s['findings_total']}")
    print(f"  - True positive:   {s['findings_true_positive']}")
    print(f"  Tasks queued:      {s['tasks_queued']}")
    print(f"  Tasks running:     {s['tasks_running']}")
    print(f"  Events logged:     {s['events_logged']}")
    print("=" * 50)

    # Show recent findings
    findings = db.list_findings()
    if findings:
        print("\n  Recent findings:")
        for f in findings[-5:]:
            print(f"  [{f['severity']:7s}] {f['title'][:60]}")
            print(f"       Verdict: {f['verdict']:16s}  CWE: {f.get('cwe_id') or 'N/A'}")


def cmd_run(target_dir: str, model: str = "llama3.1:8b", limit: int = 3,
            use_semgrep: bool = False):
    """Full pipeline: scan + analyze."""
    db = get_db()
    db.init_schema()

    print("=" * 50)
    print("  VulnForge — Full Pipeline")
    print("=" * 50)

    cmd_scan(target_dir, db=db, use_semgrep=use_semgrep)
    print()
    cmd_analyze(db=db, model=model, limit=limit)
    print()
    cmd_stats(db=db)


# --- CLI Entry Point ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]

    if command == "scan":
        # Check for --semgrep flag
        args = sys.argv[2:]
        use_semgrep = "--semgrep" in args
        args = [a for a in args if a != "--semgrep"]
        target = args[0] if args else "tests/fixtures"
        db = get_db()
        db.init_schema()
        cmd_scan(target, db=db, use_semgrep=use_semgrep)
        cmd_stats(db=db)

    elif command == "analyze":
        model = sys.argv[2] if len(sys.argv) > 2 else "llama3.1:8b"
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 3
        cmd_analyze(model=model, limit=limit)

    elif command == "run":
        target = sys.argv[2] if len(sys.argv) > 2 else "tests/fixtures"
        model_default = "llama3.1:8b"
        try:
            import json
            config_path = Path(__file__).resolve().parent.parent / "wa_config.json"
            if config_path.exists():
                with open(config_path, encoding="utf-8") as fh:
                    raw = fh.read().lstrip("\ufeff")
                    model_default = json.loads(raw).get("model", {}).get("default", "llama3.1:8b")
        except Exception:
            pass
        model = sys.argv[3] if len(sys.argv) > 3 else model_default
        limit = int(sys.argv[4]) if len(sys.argv) > 4 else 3
        cmd_run(target, model=model, limit=limit)

    elif command == "stats":
        cmd_stats()

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)
