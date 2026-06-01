"""End-to-end test: scan -> hook -> LLM analysis -> finding -> DB.

Verifies the complete chain from code scanning to vulnerability discovery.
Target: vuln_demo Flask app with deliberate SQL injection flaws.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from db import get_db
from feature_extractor import extract_directory
from pipeline import ANALYZE_HOOK_PROMPT

DEMO_DIR = Path(__file__).resolve().parent / "fixtures" / "vuln_demo"


def _resolve_model() -> str:
    import ollama

    available = set()
    try:
        for m in ollama.list().get("models", []):
            available.add(m.model if hasattr(m, 'model') else m["model"])
    except Exception:
        pass

    candidates = [
        "alpernae/qwen2.5-auditor:latest",
        "alpernae/qwen2.5-auditor",
        "qwen2.5-coder:7b",
        "llama3.1:8b",
    ]
    for c in candidates:
        if c in available:
            return c
    return "llama3.1:8b"


def call_ollama(model: str, prompt: str, temperature: float = 0.0) -> dict:
    import ollama

    response = ollama.chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": temperature, "num_predict": 1024},
    )
    raw = response["message"]["content"].strip()

    json_str = raw
    if "```json" in raw:
        json_str = raw.split("```json")[1].split("```")[0]
    elif "```" in raw:
        json_str = raw.split("```")[1].split("```")[0]

    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        print(f"  [WARN] Failed to parse JSON from model output:")
        print(f"  Raw: {raw[:500]}")
        parsed = {
            "verdict": "needs_review",
            "severity": "info",
            "title": "JSON parse failed",
            "description": raw,
            "cwe_id": None,
            "confidence": 0.0,
        }

    return {
        "parsed": parsed,
        "raw": raw,
        "prompt_eval_count": response.get("prompt_eval_count", 0),
        "eval_count": response.get("eval_count", 0),
    }


def build_audit_prompt(hook: dict) -> str:
    metadata = hook.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {}

    snippet = hook.get("snippet", metadata.get("description", ""))

    return ANALYZE_HOOK_PROMPT.format(
        file_path=hook["file_path"],
        func_name=hook.get("func_name", "unknown"),
        line_start=hook.get("line_start", 0),
        line_end=hook.get("line_end", 0),
        language=hook.get("language", "unknown"),
        hook_type=hook.get("hook_type", "unknown"),
        called_function=metadata.get("called_function", "unknown"),
        snippet=snippet[:3000],
    )


def test_e2e_pipeline():
    db = get_db()
    db.init_schema()

    model = _resolve_model()
    print(f"Model: {model}")
    print(f"Target: {DEMO_DIR.resolve()}")
    print()

    # ── Step 1: Scan ──────────────────────────────────────────────
    print("[1/6] Scanning vuln_demo ...")
    results = extract_directory(str(DEMO_DIR), db=db)
    hooks = []
    for r in results:
        hooks.extend(r.hooks)

    if not hooks:
        print("FAIL: No hooks extracted from vuln_demo")
        for r in results:
            if r.errors:
                print(f"  Errors in {r.file_path}: {r.errors}")
        return False

    execute_hooks = [h for h in hooks
                     if h.get("metadata", {}).get("called_function") == "execute"]
    print(f"  Hooks found: {len(hooks)} total, {len(execute_hooks)} SQL execute hook(s)")

    for h in hooks:
        db.create_task(
            agent_id="code_auditor",
            hook_id=h["hook_id"],
            task_type="analyze_hook",
            status="queued",
        )

    db_hooks = db.list_hooks()
    assert len(db_hooks) >= len(hooks), (
        f"DB hook count mismatch: {len(db_hooks)} < {len(hooks)}"
    )
    print(f"  [OK] {len(db_hooks)} hooks stored in database")

    # ── Step 2: Select target hook ─────────────────────────────────
    # Prefer a SQL execute hook for the most interesting test
    target = execute_hooks[0] if execute_hooks else hooks[0]
    metadata = target.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    print(f"\n[2/6] Selected hook for analysis:")
    print(f"  Function:   {target['func_name']}")
    print(f"  Language:   {target['language']}")
    print(f"  Hook type:  {target['hook_type']}")
    print(f"  Trigger:    {metadata.get('called_function', 'unknown')}()")
    print(f"  Line:       {target['line_start']}")
    db.update_hook_status(target["hook_id"], "analyzing")

    # ── Step 3: Build prompt ───────────────────────────────────────
    print(f"\n[3/6] Building security audit prompt ...")
    prompt = build_audit_prompt(target)
    print(f"  Prompt length: {len(prompt)} chars")
    assert len(prompt) > 100, "Prompt too short — likely missing snippet"

    # ── Step 4: Call LLM ───────────────────────────────────────────
    print(f"\n[4/6] Calling Ollama ({model}) ...")
    t0 = time.time()
    llm_result = call_ollama(model, prompt)
    elapsed = time.time() - t0

    prompt_tokens = llm_result["prompt_eval_count"]
    completion_tokens = llm_result["eval_count"]
    print(f"  Response in {elapsed:.1f}s")
    print(f"  Tokens: {prompt_tokens} prompt + {completion_tokens} completion")

    # ── Step 5: Parse & store finding ──────────────────────────────
    print(f"\n[5/6] Parsing model output & storing finding ...")
    finding = llm_result["parsed"]

    verdict = finding.get("verdict", "needs_review")
    severity = finding.get("severity", "info")
    title = finding.get("title", "Untitled")
    description = finding.get("description", "")
    cwe_id = finding.get("cwe_id")
    confidence = finding.get("confidence", 0.0)

    print(f"  Verdict:    {verdict}")
    print(f"  Severity:   {severity}")
    print(f"  Title:      {title}")
    print(f"  CWE:        {cwe_id or 'N/A'}")
    print(f"  Confidence: {confidence}")

    assert finding is not None, "Model returned nothing"
    assert title != "Untitled", "Model did not produce a meaningful title"

    finding_id = db.insert_finding(
        hook_id=target["hook_id"],
        agent_id="e2e_test_auditor",
        severity=severity,
        title=title,
        description=description,
        cwe_id=cwe_id,
        verdict=verdict,
        confidence=confidence,
        raw_response=json.dumps(finding, ensure_ascii=False),
    )

    db.insert_token_usage(
        agent_name=f"e2e_test:{model}",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )

    print(f"  Finding ID: {finding_id}")
    print(f"  Token record: {prompt_tokens} + {completion_tokens} = {prompt_tokens + completion_tokens}")

    # ── Step 6: Verify in DB ───────────────────────────────────────
    print(f"\n[6/6] Verifying finding in database ...")
    findings = db.list_findings()
    matching = [f for f in findings if f["finding_id"] == finding_id]

    assert len(matching) == 1, f"Expected 1 matching finding, got {len(matching)}"
    stored = matching[0]
    assert stored["verdict"] == verdict
    assert stored["title"] == title

    db.update_hook_status(target["hook_id"], "verified", confidence=confidence)

    # Verify token tracking
    usage = db.get_total_usage()
    e2e_usage = [u for u in usage if u["agent_name"].startswith("e2e_test")]
    assert len(e2e_usage) > 0, "No token usage record found"
    print(f"  Token usage tracked: {e2e_usage[0]['total_prompt']} prompt, "
          f"{e2e_usage[0]['total_completion']} completion")

    # ── Print summary ──────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  E2E Test Summary")
    print(f"{'=' * 60}")
    print(f"  Model:        {model}")
    print(f"  Hook:         {target['func_name']}::{metadata.get('called_function', '?')}()")
    print(f"  Vulnerability: {title}")
    print(f"  Verdict:      {verdict}")
    print(f"  Severity:     {severity}")
    print(f"  Confidence:   {confidence}")
    print(f"  CWE:          {cwe_id or 'N/A'}")
    print(f"  Tokens:       {prompt_tokens} prompt + {completion_tokens} completion")
    print(f"  Finding ID:   {finding_id}")
    print(f"  Duration:     {elapsed:.1f}s")
    print(f"\n  [PASS] E2E 测试通过：扫描 → 钩子 → 模型分析 → 发现入库 链路完整")
    print(f"{'=' * 60}")

    return True


if __name__ == "__main__":
    success = test_e2e_pipeline()
    sys.exit(0 if success else 1)
