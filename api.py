"""VulnForge API — One-click security scan endpoint.

Deploy: uvicorn api:app --host 0.0.0.0 --port 8003

Endpoints:
  POST /scan          — Submit repo for scanning
  GET  /report/{id}   — Get scan results
  GET  /health        — Health check
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from db import get_db, Database
from false_positive_filter import filter_false_positives, estimate_confidence
from cwe_classifier import batch_classify, get_cwe_stats
from report_generator import export_report, export_json
from feature_extractor import extract_directory, summary as extract_summary
from agents.scheduler import CollaborationScheduler, TokenBudgetExceeded

app = FastAPI(title="VulnForge API", version="1.2.0")

# — Storage —
REPORTS_DIR = Path(__file__).parent / "reports"
SCAN_DIR = Path(__file__).parent / "scans"
REPORTS_DIR.mkdir(exist_ok=True)
SCAN_DIR.mkdir(exist_ok=True)

# In-memory job tracker
_jobs: dict[str, dict] = {}


class ScanRequest(BaseModel):
    repo_url: str
    scan_type: str = "quick"  # quick | deep | security


class ScanResponse(BaseModel):
    report_id: str
    status: str
    results_url: str
    message: str


# — Helpers —

def _build_report(job_id: str, project_path: str, findings: list[dict],
                  stats: dict, elapsed_sec: float) -> dict:
    """Build structured report from scan results."""
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in by_severity:
            by_severity[sev].append({
                "title": f.get("title", "Untitled"),
                "cwe": f.get("cwe_id") or f.get("cwe", "N/A"),
                "confidence": f.get("confidence", 0),
                "description": (f.get("description") or f.get("reason", ""))[:300],
                "poc": (f.get("poc_code") or f.get("poc", ""))[:500],
            })

    return {
        "report_id": job_id,
        "timestamp": datetime.now().isoformat(),
        "scan_type": _jobs.get(job_id, {}).get("scan_type", "quick"),
        "repo_url": _jobs.get(job_id, {}).get("repo_url", ""),
        "elapsed_sec": round(elapsed_sec, 1),
        "stats": {
            "files_scanned": stats.get("files_scanned", 0),
            "total_hooks": stats.get("hooks_total", 0),
            "total_findings": len(findings),
            "true_positives": len([f for f in findings if f.get("verdict", "") == "true_positive"]),
        },
        "findings_by_severity": {
            sev: len(items) for sev, items in by_severity.items()
        },
        "findings": by_severity,
    }



def _extract_ast_findings(extract_results) -> list[dict]:
    """Convert AST hook results with FP filtering and CWE classification."""
    findings = []
    for result in extract_results:
        # Read file content for dataflow analysis
        try:
            with open(result.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()
        except Exception:
            file_content = ""
        
        # Apply false positive filter (dataflow-aware)
        filtered = filter_false_positives(result.hooks, file_content, result.language)
        
        # Apply CWE classification
        classified = batch_classify(filtered, result.language)
        
        for hook in classified:
            findings.append({
                "title": f"{hook.get('cwe_id', 'CWE-0')}: {hook.get('cwe_title', hook.get('hook_type', '?'))} in {hook.get('func_name', '?')}()",
                "severity": hook.get('severity', 'info') or 'info',
                "cwe": hook.get('cwe_id', 'N/A'),
                "confidence": estimate_confidence(hook),
                "description": hook.get('metadata', {}).get('description', ''),
                "poc": hook.get('snippet', ''),
                "verdict": "unreviewed",
                "cwe_title": hook.get('cwe_title', ''),
                "remediation": hook.get('remediation', ''),
                "file_path": hook.get('file_path', ''),
                "func_name": hook.get('func_name', ''),
                "line_start": hook.get('line_start', 0),
            })
    return findings


def _run_scan(repo_url: str, scan_type: str, job_id: str) -> dict:
    """Clone repo, run AST extraction, optionally run AI analysis, build report."""
    t0 = time.time()

    # 1. Clone (shallow, with timeout)
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    if not repo_name:
        repo_name = f"repo_{job_id[:8]}"
    target = SCAN_DIR / f"{repo_name}_{job_id[:8]}"

    if target.exists():
        shutil.rmtree(target, ignore_errors=True)

    clone_cmd = f"git clone --depth 1 {repo_url} {target}"
    result = subprocess.run(clone_cmd, shell=True, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"Clone failed: {result.stderr[:200]}")

    # 2. AST extraction
    db = get_db()
    db.init_schema()
    extract_results = extract_directory(str(target), db=db)
    extract_stats = extract_summary(extract_results)

    # 3. AST findings (always, fast)
    findings = _extract_ast_findings(extract_results)

    # 4. AI analysis — only for deep/security mode (slow, needs Ollama)
    if scan_type in ("deep", "security") and extract_stats["total_hooks"] > 0:
        try:
            model = "llama3.1:8b"
            scheduler = CollaborationScheduler(db=db, model=model)
            ai_findings = scheduler.run_collaborative_audit(str(target))
            # Merge AI findings (they have richer context)
            if ai_findings:
                findings = ai_findings
        except TokenBudgetExceeded:
            pass
        except Exception:
            # AI analysis failed — keep AST findings
            pass

    # 5. Build report
    db_stats = db.stats()
    elapsed = time.time() - t0
    report = _build_report(job_id, str(target), findings, db_stats, elapsed)

    # Save report to disk
    report_path = REPORTS_DIR / f"{job_id}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


# — Endpoints —

@app.get("/health")
def health():
    return {"status": "ok", "service": "VulnForge", "version": "1.2.0"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    job_id = uuid.uuid4().hex[:16]

    _jobs[job_id] = {
        "status": "scanning",
        "repo_url": request.repo_url,
        "scan_type": request.scan_type,
        "created_at": datetime.now().isoformat(),
    }

    # Run scan in background thread
    import threading
    def _scan_bg():
        try:
            report = _run_scan(request.repo_url, request.scan_type, job_id)
            _jobs[job_id]["status"] = "completed"
            _jobs[job_id]["report"] = report
        except Exception as e:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = str(e)

    threading.Thread(target=_scan_bg, daemon=True).start()

    return ScanResponse(
        report_id=job_id,
        status="scanning",
        results_url=f"/report/{job_id}",
        message=f"Scan started. Clone + AST analysis in progress. Poll /report/{job_id} for results."
    )


@app.get("/report/{report_id}")
async def get_report(report_id: str):
    # Check in-memory
    if report_id in _jobs:
        job = _jobs[report_id]
        if job["status"] == "scanning":
            return {"report_id": report_id, "status": "scanning", "message": "Scan in progress..."}
        if job["status"] == "failed":
            return {"report_id": report_id, "status": "failed", "error": job.get("error", "Unknown error")}
        return job.get("report", {"status": "not_found"})

    # Check disk
    report_path = REPORTS_DIR / f"{report_id}.json"
    if report_path.exists():
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)

    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/reports")
async def list_reports():
    """List all completed reports."""
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                r = json.load(fh)
            reports.append({
                "report_id": r.get("report_id"),
                "timestamp": r.get("timestamp"),
                "repo_url": r.get("repo_url"),
                "findings": r.get("stats", {}).get("total_findings", 0),
                "elapsed_sec": r.get("elapsed_sec", 0),
            })
        except Exception:
            pass
    return {"reports": reports}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
