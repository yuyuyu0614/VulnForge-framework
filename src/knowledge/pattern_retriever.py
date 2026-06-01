"""Retrieve similar vulnerability patterns from the knowledge base.

Two-stage retrieval:
  1. Deterministic: CWE + regex match against code_signature and detection_rule
  2. Semantic fallback: nomic-embed-text embeddings + cosine similarity (Ollama)
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import get_db, Database


def _deterministic_match(snippet: str, hook_type: str,
                         language: str = "unknown") -> list[dict]:
    """Match code snippet against stored patterns via CWE-type + regex.

    Returns up to 3 matching patterns, ranked by regex match quality.
    """
    db = get_db()
    all_patterns = db.list_patterns()

    if not all_patterns:
        return []

    scored: list[tuple[int, dict]] = []

    # Map hook_type to likely CWE for prioritization
    type_cwe_map = {
        "injection": "CWE-89",
        "command_exec": "CWE-78",
        "file_operation": "CWE-22",
        "auth_bypass": "CWE-862",
        "auth_bypass_pattern": "CWE-862",
        "dangerous_call": "CWE-78",
        "deserialization": "CWE-502",
        "info_leak": "CWE-200",
        "input_source": "CWE-79",
        "route_entry": "CWE-862",
    }
    suspected_cwe = type_cwe_map.get(hook_type, "")

    for pat in all_patterns:
        score = 0

        # CWE match bonus
        if suspected_cwe and pat.get("cwe_id") == suspected_cwe:
            score += 3

        # Try detection_rule regex match
        detection_rule = pat.get("detection_rule", "")
        if detection_rule:
            try:
                if re.search(detection_rule, snippet, re.IGNORECASE):
                    score += 5
            except re.error:
                pass

        # Try code_signature regex match
        code_sig = pat.get("code_signature", "")
        if code_sig:
            try:
                if re.search(code_sig, snippet, re.IGNORECASE):
                    score += 4
            except re.error:
                pass

        # Check for shared keywords (function names, vulnerable patterns)
        keywords = ["execute", "cursor", "query", "SELECT", "INSERT",
                    "exec", "system", "popen", "subprocess", "eval",
                    "open(", "file(", "os.", "request.", "input",
                    "innerHTML", "render", "redirect"]
        snippet_lower = snippet.lower()
        pat_snippet = pat.get("vulnerable_snippet", "").lower()
        common_keywords = sum(
            1 for kw in keywords
            if kw.lower() in snippet_lower and kw.lower() in pat_snippet
        )
        score += min(common_keywords, 3)  # cap keyword bonus at 3

        if score > 0:
            scored.append((score, dict(pat)))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored[:3]]


def _semantic_match(snippet: str, top_k: int = 3) -> list[dict]:
    """Semantic retrieval using nomic-embed-text embeddings via Ollama.

    Falls back to deterministic if Ollama is unavailable.
    """
    db = get_db()
    all_patterns = db.list_patterns()

    if not all_patterns:
        return []

    try:
        import ollama

        # Get embedding for the query snippet
        query_response = ollama.embeddings(
            model="nomic-embed-text",
            prompt=snippet[:2000],
        )
        query_emb = query_response.get("embedding", [])

        if not query_emb:
            return _deterministic_match(snippet, "unknown")

        # Get embeddings for all stored patterns (or use cached ones)
        similarities: list[tuple[float, dict]] = []
        for pat in all_patterns:
            pat_text = (
                f"{pat.get('pattern_type', '')} {pat.get('cwe_id', '')} "
                f"{pat.get('vulnerable_snippet', '')[:500]}"
            )
            try:
                pat_response = ollama.embeddings(
                    model="nomic-embed-text",
                    prompt=pat_text[:2000],
                )
                pat_emb = pat_response.get("embedding", [])
                if pat_emb:
                    sim = _cosine_similarity(query_emb, pat_emb)
                    similarities.append((sim, dict(pat)))
            except Exception:
                continue

        similarities.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in similarities[:top_k] if _ > 0.3]

    except Exception:
        # If Ollama embeddings fail, fall back to deterministic
        return _deterministic_match(snippet, "unknown")


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def retrieve_patterns(snippet: str, hook_type: str = "unknown",
                      language: str = "unknown",
                      use_semantic: bool = True) -> list[dict]:
    """Main retrieval entry point.

    1. Try deterministic CWE+regex matching first.
    2. If fewer than 3 results, supplement with semantic search.
    3. Return top-3 patterns (capped).

    Returns list of pattern dicts with keys:
      pattern_type, cwe_id, code_signature, vulnerable_snippet,
      fix_snippet, detection_rule
    """
    if not snippet or len(snippet.strip()) < 10:
        return []

    # Stage 1: deterministic match
    results = _deterministic_match(snippet, hook_type, language)

    # Stage 2: supplement with semantic if needed
    if len(results) < 3 and use_semantic:
        try:
            semantic_results = _semantic_match(snippet, top_k=3)
            existing_ids = {p.get("id") for p in results}
            for sr in semantic_results:
                if sr.get("id") not in existing_ids:
                    results.append(sr)
                    existing_ids.add(sr.get("id"))
                if len(results) >= 3:
                    break
        except Exception:
            pass

    return results[:3]


def format_patterns_for_prompt(patterns: list[dict]) -> str:
    """Format retrieved patterns for injection into the Auditor's system prompt."""
    if not patterns:
        return "（暂无匹配的历史漏洞模式）"

    lines = ["## 历史漏洞模式（来自知识库）\n"]
    lines.append("以下是从知识库中检索到的相似漏洞模式，请参考这些模式辅助判断：\n")

    for i, pat in enumerate(patterns, 1):
        lines.append(f"### 模式 {i}: {pat.get('pattern_type', '?')} ({pat.get('cwe_id', '?')})")
        lines.append(f"**漏洞代码特征**:")
        lines.append(f"```")
        lines.append(pat.get('vulnerable_snippet', '')[:400])
        lines.append(f"```")
        fix = pat.get('fix_snippet', '')
        if fix:
            lines.append(f"**修复建议**: {fix[:300]}")
        lines.append("")

    return "\n".join(lines)
