"""VulTrial courtroom orchestrator — four-role multi-round vulnerability debate.

Flow:
  1. Prosecutor presents evidence (vulnerability claim + code + reasoning)
  2. Defender responds (code author's perspective, mitigation arguments)
  3. [Optional] Multi-round rebuttal
  4. Judge summarizes both sides
  5. Jury delivers final verdict + severity + confidence

Integration:
  — Grants +25 confidence points when jury confirms vulnerability
  — Stores trial records in audit_trials table
  — Callable from CollaborationScheduler or directly
"""

import json
import sys
import time
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import get_db, Database
from agents.scheduler import _call_ollama, _parse_json_response

FINAL_RESULT_MARKER = "FINAL_RESULT"


# ── System Prompts ──────────────────────────────────────────────

PROSECUTOR_SYSTEM = """你是模拟法庭的检察官（安全研究员）。你的职责是：

1. 提出漏洞指控——明确指出代码中存在的安全漏洞
2. 提供代码证据——引用具体的代码行和逻辑来支持你的指控
3. 解释攻击向量——说明攻击者如何利用这个漏洞
4. 评估严重度——给出 severity（critical/high/medium/low）和 CWE 分类
5. 回应辩护方的反驳——针对辩护律师的论点进行反击

输出格式（纯 JSON）：
{
  "opening_statement": "开案陈词：简要说明指控要点",
  "vulnerability_claim": {
    "title": "漏洞标题",
    "cwe": "CWE-XX",
    "severity": "high",
    "attack_vector": "攻击向量描述",
    "code_evidence": ["证据1: 具体代码行和推理", "证据2: ..."]
  },
  "confidence": 0.75
}

辩论结束时输出：FINAL_RESULT"""

DEFENDER_SYSTEM = """你是模拟法庭的辩护律师（代码作者视角）。你的职责是：

1. 为代码的设计意图辩护——解释为什么代码这样写是合理的
2. 指出检察官可能忽略的安全措施——如输入验证、鉴权中间件等
3. 承认真正存在问题的部分——不要狡辩，但要诚实评估风险
4. 提出缓解措施——即使漏洞存在，有什么方法可以降低风险
5. 回应检察官的新论点——在后续回合中针对性反驳

输出格式（纯 JSON）：
{
  "defense_statement": "辩护陈述",
  "counter_arguments": [
    {"claim_ref": "针对的指控点", "rebuttal": "反驳理由"}
  ],
  "mitigating_factors": ["缓解因素1", "缓解因素2"],
  "concession": "如果确实存在漏洞，说明哪些部分是你认可的",
  "severity_adjustment": "建议将严重度调整为 high/medium/low（或保持原判）"
}

辩论结束时输出：FINAL_RESULT"""

JUDGE_SYSTEM = """你是模拟法庭的法官。你的职责是：

1. 引导多轮辩论流程——确保双方充分表达
2. 在辩论结束后进行客观总结——不偏袒任何一方
3. 整理双方的核心论点和证据
4. 为陪审团提供清晰的事实梳理

输出格式（纯 JSON）：
{
  "prosecutor_summary": "检察官核心论点总结",
  "defender_summary": "辩护方核心论点总结",
  "key_disagreements": ["争议点1", "争议点2"],
  "established_facts": ["已确认事实1", "已确认事实2"],
  "recommendation_note": "给陪审团的注意事项"
}

总结完成后输出：FINAL_RESULT"""

JURY_SYSTEM = """你是模拟法庭的陪审团。你的职责是：

1. 综合检察官、辩护律师和法官的总结
2. 对漏洞是否真实存在给出最终裁决
3. 评估漏洞的严重度
4. 给出裁决理由和置信度

输出格式（纯 JSON）：
{
  "verdict": "valid|invalid|partially_valid",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "final_score": 0-100,
  "reasoning": "裁决理由的详细说明",
  "recommended_action": "建议的安全修复措施",
  "cwe_confirmation": "确认或修正的 CWE 编号"
}

裁决完成后输出：FINAL_RESULT"""


# ── Trial Orchestrator ──────────────────────────────────────────

class VulTrial:
    """Orchestrates a multi-round mock courtroom trial for a single finding."""

    def __init__(self, db: Database | None = None,
                 model: str = "alpernae/qwen2.5-auditor:latest",
                 max_rounds: int = 2):
        self.db = db or get_db()
        self.db.init_schema()
        self.model = model
        self.max_rounds = max_rounds

        self.on_log: Callable[[str], None] | None = None
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)
        else:
            print(f"  [VulTrial] {msg}")

    def _call_role(self, role_name: str, system: str, user: str) -> dict:
        self._log(f"{role_name} thinking ...")
        t0 = time.time()

        response = _call_ollama(self.model, system, user)
        raw = response["message"]["content"].strip()

        elapsed = time.time() - t0
        self._log(f"{role_name}: {elapsed:.1f}s, {len(raw)} chars")

        # Record token usage
        self.db.insert_token_usage(
            agent_name=f"courtroom:{role_name}",
            prompt_tokens=response.get("prompt_eval_count", 0),
            completion_tokens=response.get("eval_count", 0),
        )

        parsed, _ = _parse_json_response(raw, role_name)
        return parsed

    def run_trial(self, finding: dict, hook: dict | None = None,
                  code_context: str = "") -> dict:
        """Execute a full mock trial on a single finding.

        Args:
            finding: dict with title, description, hook_id, severity, cwe
            hook: optional hook dict with file_path, snippet, etc.
            code_context: full code snippet for context

        Returns:
            Jury verdict dict with verdict, severity, confidence, final_score
        """
        self._cancelled = False

        # Build code context if not provided
        if not code_context and hook:
            code_context = hook.get("snippet", "")
        if not code_context:
            code_context = finding.get("description", "")[:2000]

        # Build the initial charge document
        charge = self._build_charge(finding, hook, code_context)

        self._log(f"Trial begins: {finding.get('title', 'Untitled')}")
        self._log(f"  Model: {self.model}, Max rounds: {self.max_rounds}")

        trial_rounds = []
        prosecutor_statement = None
        defender_statement = None

        for rnd in range(1, self.max_rounds + 1):
            if self._cancelled:
                break

            self._log(f"--- Round {rnd}/{self.max_rounds} ---")

            # Prosecutor presents / rebuts
            if rnd == 1:
                prosecutor_prompt = self._build_prosecutor_prompt_opening(
                    charge, code_context
                )
            else:
                prosecutor_prompt = self._build_prosecutor_prompt_rebuttal(
                    charge, code_context, defender_statement
                )

            prosecutor_result = self._call_role(
                f"Prosecutor-R{rnd}", PROSECUTOR_SYSTEM, prosecutor_prompt
            )

            # Defender responds
            defender_prompt = self._build_defender_prompt(
                charge, code_context, prosecutor_result, rnd
            )
            defender_result = self._call_role(
                f"Defender-R{rnd}", DEFENDER_SYSTEM, defender_prompt
            )

            prosecutor_statement = prosecutor_result
            defender_statement = defender_result

            trial_rounds.append({
                "round": rnd,
                "prosecutor": prosecutor_result,
                "defender": defender_result,
            })

        # Judge summarizes
        self._log("Judge deliberating ...")
        judge_prompt = self._build_judge_prompt(
            charge, code_context, trial_rounds
        )
        judge_result = self._call_role("Judge", JUDGE_SYSTEM, judge_prompt)

        # Jury delivers verdict
        self._log("Jury voting ...")
        jury_prompt = self._build_jury_prompt(
            charge, code_context, judge_result, trial_rounds
        )
        jury_result = self._call_role("Jury", JURY_SYSTEM, jury_prompt)

        # ── Persist trial record ────────────────────────────────────
        finding_id = finding.get("finding_id", "UNKNOWN")
        trial_id = self.db.insert_trial(
            finding_id=finding_id,
            round_number=self.max_rounds,
            prosecutor_view=json.dumps(
                trial_rounds[-1]["prosecutor"] if trial_rounds else {},
                ensure_ascii=False,
            ),
            defender_view=json.dumps(
                trial_rounds[-1]["defender"] if trial_rounds else {},
                ensure_ascii=False,
            ),
            judge_summary=json.dumps(judge_result, ensure_ascii=False),
            jury_verdict=jury_result.get("verdict", "unknown"),
            jury_score=jury_result.get("final_score", 0),
            jury_reasoning=jury_result.get("reasoning", ""),
        )

        self._log(
            f"Trial complete: verdict={jury_result.get('verdict')}, "
            f"severity={jury_result.get('severity')}, "
            f"score={jury_result.get('final_score')}"
        )

        return {
            **jury_result,
            "trial_id": trial_id,
            "trial_rounds": len(trial_rounds),
            "judge_summary": judge_result,
        }

    # ── Prompt Builders ──────────────────────────────────────────

    def _build_charge(self, finding: dict, hook: dict | None,
                      code_context: str) -> str:
        lines = [
            f"## 案件编号: {finding.get('finding_id', 'UNKNOWN')}",
            f"## 漏洞指控: {finding.get('title', 'Untitled')}",
            f"## AI审计结论",
            f"- 严重度: {finding.get('severity', 'unknown')}",
            f"- CWE: {finding.get('cwe_id', finding.get('cwe', 'N/A'))}",
            f"- 置信度: {finding.get('confidence', 0.0)}",
            f"- 描述: {finding.get('description', finding.get('reason', 'N/A'))}",
        ]
        if hook:
            lines.append(f"\n## 代码位置")
            lines.append(f"- 文件: {hook.get('file_path', '?')}")
            lines.append(f"- 函数: {hook.get('func_name', hook.get('function_name', '?'))}")
            lines.append(f"- 语言: {hook.get('language', 'unknown')}")

        lines.append(f"\n## 代码片段")
        lines.append(f"```")
        lines.append(code_context[:3000])
        lines.append(f"```")
        return "\n".join(lines)

    def _build_prosecutor_prompt_opening(self, charge: str,
                                          code_context: str) -> str:
        return f"""{charge}

作为检察官，请进行开案陈词。你需要：
1. 明确提出你对这个漏洞的指控
2. 引用代码中的具体证据
3. 说明攻击者如何利用这个漏洞
4. 给出你认为合适的 CWE 分类和严重度评级

输出格式：纯 JSON，包含 opening_statement 和 vulnerability_claim 字段。
完成后输出：{FINAL_RESULT_MARKER}"""

    def _build_prosecutor_prompt_rebuttal(self, charge: str,
                                           code_context: str,
                                           defender_statement: dict) -> str:
        def_json = json.dumps(defender_statement, ensure_ascii=False, indent=2)
        return f"""{charge}

## 辩护律师的回应
```json
{def_json}
```

作为检察官，请对辩护律师的论点进行反击。逐一驳斥不合理的辩护理由，强化你的指控。
如果辩护方提到的缓解因素确实有效，也应诚实承认。

输出格式：纯 JSON，包含 opening_statement 和 vulnerability_claim 字段。
完成后输出：{FINAL_RESULT_MARKER}"""

    def _build_defender_prompt(self, charge: str, code_context: str,
                                prosecutor_result: dict, rnd: int) -> str:
        pros_json = json.dumps(prosecutor_result, ensure_ascii=False, indent=2)
        return f"""{charge}

## 检察官陈述（第 {rnd} 轮）
```json
{pros_json}
```

作为辩护律师，请从代码作者的角度进行辩护。你可以：
- 解释代码设计意图
- 指出可能被忽略的安全措施
- 诚实地评估风险（如果漏洞确实存在，请不要狡辩）
- 提出缓解措施或修复建议

输出格式：纯 JSON，包含 defense_statement 和 counter_arguments 字段。
完成后输出：{FINAL_RESULT_MARKER}"""

    def _build_judge_prompt(self, charge: str, code_context: str,
                             trial_rounds: list[dict]) -> str:
        rounds_json = json.dumps(
            [{"round": r["round"],
              "prosecutor": r["prosecutor"],
              "defender": r["defender"]}
             for r in trial_rounds],
            ensure_ascii=False, indent=2,
        )
        return f"""{charge}

## 完整辩论记录
```json
{rounds_json}
```

作为法官，请对双方的论战进行客观总结。你需要：
1. 概括检察官的核心论点和证据
2. 概括辩护方的核心论点和缓解因素
3. 指出双方的关键争议点
4. 列出已确认的事实
5. 给陪审团提供注意事项

输出格式：纯 JSON，包含所有必需字段。
完成后输出：{FINAL_RESULT_MARKER}"""

    def _build_jury_prompt(self, charge: str, code_context: str,
                            judge_result: dict,
                            trial_rounds: list[dict]) -> str:
        judge_json = json.dumps(judge_result, ensure_ascii=False, indent=2)
        return f"""{charge}

## 法官总结
```json
{judge_json}
```

作为陪审团，请综合检察官、辩护律师和法官的总结，给出最终裁决。你需要：
1. 判断漏洞是否真实存在（valid / invalid / partially_valid）
2. 评估最终严重度
3. 给出信心评分（0-100）和置信度（0.0-1.0）
4. 详细说明裁决理由
5. 建议后续操作（如修复方案、进一步验证等）

输出格式：纯 JSON，包含所有必需字段。
完成后输出：{FINAL_RESULT_MARKER}"""


# ── Convenience ─────────────────────────────────────────────────

def run_courtroom_for_finding(
    finding: dict,
    hook: dict | None = None,
    code_context: str = "",
    model: str = "llama3.1:8b",
    max_rounds: int = 2,
    db: Database | None = None,
) -> dict:
    """One-shot convenience: run a full trial on a finding.

    Returns the jury verdict dict. Grants +25 confidence points if verdict == 'valid'.
    """
    trial = VulTrial(db=db, model=model, max_rounds=max_rounds)
    return trial.run_trial(finding, hook, code_context)
