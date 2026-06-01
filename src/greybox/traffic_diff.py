'''
流量对比引擎 — 登录态 vs 未登录态自动 Diff
输入：两组 BurpRequest 列表（已登录 / 未登录）
输出：差异报告，标记潜在鉴权缺陷
'''

from dataclasses import dataclass, field
from typing import Optional
import hashlib
import json


@dataclass
class DiffFinding:
    endpoint: str
    method: str
    severity: str  # HIGH / MEDIUM / LOW / INFO
    auth_status_logged_in: int
    auth_status_anonymous: int
    diff_type: str  # STATUS_MISMATCH / BODY_LEAK / HEADER_LEAK
    detail: str
    verification_steps: list[str] = field(default_factory=list)


class TrafficDiffer:
    def __init__(self):
        self.findings: list[DiffFinding] = []

    def diff(
        self,
        logged_in: list,   # list[BurpRequest]
        anonymous: list,   # list[BurpRequest]
    ) -> list[DiffFinding]:
        anon_map = {self._key(m): m for m in anonymous}
        self.findings = []

        for m in logged_in:
            key = self._key(m)
            anon = anon_map.get(key)
            if anon is None:
                continue
            finding = self._compare(m, anon)
            if finding:
                self.findings.append(finding)

        return sorted(self.findings, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}[f.severity])

    def _key(self, msg) -> str:
        return hashlib.md5(f"{msg.method}:{msg.path}".encode()).hexdigest()

    def _compare(self, logged_in_msg, anon_msg) -> Optional[DiffFinding]:
        li_status = logged_in_msg.response_status
        an_status = anon_msg.response_status
        li_body = self._normalize(logged_in_msg.response_body)
        an_body = self._normalize(anon_msg.response_body)

        # 规则1: 登录态200，未登录也200 → 可能未授权可访问
        if li_status == 200 and an_status == 200:
            if li_body and an_body and len(an_body) > 100:
                similarity = self._similarity(li_body, an_body)
                if similarity > 0.7:
                    return DiffFinding(
                        endpoint=logged_in_msg.path,
                        method=logged_in_msg.method,
                        severity="HIGH",
                        auth_status_logged_in=li_status,
                        auth_status_anonymous=an_status,
                        diff_type="BODY_LEAK",
                        detail=f"未登录态返回与登录态相似度 {similarity:.0%} 的数据，可能存在未授权访问",
                        verification_steps=[
                            f"1. 在无痕窗口访问 {logged_in_msg.url}",
                            "2. 对比响应是否包含敏感业务数据",
                            "3. 如果包含用户数据 → 高危越权",
                            "4. 如果仅公开配置 → 正常",
                        ]
                    )

        # 规则2: 登录态200，未登录非401/403 → 鉴权异常
        if li_status == 200 and an_status not in (401, 403, 302):
            return DiffFinding(
                endpoint=logged_in_msg.path,
                method=logged_in_msg.method,
                severity="MEDIUM",
                auth_status_logged_in=li_status,
                auth_status_anonymous=an_status,
                diff_type="STATUS_MISMATCH",
                detail=f"登录态返回 {li_status}，未登录返回 {an_status}（非 401/403），需验证是否越权",
                verification_steps=[
                    f"1. 无痕窗口访问 {logged_in_msg.url}",
                    f"2. 确认返回的 {an_status} 响应内容",
                    "3. 判断是否泄露了本应鉴权的数据",
                ]
            )

        # 规则3: 响应头差异（如 CORS 配置异常）
        li_cors = logged_in_msg.response_headers.get("access-control-allow-origin", "")
        an_cors = anon_msg.response_headers.get("access-control-allow-origin", "")
        if an_cors and an_cors != li_cors and "*" in an_cors:
            return DiffFinding(
                endpoint=logged_in_msg.path,
                method=logged_in_msg.method,
                severity="LOW",
                auth_status_logged_in=li_status,
                auth_status_anonymous=an_status,
                diff_type="HEADER_LEAK",
                detail=f"未登录态 CORS 头异常: {an_cors}（可能导致信息泄露）",
                verification_steps=[
                    "1. 检查 CORS 配置是否为预期值",
                ]
            )

        return None

    def _normalize(self, body: str) -> str:
        if not body:
            return ""
        try:
            parsed = json.loads(body)
            return json.dumps(parsed, sort_keys=True)
        except (json.JSONDecodeError, TypeError):
            return body.strip()[:2000]

    def _similarity(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        a_set = set(a[i:i+50] for i in range(0, len(a), 50))
        b_set = set(b[i:i+50] for i in range(0, len(b), 50))
        if not a_set or not b_set:
            return 0.0
        return len(a_set & b_set) / len(a_set | b_set)
