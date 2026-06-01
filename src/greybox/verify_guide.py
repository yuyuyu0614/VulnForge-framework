'''
验证路径指引生成器
对每个 Finding 输出可操作的手工验证步骤
'''

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VerificationGuide:
    finding_id: str
    title: str
    confidence: int  # 0-100
    auto_verifiable: bool
    steps: list[str] = field(default_factory=list)
    manual_reason: str = ""
    suggested_tools: list[str] = field(default_factory=list)


class GuideGenerator:
    def generate(self, findings: list) -> list[VerificationGuide]:
        guides = []
        for i, f in enumerate(finding := findings):
            guide = self._build_guide(f, i)
            guides.append(guide)
        return guides

    def _build_guide(self, finding, idx: int) -> VerificationGuide:
        fid = f"F{idx+1}"

        if "STATUS_MISMATCH" in str(getattr(finding, "diff_type", "")):
            return VerificationGuide(
                finding_id=fid,
                title=f"鉴权异常: {getattr(finding, 'endpoint', 'unknown')}",
                confidence=60,
                auto_verifiable=False,
                steps=[
                    f"1. 打开无痕窗口访问 {getattr(finding, 'endpoint', '')}",
                    "2. 对比登录态与未登录态响应差异",
                    "3. 判断是否泄露用户数据 / 业务数据",
                    "4. 若泄露敏感字段(姓名/手机号等) → 高危",
                    "5. 若仅为公开配置 → 正常",
                ],
                manual_reason="需要人工判断响应内容是否包含敏感信息",
                suggested_tools=["Burp Suite Repeater", "浏览器无痕窗口"],
            )

        if "BODY_LEAK" in str(getattr(finding, "diff_type", "")):
            return VerificationGuide(
                finding_id=fid,
                title=f"未授权访问: {getattr(finding, 'endpoint', 'unknown')}",
                confidence=80,
                auto_verifiable=False,
                steps=[
                    f"1. curl -X {getattr(finding, 'method', 'GET')} {getattr(finding, 'endpoint', '')} (无Cookie)",
                    "2. 检查响应是否包含用户相关字段",
                    "3. 扩大参数范围测试越权(如 id=1,2,3...)",
                    "4. 截图保存为复现证据",
                ],
                manual_reason="需确认返回数据是否为公开设计vs鉴权缺失",
                suggested_tools=["curl", "浏览器无痕窗口"],
            )

        return VerificationGuide(
            finding_id=fid,
            title=f"待验证: {getattr(finding, 'endpoint', 'unknown')}",
            confidence=30,
            auto_verifiable=False,
            steps=[
                "1. 确认该接口的业务功能",
                "2. 判断当前鉴权是否符合预期",
                "3. 测试参数注入/越权可能性",
            ],
            manual_reason="自动分析置信度较低，需人工判断",
            suggested_tools=["浏览器DevTools", "curl"],
        )
