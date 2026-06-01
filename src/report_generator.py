"""SRC Report Generator — 补天/HackerOne/TSRC multi-platform export.

Generates submission-ready vulnerability reports with CWE classification,
confidence scoring, PoC generation, and multi-platform formatting.
"""

import json
import re
from datetime import datetime
from pathlib import Path


BUTIAN_LOW_IMPACT_CWE = {
    "CWE-200": "Information Exposure",
    "CWE-532": "Sensitive Info in Logs",
    "CWE-209": "Error Message Info Leak",
    "CWE-798": "Hardcoded Credentials",
    "CWE-204": "Observable Response Discrepancy",
    "CWE-548": "Directory Listing",
    "CWE-693": "Protection Mechanism Failure",
}

BUTIAN_SEVERITY_DOWNGRADE = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}


def apply_butian_compliance(findings):
    """Apply Butian rules: downgrade pure info-leak findings."""
    adjusted = []
    for f in findings:
        cwe = f.get("cwe_id", "")
        f = dict(f)
        if cwe in BUTIAN_LOW_IMPACT_CWE:
            old_sev = f.get("severity", "low")
            new_sev = BUTIAN_SEVERITY_DOWNGRADE.get(old_sev, old_sev)
            f["severity"] = new_sev
            f["butian_risk"] = "low_impact"
            f["butian_note"] = BUTIAN_LOW_IMPACT_CWE[cwe] + ": info leak, low impact per Butian rules"
        else:
            f["butian_risk"] = "actionable"
        adjusted.append(f)
    return adjusted


def filter_butian_submittable(findings):
    """Split findings into submittable vs needs-more-evidence."""
    submittable = []
    needs_evidence = []
    for f in findings:
        sev = f.get("severity", "info")
        conf = f.get("confidence", 0)
        risk = f.get("butian_risk", "actionable")
        if risk == "low_impact":
            needs_evidence.append(f)
        elif sev in ("critical", "high", "medium") and conf >= 60:
            submittable.append(f)
        else:
            needs_evidence.append(f)
    return submittable, needs_evidence

PLATFORM_TEMPLATES = {
    "butian": {
        "name": "补天SRC",
        "fields": ["漏洞标题", "漏洞类型(CWE)", "危害等级", "漏洞URL/位置", "漏洞描述", "复现步骤", "修复建议", "置信度"],
    },
    "hackerone": {
        "name": "HackerOne",
        "fields": ["Title", "CWE", "Severity", "Endpoint", "Description", "Steps to Reproduce", "Remediation", "Confidence"],
    },
    "tsrc": {
        "name": "腾讯TSRC",
        "fields": ["漏洞标题", "漏洞类型", "危害等级", "影响URL", "漏洞详情", "复现步骤", "修复方案", "自评等级"],
    },
    "360src": {
        "name": "360SRC",
        "fields": ["标题", "类型", "等级", "漏洞地址", "详细描述", "PoC", "修复建议", "可信度"],
    },
}


def _extract_danger_line(snippet):
    lines = snippet.split('\\n')
    for line in lines:
        if '>>>' in line:
            return line.replace('>>>', '').strip()
    return snippet[:200]


def generate_poc(hook):
    cwe = hook.get('cwe_id', 'CWE-0')
    func_name = hook.get('func_name', 'unknown')
    dang_line = _extract_danger_line(hook.get('snippet', ''))
    code_block = '```\\n' + dang_line + '\\n```'
    
    templates = {
        'CWE-89': 'SQL Injection PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack:\\n```\\nGET /' + func_name + "?id=1' OR '1'='1 HTTP/1.1\\n```",
        'CWE-78': 'Command Injection PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack:\\n```\\nPOST /' + func_name + '\\ncmd=; cat /etc/passwd\\n```',
        'CWE-22': 'Path Traversal PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack:\\n```\\nGET /' + func_name + '?file=../../../etc/passwd\\n```',
        'CWE-94': 'Code Injection PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack: inject malicious code via ' + func_name + '()',
        'CWE-502': 'Deserialization PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack: send malicious pickled object',
        'CWE-918': 'SSRF PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack:\\n```\\nGET /' + func_name + '?url=http://169.254.169.254/\\n```',
        'CWE-79': 'XSS PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack:\\n```\\nGET /' + func_name + '?name=<script>alert(1)</script>\\n```',
        'CWE-798': 'Hardcoded Credentials\\n\\nVulnerable code:\\n' + code_block + '\\n\\nRisk: credentials exposed in source code',
        'CWE-601': 'Open Redirect PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack:\\n```\\nGET /' + func_name + '?next=https://evil.com\\n```',
        'CWE-611': 'XXE PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nAttack: send malicious XML with external entity',
    }
    return templates.get(cwe, 'PoC\\n\\nVulnerable code:\\n' + code_block + '\\n\\nManual verification required.')


def build_report(findings, platform='butian', repo_url=''):
    tmpl = PLATFORM_TEMPLATES.get(platform, PLATFORM_TEMPLATES['butian'])
    lines = []
    lines.append('# VulnForge Security Audit Report')
    lines.append('')
    lines.append(f'- Platform: {tmpl["name"]}')
    lines.append(f'- Generated: {datetime.now().isoformat()}')
    lines.append(f'- Target: {repo_url}')
    lines.append(f'- Total Findings: {len(findings)}')
    lines.append('')
    lines.append('---')
    lines.append('')
    
    by_sev = {'critical': [], 'high': [], 'medium': [], 'low': []}
    for f in findings:
        sev = f.get('severity', 'medium')
        if sev in by_sev:
            by_sev[sev].append(f)
    
    idx = 1
    for sev in ['critical', 'high', 'medium', 'low']:
        for f in by_sev[sev]:
            title = f.get('title', 'Untitled')
            cwe = f.get('cwe_id', 'CWE-0')
            desc = f.get('description', '')
            confidence = f.get('confidence', 50)
            remediation = f.get('remediation', 'Review and fix')
            file_path = f.get('file_path', '')
            
            lines.append(f'## #{idx} [{sev.upper()}] {cwe}: {title}')
            lines.append('')
            lines.append(f'| Field | Value |')
            lines.append(f'|-------|-------|')
            lines.append(f'| CWE | {cwe} |')
            lines.append(f'| Severity | {sev} |')
            lines.append(f'| Location | {file_path} |')
            lines.append(f'| Confidence | {confidence}% |')
            lines.append(f'| Description | {desc} |')
            lines.append(f'| Remediation | {remediation} |')
            lines.append('')
            poc = generate_poc(f)
            lines.append(poc)
            lines.append('')
            lines.append('---')
            lines.append('')
            idx += 1
    
    lines.append('## Summary')
    lines.append('')
    cwe_counts = {}
    for f in findings:
        cwe = f.get('cwe_id', 'CWE-0')
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    for cwe, cnt in sorted(cwe_counts.items()):
        lines.append(f'- {cwe}: {cnt}')
    
    return '\\n'.join(lines)


def export_report(findings, output_path, platform='butian', repo_url=''):
    report = build_report(findings, platform, repo_url)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    return output_path


def export_json(findings, output_path):
    export = {
        'meta': {
            'tool': 'VulnForge',
            'version': '1.3.0',
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
        },
        'findings': []
    }
    for f in findings:
        export['findings'].append({
            'cwe': f.get('cwe_id', 'CWE-0'),
            'severity': f.get('severity', 'info'),
            'title': f.get('title', ''),
            'description': f.get('description', ''),
            'file': f.get('file_path', ''),
            'line': f.get('line_start', 0),
            'confidence': f.get('confidence', 50),
            'poc': generate_poc(f),
            'remediation': f.get('remediation', ''),
            'function': f.get('func_name', ''),
        })
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(export, f, ensure_ascii=False, indent=2)
    return output_path


def build_butian_report(findings: list[dict], domain: str, project_name: str = "", vulnforge_version: str = "v3.0") -> str:
    """Generate Butian-compliant vulnerability submission report.
    
    Butian requirements:
    - Title: [domain] + vuln name
    - Full reproduction steps, screenshots, PoC code
    - Category: Web vulnerability
    - Attachments: zip only (remind user)
    """
    import datetime
    now = datetime.datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    
    # Filter verified findings only
    verified = [f for f in findings if f.get("verified", False) or f.get("confidence", 0) >= 80]
    unverified = [f for f in findings if f not in verified]
    
    lines = [
        "# 补天漏洞提交报告",
        "",
        f"- **提交日期**: {date_str}",
        f"- **厂商/项目**: {project_name or domain}",
        f"- **漏洞类别**: Web漏洞",
        f"- **工具版本**: VulnForge {vulnforge_version}",
        f"- **已验证漏洞**: {len(verified)} 个",
        f"- **待手动验证**: {len(unverified)} 个",
        "",
        "---",
        "",
        "## 提交前检查清单",
        "",
        "- [ ] 已删除所有本地测试记录",
        "- [ ] 未保存/传播任何测试数据",
        "- [ ] 漏洞详情含完整复现步骤",
        "- [ ] PoC代码经过手工验证",
        "- [ ] 附件压缩为ZIP格式",
        "",
        "---",
        "",
    ]
    
    for i, f in enumerate(verified, 1):
        severity = f.get("severity", "low")
        sev_cn = {"high": "高危", "medium": "中危", "low": "低危", "critical": "严重"}.get(severity, severity)
        title = f.get("title", "未命名漏洞")
        cwe = f.get("cwe_id", f.get("cwe", "?"))
        
        lines.append(f"## 漏洞 {i}: [{domain}] {title}")
        lines.append("")
        lines.append("### 基础信息")
        lines.append("")
        lines.append(f"| 项目 | 值 |")
        lines.append(f"|------|------|")
        lines.append(f"| 漏洞标题 | [{domain}] {title} |")
        lines.append(f"| 漏洞类别 | Web漏洞 |")
        lines.append(f"| 严重程度 | {sev_cn} |")
        lines.append(f"| CWE编号 | {cwe} |")
        lines.append(f"| 置信度 | {f.get('confidence', '?')}% |")
        lines.append(f"| 目标URL | {f.get('url', domain)} |")
        lines.append("")
        
        lines.append("### 漏洞描述")
        lines.append("")
        lines.append(f.get("description", "详见下方复现步骤"))
        lines.append("")
        
        lines.append("### 复现步骤")
        lines.append("")
        if f.get("reproduction_steps"):
            for step in f["reproduction_steps"]:
                lines.append(f"1. {step}")
        else:
            lines.append(f"1. 访问 {f.get('url', domain)}")
            lines.append(f"2. 查看响应/页面源码")
            lines.append(f"3. 发现上述漏洞")
        lines.append("")
        
        lines.append("### PoC代码")
        lines.append("")
        poc = f.get("poc", "")
        if poc:
            lines.append("```")
            lines.append(poc)
            lines.append("```")
        else:
            lines.append("```curl")
            lines.append(f"# 访问 {f.get('url', '')}")
            lines.append(f"curl -i {f.get('url', domain)}")
            lines.append("```")
        lines.append("")
        
        lines.append("### 漏洞证据")
        lines.append("")
        evidence = f.get("evidence", "")
        if evidence:
            lines.append("```")
            lines.append(evidence[:500])
            lines.append("```")
        lines.append("")
        
        lines.append("### 修复建议")
        lines.append("")
        lines.append(f.get("remediation", "请参考对应CWE编号召的标准修复方案"))
        lines.append("")
        
        lines.append("---")
        lines.append("")
    
    if unverified:
        lines.append("## 待手动验证")
        lines.append("")
        for i, f in enumerate(unverified, 1):
            lines.append(f"{i}. {f.get('title', '?')} (confidence: {f.get('confidence', '?')}%)")
        lines.append("")
    
    return "\n".join(lines)
