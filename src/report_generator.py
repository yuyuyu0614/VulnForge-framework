"""SRC Report Generator 鈥?琛ュぉ/Platform D/Platform B multi-platform export.

Generates submission-ready vulnerability reports with CWE classification,
confidence scoring, PoC generation, and multi-platform formatting.
"""

import json
import re
from datetime import datetime
from pathlib import Path

PLATFORM_TEMPLATES = {
    "platform_a": {
        "name": "Platform A",
        "fields": ["婕忔礊鏍囬", "婕忔礊绫诲瀷(CWE)", "鍗卞绛夌骇", "婕忔礊URL/浣嶇疆", "婕忔礊鎻忚堪", "澶嶇幇姝ラ", "淇寤鸿", "缃俊搴?],
    },
    "Platform D": {
        "name": "Platform D",
        "fields": ["Title", "CWE", "Severity", "Endpoint", "Description", "Steps to Reproduce", "Remediation", "Confidence"],
    },
    "Platform B": {
        "name": "Platform B",
        "fields": ["婕忔礊鏍囬", "婕忔礊绫诲瀷", "鍗卞绛夌骇", "褰卞搷URL", "婕忔礊璇︽儏", "澶嶇幇姝ラ", "淇鏂规", "鑷瘎绛夌骇"],
    },
    "Platform C": {
        "name": "Platform C",
        "fields": ["鏍囬", "绫诲瀷", "绛夌骇", "婕忔礊鍦板潃", "璇︾粏鎻忚堪", "PoC", "淇寤鸿", "鍙俊搴?],
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


def build_report(findings, platform='platform_a', repo_url=''):
    tmpl = PLATFORM_TEMPLATES.get(platform, PLATFORM_TEMPLATES['platform_a'])
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


def export_report(findings, output_path, platform='platform_a', repo_url=''):
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


def build_platform_a_report(findings: list[dict], domain: str, project_name: str = "", vulnforge_version: str = "v3.0") -> str:
    """Generate platform_a-compliant vulnerability submission report.
    
    platform_a requirements:
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
        "# 琛ュぉ婕忔礊鎻愪氦鎶ュ憡",
        "",
        f"- **鎻愪氦鏃ユ湡**: {date_str}",
        f"- **鍘傚晢/椤圭洰**: {project_name or domain}",
        f"- **婕忔礊绫诲埆**: Web婕忔礊",
        f"- **宸ュ叿鐗堟湰**: VulnForge {vulnforge_version}",
        f"- **宸查獙璇佹紡娲?*: {len(verified)} 涓?,
        f"- **寰呮墜鍔ㄩ獙璇?*: {len(unverified)} 涓?,
        "",
        "---",
        "",
        "## 鎻愪氦鍓嶆鏌ユ竻鍗?,
        "",
        "- [ ] 宸插垹闄ゆ墍鏈夋湰鍦版祴璇曡褰?,
        "- [ ] 鏈繚瀛?浼犳挱浠讳綍娴嬭瘯鏁版嵁",
        "- [ ] 婕忔礊璇︽儏鍚畬鏁村鐜版楠?,
        "- [ ] PoC浠ｇ爜缁忚繃鎵嬪伐楠岃瘉",
        "- [ ] 闄勪欢鍘嬬缉涓篫IP鏍煎紡",
        "",
        "---",
        "",
    ]
    
    for i, f in enumerate(verified, 1):
        severity = f.get("severity", "low")
        sev_cn = {"high": "楂樺嵄", "medium": "涓嵄", "low": "浣庡嵄", "critical": "涓ラ噸"}.get(severity, severity)
        title = f.get("title", "鏈懡鍚嶆紡娲?)
        cwe = f.get("cwe_id", f.get("cwe", "?"))
        
        lines.append(f"## 婕忔礊 {i}: [{domain}] {title}")
        lines.append("")
        lines.append("### 鍩虹淇℃伅")
        lines.append("")
        lines.append(f"| 椤圭洰 | 鍊?|")
        lines.append(f"|------|------|")
        lines.append(f"| 婕忔礊鏍囬 | [{domain}] {title} |")
        lines.append(f"| 婕忔礊绫诲埆 | Web婕忔礊 |")
        lines.append(f"| 涓ラ噸绋嬪害 | {sev_cn} |")
        lines.append(f"| CWE缂栧彿 | {cwe} |")
        lines.append(f"| 缃俊搴?| {f.get('confidence', '?')}% |")
        lines.append(f"| 鐩爣URL | {f.get('url', domain)} |")
        lines.append("")
        
        lines.append("### 婕忔礊鎻忚堪")
        lines.append("")
        lines.append(f.get("description", "璇﹁涓嬫柟澶嶇幇姝ラ"))
        lines.append("")
        
        lines.append("### 澶嶇幇姝ラ")
        lines.append("")
        if f.get("reproduction_steps"):
            for step in f["reproduction_steps"]:
                lines.append(f"1. {step}")
        else:
            lines.append(f"1. 璁块棶 {f.get('url', domain)}")
            lines.append(f"2. 鏌ョ湅鍝嶅簲/椤甸潰婧愮爜")
            lines.append(f"3. 鍙戠幇涓婅堪婕忔礊")
        lines.append("")
        
        lines.append("### PoC浠ｇ爜")
        lines.append("")
        poc = f.get("poc", "")
        if poc:
            lines.append("```")
            lines.append(poc)
            lines.append("```")
        else:
            lines.append("```curl")
            lines.append(f"# 璁块棶 {f.get('url', '')}")
            lines.append(f"curl -i {f.get('url', domain)}")
            lines.append("```")
        lines.append("")
        
        lines.append("### 婕忔礊璇佹嵁")
        lines.append("")
        evidence = f.get("evidence", "")
        if evidence:
            lines.append("```")
            lines.append(evidence[:500])
            lines.append("```")
        lines.append("")
        
        lines.append("### 淇寤鸿")
        lines.append("")
        lines.append(f.get("remediation", "璇峰弬鑰冨搴擟WE缂栧彿鍙殑鏍囧噯淇鏂规"))
        lines.append("")
        
        lines.append("---")
        lines.append("")
    
    if unverified:
        lines.append("## 寰呮墜鍔ㄩ獙璇?)
        lines.append("")
        for i, f in enumerate(unverified, 1):
            lines.append(f"{i}. {f.get('title', '?')} (confidence: {f.get('confidence', '?')}%)")
        lines.append("")
    
    return "\n".join(lines)
