import re, json, hashlib
from pathlib import Path
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import (
    SECRET_PATTERNS, API_PATTERNS, SECURITY_HEADERS, TECH_PATTERNS,
    GreyboxFinding
)
from .sandbox_validator import SandboxValidator
from .vendor_matcher import filter_submittable, check_submittable
from .network import NetworkChecker
from .api_fuzzer import APIFuzzer
from .auth_scanner import AuthScanner, IDOREngine, HARParser


# ---- Severity labels in Chinese ----
SEVERITY_CN = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}

CATEGORY_CN = {
    "api_leak": "API路由泄露",
    "secret_leak": "硬编码密钥泄露",
    "subdomain_leak": "子域名信息泄露",
    "security_header": "安全头缺失",
    "cookie_security": "Cookie配置不安全",
    "cors_misconfig": "CORS配置错误",
    "endpoint_exposure": "敏感端点暴露",
    "info_leak": "信息泄露",
}


class GreyboxScanner:
    """Greybox web scanner - passive analysis of web assets."""
    
    def __init__(self, timeout=15, max_workers=5, verify_ssl=True):
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.session = self._build_session()
        self.findings = []
        self.scanned_js = set()
        self.discovered_subs = set()
        self.tech_stack = {}
        self.validator = SandboxValidator()

    
    def _build_session(self):
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        return session
    
    def scan_url(self, url: str, deep: bool = False, tier: str = None, har_path: str = None) -> list[GreyboxFinding]:
        self.findings = []
        self.scanned_js = set()
        self.discovered_subs = set()
        self.tech_stack = {}
        self.validator = SandboxValidator()

        
        print(f"\n{'='*60}")
        print(f"  灰盒扫描: {url}")
        print(f"{'='*60}")
        
        html, final_url = self._fetch(url)
        if not html:
            print(f"  [失败] 无法获取 {url}")
            return self.findings
        
        parsed = urlparse(final_url)
        self.base_domain = parsed.netloc
        
        # Phase 1: Security header check
        self._check_security_headers(final_url)
        
        # Phase 2: Network-level passive checks
        net = NetworkChecker(self.session, self.timeout)
        net_findings = net.run_all(final_url)
        self.findings.extend(net_findings)
        
        # Phase 3: Tech fingerprint
        self._fingerprint_tech(html, final_url)
        
        # Phase 3.5: HAR-based authenticated scan (if HAR provided)
        if har_path:
            self._auth_scan_from_har(har_path, final_url)

        
        # Phase 4: Extract subdomains from HTML
        self._extract_subdomains(html, self.base_domain)
        
        # Phase 4.5: API Fuzzing (compliance-safe, low-concurrency)
        fuzzer = APIFuzzer(self.session, final_url)
        fuzzer.set_spa_signature(len(html))  # Use HTML length as SPA signature
        endpoints = fuzzer.fuzz(tech_stack=self.tech_stack)
        for ep in endpoints:
            cat = "endpoint_exposure"
            if ep["status"] == 405:
                cat = "endpoint_exposure"
            self.findings.append(GreyboxFinding(
                finding_id=self._hash(ep["url"] + "fuzz"),
                category=cat,
                severity="low",
                cwe_id="CWE-200",
                title=f"鍙戠幇绔偣: {ep['path']} (HTTP {ep['status']})",
                description=f"API Fuzzer鍙戠幇绔偣 {ep['path']} 杩斿洖 {ep['status']}锛屽ぇ灏?{ep['size']}瀛楄妭",
                evidence=f"{ep['url']} -> {ep['status']} ({ep['size']} bytes, {ep.get('content_type', 'unknown')})",
                url=ep["url"],
                remediation="Ensure sensitive endpoints have authentication protection", confidence=40
            ))
        
        # Phase 5: Find and scan JS files
        js_urls = self._extract_js_urls(html, final_url)
        print(f"  [JS] 发现 {len(js_urls)} 个脚本文件")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_js_file, url, final_url): url for url in js_urls[:20]}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass
        
        self.findings = self._deduplicate(self.findings)
        
        # Apply vendor-specific filtering if vendor specified
        if tier:
            submittable, rejected = filter_submittable(
                [{"category": f.category, "severity": f.severity, "title": f.title} for f in self.findings], tier)
            rejected_cats = {r["category"] for r in rejected}
            self.findings = [f for f in self.findings if f.category not in rejected_cats]
            print(f"  [Tier:{vendor}] Filtered: {len(self.findings)} submittable, {len(rejected)} rejected")
        
        print(f"  [完成] 共发现 {len(self.findings)} 个漏洞")
        return self.findings
    
    def _fetch(self, url: str) -> tuple[Optional[str], Optional[str]]:
        try:
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True)
            r.raise_for_status()
            return r.text, r.url
        except Exception as e:
            print(f"  [错误] 请求失败 {url}: {e}")
            return None, None
    
    def _check_security_headers(self, url: str):
        try:
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True)
            missing = []
            for header, cwe in SECURITY_HEADERS.items():
                if header not in r.headers:
                    missing.append(header)
            
            if missing:
                self.findings.append(GreyboxFinding(
                    finding_id=self._hash(url + "security_headers"),
                    category="security_header",
                    severity="low",
                    cwe_id="CWE-693",
                    title=f"缺少 {len(missing)} 个安全响应头",
                    description=f"以下安全响应头缺失：{', '.join(missing)}",
                    evidence=str(missing),
                    url=url,
                    remediation="在反向代理或应用层添加缺失的安全响应头。",
                    confidence=90
                ))
        except Exception as e:
            pass
    
    def _fingerprint_tech(self, html: str, url: str):
        detected = {}
        for tech, pattern in TECH_PATTERNS.items():
            match = re.search(pattern, html, re.I)
            if match:
                version = match.group(1) if match.groups() else "detected"
                detected[tech] = version
        self.tech_stack = detected
    
    def _extract_subdomains(self, html: str, base_domain: str):
        parts = base_domain.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
        else:
            root = base_domain
        
        pattern = rf"https?://([\w.-]*{re.escape(root)})"
        matches = set(re.findall(pattern, html, re.I))
        
        new_subs = matches - self.discovered_subs
        self.discovered_subs.update(matches)
        
        if new_subs:
            self.findings.append(GreyboxFinding(
                finding_id=self._hash(base_domain + "subdomain_leak"),
                category="subdomain_leak",
                severity="low",
                cwe_id="CWE-200",
                title=f"页面泄露 {len(new_subs)} 个内部子域名",
                description=f"HTML/JS内容中暴露了 {len(new_subs)} 个内部子域名，攻击者可利用这些信息扩大攻击面。",
                evidence=str(sorted(new_subs)),
                url=base_domain,
                remediation="从公开页面中移除内部子域名引用。",
                confidence=70
            ))
    
    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        scripts = set(re.findall(r"<script[^>]+src=\x22([^\x22]+)\x22", html, re.I))
        scripts.update(re.findall(r"<script[^>]+src='([^']+)'", html, re.I))
        
        resolved = []
        for s in scripts:
            if s.startswith("//"):
                s = "https:" + s
            elif not s.startswith("http"):
                s = urljoin(base_url, s)
            if s not in self.scanned_js:
                resolved.append(s)
        return resolved
    
    def _scan_js_file(self, js_url: str, page_url: str):
        if js_url in self.scanned_js:
            return
        self.scanned_js.add(js_url)
        
        try:
            r = self.session.get(js_url, timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code != 200:
                return
            if len(r.text) < 50:
                return
            
            body = r.content.decode("utf-8", errors="replace")
            file_name = js_url.split("/")[-1][:40]
            
            self._check_secrets(body, js_url, file_name)
            self._extract_apis(body, js_url, file_name)
            self._extract_subdomains(body, page_url)
            
        except Exception as e:
            pass
    
    def _check_secrets(self, body: str, url: str, file_name: str):
        found_secrets = []
        for secret_type, pattern, severity in SECRET_PATTERNS:
            matches = re.findall(pattern, body, re.I)
            for m in matches:
                secret_value = m if isinstance(m, str) else m[0]
                if len(secret_value) < 8 or len(secret_value) > 200:
                    continue
                if secret_value.startswith("http"):
                    continue
                if secret_value in ["undefined", "null", "true", "false"]:
                    continue
                found_secrets.append((secret_type, secret_value[:60], severity))
        
        if found_secrets:
            for stype, sval, sev in found_secrets[:3]:
                self.findings.append(GreyboxFinding(
                    finding_id=self._hash(url + stype + sval[:20]),
                    category="secret_leak",
                    severity=sev,
                    cwe_id="CWE-798",
                    title=f"前端JS文件包含硬编码{stype}",
                    description=f"JS文件 {file_name} 中包含硬编码的 {stype}: {sval}",
                    evidence=f"文件: {file_name}\n类型: {stype}\n值: {sval}",
                    url=url,
                    remediation="移除硬编码的密钥，改用环境变量或密钥管理服务。",
                    confidence=60
                ))
    
    def _extract_apis(self, body: str, url: str, file_name: str):
        all_apis = set()
        for pattern in API_PATTERNS:
            matches = re.findall(pattern, body, re.I)
            all_apis.update(matches)
        
        filtered = {a for a in all_apis if len(a) > 5 and not a.endswith((".js", ".css", ".png", ".jpg", ".svg"))}
        
        if len(filtered) > 3:
            self.findings.append(GreyboxFinding(
                finding_id=self._hash(url + "api_leak"),
                category="api_leak",
                severity="low",
                cwe_id="CWE-200",
                title=f"前端JS暴露 {len(filtered)} 个API路由",
                description=f"前端JS文件 {file_name} 中暴露了 {len(filtered)} 个后端API路由，攻击者可直接获取所有API路径。",
                evidence="\n".join(sorted(filtered)[:15]),
                url=url,
                remediation="对前端JS进行混淆压缩，避免直接暴露后端路由结构。",
                confidence=70
            ))
    
    def _hash(self, text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()[:12]
    
    
    def _auth_scan_from_har(self, har_path: str, base_url: str):
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        api_domain = parsed.netloc
        print(f"  [AuthScan] Loading HAR: {har_path}")
        try:
            entries = HARParser.parse(har_path)
            api_entries = [e for e in entries if api_domain in e.url or "api" in e.url]
            if not api_entries:
                return
            apis = HARParser.extract_api_paths(api_entries)
            print(f"  [AuthScan] {len(apis)} unique APIs")
            auth_headers = {}
            for name, value in api_entries[0].headers.items():
                if any(k in name.lower() for k in ("authorization", "token", "user_id", "device_id", "px-")):
                    auth_headers[name] = value
            if not auth_headers:
                return
            scanner = AuthScanner(self.session)
            scanner.set_auth(auth_headers, f"https://{api_domain}")
            for api in apis[:40]:
                resp = scanner.probe(api["method"], api["path"], api.get("post_data"))
                if resp is None or resp.status_code != 200 or len(resp.text) < 500:
                    continue
                rt = resp.text
                hits = [p for p in ["telephone", "phone", "userId", "nickname", "orderId", "token"] if p in rt]
                if hits:
                    self.findings.append(GreyboxFinding(
                        finding_id=self._hash(api["path"] + "auth"),
                        category="info_leak", severity="medium", cwe_id="CWE-200",
                        title=f"Auth: {api["method"]} {api["path"]} leaks user data",
                        description=f"{len(hits)} sensitive fields found: {hits}",
                        evidence=rt[:500], url=base_url + api["path"],
                        remediation="Verify authorization on this endpoint", confidence=60
                    ))
                    print(f"  [AuthScan] ! {api["method"]} {api["path"]} -> {len(rt)}b")
        except Exception as e:
            print(f"  [AuthScan] Error: {e}")

    def _deduplicate(self, findings: list[GreyboxFinding]) -> list[GreyboxFinding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.category, f.title[:80])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
    
    # ---- Chinese report generation ----
    
    def report(self, format: str = "markdown") -> str:
        if not self.findings:
            return "# 灰盒扫描报告\n\n未发现漏洞。"
        
        lines = [
            "# 安全漏洞报告",
            "",
            f"- **目标资产:** {self.base_domain}",
            f"- **发现漏洞:** {len(self.findings)} 个",
            f"- **技术栈:** {', '.join(f'{k}({v})' for k, v in self.tech_stack.items())}",
            f"- **扫描方式:** 被动灰盒扫描（无攻击行为）",
            "",
            "---",
            ""
        ]
        
        # Group by severity
        for sev_level in ["critical", "high", "medium", "low"]:
            group = [f for f in self.findings if f.severity == sev_level]
            if not group:
                continue
            for i, f in enumerate(group, 1):
                sev_cn = SEVERITY_CN.get(f.severity, f.severity)
                cat_cn = CATEGORY_CN.get(f.category, f.category)
                lines.append(f"## [{sev_cn}] {f.title}")
                lines.append("")
                lines.append(f"| 属性 | 值 |")
                lines.append(f"|------|------|")
                lines.append(f"| 漏洞类型 | {cat_cn} |")
                lines.append(f"| 严重程度 | {sev_cn} |")
                lines.append(f"| CWE编号 | {f.cwe_id} |")
                lines.append(f"| 目标URL | {f.url} |")
                lines.append(f"| 置信度 | {f.confidence}% |")
                lines.append("")
                lines.append(f"**漏洞描述:** {f.description}")
                lines.append("")
                lines.append(f"**复现步骤:**")
                lines.append(f"1. 访问 {f.url}")
                lines.append(f"2. 查看页面源代码/JS文件")
                lines.append(f"3. 发现上述漏洞证据")
                lines.append("")
                lines.append(f"**漏洞证据:**")
                lines.append(f"```")
                lines.append(f.evidence[:500])
                lines.append(f"```")
                lines.append("")
                                # Auto-validate finding
                validation = self.validator.validate({
                    "finding_id": f.finding_id,
                    "cwe_id": f.cwe_id,
                    "category": f.category,
                    "url": f.url,
                    "file": f.evidence[:100] if f.evidence else "",
                    "line_start": "?",
                    "func_name": "?",
                    "confidence": f.confidence
                })
                
                if validation.auto_validated:
                    f.confidence = validation.confidence_after
                    if validation.validated:
                        lines.append(f"""**自动验证结果:** 
```
{validation.evidence}
```
""")
                    else:
                        lines.append(f"""**自动验证结果:** 
```
{validation.evidence} (已验证为误报)
```
""")
                else:
                    lines.append(f"**验证路径指引:**")
                    for step in validation.verification_path:
                        lines.append(f"  {step}")
                    lines.append("")
                lines.append(f"**修复建议:** {f.remediation}")
                lines.append("")
                lines.append("---")
                lines.append("")
        
        return "\n".join(lines)