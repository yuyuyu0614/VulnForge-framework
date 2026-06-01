"""Sandbox Validator - Auto-validate findings where possible.

For findings that CAN be auto-validated (SQL injection, command injection,
security headers, cookies): run automated checks.

For findings that CANNOT be auto-validated (deserialization, code injection,
logic flaws): generate a verification path guide for manual review.
"""

import re
import json
import subprocess
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class ValidationResult:
    finding_id: str
    auto_validated: bool  # True if we could test it automatically
    validated: bool       # True if finding confirmed
    confidence_after: int # Updated confidence
    evidence: str
    verification_path: list[str]  # Steps for manual review


class SandboxValidator:
    """Validates findings automatically where possible, generates guides otherwise."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
    
    def validate(self, finding: dict) -> ValidationResult:
        """Main entry: validate a single finding."""
        cwe = finding.get("cwe_id", "")
        category = finding.get("category", "")
        
        # Auto-validatable categories
        if category == "security_header":
            return self._validate_security_headers(finding)
        elif category == "cookie_security":
            return self._validate_cookie(finding)
        elif "CWE-89" in cwe or "sql" in category.lower():
            return self._validate_sql_injection(finding)
        elif "CWE-78" in cwe or "command" in category.lower():
            return self._validate_command_injection(finding)
        elif category == "cors_misconfig":
            return self._validate_cors(finding)
        elif category == "endpoint_exposure":
            return self._validate_endpoint(finding)
        
        # Non-automatable: generate verification path
        return self._generate_verification_path(finding)
    
    # ---- Auto-validatable checks ----
    
    def _validate_security_headers(self, finding: dict) -> ValidationResult:
        url = finding.get("url", "")
        try:
            r = self.session.get(url, timeout=10, verify=True, allow_redirects=True)
            required = [
                "Content-Security-Policy", "X-Content-Type-Options", 
                "X-Frame-Options", "Strict-Transport-Security",
                "Referrer-Policy", "Permissions-Policy"
            ]
            missing = [h for h in required if h not in r.headers]
            
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=True,
                validated=len(missing) > 0,
                confidence_after=95 if missing else 0,
                evidence=f"Missing headers: {', '.join(missing) if missing else 'ALL PRESENT'}",
                verification_path=[]
            )
        except Exception as e:
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=False,
                validated=False,
                confidence_after=50,
                evidence=f"Could not verify: {e}",
                verification_path=["手动访问URL查看响应头"]
            )
    
    def _validate_cookie(self, finding: dict) -> ValidationResult:
        url = finding.get("url", "")
        try:
            r = self.session.get(url, timeout=10, verify=True, allow_redirects=False)
            cookies = r.headers.get("Set-Cookie", "")
            
            insecure = []
            for c in cookies.split(","):
                c = c.strip()
                if not c:
                    continue
                name = c.split("=")[0] if "=" in c else c[:20]
                issues = []
                if "Secure" not in c:
                    issues.append("Secure")
                if "HttpOnly" not in c:
                    issues.append("HttpOnly")
                if "SameSite" not in c:
                    issues.append("SameSite")
                if issues:
                    insecure.append(f"{name}: missing {', '.join(issues)}")
            
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=True,
                validated=len(insecure) > 0,
                confidence_after=90 if insecure else 0,
                evidence=str(insecure) if insecure else "All cookies properly configured",
                verification_path=[]
            )
        except Exception as e:
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=False,
                validated=False,
                confidence_after=50,
                evidence=f"Could not verify: {e}",
                verification_path=["手动访问URL查看Set-Cookie响应头"]
            )
    
    def _validate_sql_injection(self, finding: dict) -> ValidationResult:
        """Basic SQL injection detection using sqlmap or simple payloads."""
        url = finding.get("url", "")
        # Try with sqlmap first if available
        try:
            result = subprocess.run(
                ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--timeout=10"],
                capture_output=True, text=True, timeout=60
            )
            vulnerable = "vulnerable" in result.stdout.lower() and "identified" in result.stdout.lower()
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=True,
                validated=vulnerable,
                confidence_after=80 if vulnerable else 30,
                evidence=result.stdout[:500] if vulnerable else "No SQL injection detected via sqlmap",
                verification_path=[]
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Fallback: manual test with sleep payload
        try:
            r = self.session.get(url + "' AND SLEEP(2)-- ", timeout=8)
            if r.elapsed.total_seconds() > 3:
                return ValidationResult(
                    finding_id=finding.get("finding_id", "unk"),
                    auto_validated=True,
                    validated=True,
                    confidence_after=70,
                    evidence=f"Time-based SQLi detected: response took {r.elapsed.total_seconds()}s",
                    verification_path=[]
                )
        except:
            pass
        
        return ValidationResult(
            finding_id=finding.get("finding_id", "unk"),
            auto_validated=False,
            validated=False,
            confidence_after=30,
            evidence="Cannot auto-validate SQL injection - manual testing required",
            verification_path=[
                f"1. 打开 {finding.get('file', '未知文件')}，查看第 {finding.get('line_start', '?')} 行",
                "2. 确认SQL查询中的参数来源",
                "3. 如果参数来自用户输入 → 高危",
                "4. 如果参数是内部常量 → 假阳性"
            ]
        )
    
    def _validate_command_injection(self, finding: dict) -> ValidationResult:
        url = finding.get("url", "")
        # For command injection in web, try time-based detection
        try:
            r = self.session.get(url + "?cmd=ping+-n+3+127.0.0.1", timeout=8)
            if r.elapsed.total_seconds() > 2.5:
                return ValidationResult(
                    finding_id=finding.get("finding_id", "unk"),
                    auto_validated=True,
                    validated=True,
                    confidence_after=70,
                    evidence=f"Time-based RCE: response took {r.elapsed.total_seconds()}s",
                    verification_path=[]
                )
        except:
            pass
        
        return ValidationResult(
            finding_id=finding.get("finding_id", "unk"),
            auto_validated=False,
            validated=False,
            confidence_after=30,
            evidence="Cannot auto-validate command injection",
            verification_path=[
                f"1. 打开 {finding.get('file', '未知文件')}，查看第 {finding.get('line_start', '?')} 行",
                "2. 追踪参数是否来自用户输入（request.args, req.body, sys.argv）",
                "3. 如果参数经过过滤 → 检查过滤是否可绕过",
                "4. 如果参数来自用户且无过滤 → 高危"
            ]
        )
    
    def _validate_cors(self, finding: dict) -> ValidationResult:
        url = finding.get("url", "")
        try:
            r = self.session.options(url, headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET"
            }, timeout=10, verify=True)
            
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            
            vulnerable = (acao == "*" and acac == "true") or acao == "https://evil.com"
            
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=True,
                validated=vulnerable,
                confidence_after=85 if vulnerable else 10,
                evidence=f"ACAO={acao}, ACAC={acac}",
                verification_path=[]
            )
        except:
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=False,
                validated=False,
                confidence_after=50,
                evidence="Could not verify CORS",
                verification_path=["手动发送OPTIONS请求，检查ACAO/ACAC响应头"]
            )
    
    def _validate_endpoint(self, finding: dict) -> ValidationResult:
        url = finding.get("url", "")
        try:
            r = self.session.get(url, timeout=10, verify=True, allow_redirects=False)
            
            # SPA check: if a random path returns same content, it is SPA
            import random, string
            random_path = "".join(random.choices(string.ascii_lowercase, k=10))
            base_url = url.rstrip("/").rsplit("/", 1)[0]
            r_spa = self.session.get(f"{base_url}/{random_path}", timeout=8, verify=True, allow_redirects=False)
            
            is_spa = (r_spa.status_code == 200 and len(r_spa.text) == len(r.text) and r_spa.text[:200] == r.text[:200])
            
            if is_spa:
                return ValidationResult(
                    finding_id=finding.get("finding_id", "unk"),
                    auto_validated=True,
                    validated=False,
                    confidence_after=0,
                    evidence="SPA application detected - endpoint not actually exposed",
                    verification_path=[]
                )
            
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=True,
                validated=r.status_code == 200,
                confidence_after=80 if r.status_code == 200 else 40,
                evidence=f"Endpoint status: {r.status_code}, length: {len(r.text)}",
                verification_path=[]
            )
        except:
            return ValidationResult(
                finding_id=finding.get("finding_id", "unk"),
                auto_validated=False,
                validated=False,
                confidence_after=40,
                evidence="Could not verify endpoint",
                verification_path=["手动访问URL确认端点是否存在"]
            )
    
    # ---- Verification path generator ----
    
    def _generate_verification_path(self, finding: dict) -> ValidationResult:
        """Generate manual verification path for findings that cannot be auto-validated."""
        cwe = finding.get("cwe_id", "")
        file_path = finding.get("file", "未知文件")
        line = finding.get("line_start", "?")
        func = finding.get("func_name", finding.get("call", "未知函数"))
        
        if "CWE-502" in cwe:
            path = [
                f"1. 打开 {file_path}，查看第 {line} 行",
                f"2. 查看谁在调用 {func}()（Ctrl+Click 跳转到调用者）",
                "3. 判断调用者是否接收了用户输入",
                "4. 如果参数来自用户请求 → 高危",
                "5. 如果参数是内部数据 → 假阳性",
                f"自动验证: ❌ 无法自动验证（需要判断数据流上下文）",
                "建议: 手动审查调用链"
            ]
        elif "CWE-94" in cwe:
            path = [
                f"1. 打开 {file_path}，查看第 {line} 行",
                f"2. 追踪 {func}() 的参数是如何构造的",
                "3. 检查参数中是否包含用户可控的数据（request.*、input()、sys.argv）",
                "4. 如果参数完全由用户控制 → 严重",
                "5. 如果参数经过严格过滤 → 降级或假阳性",
                f"自动验证: ❌ 无法自动验证",
                "建议: 审计参数构造的完整链路"
            ]
        elif "CWE-22" in cwe:
            path = [
                f"1. 打开 {file_path}，查看第 {line} 行",
                "2. 检查文件路径是否由用户输入拼接而成",
                "3. 尝试构造 ../ 路径穿越 payload",
                "4. 如果成功读取到非预期文件 → 高危",
                f"自动验证: ❌ 无法自动验证",
                "建议: 手动测试路径穿越 payload"
            ]
        else:
            path = [
                f"1. 打开 {file_path}，查看第 {line} 行",
                "2. 追踪参数来源（用户输入 vs 内部数据）",
                "3. 评估利用条件和影响范围",
                "4. 判断是否为真实漏洞",
                f"自动验证: ❌ 无法自动验证",
                "建议: 手动审查代码上下文"
            ]
        
        return ValidationResult(
            finding_id=finding.get("finding_id", "unk"),
            auto_validated=False,
            validated=False,
            confidence_after=finding.get("confidence", 60),
            evidence="需要人工审查",
            verification_path=path
        )