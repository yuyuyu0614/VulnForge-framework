"""Greybox Network Module - Passive network-level checks.

All checks are PASSIVE: single GET requests, no fuzzing, no brute force.
"""

import re
from urllib.parse import urljoin
from dataclasses import dataclass
from typing import Optional
import requests

from . import GreyboxFinding


class NetworkChecker:
    """Passive network-level security checks."""
    
    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self.findings = []
    
    def run_all(self, base_url: str) -> list[GreyboxFinding]:
        """Run all passive network checks."""
        self.findings = []
        
        self._check_cookie_security(base_url)
        self._check_cors_config(base_url)
        self._check_info_leaks(base_url)
        self._check_common_endpoints(base_url)
        
        return self.findings
    
    # ---- Cookie Security ----
    
    def _check_cookie_security(self, url: str):
        """Check for missing Secure/HttpOnly/SameSite on cookies."""
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            cookies = r.headers.get("Set-Cookie", "")
            if not cookies:
                # Try with a fresh request that might trigger Set-Cookie
                r2 = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                cookies = r2.headers.get("Set-Cookie", "")
            
            if cookies:
                insecure = []
                for cookie_str in cookies.split(","):
                    cookie_str = cookie_str.strip()
                    if not cookie_str:
                        continue
                    name = cookie_str.split("=")[0] if "=" in cookie_str else cookie_str[:20]
                    issues = []
                    if "Secure" not in cookie_str:
                        issues.append("Secure")
                    if "HttpOnly" not in cookie_str:
                        issues.append("HttpOnly")
                    if "SameSite" not in cookie_str:
                        issues.append("SameSite")
                    if issues:
                        insecure.append(f"{name}: missing {', '.join(issues)}")
                
                if insecure:
                    self.findings.append(GreyboxFinding(
                        finding_id=f"cookie_{hash(url)}",
                        category="cookie_security",
                        severity="low",
                        cwe_id="CWE-614",
                        title=f"Insecure Cookie Configuration ({len(insecure)} cookie(s))",
                        description=f"Cookies missing security flags: {'; '.join(insecure[:5])}",
                        evidence="\n".join(insecure[:10]),
                        url=url,
                        remediation="Set Secure, HttpOnly, and SameSite=Lax on all cookies.",
                        confidence=85
                    ))
                    print(f"  [COOKIE] {len(insecure)} insecure cookie(s)")
        except Exception as e:
            pass
    
    # ---- CORS Configuration ----
    
    def _check_cors_config(self, url: str):
        """Check for overly permissive CORS configuration."""
        try:
            # Test with a cross-origin request
            r = self.session.options(url, headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
            }, timeout=self.timeout, allow_redirects=False)
            
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == "*" and acac == "true":
                self.findings.append(GreyboxFinding(
                    finding_id=f"cors_{hash(url)}",
                    category="cors_misconfig",
                    severity="medium",
                    cwe_id="CWE-942",
                    title="Overly Permissive CORS Configuration",
                    description="CORS allows any origin (*) with credentials, enabling cross-origin attacks.",
                    evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    url=url,
                    remediation="Restrict Access-Control-Allow-Origin to trusted domains.",
                    confidence=75
                ))
                print(f"  [CORS] Permissive: {acao} with credentials")
            elif acao == "*":
                self.findings.append(GreyboxFinding(
                    finding_id=f"cors_{hash(url)}",
                    category="cors_misconfig",
                    severity="low",
                    cwe_id="CWE-942",
                    title="Wildcard CORS Origin",
                    description="CORS allows any origin (*). While credentials are not allowed, this may still be overly permissive.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    url=url,
                    remediation="Restrict to specific origins if possible.",
                    confidence=60
                ))
                print(f"  [CORS] Wildcard origin: {acao}")
        except Exception as e:
            pass
    
    # ---- Information Leak Endpoints ----
    
    # Passive-only paths: informational files that SHOULD be public or reveal config issues
    INFO_PATHS = [
        ("/robots.txt", "Robots.txt - May reveal hidden paths"),
        ("/sitemap.xml", "Sitemap.xml - May reveal all site routes"),
        ("/.well-known/security.txt", "security.txt - Security contact info"),
        ("/crossdomain.xml", "crossdomain.xml - Flash cross-domain policy (legacy)"),
        ("/clientaccesspolicy.xml", "clientaccesspolicy.xml - Silverlight policy (legacy)"),
    ]
    
    def _check_info_leaks(self, url: str):
        """Check informational endpoints for sensitive content."""
        for path, description in self.INFO_PATHS:
            try:
                full_url = urljoin(url, path)
                r = self.session.get(full_url, timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    # Check if content reveals interesting paths
                    if path == "/robots.txt":
                        disallowed = re.findall(r"Disallow:\s*(/\S+)", r.text, re.I)
                        if disallowed and len(disallowed) > 2:
                            self.findings.append(GreyboxFinding(
                                finding_id=f"robots_{hash(url)}",
                                category="info_leak",
                                severity="low",
                                cwe_id="CWE-200",
                                title=f"Robots.txt Reveals {len(disallowed)} Hidden Paths",
                                description=f"robots.txt disallows {len(disallowed)} paths, revealing internal structure.",
                                evidence="\n".join(disallowed[:15]),
                                url=full_url,
                                remediation="Review if hidden paths should be exposed in robots.txt.",
                                confidence=50
                            ))
                            print(f"  [INFO] robots.txt reveals {len(disallowed)} disallowed paths")
                    
                    if path == "/crossdomain.xml" or path == "/clientaccesspolicy.xml":
                        if "allow-access-from" in r.text.lower() and "*" in r.text:
                            self.findings.append(GreyboxFinding(
                                finding_id=f"crossdomain_{hash(url)}",
                                category="info_leak",
                                severity="low",
                                cwe_id="CWE-942",
                                title=f"Permissive {path} Policy",
                                description=f"{path} allows access from any domain (wildcard), which is a legacy security risk.",
                                evidence=r.text[:300],
                                url=full_url,
                                remediation="Remove legacy cross-domain policy files or restrict to specific domains.",
                                confidence=60
                            ))
                            print(f"  [INFO] Permissive {path}")
            except:
                pass
    
    # ---- Common Endpoint Discovery (existence only, no fuzzing) ----
    
    # Limited set of informative endpoints - not a brute force list
    COMMON_ENDPOINTS = [
        ("/login", "Login page"),
        ("/register", "Registration page"),
        ("/admin", "Admin panel"),
        ("/api", "API endpoint"),
        ("/docs", "Documentation"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/swagger-ui/index.html", "Swagger UI"),
        ("/actuator/health", "Spring Actuator Health"),
        ("/.env", "Environment file"),
        ("/.git/HEAD", "Git repository"),
    ]
    
    def _check_common_endpoints(self, url: str):
        """Check existence of common endpoints (single request each        
        # SPA check: if /known-random-path returns same content as /, skip endpoint detection
        is_spa = False
        try:
            r_spa = self.session.get(urljoin(url, "/__spa_check__xyz123__"), timeout=self.timeout, allow_redirects=False)
            r_base = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            if r_spa.status_code == 200 and r_base.status_code == 200:
                if len(r_spa.text) == len(r_base.text) and r_spa.text[:500] == r_base.text[:500]:
                    is_spa = True
                    print(f"  [SPA] Detected SPA mode - skipping endpoint discovery")
        except:
            pass
        
        if is_spa:
            return
        , no brute force)."""
        discovered = []
        for path, label in self.COMMON_ENDPOINTS:
            try:
                full_url = urljoin(url, path)
                r = self.session.get(full_url, timeout=self.timeout, allow_redirects=False)
                
                # Detect sensitive endpoints
                if r.status_code == 200:
                    if path in ["/.env", "/.git/HEAD"]:
                        discovered.append((path, "critical", "Sensitive file exposed"))
                    elif path in ["/swagger-ui.html", "/swagger-ui/index.html", "/actuator/health"]:
                        discovered.append((path, "medium", f"{label} exposed"))
                    elif path in ["/admin"]:
                        discovered.append((path, "low", f"{label} discovered"))
                elif r.status_code == 403:
                    if path in ["/.env", "/.git/HEAD"]:
                        discovered.append((path, "info", f"{label} exists but is forbidden (403)"))
                    elif path in ["/swagger-ui.html", "/actuator/health"]:
                        discovered.append((path, "info", f"{label} exists but is forbidden (403)"))
            except:
                pass
        
        if discovered:
            critical = [d for d in discovered if d[2] == "critical"]
            medium = [d for d in discovered if d[1] == "medium"]
            
            if critical:
                self.findings.append(GreyboxFinding(
                    finding_id=f"endpoint_{hash(url)}",
                    category="endpoint_exposure",
                    severity="high",
                    cwe_id="CWE-538",
                    title=f"Sensitive File Exposure ({len(critical)} endpoint(s))",
                    description=f"Sensitive files are publicly accessible: {', '.join(d[0] for d in critical)}",
                    evidence="\n".join(f"{d[0]}: {d[2]}" for d in critical),
                    url=url,
                    remediation="Restrict access to sensitive files at the web server level.",
                    confidence=80
                ))
                print(f"  [ENDPOINT] CRITICAL: {', '.join(d[0] for d in critical)}")
            
            if medium:
                self.findings.append(GreyboxFinding(
                    finding_id=f"endpoint_medium_{hash(url)}",
                    category="endpoint_exposure",
                    severity="medium",
                    cwe_id="CWE-200",
                    title=f"Development Endpoint Exposure ({len(medium)} endpoint(s))",
                    description=f"Development/documentation endpoints are exposed: {', '.join(d[0] for d in medium)}",
                    evidence="\n".join(f"{d[0]}: {d[2]}" for d in medium),
                    url=url,
                    remediation="Disable development endpoints in production.",
                    confidence=65
                ))
                print(f"  [ENDPOINT] Medium: {', '.join(d[0] for d in medium)}")