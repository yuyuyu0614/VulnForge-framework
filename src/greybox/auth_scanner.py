"""Authenticated Scanner - session-aware greybox testing.

Adds to VulnForge:
1. HAR file parsing for API discovery
2. Session cookie injection for authenticated scanning
3. IDOR testing engine (horizontal privilege escalation)
"""

import json, re, hashlib, time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class HAREntry:
    """Parsed HAR request entry."""
    method: str
    url: str
    path: str
    headers: dict
    post_data: Optional[str]
    response_status: int
    response_size: int


@dataclass
class IDORResult:
    """Result of an IDOR test."""
    url: str
    method: str
    param: str
    original_value: str
    tested_value: str
    status: int
    response_preview: str
    is_vulnerable: bool
    confidence: int


class HARParser:
    """Parse browser HAR export files for API discovery."""
    
    @staticmethod
    def parse(har_path: str, domain_filter: str = None) -> list[HAREntry]:
        """Parse a HAR file and return API entries.
        
        Args:
            har_path: Path to .har file
            domain_filter: Only return entries matching this domain (e.g. 'example-api.target.com')
        """
        with open(har_path, 'r', encoding='utf-8') as f:
            har = json.load(f)
        
        entries = []
        for e in har['log']['entries']:
            req = e['request']
            url = req['url']
            
            if domain_filter and domain_filter not in url:
                continue
            
            parsed = urlparse(url)
            
            headers = {}
            for h in req['headers']:
                headers[h['name']] = h['value']
            
            resp = e['response']
            
            entries.append(HAREntry(
                method=req['method'],
                url=url,
                path=parsed.path + ('?' + parsed.query if parsed.query else ''),
                headers=headers,
                post_data=req.get('postData', {}).get('text', None),
                response_status=resp['status'],
                response_size=resp['content'].get('size', 0),
            ))
        
        return entries
    
    @staticmethod
    def extract_api_paths(entries: list[HAREntry]) -> list[dict]:
        """Extract unique API endpoints with their parameters."""
        apis = {}
        for e in entries:
            key = f"{e.method} {e.path.split('?')[0]}"
            if key not in apis:
                apis[key] = {
                    'method': e.method,
                    'path': e.path.split('?')[0],
                    'full_path': e.path,
                    'post_data': e.post_data,
                    'sample_headers': {k: v for k, v in e.headers.items()
                                      if k.lower() in ('content-type', 'authorization', 'cookie', 
                                                       'px-authorization-user', 'px-authorization-merchant',
                                                       'user_id', 'device_id', 'client_type')},
                    'status': e.response_status,
                    'size': e.response_size,
                }
        return list(apis.values())


class AuthScanner:
    """Session-aware scanner that uses real auth tokens from HAR or manual input."""
    
    def __init__(self, session: requests.Session = None, timeout: int = 10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.auth_headers = {}
        self.base_url = ""
        self.findings = []
    
    def load_from_har(self, har_path: str, api_domain: str) -> bool:
        """Load auth headers from the first matching HAR entry."""
        entries = HARParser.parse(har_path, domain_filter=api_domain)
        if not entries:
            print(f"  [AuthScanner] No entries found for domain {api_domain}")
            return False
        
        # Extract auth-relevant headers
        for e in entries:
            for name, value in e.headers.items():
                name_lower = name.lower()
                if any(k in name_lower for k in ('authorization', 'token', 'cookie', 'user_id', 'device_id')):
                    self.auth_headers[name] = value
        
        self.base_url = f"https://{api_domain}"
        print(f"  [AuthScanner] Loaded {len(self.auth_headers)} auth headers from HAR")
        return True
    
    def set_auth(self, headers: dict, base_url: str):
        """Manually set auth headers."""
        self.auth_headers = headers
        self.base_url = base_url.rstrip('/')
    
    def probe(self, method: str, path: str, body: str = None, extra_headers: dict = None) -> Optional[requests.Response]:
        """Make an authenticated request."""
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        headers = {**self.auth_headers}
        if extra_headers:
            headers.update(extra_headers)
        
        try:
            if method == 'GET':
                return self.session.get(url, headers=headers, timeout=self.timeout)
            else:
                headers['content-type'] = headers.get('content-type', 'application/json')
                return self.session.post(url, headers=headers, data=body or '{}', timeout=self.timeout)
        except requests.RequestException as e:
            return None
    
    def scan_from_har(self, har_path: str, api_domain: str) -> list[dict]:
        """Full scan: parse HAR, extract APIs, test each one."""
        entries = HARParser.parse(har_path, domain_filter=api_domain)
        apis = HARParser.extract_api_paths(entries)
        
        print(f"  [HARScan] {len(entries)} entries, {len(apis)} unique APIs")
        
        findings = []
        for api in apis[:50]:  # Limit to 50
            method = api['method']
            path = api['path']
            body = api.get('post_data')
            
            resp = self.probe(method, path, body)
            if resp is None:
                continue
            
            # Check if response contains potentially sensitive data
            rt = resp.text
            size = len(rt)
            
            # Heuristic: large JSON response with user-like data = interesting
            if size > 1000 and resp.status_code == 200:
                sensitive_patterns = ['"userId"', '"telphone"', '"phone"', '"nickname"', 
                                      '"avatar"', '"orderId"', '"token"', '"password"']
                hits = [p for p in sensitive_patterns if p in rt]
                if hits:
                    findings.append({
                        'path': path,
                        'method': method,
                        'size': size,
                        'sensitive_fields': hits,
                        'preview': rt[:200],
                        'response': rt,
                    })
                    print(f"  [!] {method} {path} -> {size}b, fields: {hits}")
            
            time.sleep(0.3)  # Rate limit
        
        return findings


class IDOREngine:
    """Automated IDOR (Insecure Direct Object Reference) testing."""
    
    # Patterns that suggest the endpoint accepts a user-controllable resource ID
    IDOR_PARAMS = [
        ('query', ['userId', 'userId', 'id', 'orderId', 'productId', 'refundId', 'itemId']),
        ('body', ['"userId"', '"userId"', '"id"', '"orderId"', '"productId"', '"mainOrderId"', '"refundId"']),
    ]
    
    def __init__(self, auth_scanner: AuthScanner):
        self.scanner = auth_scanner
        self.results: list[IDORResult] = []
    
    def test_endpoint(self, method: str, path: str, body: str = None,
                      param_name: str = None, original_value: str = None,
                      test_values: list[str] = None) -> list[IDORResult]:
        """Test a single endpoint for IDOR.
        
        Tries replacing the resource ID with different values.
        """
        test_values = test_values or ['1', '2', '10', '100', '0', 'admin']
        results = []
        
        for test_val in test_values:
            if param_name:
                # Try URL param replacement
                if '?' in path:
                    import re
                    new_path = re.sub(f'{param_name}=[^&]+', f'{param_name}={test_val}', path)
                else:
                    new_path = f"{path}?{param_name}={test_val}"
                
                resp = self.scanner.probe(method, new_path)
            elif body and param_name:
                # Try body param replacement
                import re
                new_body = re.sub(f'"{param_name}"\s*:\s*"[^"]*"', f'"{param_name}":"{test_val}"', body)
                new_body = re.sub(f'"{param_name}"\s*:\s*[0-9]+', f'"{param_name}":{test_val}', new_body)
                resp = self.scanner.probe(method, path, new_body)
            else:
                continue
            
            if resp is None:
                continue
            
            rt = resp.text
            is_leak = resp.status_code == 200 and len(rt) > 50
            # Check if response contains different user data than expected
            has_sensitive = bool(re.search(r'(userId|telphone|nickname|phone|orderId|password)', rt))
            
            result = IDORResult(
                url=path, method=method, param=param_name or 'unknown',
                original_value=original_value or '?', tested_value=test_val,
                status=resp.status_code,
                response_preview=rt[:200],
                is_vulnerable=is_leak and has_sensitive,
                confidence=70 if (is_leak and has_sensitive) else 30,
            )
            results.append(result)
            
            if result.is_vulnerable:
                print(f"  [IDOR!] {method} {path} param={param_name} test={test_val} -> {len(rt)}b leaked")
            
            time.sleep(0.5)
        
        self.results.extend(results)
        return results
    
    def auto_detect(self, findings: list[dict]) -> list[IDORResult]:
        """Auto-detect IDOR-vulnerable params from findings and test them."""
        all_results = []
        for finding in findings:
            path = finding['path']
            method = finding['method']
            body = finding.get('post_data')
            response = finding.get('response', '')
            
            # Detect likely resource IDs from response
            id_patterns = re.findall(r'"(\w*[iI]d)"\s*:\s*"?([0-9]+)"?', response)
            
            for param_name, param_value in id_patterns[:5]:  # Top 5 IDs
                test_vals = [str(int(param_value) + 1), str(int(param_value) - 1), '1', '0']
                results = self.test_endpoint(method, path, body, param_name, param_value, test_vals)
                all_results.extend(results)
        
        return all_results


def run_auth_scan(har_path: str, api_domain: str, 
                  manual_headers: dict = None) -> list[dict]:
    """One-shot authenticated scan from HAR file.
    
    Args:
        har_path: Path to browser HAR export
        api_domain: API domain to target (e.g. 'example-api.target.com')
        manual_headers: Override/additional auth headers
    
    Returns:
        List of findings with sensitive data
    """
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    scanner = AuthScanner(session)
    
    if manual_headers:
        scanner.set_auth(manual_headers, f'https://{api_domain}')
    else:
        scanner.load_from_har(har_path, api_domain)
    
    findings = scanner.scan_from_har(har_path, api_domain)
    
    # Run IDOR on findings
    if findings:
        engine = IDOREngine(scanner)
        idor_results = engine.auto_detect(findings)
        
        # Filter to only confirmed leaks
        leaks = [r for r in idor_results if r.is_vulnerable]
        if leaks:
            print(f"\n  [IDOR] Found {len(leaks)} potential IDOR vulnerabilities!")
            for leak in leaks:
                print(f"    {leak.method} {leak.url} {leak.param}={leak.tested_value}")
    
    return findings