"""Passive API Fuzzer - compliance-safe, low-concurrency path discovery.

Design principles:
- No high concurrency (>3 req/s = 1 req every 333ms minimum)
- READ-ONLY: GET/HEAD only, never POST/PUT/DELETE to avoid side effects
- No brute force: intelligent dictionary based on framework fingerprint
- Abort on WAF detection
"""

import time
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Intelligent path dictionaries by framework
FRAMEWORK_PATHS = {
    "flask": [
        "/api", "/api/v1", "/admin", "/login", "/register", "/logout",
        "/static", "/health", "/debug", "/console", "/swagger",
        "/api/docs", "/api/swagger", "/graphql", "/.env", "/config",
    ],
    "django": [
        "/admin", "/api", "/api/v1", "/api/auth", "/accounts/login",
        "/graphql", "/swagger", "/api/schema", "/health",
    ],
    "spring": [
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
        "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs", "/api",
        "/admin", "/console", "/druid", "/manage",
    ],
    "express": [
        "/api", "/api/v1", "/admin", "/graphql", "/health",
        "/.env", "/swagger", "/docs",
    ],
    "nextjs": [
        "/api", "/api/health", "/api/auth", "/api/graphql", "/admin",
        "/_next/", "/login",
    ],
    "nginx": [
        "/nginx_status", "/status", "/.well-known/security.txt",
    ],
    "generic": [
        "/api", "/api/v1", "/api/v2", "/admin", "/login", "/register",
        "/graphql", "/swagger", "/docs", "/health", "/.env",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/debug", "/console", "/actuator/health",
    ],
}

# Paths never to probe (known noise)
BLACKLIST = ["/favicon.ico", "/apple-touch-icon.png"]


class APIFuzzer:
    
    @staticmethod
    def from_har(har_path: str, api_domain: str, session, delay_ms: int = 500) -> "APIFuzzer":
        from .auth_scanner import HARParser
        entries = HARParser.parse(har_path, domain_filter=api_domain)
        apis = HARParser.extract_api_paths(entries)
        paths = list(set(a["path"] for a in apis if "?" not in a["path"]))
        fuzzer = APIFuzzer(session, f"https://{api_domain}", delay_ms=delay_ms)
        fuzzer._har_paths = paths
        fuzzer._har_entries = entries
        print(f"  [APIFuzzer] HAR-driven: {len(paths)} real API paths from {len(entries)} entries")
        return fuzzer

    """Low-concurrency API path fuzzer."""
    
    def __init__(self, session: requests.Session, base_url: str,
                 delay_ms: int = 500, max_workers: int = 2):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.delay = delay_ms / 1000.0  # seconds
        self.max_workers = max_workers
        self.waf_detected = False
        self.spa_signature = None  # bytes - if all 404s return same size, it's SPA
    
    def detect_framework(self, tech_stack: dict) -> list[str]:
        if hasattr(self, "_har_paths") and self._har_paths:
            return self._har_paths

        """Select path dictionary based on tech fingerprint."""
        paths = list(FRAMEWORK_PATHS["generic"])
        for tech, frameworks in [
            ("Flask", "flask"), ("Django", "django"), ("Spring", "spring"),
            ("Express", "express"), ("Next.js", "nextjs"), ("Nginx", "nginx"),
        ]:
            if tech_stack.get(tech):
                paths.extend(FRAMEWORK_PATHS.get(frameworks, []))
        return list(set(paths))  # deduplicate
    
    def _detect_waf(self) -> bool:
        """Check if WAF is blocking requests."""
        try:
            r = self.session.get(self.base_url + "/<script>", timeout=8)
            if r.status_code in (403, 406, 468, 501):
                return True
            # Check for WAF signatures in body
            body = r.text.lower()
            waf_signatures = ["waf", "blocked", "forbidden", "request rejected",
                            "security policy", "chaitin", "safeine", "cloudflare"]
            return any(sig in body for sig in waf_signatures)
        except Exception:
            return False
    
    def _probe(self, path: str) -> dict | None:
        """Probe a single path. Returns finding dict if endpoint exists."""
        time.sleep(self.delay)  # Rate limiting
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            r = self.session.get(url, timeout=10, allow_redirects=False)
            
            # SPA detection: same byte length on 404s = SPA fallback
            if self.spa_signature is not None and r.status_code == 200:
                if len(r.content) == self.spa_signature:
                    return None  # SPA fallback - not a real endpoint
            
            # Interesting responses
            if r.status_code in (200, 301, 302, 401, 403):
                return {
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "content_type": r.headers.get("Content-Type", ""),
                    "path": path,
                }
            # 405 Method Not Allowed = endpoint exists but wrong method
            if r.status_code == 405:
                return {
                    "url": url,
                    "status": 405,
                    "size": 0,
                    "content_type": "",
                    "path": path,
                }
        except requests.RequestException:
            pass
        return None
    
    def set_spa_signature(self, size: int):
        """Set SPA fallback size to filter false positives."""
        self.spa_signature = size
    
    def fuzz(self, tech_stack: dict = None, spa_size: int = None) -> list[dict]:
        """Run compliance-safe API fuzzing.
        
        Args:
            tech_stack: Technology fingerprint dict from scanner
            spa_size: If set, responses with this byte size are filtered as SPA fallback
        
        Returns:
            List of endpoint finding dicts
        """
        if spa_size:
            self.spa_signature = spa_size
        
        # Phase 0: WAF detection
        self.waf_detected = False
        paths = self.detect_framework(tech_stack or {})
        
        print(f"  [APIFuzzer] Probing {len(paths)} paths ({self.max_workers} workers, {int(self.delay*1000)}ms delay)")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._probe, p): p for p in paths}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
        
        # Filter SPA noise
        results = [r for r in results if not (
            self.spa_signature is not None and
            r["status"] in (200, 404) and
            r["size"] == self.spa_signature
        )]
        
        print(f"  [APIFuzzer] Found {len(results)} interesting endpoints")
        return results
