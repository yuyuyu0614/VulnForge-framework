'''
Burp Suite 被动代理采集模块
通过 Burp REST API 拉取流量，纯被动不主动发请求
'''

import json
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class BurpConfig:
    host: str = "127.0.0.1"
    port: int = 8090
    api_key: str = ""


@dataclass
class BurpRequest:
    method: str
    url: str
    host: str
    path: str
    headers: dict
    body: str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""


class BurpCollector:
    def __init__(self, config: BurpConfig = None):
        self.config = config or BurpConfig()
        self.base_url = f"http://{self.config.host}:{self.config.port}"

    def _call(self, endpoint: str) -> dict:
        url = f"{self.base_url}{endpoint}"
        req = urllib.request.Request(url)
        if self.config.api_key:
            req.add_header("Authorization", f"Bearer {self.config.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.URLError as e:
            raise ConnectionError(f"无法连接 Burp Suite API ({url}): {e}")

    def check_health(self) -> bool:
        try:
            self._call("/v1/health")
            return True
        except Exception:
            return False

    def get_messages(self, url_filter: str = "", limit: int = 500) -> list[BurpRequest]:
        endpoint = f"/v1/messages?limit={limit}"
        if url_filter:
            endpoint += f"&url={urllib.parse.quote(url_filter)}"
        raw = self._call(endpoint).get("messages", [])
        return [self._parse_message(m) for m in raw]

    def _parse_message(self, msg: dict) -> BurpRequest:
        req = msg.get("request", {})
        resp = msg.get("response", {})
        url = req.get("url", "")
        parsed = urllib.parse.urlparse(url)
        return BurpRequest(
            method=req.get("method", "GET"),
            url=url,
            host=parsed.netloc,
            path=parsed.path,
            headers={h.get("name",""): h.get("value","") for h in req.get("headers", [])},
            body=req.get("body", ""),
            response_status=resp.get("status", 0),
            response_headers={h.get("name",""): h.get("value","") for h in resp.get("headers", [])},
            response_body=resp.get("body", ""),
        )

    def get_api_endpoints(self, host: str = "") -> list[str]:
        msgs = self.get_messages(url_filter=host) if host else self.get_messages()
        endpoints = set()
        for m in msgs:
            if any(k in m.path for k in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/", "/v4/"]):
                endpoints.add(f"{m.method} {m.path}")
        return sorted(endpoints)
