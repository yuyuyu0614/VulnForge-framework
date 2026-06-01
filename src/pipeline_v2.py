"""VulnForge Pipeline v2 - Integrated whitebox + greybox scanning.

Usage:
    python pipeline.py whitebox <dir>    # AST whitebox scan
    python pipeline.py greybox <url>     # Web greybox scan  
    python pipeline.py full <target>      # Auto-detect and run both
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def run_whitebox(target_dir: str):
    """Run whitebox AST analysis."""
    from feature_extractor import extract_directory
    from false_positive_filter import filter_false_positives
    from cwe_classifier import classify_cwe
    from report_generator import build_report
    
    print(f"\n[WHITEBOX] Scanning: {target_dir}")
    hooks = extract_directory(target_dir)
    print(f"  Raw hooks: {len(hooks)}")
    
    findings = []
    for h in hooks:
        lang = h.get("language", "python")
        fh = filter_false_positives([h], h.get("snippet", ""), lang)
        if fh:
            cwe = classify_cwe(h, lang)
            if cwe.get("cwe_id"):
                h["cwe"] = cwe
                findings.append(h)
    
    print(f"  Findings: {len(findings)}")
    for f in findings[:10]:
        c = f.get("cwe", {})
        print(f"  [{c.get('cwe_id', '?')}] {f.get('file', '?')}:{f.get('line_start', '?')}")
    
    if findings:
        report = build_report(findings, "default", target_dir)
        out = Path(target_dir).parent / f"whitebox_{Path(target_dir).name}_report.md"
        out.write_text(report, encoding="utf-8")
        print(f"  Report: {out}")
    return findings


def run_greybox(target_url: str, tier: str = None, har_path: str = None):
    """Run greybox web analysis."""
    from greybox.scanner import GreyboxScanner
    
    scanner = GreyboxScanner()
    findings = scanner.scan_url(target_url, tier=tier, har_path=har_path)
    
    report = scanner.report()
    out = Path.cwd() / f"greybox_{scanner.base_domain.replace(':', '_')}_report.md"
    out.write_text(report, encoding="utf-8")
    print(f"\n  Report: {out}")
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python pipeline.py whitebox <directory>")
        print("  python pipeline.py greybox <url>")
        print("  python pipeline.py full <target>")
        sys.exit(1)
    
    mode = sys.argv[1]
    target = sys.argv[2]
    
    # Parse optional --tier flag
    tier = None
    har_path = None
    args = sys.argv[3:] if len(sys.argv) > 3 else []
    for i, arg in enumerate(args):
        if arg == "--tier" and i + 1 < len(args):
            tier = args[i + 1]
        if arg == "--har" and i + 1 < len(args):
            har_path = args[i + 1]
    
    if mode == "whitebox":
        run_whitebox(target)
    elif mode == "greybox":
        run_greybox(target, tier=tier, har_path=har_path)
    elif mode == "full":
        if target.startswith("http"):
            run_greybox(target, tier=tier, har_path=har_path)
        else:
            run_whitebox(target)
    else:
        print(f"Unknown mode: {mode}")


def run_auth(har_path: str, api_domain: str):
    from greybox.auth_scanner import run_auth_scan
    findings = run_auth_scan(har_path, api_domain)
    out = Path.cwd() / f"auth_scan_{api_domain.replace(":","_")}_report.md"
    lines = ["# Auth Scan Report", "", f"HAR: {har_path}", f"Domain: {api_domain}", f"Findings: {len(findings)}", ""]
    for f in findings:
        lines.append("## " + f.get("method","?") + " " + f.get("path","?"))
        lines.append("- Size: " + str(f.get("size",0)) + "b")
        lines.append("- Sensitive fields: " + str(f.get("sensitive_fields",[])))
        lines.append("```")
        lines.append(f.get("preview",""))
        lines.append("```")
        lines.append("")
    out.write_text(chr(10).join(lines), encoding="utf-8")
    print(f"Report: {out}")
    return findings



def run_traffic_diff(burp_host: str = "127.0.0.1", burp_port: int = 8090, target_host: str = ""):
    """Run Burp passive traffic diff analysis — 纯被动，完全合规."""
    from greybox.burp_collector import BurpCollector, BurpConfig
    from greybox.traffic_diff import TrafficDiffer
    from greybox.verify_guide import GuideGenerator

    config = BurpConfig(host=burp_host, port=burp_port)
    collector = BurpCollector(config)

    if not collector.check_health():
        print("[!] Burp Suite API 不可达，请确认 Burp 已启动并开启 REST API (User options > Misc > REST API)")
        return []

    print(f"[TRAFFIC_DIFF] 正在从 Burp 拉取流量... (target: {target_host or 'all'})")

    msgs_all = collector.get_messages(url_filter=target_host)
    if not msgs_all:
        print("[!] Burp 中没有流量记录。请先在浏览器中正常浏览目标站点。")
        return []

    logged_in = [m for m in msgs_all if ":authority" in str(m.headers).lower() or "cookie" in str(m.headers).lower()]
    anonymous = [m for m in msgs_all if "cookie" not in str(m.headers).lower() and "authorization" not in str(m.headers).lower()]

    print(f"  已登录请求: {len(logged_in)}")
    print(f"  未登录请求: {len(anonymous)}")

    differ = TrafficDiffer()
    findings = differ.diff(logged_in, anonymous)

    print(f"\n  差异发现: {len(findings)}")
    for f in findings:
        print(f"    [{f.severity}] {f.method} {f.endpoint}")
        print(f"           {f.detail[:80]}...")

    guide_gen = GuideGenerator()
    guides = guide_gen.generate(findings)

    print(f"\n  验证指引 ({len(guides)} 条):")
    for g in guides:
        print(f"    [{g.finding_id}] {g.title} (置信度: {g.confidence}%)")
        for s in g.steps:
            print(f"      {s}")
        if not g.auto_verifiable:
            print(f"      [!] 需人工验证: {g.manual_reason}")

    return findings
