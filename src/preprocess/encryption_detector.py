"""Code encryption detector — Detects obfuscated/encrypted code before audit.

Encrypted code cannot be audited; detect early to avoid wasted effort.
If auditable code < 80%, recommend skipping the target.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field

PHP_ENCRYPTION_SIGNATURES = [
    b"SourceGuardian", b"php_screw",
    b"ionCube", b"Zend Guard", b"eval(base64_decode",
]

@dataclass
class EncryptionReport:
    total_files: int = 0
    encrypted_files: int = 0
    encrypted_ratio: float = 0.0
    encryption_type: str = "none"
    verdict: str = "safe"
    recommendation: str = ""
    sample_encrypted: list = field(default_factory=list)

class EncryptionDetector:
    SAFE_THRESHOLD = 0.10
    RISKY_THRESHOLD = 0.30

    def scan(self, root_path):
        report = EncryptionReport()
        root = Path(root_path)
        if not root.exists():
            report.verdict = "skip"
            report.recommendation = "路径不存在"
            return report
        php_files = list(root.rglob("*.php"))
        report.total_files = len(php_files)
        if report.total_files == 0:
            report.verdict = "safe"
            report.recommendation = "无PHP文件"
            return report
        encrypted = []
        for f in php_files[:500]:
            try:
                first = f.read_bytes().split(b"\n")[0][:200]
                if any(sig in first for sig in PHP_ENCRYPTION_SIGNATURES):
                    encrypted.append(str(f.relative_to(root)))
            except: pass
        report.encrypted_files = len(encrypted)
        report.encrypted_ratio = report.encrypted_files / max(report.total_files, 1)
        report.sample_encrypted = encrypted[:10]
        for f in (php_files[:5] + [root / "restapi" / "public" / "app.php"]):
            try:
                content = f.read_bytes()[:500]
                for sig in PHP_ENCRYPTION_SIGNATURES:
                    if sig in content:
                        report.encryption_type = sig.decode(errors="ignore")
                        break
            except: pass
            if report.encryption_type != "none": break
        if report.encrypted_ratio >= self.RISKY_THRESHOLD:
            report.verdict = "skip"
            report.recommendation = f"加密率{report.encrypted_ratio:.0%}，建议跳过"
        elif report.encrypted_ratio >= self.SAFE_THRESHOLD:
            report.verdict = "risky"
            report.recommendation = f"加密率{report.encrypted_ratio:.0%}，部分文件加密"
        else:
            report.verdict = "safe"
            report.recommendation = f"加密率{report.encrypted_ratio:.0%}，可审计"
        return report