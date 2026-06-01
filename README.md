# 🔨 VulnForge — AI-Driven Vulnerability Mining Framework
# AI驱动的漏洞挖掘框架

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

VulnForge is an AI-augmented security audit framework for white-box and grey-box vulnerability mining. It combines static analysis, code pattern extraction, multi-agent collaboration, and courtroom-style verification to help researchers surface real vulnerabilities before attackers do.

VulnForge 是一个AI增强的安全审计框架，面向白盒和灰盒漏洞挖掘场景。通过静态分析、代码模式提取、多智能体协作和模拟法庭式交叉验证，在攻击者之前发现真实漏洞。

---

## 🧱 Architecture / 架构

```
VulnForge/
├── api.py                    # FastAPI scan endpoint / 扫描API端点
├── requirements.txt          # Python dependencies / Python依赖
├── src/
│   ├── agents/               # Multi-agent collaboration scheduler / 多智能体协作调度
│   ├── courtroom/            # VulTrial — 4-role adversarial verification / 模拟法庭交叉验证
│   ├── greybox/              # Grey-box scanners (auth, API, network) / 灰盒扫描器
│   ├── knowledge/            # Pattern extraction & retrieval / 漏洞模式提取检索
│   ├── preprocess/           # Pre-audit detectors (secrets, encryption, semgrep) / 前置检测
│   └── ui/                   # PySide6 desktop dispatch center / 桌面调度中心
├── tests/                    # Unit & E2E tests / 单元与端到端测试
└── .gitignore                # Excludes scans, reports, data / 排除扫描数据与报告
```

---

## 🚀 Quick Start / 快速开始

### Prerequisites / 环境要求

- Python 3.10+
- [Ollama](https://ollama.com/) (for AI analysis / AI分析引擎)
- [Semgrep](https://semgrep.dev/) (optional / 可选)
- [truffleHog](https://github.com/trufflesecurity/trufflehog) (optional / 可选)

### Install / 安装

```bash
git clone https://github.com/yuyuyu0614/VulnForge-framework.git
cd VulnForge-framework
pip install -r requirements.txt

# Pull local LLM (optional, for AI-powered analysis / 可选，AI分析用)
ollama pull llama3.1:8b
```

### Run a Scan / 运行扫描

```bash
# White-box audit on a local repo / 白盒审计本地仓库
python src/pipeline.py analyze --path /path/to/target --mode deep

# Start the API server / 启动API服务
uvicorn api:app --host 0.0.0.0 --port 8003

# One-click scan via API / 通过API一键扫描
curl -X POST http://localhost:8003/scan -H '"'"'Content-Type: application/json'"'"' -d '"'"'{"repo_url":"...", "scan_type":"quick"}'"'"'
```

### Desktop UI / 桌面界面

```bash
python src/ui/main_window.py
```

---

## 🎯 Core Modules / 核心模块

| Module / 模块 | Description / 描述 |
|---|---|
| `code_chunker.py` | Function/class boundary splitting across 5 languages / 5语言函数级代码分割 |
| `feature_extractor.py` | AST-based feature extraction / 基于AST的代码特征提取 |
| `hallucination_checker.py` | AI output hallucination detection (4 types) / AI幻觉检测（4类） |
| `false_positive_filter.py` | Data-flow reachability analysis, ~93% FP reduction / 数据流可达性分析，过滤93%误报 |
| `cwe_classifier.py` | Precise CWE classification (10 categories) / CWE精确分类（10类） |
| `report_generator.py` | Multi-platform report export / 多平台漏洞报告导出 |
| `secrets_scanner.py` | Hardcoded secret detection (truffleHog + 40+ regex) / 硬编码密钥检测 |
| `encryption_detector.py` | Pre-scan code encryption rate detector / 扫描前代码加密率检测 |
| `courtroom/trial.py` | VulTrial — 4-role adversarial verification / 模拟法庭4角色交叉验证 |
| `greybox/scanner.py` | HAR-driven grey-box scanner / HAR驱动的灰盒扫描器 |
| `greybox/burp_collector.py` | Burp Suite passive traffic collector / Burp Suite被动流量收集 |

---

## 🔬 Confidence Scoring / 置信度评分体系

| Stage / 阶段 | Score / 得分 |
|---|---|
| AI report finding / AI初步报告 | 0 pts |
| Hallucination check pass / 幻觉检测通过 | +15 pts |
| VulTrial courtroom confirmation / 模拟法庭确认 | +25 pts |
| Cross-model verification / 跨模型交叉验证 | +10 pts |
| Docker PoC reproduction / Docker环境复现 | +50 pts |
| **Submission threshold / 提交阈值** | **>= 60 pts** |

---

## ⚠️ Disclaimer / 免责声明

This tool is designed for **authorized security testing only**. Users must obtain explicit permission before testing any target. The authors assume no liability for misuse.

本工具仅用于**授权安全测试**。使用前必须获得明确授权，作者不承担任何误用责任。

---

## 📄 License / 许可证

MIT License.
