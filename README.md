# Code Agent Scan

Security audit tooling for Codex/Claude skills. It performs a local LLM review of skill files (no script upload) and checks outbound domains against VirusTotal.

## Key Features

- LLM review of `SKILL.md` + `scripts/*` for backdoor behaviors and suspicious encryption/obfuscation
- VirusTotal domain reputation checks for outbound URLs
- One-click end-to-end scan with reports
- Cross-platform cache to reduce VT API usage

## Workflow Summary

1. Collect `SKILL.md` and `scripts/*` from installed skills
2. Generate LLM audit input (`llm_input.txt`)
3. Extract outbound domains and query VirusTotal
4. Write summary/detail reports and a placeholder `llm_report.txt`

## Project Layout

- `SKILL.md`: skill entry point and workflow
- `config.json`: VT API key config (local only)
- `scripts/scan_all.py`: one-click scan (LLM input + VT scan + reports)
- `scripts/vt_domain_scan.py`: VT-only domain scan
- `scripts/vt_utils.py`: shared helpers (domain extraction, cache, VT API)
- `references/llm_scan_prompt.md`: LLM audit prompt
- `references/virustotal_api.md`: VT API notes

## Requirements

- Python 3.8+
- VirusTotal API key

## Configure VT API Key

Option A: config file (recommended, local only)

```
config.json
{
  "VT_API_KEY": "your_key"
}
```

Option B: environment variable

```
VT_API_KEY=your_key
```

## How to Get a VirusTotal API Key

1. Sign in or create an account: https://www.virustotal.com/
2. Go to your profile: https://www.virustotal.com/gui/user/
3. Open the API key section and copy your key.
4. Paste it into `config.json` or set `VT_API_KEY`.

## Quick Start (One-Click)

Run from the project root:

```bash
python scripts/scan_all.py
```

Common flags:

```bash
python scripts/scan_all.py --skills-root /path/to/skills --include-bare-domains --max-domains 50 --sleep 0.5
```

## Outputs

Reports are written to the OS user data directory under `codex-risk/reports`.

- `summary.txt`: high-level summary
- `detail.txt`: full VT results
- `llm_input.txt`: file contents for LLM audit
- `llm_report.txt`: write LLM findings (high/medium only)

## LLM Audit Workflow

1. Open `llm_input.txt` and use `references/llm_scan_prompt.md`.
2. Record findings in `llm_report.txt`.
3. Flag any complex encryption/obfuscation for manual review.

## VT Domain Scan Only

```bash
python scripts/vt_domain_scan.py --skills-root /path/to/skills
```

Options:

- `--include-bare-domains`: detect domains without http(s):// or www (more false positives)
- `--max-domains N`: limit scan size
- `--sleep 0.5`: delay between requests
- `--cache-ttl-days 7`: cache TTL in days

## Cache

VT responses are cached at:

- Windows: `%LOCALAPPDATA%\codex-risk\vt_cache.json`
- macOS: `~/Library/Application Support/codex-risk/vt_cache.json`
- Linux: `~/.local/share/codex-risk/vt_cache.json`

## Install As Codex Skill

Copy this folder to:

- `C:\Users\<User>\.codex\skills\code-agent-scan`

---

# 代码代理扫描（中文版）

面向 Codex/Claude 技能的安全审计工具。先对技能内容进行本地 LLM 审计（不上传脚本），再对外联域名进行 VirusTotal 信誉查询。

## 核心功能

- 对 `SKILL.md` 与 `scripts/*` 进行 LLM 审计，关注后门/持久化/隐蔽执行/凭据/外传/权限提升
- 检测复杂加密/混淆并标记为高优先级人工复核
- 一键生成报告与 LLM 输入
- VT 结果缓存，减少 API 调用

## 工作流概览

1. 收集已安装 skills 中的 `SKILL.md` 与 `scripts/*`
2. 生成 LLM 审计输入（`llm_input.txt`）
3. 提取外联域名并调用 VirusTotal
4. 输出摘要/明细报告与 `llm_report.txt`

## 目录结构

- `SKILL.md`: 技能入口与流程
- `config.json`: VT API Key 配置（仅本地）
- `scripts/scan_all.py`: 一键扫描
- `scripts/vt_domain_scan.py`: 仅做域名 VT 扫描
- `scripts/vt_utils.py`: 工具函数
- `references/llm_scan_prompt.md`: LLM 审计提示
- `references/virustotal_api.md`: VT API 说明

## 依赖

- Python 3.8+
- VirusTotal API Key

## 配置 VT API Key

方式一：配置文件（推荐，本地使用）

```
config.json
{
  "VT_API_KEY": "your_key"
}
```

方式二：环境变量

```
VT_API_KEY=your_key
```

## 如何申请 VirusTotal API Key

1. 注册/登录：https://www.virustotal.com/
2. 进入个人资料：https://www.virustotal.com/gui/user/
3. 在 API Key 页面复制密钥
4. 写入 `config.json` 或设置 `VT_API_KEY`

## 一键扫描

```bash
python scripts/scan_all.py
```

常用参数：

```bash
python scripts/scan_all.py --skills-root /path/to/skills --include-bare-domains --max-domains 50 --sleep 0.5
```

## 输出说明

默认输出到用户数据目录 `codex-risk/reports`。

- `summary.txt`：摘要
- `detail.txt`：完整 VT 结果
- `llm_input.txt`：LLM 审计输入
- `llm_report.txt`：写入高中风险审计结果

## LLM 审计流程

1. 打开 `llm_input.txt`，配合 `references/llm_scan_prompt.md`
2. 将结论写入 `llm_report.txt`
3. 若发现复杂加密/混淆，标记为高优先级复核

## 仅做 VT 域名扫描

```bash
python scripts/vt_domain_scan.py --skills-root /path/to/skills
```

参数说明：

- `--include-bare-domains`：识别裸域名（覆盖更广，误报更高）
- `--max-domains N`：限制扫描数量
- `--sleep 0.5`：请求间隔
- `--cache-ttl-days 7`：缓存天数

## 缓存路径

- Windows: `%LOCALAPPDATA%\codex-risk\vt_cache.json`
- macOS: `~/Library/Application Support/codex-risk/vt_cache.json`
- Linux: `~/.local/share/codex-risk/vt_cache.json`

## 安装为 Codex Skill

将本目录复制到：

- `C:\Users\<User>\.codex\skills\code-agent-scan`
