<p align="center">
  <h1 align="center">SkillRay</h1>
  <p align="center">
    <strong>AI 技能安全扫描器</strong>
    <br />
    在 AI 技能扫描你的秘密之前，先扫描它们。
  </p>
  <p align="center">
    <a href="README.md">English</a>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/skillray?color=blue" alt="PyPI" />
  <img src="https://img.shields.io/pypi/pyversions/skillray" alt="Python" />
  <img src="https://img.shields.io/github/license/hejuntao/skillRay" alt="License" />
  <img src="https://img.shields.io/github/actions/workflow/status/hejuntao/skillRay/ci.yml" alt="CI" />
</p>

---

## 为什么需要 SkillRay？

**36.82% 的 AI 技能存在安全缺陷**（Snyk ToxicSkills, 2024）。随着 AI 代理获得工具使用能力，一个恶意技能就可以窃取凭证、泄露数据或危害整个系统。

SkillRay 是一个**轻量级、离线、多引擎静态分析器**，专为 AI 技能安全而构建 — 无需 ML 模型、无需 API 密钥、无需 YARA C 依赖。

## 核心特性

- **5 大检测引擎** — 正则、AST、熵分析、数据流、Prompt 分析
- **37+ 安全规则**，覆盖 9 大威胁类别
- **5 级严重性** — 严重 / 高 / 中 / 低 / 信息
- **美观终端输出** — Rich 表格、颜色、进度指示
- **多种输出格式** — 文本、JSON、SARIF、Markdown
- **Claude Code 技能** — 原生集成为 Claude Code 技能
- **中英双语** — 支持中文输出（`--lang zh`）
- **零 ML 依赖** — 仅需 `rich`（约 3MB）
- **离线且快速** — 无 API 调用，毫秒级扫描

## 快速开始

```bash
# 安装
pip install skillray
# 或
uvx skillray

# 扫描当前目录
skillray .

# CI 集成（发现高危问题时退出码为 1）
skillray ./skills --fail-on high

# JSON 输出
skillray . --format json --output report.json

# 中文输出
skillray . --lang zh
```

## 威胁类别

| 类别 | 规则数 | 引擎 | 示例威胁 |
|------|--------|------|---------|
| **SR-PROMPT** | 5 | Prompt | 隐藏指令、角色覆盖、不可见 Unicode |
| **SR-TOOL** | 3 | Prompt | 工具投毒、MCP 覆盖、隐藏行为 |
| **SR-CRED** | 5 | 熵分析 + 正则 | 硬编码密钥（AWS/GitHub/OpenAI）、环境变量窃取 |
| **SR-EXFIL** | 4 | 数据流 + 正则 | 敏感文件读取 + 网络发送、DNS 隧道 |
| **SR-SUPPLY** | 4 | 正则 + AST | 拼写欺骗、运行时安装、未固定依赖 |
| **SR-PRIV** | 4 | 正则 | sudo、容器逃逸、安全绕过 |
| **SR-OBFUSC** | 5 | 正则 + Prompt | Base64/十六进制载荷、同形字、字符串拼接 |
| **SR-DESTRUCT** | 3 | 正则 | rm -rf、磁盘格式化、git 历史破坏 |
| **SR-EXEC** | 4 | AST + 正则 | eval/exec、shell=True、下载并执行 |

## 检测引擎

| 引擎 | 目标文件 | 依赖 | 作用 |
|------|---------|------|------|
| **RegexEngine** | 所有 | stdlib `re` | 模式匹配（约 60 个模式） |
| **ASTEngine** | `.py` | stdlib `ast` | Python AST 分析，消除注释/字符串误报 |
| **EntropyEngine** | 所有 | stdlib `math` | Shannon 熵检测 + 约 15 种已知密钥格式 |
| **DataflowEngine** | `.py` / shell | stdlib `ast` | 轻量污点追踪：源（敏感读取）→ 汇（网络发送） |
| **PromptEngine** | `.md` / SKILL.md | stdlib | Prompt 注入启发式检测 |

## 与竞品对比

| 特性 | SkillRay | AgentVet | Cisco Scanner |
|------|----------|----------|---------------|
| 外部依赖 | 仅 `rich` | YARA + 多个 | YARA + LLM |
| 检测引擎 | 5 个 | 3 个 | 3 个 |
| Prompt 注入检测 | 专用引擎 | 无 | LLM 驱动 |
| AST 分析 | 有 | 无 | 无 |
| 熵分析 | 有 | 无 | 无 |
| Claude Code 技能 | 原生支持 | 无 | 无 |
| 离线运行 | 是 | 是 | 否（需要 LLM） |
| 中文支持 | 是 | 否 | 否 |

## Claude Code 技能模式

SkillRay 可作为原生 Claude Code 技能使用。安装后，只需说：

> "扫描这个目录的安全问题"

项目根目录的 `SKILL.md` 使 Claude Code 能自动调用 SkillRay 并以对话形式呈现发现。

## 忽略规则（`.skillrayignore`）

```text
# 全局忽略某规则
SR-PRIV-001

# 对特定文件忽略某规则
SR-CRED-001:tests/**/*.py
```

## 开发

```bash
# 克隆并安装
git clone https://github.com/hejuntao/skillRay
cd skillRay
uv sync

# 运行测试
uv run pytest tests/ -v

# 扫描测试样本
uv run python3 -m skillray tests/samples/malicious/
uv run python3 -m skillray tests/samples/benign/
```

## 许可证

Apache-2.0
