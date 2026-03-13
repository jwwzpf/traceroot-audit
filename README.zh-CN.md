# TraceRoot Audit

[English](./README.md)

[![npm version](https://img.shields.io/npm/v/traceroot-audit.svg)](https://www.npmjs.com/package/traceroot-audit)
[![CI](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

**面向“真正定义 AI agent 能做什么的本地文件和配置”的开源扫描器。**

TraceRoot Audit 用来帮助开发者看清 OpenClaw 一类本地 agent 生态背后的 action surface：runtime 配置、skill / tool 包、agent 可执行脚本，以及把 shell、network、filesystem、email 等真实动作串起来的本地代码和配置。

![TraceRoot Audit 动图演示](./docs/assets/traceroot-demo.gif)

## 为什么需要它

现在的 agent skill 已经可以触发真实动作，例如：

- 执行 shell 命令
- 访问本地文件
- 发起网络请求
- 修改邮件
- 触发购买或其他副作用

TraceRoot Audit 继续保持收敛：只扫描本地 action-capable surface，并给出可执行的风险提示。

## 本地开发

```bash
pnpm install
pnpm build
```

如果你本地不用 `pnpm`，也可以直接用 npm 做本地开发：

```bash
npm install
npm run build
```

## 最快的本地用法

无需全局安装，直接运行：

```bash
npx traceroot-audit doctor
npx traceroot-audit doctor /path/to/openclaw
npx traceroot-audit doctor /path/to/openclaw --watch --interval 60
npx traceroot-audit doctor /path/to/openclaw --watch --notify-webhook http://127.0.0.1:8787/notify
```

对大多数用户来说，`doctor` 现在是主入口。它会先找到可能的 surface，再问你真正想让 AI 做什么，然后自动生成更小的批准边界和更安全的补丁包；如果加上 `--watch`，它还会继续替你守着这个边界。

我们也已经把下一步产品主线收敛出来了：除了静态扫描之外，TraceRoot 还要走向本地运行时审计，持续观察 live agent 行为、写入本地审计日志，并在高风险动作开始时及时提醒。当前 v1 规格在 [docs/runtime-audit-v1.md](./docs/runtime-audit-v1.md)。

第一条本地运行时审计链路现在已经能跑起来了：

```bash
npx traceroot-audit doctor /path/to/openclaw --watch --interval 60
npx traceroot-audit logs
```

现在只要 OpenClaw / MCP / 本地 runtime 在目标目录里吐出结构化事件流，TraceRoot 也会尽量直接听懂这些动作，而不要求你先做很多手动接线。

第一条动作级事件接入也已经能用了，适合包裹本地 skill / script：

```bash
npx traceroot-audit tap --action send-email --severity high-risk -- node send-email.js
```

如果你想使用更底层的命令，它们仍然都在：

先判断当前目录更像哪种扫描对象：

```bash
node dist/cli/index.js discover
```

如果你根本不知道 OpenClaw、skill、runtime 配置装在哪里：

```bash
node dist/cli/index.js discover --host
```

如果你希望主机级发现也把当前工作目录一起算进去：

```bash
node dist/cli/index.js discover --host --include-cwd
```

直接扫描当前目录：

```bash
npx traceroot-audit scan .
```

生成一个初始 trust manifest：

```bash
node dist/cli/index.js init
```

启动交互式硬化向导：

```bash
node dist/cli/index.js harden --host
```

持续守望整台机器或某个项目的风险变化：

```bash
node dist/cli/index.js guard --host --interval 60
```

查看本地运行时审计时间线：

```bash
node dist/cli/index.js logs
node dist/cli/index.js logs --today
node dist/cli/index.js logs --tail
```

包裹一个真实高风险动作，让 TraceRoot 在执行前后都写入审计事件：

```bash
node dist/cli/index.js tap --action send-email --severity high-risk -- node send-email.js
```

把当前问题记录成 baseline：

```bash
node dist/cli/index.js baseline
```

## 快速开始

大多数用户建议直接从这里开始：

```bash
node dist/cli/index.js doctor
```

如果你已经知道目标目录：

```bash
node dist/cli/index.js doctor /path/to/openclaw
```

如果你希望同一个入口继续守着这个边界：

```bash
node dist/cli/index.js doctor /path/to/openclaw --watch --interval 60

# 如果你想把高风险动作同步发到自己的提醒入口：
node dist/cli/index.js doctor /path/to/openclaw --watch --notify-webhook http://127.0.0.1:8787/notify
```

之后可以直接回看本地审计记录：

```bash
node dist/cli/index.js logs
node dist/cli/index.js logs --target /path/to/openclaw --today
```

进阶工作流：

先识别当前项目更适合怎么扫：

```bash
node dist/cli/index.js discover .
```

在整台机器的常见位置里查找可能的 OpenClaw / runtime / skill surface：

```bash
node dist/cli/index.js discover --host
```

扫描当前项目：

```bash
node dist/cli/index.js scan .
```

扫描一个 OpenClaw 风格的本地 runtime 仓库：

```bash
node dist/cli/index.js scan /path/to/openclaw
```

扫描某个单独的 skill / tool 包：

```bash
node dist/cli/index.js scan /path/to/openclaw/skills/send-email-skill
```

如果你已经知道目标目录，也可以直接对它运行交互式硬化向导：

```bash
node dist/cli/index.js harden /path/to/openclaw
```

扫描内置高风险示例：

```bash
node dist/cli/index.js scan ./examples/risky-skill
```

为 CI 输出 JSON：

```bash
node dist/cli/index.js scan . --format json
```

输出适合直接贴进 PR / issue 的 Markdown：

```bash
node dist/cli/index.js scan . --format markdown
```

输出更短、更适合移动端 PR 评论的 Markdown：

```bash
node dist/cli/index.js scan . --format markdown --compact
```

在发现高风险问题时让 CI 失败：

```bash
node dist/cli/index.js scan . --fail-on high
```

某次扫描临时忽略 baseline：

```bash
node dist/cli/index.js scan . --ignore-baseline
```

显式指定 baseline 文件：

```bash
node dist/cli/index.js scan . --baseline ./traceroot.baseline.json
```

生成用于 GitHub code scanning 的 SARIF：

```bash
node dist/cli/index.js scan . --format sarif > traceroot.sarif
```

列出内置规则：

```bash
node dist/cli/index.js rules
```

解释某条规则：

```bash
node dist/cli/index.js explain C002
```

## 最简单的路径：doctor

对大多数用户来说，主命令现在是 `doctor`。

```bash
node dist/cli/index.js doctor
```

`doctor` 会：

1. 找到可能的 OpenClaw / runtime / skill surface
2. 问你真正想让 AI 做什么
3. 生成更小的批准边界
4. 生成你可以直接使用的更安全补丁包
5. 告诉你当前 live setup 还差哪些地方没收回来

如果你已经知道目录：

```bash
node dist/cli/index.js doctor /path/to/openclaw
```

如果你希望 TraceRoot 跑完之后继续守着这个边界：

```bash
node dist/cli/index.js doctor --watch --interval 60
```

## 交互式硬化向导

TraceRoot Audit 现在提供了一个真正面向普通用户的 `harden` 向导，不要求用户自己去想权限应该怎么收。

`harden` 是同一条工作流的高级形式。大多数用户更适合直接用 `doctor`。

它会一步步带着用户做：

1. 先找到可能的 OpenClaw / runtime / skill surface
2. 选择你真正想让 AI 执行的任务，可以多选
3. 选择审批策略、文件写入范围、网络暴露范围
4. 生成更小、更收敛、更适合当前任务的建议配置

命令示例：

```bash
node dist/cli/index.js harden --host
```

第一版向导内置了这些热门场景：

- 📧 邮件整理与回复
- 🧵 社交媒体发帖 / 运营
- 🛒 购物 / 下单自动化
- 💻 PR 审查 / 代码反馈
- 💬 客服 / 聊天支持 / 消息代发
- 📈 市场监控 / 图表分析

向导结束后，TraceRoot 可以生成：

- `traceroot.hardened.report.md`
- `traceroot.hardened.profile.json`
- `traceroot.manifest.hardened.json` 或 `.yaml`

## 应用更安全的补丁包

当你已经用 `harden` 批准了一套更小的边界后，可以继续运行 `apply`，让 TraceRoot 直接生成你能拿去用的补丁文件：

```bash
node dist/cli/index.js apply /path/to/openclaw
```

`apply` 当前会生成：

- `traceroot.manifest.hardened.json` 或 `.yaml`
- `traceroot.env.agent.example`
- `docker-compose.traceroot.override.yml`（当 TraceRoot 能安全地把端口收回到 localhost 时）
- `traceroot.apply.plan.md`

## 边界守护

当你已经通过 `harden` 批准了一套更安全的配置后，`doctor --watch` 是最推荐的继续使用方式。它会继续盯着这个目标，告诉你当前配置是不是仍然比批准过的边界更宽，或者后续有没有重新漂移出去。`guard` 仍然保留给更偏底层的用法。

如果你已经有自己的提醒入口，`doctor --watch` 也可以把高风险动作同步发到 webhook。这样 TraceRoot 会一边继续在本地记审计时间线，一边把值得你立刻留意的动作提醒出去；相同动作短时间内不会反复提醒，避免把你轰炸到不想再看。默认情况下，陪跑模式也会尽量保持安静：没有新变化时，它不会每一轮都刷存在感。

示例：

```bash
node dist/cli/index.js doctor /path/to/openclaw --watch --interval 60
```

如果目录里有保存下来的 `traceroot.hardened.profile.json`，`guard` 现在会重点提醒：

- 当前能力是否仍然比批准的工作流更宽
- 你明明要求 localhost only，但 runtime 是否又重新暴露了
- 外发型副作用动作是否缺少确认门
- 与当前任务无关的 secrets 是否仍然暴露给 runtime

## 应该扫描什么

TraceRoot Audit 最适合扫描那些真正决定 agent 能做什么的本地文件：

- `.env`、`docker-compose.yml`、runtime wiring 这类本地运行时配置
- skill、tool、plugin、MCP server 这类能力包
- agent 会调用的脚本和源代码

如果你不知道应该从哪个目录开始，先运行：

```bash
node dist/cli/index.js discover .
```

如果你完全不知道 OpenClaw、skill 包、runtime 配置在哪个目录，先运行：

```bash
node dist/cli/index.js discover --host
```

`discover` 会把目标归类成下面 3 类之一：

- `agent project`
- `skill / tool package`
- `runtime config`

并给出下一步最值得扫描的路径建议。

`discover --host` 不会粗暴地全盘扫描整台电脑，而是只检查常见的高价值位置，例如：

- `~/.openclaw`
- `~/.mcp`
- `~/.config`
- `~/Code`
- `~/Projects`
- `~/workspace`
- macOS 下的 `~/Library/Application Support`

默认情况下，它会排除你当前所在的工作目录子树，避免“主机级发现”又把你刚刚打开的仓库重新识别一遍。如果你想同时包含当前工作区，可以加上 `--include-cwd`。

目标是让不熟悉命令行和目录结构的用户，也能先找到值得扫描的本地 agent action surface。

现在 host discovery 还会直接给每个候选面推荐下一步动作：

- `scan`：先量化当前 blast radius
- `harden`：这个 surface 已经很像 skill/tool/MCP，应该先收缩权限面再信任它

## 忽略生成目录或无关路径

在扫描根目录放一个 `.tracerootignore`：

```text
# 忽略构建产物
dist/**
coverage/**

# 忽略 vendored skills 或自动生成脚本
vendor/**
generated/**
```

匹配到的文件会在扫描发现阶段被跳过。

## Baseline 工作流

baseline 适合在历史包袱较多的仓库里逐步接入：

```bash
node dist/cli/index.js baseline .
node dist/cli/index.js scan .
```

第一条命令会生成 `traceroot.baseline.json`。之后 `scan` 会自动识别这个文件，把已经接受的旧问题压掉，只保留新增问题。

## GitHub Actions

可以直接使用仓库内置的 composite action：

```yaml
name: TraceRoot Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/traceroot-audit@v1
        with:
          path: .
          fail-on: high
```

发布并打出 `v1` tag 之后，把 `your-org` 替换成真实的 GitHub owner 即可。

如果你更偏向直接在 CI 里跑 CLI：

```yaml
- uses: actions/checkout@v4
- uses: pnpm/action-setup@v4
  with:
    version: 10.6.5
- uses: actions/setup-node@v4
  with:
    node-version: 20
- run: pnpm install --no-frozen-lockfile
- run: pnpm build
- run: node dist/cli/index.js scan . --fail-on high
```

如果你想把结果上传到 GitHub code scanning：

```yaml
- uses: actions/checkout@v4
- uses: pnpm/action-setup@v4
  with:
    version: 10.6.5
- uses: actions/setup-node@v4
  with:
    node-version: 20
- run: pnpm install --no-frozen-lockfile
- run: pnpm build
- run: node dist/cli/index.js scan . --format sarif > traceroot.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: traceroot.sarif
```

PR 评论摘要：

仓库 CI 现在还会执行：

```bash
node dist/cli/index.js scan . --format markdown --compact
```

然后把结果以 upsert 方式写回 PR 评论，不会每次 push 都刷出一条新评论。
这个仓库还提交了根目录 `traceroot.baseline.json`，所以 PR 评论默认只聚焦新增问题，不会反复把已知示例或测试夹具噪音刷出来。
如果是 fork 提交的 PR，工作流会退回到 GitHub Actions 的 job summary，因为 `pull_request` 事件下 GitHub 提供的是只读 token。

## 发布前检查

这个包已经按 `npx traceroot-audit ...` 和公开发布到 npm 的方式准备好了。

发布前推荐执行：

```bash
npm run lint
npm test
npm run build
npm run package:check
```

## 自动发布

仓库里已经加入了基于 tag 的 npm 发布工作流，文件在 [`.github/workflows/release.yml`](./.github/workflows/release.yml)。

使用方式：

1. 在 npm 上为这个包和仓库配置 trusted publishing
2. 更新 `package.json` 版本号
3. 推送类似 `v0.2.0` 的 tag

工作流会自动执行 lint、test、build、打包预检、发布到 npm，并把生成的 tarball 挂到 GitHub Release。

如果暂时不能使用 trusted publishing，再退回到 granular npm token。那时把 token 作为 GitHub Actions secret，名称设为 `NPM_TOKEN`，并把发布步骤改成使用 `NODE_AUTH_TOKEN`。

## 已实现规则

- `C001` Public Runtime Exposure
- `C002` Remote Fetch and Execute
- `C003` Untrusted Shell + Network + Filesystem Combo
- `C004` Dangerous Destructive Capability Without Safeguards
- `H001` Missing Trust Metadata
- `H002` Overbroad Permission Declaration
- `H004` Hardcoded External Endpoints
- `H006` No Replay / Idempotency Declaration
- `H007` Missing Interrupt / Stop Contract Declaration

规则详情与最小 manifest schema 见 [docs/rules.md](./docs/rules.md)。

## 第一阶段目标

v1 里程碑刻意保持很小：

1. `pnpm build`
2. `node dist/cli/index.js init`
3. `node dist/cli/index.js scan ./examples/risky-skill`
4. `node dist/cli/index.js scan ./examples/risky-skill --format json`
5. `node dist/cli/index.js scan ./examples/risky-skill --fail-on high`

## 许可证

Apache-2.0
