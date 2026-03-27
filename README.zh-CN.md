# TraceRoot Audit

[English](./README.md)

[![npm version](https://img.shields.io/npm/v/traceroot-audit.svg)](https://www.npmjs.com/package/traceroot-audit)
[![CI](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

**本地 agent 的运行时审计产品。**

TraceRoot Audit 会陪着 OpenClaw、MCP 和其他本地 agent runtime 一起运行：当它们尝试高风险动作时，TraceRoot 会及时提醒，并留下之后可以回看的本地审计记录。

![TraceRoot Audit 动图演示](./docs/assets/traceroot-demo.gif)

## 开始使用

```bash
npx traceroot-audit@0.3.1 doctor --watch --host
npx traceroot-audit@0.3.1 logs --today
```

`doctor --watch --host` 用来启动运行时陪跑。

`logs --today` 用来查看今天 agent 做了什么，以及现在最值得注意的事。

## 你会得到什么

- 当本地 agent 尝试高风险动作时，及时提醒
- 可读的本地审计记录，而不是一堆底层日志
- 支持 OpenClaw、MCP 以及其他本地 agent runtime

## 最常用的命令

陪跑整台机器上的本地 agent：

```bash
npx traceroot-audit@0.3.1 doctor --watch --host
```

如果你已经知道某个 runtime 的目录：

```bash
npx traceroot-audit@0.3.1 doctor /path/to/openclaw --watch
```

回看今天的审计记录：

```bash
npx traceroot-audit@0.3.1 logs --today
```

在启动前先做一次本地扫描：

```bash
npx traceroot-audit@0.3.1 scan .
```

## 语言

CLI 默认输出英文。

只想这一次切到中文：

```bash
npx traceroot-audit@0.3.1 doctor --watch --host --lang zh
```

把中文保存成之后都使用的语言：

```bash
npx traceroot-audit@0.3.1 language zh
```

## 本地开发

```bash
pnpm install
pnpm build
```

如果你不用 `pnpm`：

```bash
npm install
npm run build
```

## License

Apache-2.0
