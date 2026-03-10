# TraceRoot Audit

[English](./README.md)

**面向 agent skills 和本地 agent 运行时的开源信任与安全扫描器。**

TraceRoot Audit 用来帮助开发者快速发现 OpenClaw 一类 agent 生态中的高风险 skill、不安全执行模式、权限过宽、信任元数据缺失，以及运行时暴露风险。

## 为什么需要它

现在的 agent skill 已经可以触发真实动作，例如：

- 执行 shell 命令
- 访问本地文件
- 发起网络请求
- 修改邮件
- 触发购买或其他副作用

TraceRoot Audit 的目标，是在这些风险造成损失之前，把明显的问题暴露出来。

## 安装

```bash
npm install -g traceroot-audit
```

## 快速开始

扫描当前项目：

```bash
traceroot-audit scan .
```

扫描某个 skill 包：

```bash
traceroot-audit scan ./skills/my-skill
```

为 CI 输出 JSON：

```bash
traceroot-audit scan . --format json
```

在发现高风险问题时让 CI 失败：

```bash
traceroot-audit scan . --fail-on high
```

## 当前可检查内容

第一版重点检查：

- 本地运行时是否暴露到公网
- 是否存在远程拉取后执行
- 是否存在危险的 shell / network / filesystem 组合
- 是否缺少 trust metadata
- 是否权限过宽
- 是否缺少 provenance 信号
- 是否存在危险默认配置

## 当前状态

项目早期阶段。  
第一版聚焦于风险发现与暴露。

## 路线图

- CLI 扫描器
- 规则引擎
- JSON 输出
- CI 集成
- trust metadata 建议

## 许可证

Apache-2.0
