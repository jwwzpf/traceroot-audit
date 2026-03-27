import { appendFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runCli, type CliChoice, type CliPrompter } from "../src/cli/index";
import { saveCliLanguagePreference } from "../src/cli/locale";

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
  input?: string[];
  confirm?: boolean[];
}): CliPrompter {
  const chooseOneAnswers = [...(answers.chooseOne ?? [])];
  const chooseManyAnswers = [...(answers.chooseMany ?? [])];
  const inputAnswers = [...(answers.input ?? [])];
  const confirmAnswers = [...(answers.confirm ?? [])];

  return {
    async chooseOne(
      _question: string,
      choices: CliChoice[],
      options: { defaultValue?: string } = {}
    ) {
      const answer = chooseOneAnswers.shift();

      if (!answer && options.defaultValue && choices.some((choice) => choice.value === options.defaultValue)) {
        return options.defaultValue;
      }

      if (!answer && choices.some((choice) => choice.value === "local-only")) {
        return "local-only";
      }

      if (!answer || !choices.some((choice) => choice.value === answer)) {
        throw new Error(`Unexpected chooseOne answer: ${answer ?? "undefined"}`);
      }

      return answer;
    },
    async chooseMany(
      _question: string,
      choices: CliChoice[],
      options: { defaultValues?: string[] } = {}
    ) {
      const answer = chooseManyAnswers.shift();

      if (!answer && options.defaultValues && options.defaultValues.length > 0) {
        return options.defaultValues;
      }

      if (!answer || answer.some((value) => !choices.some((choice) => choice.value === value))) {
        throw new Error(`Unexpected chooseMany answer: ${answer?.join(", ") ?? "undefined"}`);
      }

      return answer;
    },
    async input() {
      const answer = inputAnswers.shift();

      if (typeof answer !== "string") {
        throw new Error("Unexpected input answer");
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

describe("Launch candidate acceptance", () => {
  let previousHome: string | undefined;
  let previousStateHome: string | undefined;
  let previousTmpDir: string | undefined;
  let previousCliLang: string | undefined;
  let previousCliLanguage: string | undefined;

  beforeEach(() => {
    previousHome = process.env.HOME;
    previousStateHome = process.env.TRACEROOT_HOME;
    previousTmpDir = process.env.TMPDIR;
    previousCliLang = process.env.TRACEROOT_LANG;
    previousCliLanguage = process.env.TRACEROOT_LANGUAGE;
    delete process.env.TRACEROOT_LANG;
    delete process.env.TRACEROOT_LANGUAGE;
  });

  afterEach(() => {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }

    if (previousStateHome === undefined) {
      delete process.env.TRACEROOT_HOME;
    } else {
      process.env.TRACEROOT_HOME = previousStateHome;
    }

    if (previousTmpDir === undefined) {
      delete process.env.TMPDIR;
    } else {
      process.env.TMPDIR = previousTmpDir;
    }

    if (previousCliLang === undefined) {
      delete process.env.TRACEROOT_LANG;
    } else {
      process.env.TRACEROOT_LANG = previousCliLang;
    }

    if (previousCliLanguage === undefined) {
      delete process.env.TRACEROOT_LANGUAGE;
    } else {
      process.env.TRACEROOT_LANGUAGE = previousCliLanguage;
    }
  });

  it("accepts a native OpenClaw runtime from ~/.openclaw end to end", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-accept-openclaw-home-"));

    try {
      const openClawDir = path.join(tempHome, ".openclaw");
      const logsDir = path.join(openClawDir, "logs");
      await mkdir(logsDir, { recursive: true });
      await writeFile(path.join(logsDir, "runtime-events.jsonl"), "", "utf8");

      process.env.HOME = tempHome;
      process.env.TRACEROOT_HOME = tempHome;
      await saveCliLanguagePreference("zh", tempHome);

      setTimeout(() => {
        void appendFile(
          path.join(logsDir, "runtime-events.jsonl"),
          `${JSON.stringify({
            event: {
              type: "send-email",
              status: "attempted",
              runtime: "openclaw",
              target: "mailer.ts",
              message: "Agent is attempting to send an external email."
            }
          })}\n`,
          "utf8"
        );
      }, 200);

      const doctorCapture = createCapture();
      const doctorExitCode = await runCli(
        ["node", "traceroot-audit", "doctor", "--watch", "--host", "--cycles", "2", "--interval", "1"],
        doctorCapture.io,
        createStaticPrompter({})
      );
      const doctorOutput = doctorCapture.read().stdout;

      expect(doctorExitCode).toBe(0);
      expect(doctorOutput).toContain("TraceRoot 现在已经接上：OpenClaw 运行位点（~/.openclaw）");
      expect(doctorOutput).toContain("TraceRoot 实时提醒");
      expect(doctorOutput).toContain("对外发邮件");

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", "--today"],
        logsCapture.io
      );
      const logsOutput = logsCapture.read().stdout;

      expect(logsExitCode).toBe(0);
      expect(logsOutput).toContain("今天的审计结论");
      expect(logsOutput).toContain("对外发邮件");
      expect(logsOutput).toContain("~/.openclaw/mailer.ts");
    } finally {
      await rm(tempHome, { recursive: true, force: true });
    }
  });

  it("accepts a config-home OpenClaw runtime without needing a project folder", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-accept-config-openclaw-home-"));

    try {
      const openClawDir = path.join(tempHome, ".config", "openclaw");
      const logsDir = path.join(openClawDir, "logs");
      await mkdir(logsDir, { recursive: true });
      await writeFile(path.join(logsDir, "runtime-events.jsonl"), "", "utf8");

      process.env.HOME = tempHome;
      process.env.TRACEROOT_HOME = tempHome;
      await saveCliLanguagePreference("zh", tempHome);

      setTimeout(() => {
        void appendFile(
          path.join(logsDir, "runtime-events.jsonl"),
          `${JSON.stringify({
            event: {
              type: "send-message",
              status: "attempted",
              runtime: "openclaw",
              target: "ops-room",
              channel: "telegram",
              sender: "@ops-room",
              message: "Agent is attempting to send an external message."
            }
          })}\n`,
          "utf8"
        );
      }, 200);

      const doctorCapture = createCapture();
      const doctorExitCode = await runCli(
        ["node", "traceroot-audit", "doctor", "--watch", "--host", "--cycles", "2", "--interval", "1"],
        doctorCapture.io,
        createStaticPrompter({})
      );
      const doctorOutput = doctorCapture.read().stdout;

      expect(doctorExitCode).toBe(0);
      expect(doctorOutput).toContain("TraceRoot 现在已经接上：OpenClaw 运行位点（~/.config/openclaw）");
      expect(doctorOutput).toContain("TraceRoot 实时提醒");
      expect(doctorOutput).toContain("对外发消息");

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", "--today"],
        logsCapture.io
      );
      const logsOutput = logsCapture.read().stdout;

      expect(logsExitCode).toBe(0);
      expect(logsOutput).toContain("今天的审计结论");
      expect(logsOutput).toContain("对外发消息");
      expect(logsOutput).toContain("Telegram（@ops-room）");
    } finally {
      await rm(tempHome, { recursive: true, force: true });
    }
  });

  it("accepts a generic config-home runtime that uses OpenClaw-style logging", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-accept-generic-runtime-home-"));

    try {
      const runtimeDir = path.join(tempHome, ".config", "shrimpbox");
      const logsDir = path.join(runtimeDir, "logs");
      await mkdir(logsDir, { recursive: true });
      await writeFile(
        path.join(runtimeDir, "runtime-config.yaml"),
        ["logging:", "  gateway:", "    file: logs/runtime-events.jsonl"].join("\n"),
        "utf8"
      );
      await writeFile(path.join(logsDir, "runtime-events.jsonl"), "", "utf8");

      process.env.HOME = tempHome;
      process.env.TRACEROOT_HOME = tempHome;
      await saveCliLanguagePreference("zh", tempHome);

      setTimeout(() => {
        void appendFile(
          path.join(logsDir, "runtime-events.jsonl"),
          `${JSON.stringify({
            event: {
              type: "sensitive-data-access",
              status: "attempted",
              runtime: "shrimpbox",
              target: "customers-2026.csv",
              message: "Runtime is trying to read a sensitive customer export."
            }
          })}\n`,
          "utf8"
        );
      }, 200);

      const doctorCapture = createCapture();
      const doctorExitCode = await runCli(
        ["node", "traceroot-audit", "doctor", "--watch", "--host", "--cycles", "2", "--interval", "1"],
        doctorCapture.io,
        createStaticPrompter({
          chooseOne: ["local-only"]
        })
      );
      const doctorOutput = doctorCapture.read().stdout;

      expect(doctorExitCode).toBe(0);
      expect(doctorOutput).toContain("~/.config/shrimpbox");
      expect(doctorOutput).toContain("TraceRoot 实时提醒");
      expect(doctorOutput).toContain("读取敏感数据");

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", "--today"],
        logsCapture.io
      );
      const logsOutput = logsCapture.read().stdout;

      expect(logsExitCode).toBe(0);
      expect(logsOutput).toContain("今天的审计结论");
      expect(logsOutput).toContain("读取敏感数据（customers-2026.csv）");
      expect(logsOutput).toContain("customers-2026.csv");
    } finally {
      await rm(tempHome, { recursive: true, force: true });
    }
  });

  it("accepts a native MCP config home and records tool calls as audit actions", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-accept-native-mcp-home-"));

    try {
      const mcpDir = path.join(tempHome, ".mcp");
      const logsDir = path.join(tempHome, "mcp-runtime-logs");
      await mkdir(mcpDir, { recursive: true });
      await mkdir(logsDir, { recursive: true });

      const runtimeLog = path.join(logsDir, "gmail-mcp-events.jsonl");
      await writeFile(
        path.join(mcpDir, "mcp.yaml"),
        `mcpServers:\n  mailer:\n    logging:\n      file: ${JSON.stringify(runtimeLog)}\n`,
        "utf8"
      );

      process.env.HOME = tempHome;
      process.env.TRACEROOT_HOME = tempHome;
      await saveCliLanguagePreference("zh", tempHome);

      setTimeout(() => {
        void appendFile(
          runtimeLog,
          `${JSON.stringify({
            timestamp: new Date().toISOString(),
            runtime: "gmail-mcp",
            channel: "telegram",
            sender: "@ops-room",
            method: "tools/call",
            params: {
              name: "send_email",
              path: "mailer.ts",
              recipient: "customer@example.com"
            }
          })}\n`,
          "utf8"
        );
      }, 200);

      const doctorCapture = createCapture();
      const doctorExitCode = await runCli(
        ["node", "traceroot-audit", "doctor", "--watch", "--host", "--cycles", "2", "--interval", "1"],
        doctorCapture.io,
        createStaticPrompter({
          chooseOne: ["local-only"]
        })
      );
      const doctorOutput = doctorCapture.read().stdout;

      expect(doctorExitCode).toBe(0);
      expect(doctorOutput).toContain("TraceRoot 现在已经接上：MCP 配置位点（~/.mcp）");
      expect(doctorOutput).toContain("TraceRoot 实时提醒");
      expect(doctorOutput).toContain("对外发邮件");

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", "--today"],
        logsCapture.io
      );
      const logsOutput = logsCapture.read().stdout;

      expect(logsExitCode).toBe(0);
      expect(logsOutput).toContain("今天的审计结论");
      expect(logsOutput).toContain("gmail-mcp 正在调用一个 MCP 工具");
      expect(logsOutput).toContain("对外发邮件");
    } finally {
      await rm(tempHome, { recursive: true, force: true });
    }
  });

  it("accepts a Lobster-family runtime from ~/.config/lobster", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-accept-lobster-home-"));

    try {
      const lobsterDir = path.join(tempHome, ".config", "lobster");
      await mkdir(lobsterDir, { recursive: true });

      const gatewayLog = path.join(tempHome, "lobster-gateway.log");
      await writeFile(
        path.join(lobsterDir, "lobster.yaml"),
        `logging:\n  gateway:\n    file: ${JSON.stringify(gatewayLog)}\n`,
        "utf8"
      );

      process.env.HOME = tempHome;
      process.env.TRACEROOT_HOME = tempHome;
      await saveCliLanguagePreference("zh", tempHome);

      setTimeout(() => {
        void appendFile(
          gatewayLog,
          `${new Date().toISOString()} WARN gateway Attempting to send email to customer@example.com from Telegram @ops-room path=mailer.ts\n`,
          "utf8"
        );
      }, 200);

      const doctorCapture = createCapture();
      const doctorExitCode = await runCli(
        ["node", "traceroot-audit", "doctor", "--watch", "--host", "--cycles", "2", "--interval", "1"],
        doctorCapture.io,
        createStaticPrompter({
          chooseOne: ["local-only"]
        })
      );
      const doctorOutput = doctorCapture.read().stdout;

      expect(doctorExitCode).toBe(0);
      expect(doctorOutput).toContain("~/.config/lobster");
      expect(doctorOutput).toContain("Lobster 运行时");
      expect(doctorOutput).toContain("TraceRoot 实时提醒");
      expect(doctorOutput).toContain("对外发邮件");

      const logsCapture = createCapture();
      const logsExitCode = await runCli(
        ["node", "traceroot-audit", "logs", "--today"],
        logsCapture.io
      );
      const logsOutput = logsCapture.read().stdout;

      expect(logsExitCode).toBe(0);
      expect(logsOutput).toContain("今天的审计结论");
      expect(logsOutput).toContain("对外发邮件");
      expect(logsOutput).toContain("lobster-gateway.log");
    } finally {
      await rm(tempHome, { recursive: true, force: true });
    }
  });
});
