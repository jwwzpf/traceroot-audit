import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  detectCliLanguageFromArgv,
  setCliLanguage,
  translateCliText
} from "../src/cli/locale";
import { runCli } from "../src/cli/index";

describe("CLI locale", () => {
  let previousCliLang: string | undefined;
  let previousCliLanguage: string | undefined;
  let previousHome: string | undefined;

  beforeEach(() => {
    previousCliLang = process.env.TRACEROOT_LANG;
    previousCliLanguage = process.env.TRACEROOT_LANGUAGE;
    previousHome = process.env.HOME;
    delete process.env.TRACEROOT_LANG;
    delete process.env.TRACEROOT_LANGUAGE;
    setCliLanguage("en");
  });

  afterEach(() => {
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

    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }

    setCliLanguage("en");
  });

  it("defaults to English when no language is specified", () => {
    expect(detectCliLanguageFromArgv(["node", "traceroot-audit", "doctor"])).toBe("en");
    expect(
      translateCliText("🔔 TraceRoot 盯到高风险动作时，要不要顺手提醒你？")
    ).toBe("🔔 When TraceRoot spots a high-risk action, should it send you a quick reminder?");
  });

  it("can switch back to Chinese explicitly", () => {
    expect(
      detectCliLanguageFromArgv(["node", "traceroot-audit", "--lang", "zh", "doctor"])
    ).toBe("zh");

    setCliLanguage("zh");
    expect(
      translateCliText("🔔 TraceRoot 盯到高风险动作时，要不要顺手提醒你？")
    ).toBe("🔔 TraceRoot 盯到高风险动作时，要不要顺手提醒你？");
  });

  it("detects zh when --lang appears after the command name", () => {
    expect(
      detectCliLanguageFromArgv(["node", "traceroot-audit", "doctor", "--lang", "zh"])
    ).toBe("zh");
  });

  it("accepts --lang after the subcommand and keeps output in Chinese", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const tempHome = mkdtempSync(path.join(tmpdir(), "traceroot-locale-home-"));
    process.env.HOME = tempHome;

    try {
      const exitCode = await runCli(
        ["node", "traceroot-audit", "doctor", "--lang", "zh", "--host", "--cycles", "1", "--interval", "1"],
        {
          stdout: (text) => stdout.push(text),
          stderr: (text) => stderr.push(text)
        },
        {
          chooseOne: async () => "local-only",
          chooseMany: async () => ["email-replies"],
          input: async () => "",
          confirm: async () => true
        }
      );

      expect(exitCode).toBe(0);
      expect(stderr.join("")).toBe("");
      expect(stdout.join("")).toContain("TraceRoot Audit Doctor");
      expect(stdout.join("")).not.toContain("unknown option '--lang'");
    } finally {
      rmSync(tempHome, { force: true, recursive: true });
    }
  });

  it("keeps the main watch flow in readable English", () => {
    const sample = [
      "🎯 现在最值得先盯住的是：~/.openclaw（OpenClaw 运行态）",
      "- runtime自己吐出来的high-risk action事件",
      "   想立刻看完整轨迹，可以直接用：traceroot-audit logs --today",
      "- 为什么现在值得你看一眼：这类动作会真正把内容发到外部世界里，通常值得你马上看一眼。",
      "- Recommendation: 先确认这封邮件是不是真的该发出去。",
      "💓 2026-03-24 04:13:18Z 这轮没有新的整机入口变化，也没有新的high-risk action提醒。TraceRoot 还在安静地watch over。"
    ].join("\n");

    expect(translateCliText(sample)).toContain(
      "🎯 Start by keeping an eye on: ~/.openclaw (OpenClaw runtime)"
    );
    expect(translateCliText(sample)).toContain(
      "- high-risk action events emitted directly by the runtime"
    );
    expect(
      translateCliText("- emitted directly by the runtimehigh-risk action事件")
    ).toBe("- high-risk action events emitted directly by the runtime");
    expect(translateCliText(sample)).toContain(
      "To review the full timeline right away, run: traceroot-audit logs --today"
    );
    expect(translateCliText(sample)).toContain(
      "- Why it matters right now: this kind of action reaches the outside world and is usually worth checking right away."
    );
    expect(translateCliText(sample)).toContain(
      "- Recommendation: Confirm that this email really should be sent before letting it go out."
    );
    expect(translateCliText(sample)).toContain(
      "No new machine-wide entry changes or new high-risk alerts in this cycle. TraceRoot is still watching quietly."
    );
    expect(
      translateCliText(
        "暂时还没在这台机器上看到明显的 OpenClaw / runtime / skill 入口。\n等你的 runtime 真正跑起来以后，再重新运行 `traceroot-audit doctor --watch` 就可以了。"
      )
    ).toContain("TraceRoot has not spotted an obvious OpenClaw, runtime, or skill entrypoint on this machine yet.");
  });
});
