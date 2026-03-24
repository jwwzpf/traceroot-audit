import { describe, expect, it } from "vitest";

import type { CliChoice, CliPrompter, CliRuntime } from "../src/cli/index";
import { promptNotificationSelection } from "../src/hardening/wizard";

function createCaptureRuntime(prompter: CliPrompter): {
  runtime: CliRuntime;
  readStdout: () => string;
} {
  let stdout = "";
  let stderr = "";

  return {
    runtime: {
      io: {
        stdout: (text: string) => {
          stdout += text;
        },
        stderr: (text: string) => {
          stderr += text;
        }
      },
      prompter,
      exitCode: 0
    },
    readStdout: () => {
      expect(stderr).toBe("");
      return stdout;
    }
  };
}

describe("notification wizard", () => {
  it("lets users fall back to local audit when a chat route target is unknown", async () => {
    const { runtime, readStdout } = createCaptureRuntime({
      chooseOne: async () => "whatsapp",
      chooseMany: async () => [],
      input: async () => "",
      confirm: async () => true
    });

    const selection = await promptNotificationSelection(runtime, {
      likelyChannels: [
        {
          channel: "telegram",
          evidence: ["openclaw.json"]
        }
      ]
    });

    expect(selection).toEqual({ mode: "local-only" });
    const output = readStdout();
    expect(output).toContain("WhatsApp");
    expect(output).toContain("OpenClaw");
    expect(output).toContain("+4917612345678");
    expect(output).toContain("先只保留本地审计时间线");
  });

  it("does not show a bare WhatsApp quick-pick when TraceRoot has not identified one", async () => {
    const seenChoices: CliChoice[][] = [];
    const { runtime } = createCaptureRuntime({
      chooseOne: async (_question: string, choices: CliChoice[]) => {
        seenChoices.push(choices);
        return "local-only";
      },
      chooseMany: async () => [],
      input: async () => "",
      confirm: async () => true
    });

    await promptNotificationSelection(runtime, {
      likelyChannels: [
        {
          channel: "telegram",
          evidence: ["telegram.json"]
        }
      ]
    });

    const firstPromptChoices = seenChoices[0] ?? [];
    expect(firstPromptChoices.some((choice) => choice.label.includes("发到 WhatsApp"))).toBe(false);
    expect(firstPromptChoices.some((choice) => choice.label.includes("发到其他已接好的聊天入口"))).toBe(true);
  });
});
