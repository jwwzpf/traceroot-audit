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
    expect(output).toContain("openclaw channels login --channel whatsapp");
    expect(output).toContain("先只保留本地审计时间线");
  });

  it("shows simple channel names instead of detected-route labels", async () => {
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
    expect(firstPromptChoices.some((choice) => choice.label === "📱 WhatsApp")).toBe(true);
    expect(firstPromptChoices.some((choice) => choice.label === "💬 Telegram")).toBe(true);
    expect(firstPromptChoices.some((choice) => choice.label.includes("发到已识别的"))).toBe(false);
  });
});
