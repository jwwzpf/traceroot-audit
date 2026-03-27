import { Command } from "commander";

import {
  loadSavedCliLanguage,
  saveCliLanguagePreference,
  setCliLanguage,
  type CliLanguage
} from "../locale";

import type { CliRuntime } from "../index";

function languageLabel(language: CliLanguage): string {
  return language === "zh" ? "简体中文" : "English";
}

function parseLanguageChoice(value: string): CliLanguage | null {
  const normalized = value.trim().toLowerCase();

  if (normalized === "en" || normalized === "english") {
    return "en";
  }

  if (
    normalized === "zh" ||
    normalized === "zh-cn" ||
    normalized === "zh_cn" ||
    normalized === "cn" ||
    normalized === "chinese"
  ) {
    return "zh";
  }

  return null;
}

export function registerLanguageCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("language")
    .description("Show or save your preferred CLI language.")
    .argument("[language]", "language to save (en or zh)")
    .action(async (language?: string) => {
      if (!language) {
        const savedLanguage = await loadSavedCliLanguage();
        const activeLanguage = savedLanguage ?? "en";

        setCliLanguage(activeLanguage);
        runtime.io.stdout(
          [
            "TraceRoot Audit 语言设置",
            "========================",
            "",
            `当前语言：${languageLabel(activeLanguage)}`,
            savedLanguage
              ? "TraceRoot 会一直记住这个语言，直到你再次切换。"
              : "还没有保存过语言偏好，所以 TraceRoot 现在默认使用 English。",
            "",
            "随时切换：",
            "- traceroot-audit language en",
            "- traceroot-audit language zh"
          ].join("\n") + "\n"
        );
        return;
      }

      const nextLanguage = parseLanguageChoice(language);

      if (!nextLanguage) {
        runtime.io.stderr("请输入 en 或 zh。\n");
        runtime.exitCode = 1;
        return;
      }

      await saveCliLanguagePreference(nextLanguage);
      setCliLanguage(nextLanguage);

      runtime.io.stdout(
        [
          "TraceRoot Audit 语言设置",
          "========================",
          "",
          `已保存语言：${languageLabel(nextLanguage)}`,
          "TraceRoot 之后会一直记住这个选择。"
        ].join("\n") + "\n"
      );
    });
}
