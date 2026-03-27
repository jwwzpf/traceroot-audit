import readline from "node:readline/promises";
import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Command, CommanderError } from "commander";

import {
  detectCliLanguageFromArgv,
  hasExplicitCliLanguage,
  loadSavedCliLanguage,
  saveCliLanguagePreference,
  type CliLanguage,
  setCliLanguage,
  translateCliText
} from "./locale";
import { registerDoctorCommand } from "./commands/doctor";
import { registerApplyCommand } from "./commands/apply";
import { registerBaselineCommand } from "./commands/baseline";
import { registerDiscoverCommand } from "./commands/discover";
import { registerExplainCommand } from "./commands/explain";
import { registerGuardCommand } from "./commands/guard";
import { registerHardenCommand } from "./commands/harden";
import { registerInitCommand } from "./commands/init";
import { registerLogsCommand } from "./commands/logs";
import { registerLanguageCommand } from "./commands/language";
import { registerRulesCommand } from "./commands/rules";
import { registerScanCommand } from "./commands/scan";
import { registerTapCommand } from "./commands/tap";

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

export interface CliRuntime {
  io: CliIO;
  prompter: CliPrompter;
  exitCode: number;
}

export interface CliChoice {
  value: string;
  label: string;
  hint?: string;
}

export interface CliPrompter {
  chooseOne(
    question: string,
    choices: CliChoice[],
    options?: { defaultValue?: string }
  ): Promise<string>;
  chooseMany(
    question: string,
    choices: CliChoice[],
    options?: { defaultValues?: string[] }
  ): Promise<string[]>;
  input(question: string, options?: { defaultValue?: string; allowEmpty?: boolean }): Promise<string>;
  confirm(question: string, defaultValue?: boolean): Promise<boolean>;
}

const defaultIo: CliIO = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text)
};

function createDefaultPrompter(): CliPrompter {
  function writeLocalized(text: string): void {
    process.stdout.write(translateCliText(text));
  }

  async function withInterface<T>(
    run: (prompt: readline.Interface) => Promise<T>
  ): Promise<T> {
    const prompt = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    try {
      return await run(prompt);
    } finally {
      prompt.close();
    }
  }

  async function chooseOne(
    question: string,
    choices: CliChoice[],
    options: { defaultValue?: string } = {}
  ): Promise<string> {
    return withInterface(async (prompt) => {
      const defaultValue =
        options.defaultValue && choices.some((choice) => choice.value === options.defaultValue)
          ? options.defaultValue
          : undefined;
      const defaultIndex =
        defaultValue !== undefined
          ? choices.findIndex((choice) => choice.value === defaultValue) + 1
          : undefined;

      while (true) {
        writeLocalized(`${question}\n`);
        choices.forEach((choice, index) => {
          const hint = choice.hint ? ` — ${choice.hint}` : "";
          const recommended = defaultValue === choice.value ? " [推荐]" : "";
          writeLocalized(`  ${index + 1}. ${choice.label}${recommended}${hint}\n`);
        });

        const answer = (
          await prompt.question(
            translateCliText(
              defaultIndex
                ? `请输入编号（直接回车采用 TraceRoot 的推荐：${defaultIndex}）：`
                : "请输入编号："
            )
          )
        ).trim();

        if (answer === "" && defaultValue) {
          return defaultValue;
        }

        const index = Number.parseInt(answer, 10);

        if (Number.isInteger(index) && index >= 1 && index <= choices.length) {
          return choices[index - 1]?.value ?? choices[0]!.value;
        }

        writeLocalized("请输入有效的编号。\n\n");
      }
    });
  }

  async function chooseMany(
    question: string,
    choices: CliChoice[],
    options: { defaultValues?: string[] } = {}
  ): Promise<string[]> {
    return withInterface(async (prompt) => {
      const defaultValues = options.defaultValues?.filter((value) =>
        choices.some((choice) => choice.value === value)
      ) ?? [];
      const defaultIndexes = defaultValues
        .map((value) => choices.findIndex((choice) => choice.value === value))
        .filter((index) => index >= 0)
        .map((index) => index + 1);

      while (true) {
        writeLocalized(`${question}\n`);
        choices.forEach((choice, index) => {
          const hint = choice.hint ? ` — ${choice.hint}` : "";
          const recommended = defaultValues.includes(choice.value) ? " [推荐]" : "";
          writeLocalized(`  ${index + 1}. ${choice.label}${recommended}${hint}\n`);
        });

        const answer = (
          await prompt.question(
            translateCliText(
              defaultIndexes.length > 0
                ? `请输入一个或多个编号（用逗号分隔，直接回车采用 TraceRoot 的推荐：${defaultIndexes.join(", ")}）：`
                : "请输入一个或多个编号（用逗号分隔）："
            )
          )
        ).trim();

        if (answer === "" && defaultValues.length > 0) {
          return defaultValues;
        }

        const indexes = answer
          .split(",")
          .map((value) => Number.parseInt(value.trim(), 10))
          .filter((value) => Number.isInteger(value));
        const values = [...new Set(indexes)]
          .filter((value) => value >= 1 && value <= choices.length)
          .map((value) => choices[value - 1]!.value);

        if (values.length > 0) {
          return values;
        }

        writeLocalized("请至少选一个有效的编号。\n\n");
      }
    });
  }

  async function confirm(question: string, defaultValue = true): Promise<boolean> {
    return withInterface(async (prompt) => {
      const suffix = defaultValue ? " [Y/n]: " : " [y/N]: ";

      while (true) {
        const answer = (
          await prompt.question(translateCliText(`${question}${suffix}`))
        )
          .trim()
          .toLowerCase();

        if (answer === "") {
          return defaultValue;
        }

        if (answer === "y" || answer === "yes") {
          return true;
        }

        if (answer === "n" || answer === "no") {
          return false;
        }

        writeLocalized("请回答 yes 或 no。\n");
      }
    });
  }

  async function input(
    question: string,
    options: { defaultValue?: string; allowEmpty?: boolean } = {}
  ): Promise<string> {
    return withInterface(async (prompt) => {
      const suffix = options.defaultValue ? ` [default: ${options.defaultValue}]: ` : ": ";

      while (true) {
        const answer = (
          await prompt.question(translateCliText(`${question}${suffix}`))
        ).trim();

        if (answer.length > 0) {
          return answer;
        }

        if (options.defaultValue !== undefined) {
          return options.defaultValue;
        }

        if (options.allowEmpty) {
          return "";
        }

        writeLocalized("请先输入一个值。\n");
      }
    });
  }

  return {
    chooseOne,
    chooseMany,
    input,
    confirm
  };
}

export function createProgram(runtime: CliRuntime): Command {
  const program = new Command();
  program.enablePositionalOptions();
  program.configureOutput({
    writeOut: (text) => runtime.io.stdout(text),
    writeErr: (text) => runtime.io.stderr(text)
  });

  program
    .name("traceroot-audit")
    .description("Shrink the blast radius of local AI runtimes and skills.")
    .version("0.3.1")
    .option("--lang <lang>", "CLI language (en or zh). Defaults to en.")
    .showHelpAfterError();

  registerDoctorCommand(program, runtime);
  registerApplyCommand(program, runtime);
  registerScanCommand(program, runtime);
  registerDiscoverCommand(program, runtime);
  registerGuardCommand(program, runtime);
  registerHardenCommand(program, runtime);
  registerBaselineCommand(program, runtime);
  registerInitCommand(program, runtime);
  registerLogsCommand(program, runtime);
  registerLanguageCommand(program, runtime);
  registerRulesCommand(program, runtime);
  registerExplainCommand(program, runtime);
  registerTapCommand(program, runtime);

  return program;
}

function stripGlobalLanguageOption(argv: string[]): string[] {
  const sanitized: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];

    if (!value) {
      continue;
    }

    if (value === "--lang") {
      index += 1;
      continue;
    }

    if (value.startsWith("--lang=")) {
      continue;
    }

    sanitized.push(value);
  }

  return sanitized;
}

function shouldPromptForCliLanguage(
  argv: string[],
  prompter: CliPrompter | undefined,
  savedLanguage: CliLanguage | null
): boolean {
  if (prompter) {
    return false;
  }

  if (savedLanguage) {
    return false;
  }

  if (hasExplicitCliLanguage(argv)) {
    return false;
  }

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return false;
  }

  return argv.includes("doctor") || argv.includes("harden");
}

async function promptForCliLanguage(): Promise<CliLanguage> {
  const prompt = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    while (true) {
      process.stdout.write(
        [
          "🌍 Choose your language",
          "  1. English [Default]",
          "  2. 简体中文",
          "Enter a number (press Enter for English): "
        ].join("\n")
      );

      const answer = (await prompt.question("")).trim();

      if (answer === "" || answer === "1") {
        return "en";
      }

      if (answer === "2") {
        return "zh";
      }

      process.stdout.write(
        "Please enter 1 or 2.\n\n"
      );
    }
  } finally {
    prompt.close();
  }
}

export async function runCli(
  argv = process.argv,
  io: CliIO = defaultIo,
  prompter?: CliPrompter
): Promise<number> {
  const explicitLanguage = detectCliLanguageFromArgv(argv);
  const savedLanguage = await loadSavedCliLanguage();
  let language = explicitLanguage ?? savedLanguage ?? "en";

  if (shouldPromptForCliLanguage(argv, prompter, savedLanguage)) {
    language = await promptForCliLanguage();
    await saveCliLanguagePreference(language);
  }

  setCliLanguage(language);
  const sanitizedArgv = stripGlobalLanguageOption(argv);

  const localizedIo: CliIO = {
    stdout: (text) => io.stdout(translateCliText(text)),
    stderr: (text) => io.stderr(translateCliText(text))
  };

  const runtime: CliRuntime = {
    io: localizedIo,
    prompter: prompter ?? createDefaultPrompter(),
    exitCode: 0
  };

  const program = createProgram(runtime);
  program.exitOverride();

  try {
    await program.parseAsync(sanitizedArgv);
    return runtime.exitCode;
  } catch (error) {
    if (error instanceof CommanderError) {
      if (
        error.code !== "commander.helpDisplayed" &&
        error.code !== "commander.version"
      ) {
        localizedIo.stderr(`${error.message}\n`);
      }

      return typeof error.exitCode === "number"
        ? error.exitCode
        : runtime.exitCode || 1;
    }

    if (error instanceof Error) {
      localizedIo.stderr(`${error.message}\n`);
      return 1;
    }

    localizedIo.stderr("Unexpected CLI error.\n");
    return 1;
  }
}

function resolveExecutablePath(filePath: string): string {
  const absolutePath = path.resolve(filePath);

  try {
    return realpathSync(absolutePath);
  } catch {
    return absolutePath;
  }
}

const currentFilePath = resolveExecutablePath(fileURLToPath(import.meta.url));
const invokedPath = process.argv[1] ? resolveExecutablePath(process.argv[1]) : null;

if (invokedPath === currentFilePath) {
  void runCli().then((exitCode) => {
    process.exitCode = exitCode;
  });
}
