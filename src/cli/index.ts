import readline from "node:readline/promises";
import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Command, CommanderError } from "commander";

import { registerDoctorCommand } from "./commands/doctor";
import { registerApplyCommand } from "./commands/apply";
import { registerBaselineCommand } from "./commands/baseline";
import { registerDiscoverCommand } from "./commands/discover";
import { registerExplainCommand } from "./commands/explain";
import { registerGuardCommand } from "./commands/guard";
import { registerHardenCommand } from "./commands/harden";
import { registerInitCommand } from "./commands/init";
import { registerLogsCommand } from "./commands/logs";
import { registerRulesCommand } from "./commands/rules";
import { registerScanCommand } from "./commands/scan";

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
  chooseOne(question: string, choices: CliChoice[]): Promise<string>;
  chooseMany(question: string, choices: CliChoice[]): Promise<string[]>;
  confirm(question: string, defaultValue?: boolean): Promise<boolean>;
}

const defaultIo: CliIO = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text)
};

function createDefaultPrompter(): CliPrompter {
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

  async function chooseOne(question: string, choices: CliChoice[]): Promise<string> {
    return withInterface(async (prompt) => {
      while (true) {
        process.stdout.write(`${question}\n`);
        choices.forEach((choice, index) => {
          const hint = choice.hint ? ` — ${choice.hint}` : "";
          process.stdout.write(`  ${index + 1}. ${choice.label}${hint}\n`);
        });

        const answer = (await prompt.question("Select one option by number: ")).trim();
        const index = Number.parseInt(answer, 10);

        if (Number.isInteger(index) && index >= 1 && index <= choices.length) {
          return choices[index - 1]?.value ?? choices[0]!.value;
        }

        process.stdout.write("Please enter a valid number.\n\n");
      }
    });
  }

  async function chooseMany(question: string, choices: CliChoice[]): Promise<string[]> {
    return withInterface(async (prompt) => {
      while (true) {
        process.stdout.write(`${question}\n`);
        choices.forEach((choice, index) => {
          const hint = choice.hint ? ` — ${choice.hint}` : "";
          process.stdout.write(`  ${index + 1}. ${choice.label}${hint}\n`);
        });

        const answer = (
          await prompt.question("Select one or more options (comma separated numbers): ")
        ).trim();
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

        process.stdout.write("Please choose at least one valid option.\n\n");
      }
    });
  }

  async function confirm(question: string, defaultValue = true): Promise<boolean> {
    return withInterface(async (prompt) => {
      const suffix = defaultValue ? " [Y/n]: " : " [y/N]: ";

      while (true) {
        const answer = (await prompt.question(`${question}${suffix}`)).trim().toLowerCase();

        if (answer === "") {
          return defaultValue;
        }

        if (answer === "y" || answer === "yes") {
          return true;
        }

        if (answer === "n" || answer === "no") {
          return false;
        }

        process.stdout.write("Please answer yes or no.\n");
      }
    });
  }

  return {
    chooseOne,
    chooseMany,
    confirm
  };
}

export function createProgram(runtime: CliRuntime): Command {
  const program = new Command();
  program.configureOutput({
    writeOut: (text) => runtime.io.stdout(text),
    writeErr: (text) => runtime.io.stderr(text)
  });

  program
    .name("traceroot-audit")
    .description("Shrink the blast radius of local AI runtimes and skills.")
    .version("0.2.0")
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
  registerRulesCommand(program, runtime);
  registerExplainCommand(program, runtime);

  return program;
}

export async function runCli(
  argv = process.argv,
  io: CliIO = defaultIo,
  prompter: CliPrompter = createDefaultPrompter()
): Promise<number> {
  const runtime: CliRuntime = {
    io,
    prompter,
    exitCode: 0
  };

  const program = createProgram(runtime);
  program.exitOverride();

  try {
    await program.parseAsync(argv);
    return runtime.exitCode;
  } catch (error) {
    if (error instanceof CommanderError) {
      if (
        error.code !== "commander.helpDisplayed" &&
        error.code !== "commander.version"
      ) {
        io.stderr(`${error.message}\n`);
      }

      return typeof error.exitCode === "number"
        ? error.exitCode
        : runtime.exitCode || 1;
    }

    if (error instanceof Error) {
      io.stderr(`${error.message}\n`);
      return 1;
    }

    io.stderr("Unexpected CLI error.\n");
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
