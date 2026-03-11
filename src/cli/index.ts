import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Command, CommanderError } from "commander";

import { registerBaselineCommand } from "./commands/baseline";
import { registerExplainCommand } from "./commands/explain";
import { registerInitCommand } from "./commands/init";
import { registerRulesCommand } from "./commands/rules";
import { registerScanCommand } from "./commands/scan";

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

export interface CliRuntime {
  io: CliIO;
  exitCode: number;
}

const defaultIo: CliIO = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text)
};

export function createProgram(runtime: CliRuntime): Command {
  const program = new Command();
  program.configureOutput({
    writeOut: (text) => runtime.io.stdout(text),
    writeErr: (text) => runtime.io.stderr(text)
  });

  program
    .name("traceroot-audit")
    .description("Trust and security scanner for agent skills and local runtimes.")
    .version("0.1.1")
    .showHelpAfterError();

  registerScanCommand(program, runtime);
  registerBaselineCommand(program, runtime);
  registerInitCommand(program, runtime);
  registerRulesCommand(program, runtime);
  registerExplainCommand(program, runtime);

  return program;
}

export async function runCli(argv = process.argv, io: CliIO = defaultIo): Promise<number> {
  const runtime: CliRuntime = {
    io,
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
