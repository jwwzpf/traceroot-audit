import os from "node:os";
import path from "node:path";

function resolveConfiguredHome(...candidates: Array<string | undefined>): string {
  const configuredHome = candidates.find((value) => value && value.trim().length > 0)?.trim();

  return path.resolve(configuredHome || os.homedir());
}

export function resolveStateHomeDir(): string {
  return resolveConfiguredHome(
    process.env.TRACEROOT_HOME,
    process.env.HOME,
    process.env.USERPROFILE
  );
}

export function resolveUserHomeDir(): string {
  return resolveConfiguredHome(process.env.HOME, process.env.USERPROFILE);
}
