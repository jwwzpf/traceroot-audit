import path from "node:path";

import { resolveUserHomeDir } from "./home";

export function toPosixPath(value: string): string {
  return value.split(path.sep).join("/");
}

export function relativeToRoot(rootDir: string, absolutePath: string): string {
  const relativePath = path.relative(rootDir, absolutePath);
  return toPosixPath(relativePath || path.basename(absolutePath));
}

export function displayUserPath(value: string, options?: { cwd?: string }): string {
  const resolved = normalizeDisplayPath(path.resolve(value));
  const cwd = options?.cwd ? path.resolve(options.cwd) : process.cwd();
  const home = normalizeDisplayPath(path.resolve(resolveUserHomeDir()));

  if (resolved === cwd) {
    return ".";
  }

  if (resolved.startsWith(`${cwd}${path.sep}`)) {
    return `./${toPosixPath(path.relative(cwd, resolved))}`;
  }

  if (resolved === home) {
    return "~";
  }

  if (resolved.startsWith(`${home}${path.sep}`)) {
    return `~/${toPosixPath(path.relative(home, resolved))}`;
  }

  return toPosixPath(resolved);
}

function normalizeDisplayPath(value: string): string {
  const normalized = path.resolve(value);

  if (normalized === "/private/tmp") {
    return "/tmp";
  }

  if (normalized.startsWith("/private/tmp/")) {
    return normalized.replace("/private/tmp/", "/tmp/");
  }

  return normalized;
}
