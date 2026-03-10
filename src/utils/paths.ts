import path from "node:path";

export function toPosixPath(value: string): string {
  return value.split(path.sep).join("/");
}

export function relativeToRoot(rootDir: string, absolutePath: string): string {
  const relativePath = path.relative(rootDir, absolutePath);
  return toPosixPath(relativePath || path.basename(absolutePath));
}
