const urlPattern = /https?:\/\/[^\s"'`<>]+/g;

export function extractUrls(text: string): string[] {
  return [...text.matchAll(urlPattern)].map((match) =>
    match[0].replace(/[),.;]+$/, "")
  );
}

export function isExternalUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    const host = parsed.hostname.toLowerCase();

    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "0.0.0.0" ||
      host.endsWith(".local")
    ) {
      return false;
    }

    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}
