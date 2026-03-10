export interface LineMatch {
  line: number;
  text: string;
}

export function splitLines(content: string): string[] {
  return content.split(/\r?\n/);
}

export function findLineMatches(content: string, pattern: RegExp): LineMatch[] {
  const lines = splitLines(content);
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;

  return lines.flatMap((text, index) => {
    const regex = new RegExp(pattern.source, flags);
    return regex.test(text)
      ? [
          {
            line: index + 1,
            text
          }
        ]
      : [];
  });
}

export function truncateEvidence(value: string, maxLength = 180): string {
  const compact = value.trim().replace(/\s+/g, " ");
  if (compact.length <= maxLength) {
    return compact;
  }

  return `${compact.slice(0, maxLength - 3)}...`;
}

export function containsAny(text: string, candidates: string[]): boolean {
  const haystack = text.toLowerCase();
  return candidates.some((candidate) => haystack.includes(candidate.toLowerCase()));
}
