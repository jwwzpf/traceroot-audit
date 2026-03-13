import { discoverFiles, resolveTarget } from "../utils/files";
import { SUPPORTED_OPENCLAW_NOTIFY_CHANNELS } from "../audit/notifier";

export interface LikelyNotifyChannel {
  channel: string;
  evidence: string[];
  target?: string;
  account?: string;
}

const displayChannelNames: Record<string, string> = {
  whatsapp: "WhatsApp",
  telegram: "Telegram",
  discord: "Discord",
  googlechat: "Google Chat",
  slack: "Slack",
  mattermost: "Mattermost",
  signal: "Signal",
  imessage: "iMessage",
  msteams: "Microsoft Teams"
};

function channelPattern(channel: string): RegExp {
  if (channel === "googlechat") {
    return /\bgoogle[\s_-]?chat\b/i;
  }

  if (channel === "msteams") {
    return /\b(?:ms[\s_-]?teams|microsoft[\s_-]?teams|teams)\b/i;
  }

  return new RegExp(`\\b${channel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
}

function uniqueStrings(values: Array<string | undefined>): string[] {
  return [...new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value)))];
}

function firstMatch(content: string, pattern: RegExp): string | undefined {
  return pattern.exec(content)?.[1]?.trim();
}

function propertyPattern(name: string): RegExp {
  return new RegExp(
    `["']?${name.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}["']?\\s*[:=]\\s*["']?([^\\s"',\\]}]+)["']?`,
    "i"
  );
}

function extractTargetCandidates(channel: string, content: string): string[] {
  const genericTargets = uniqueStrings([
    firstMatch(content, propertyPattern("target")),
    firstMatch(content, propertyPattern("recipient")),
    firstMatch(content, propertyPattern("destination")),
    firstMatch(content, propertyPattern("to"))
  ]);

  if (channel === "whatsapp" || channel === "signal") {
    const phoneMatches = [...content.matchAll(/(\+\d[\d\s()-]{6,}\d)/g)].map((match) =>
      match[1].replace(/\s+/g, "")
    );
    return uniqueStrings([...genericTargets, ...phoneMatches]);
  }

  if (channel === "telegram") {
    const handles = [...content.matchAll(/(@[A-Za-z0-9_]{4,})/g)].map((match) => match[1]);
    const chatIds = uniqueStrings([
      firstMatch(content, /\bchat[_-]?id\s*[:=]\s*["']?([^\s"',\]}]+)["']?/i)
    ]);
    return uniqueStrings([...genericTargets, ...handles, ...chatIds]);
  }

  if (channel === "slack" || channel === "discord" || channel === "mattermost" || channel === "msteams" || channel === "googlechat" || channel === "imessage") {
    const namedChannels = [...content.matchAll(/(#[A-Za-z0-9._-]{2,})/g)].map((match) => match[1]);
    const ids = uniqueStrings([
      firstMatch(content, propertyPattern("channel_id")),
      firstMatch(content, propertyPattern("channel-id")),
      firstMatch(content, propertyPattern("room_id")),
      firstMatch(content, propertyPattern("room-id"))
    ]);
    return uniqueStrings([...genericTargets, ...namedChannels, ...ids]);
  }

  return genericTargets;
}

function extractAccountCandidates(content: string): string[] {
  return uniqueStrings([
    firstMatch(content, propertyPattern("account")),
    firstMatch(content, propertyPattern("account_name")),
    firstMatch(content, propertyPattern("account-name")),
    firstMatch(content, propertyPattern("profile"))
  ]);
}

export async function detectLikelyNotifyChannels(
  target: string
): Promise<LikelyNotifyChannel[]> {
  const resolved = await resolveTarget(target);
  const files = await discoverFiles(resolved);
  const matches = new Map<string, Set<string>>();
  const targets = new Map<string, Set<string>>();
  const accounts = new Map<string, Set<string>>();

  for (const file of files) {
    const fileLabel = file.relativePath;
    const combined = `${file.relativePath}\n${file.content.slice(0, 50_000)}`;

    for (const channel of SUPPORTED_OPENCLAW_NOTIFY_CHANNELS) {
      const pattern = channelPattern(channel);
      if (!pattern.test(combined)) {
        continue;
      }

      const evidence = matches.get(channel) ?? new Set<string>();
      evidence.add(fileLabel);
      matches.set(channel, evidence);

      const targetHints = targets.get(channel) ?? new Set<string>();
      for (const candidate of extractTargetCandidates(channel, file.content)) {
        targetHints.add(candidate);
      }
      targets.set(channel, targetHints);

      const accountHints = accounts.get(channel) ?? new Set<string>();
      for (const candidate of extractAccountCandidates(file.content)) {
        accountHints.add(candidate);
      }
      accounts.set(channel, accountHints);
    }
  }

  return [...matches.entries()]
    .map(([channel, evidence]) => ({
      channel,
      evidence: [...evidence].slice(0, 2),
      target: [...(targets.get(channel) ?? new Set<string>())][0],
      account: [...(accounts.get(channel) ?? new Set<string>())][0]
    }))
    .sort((left, right) => {
      const evidenceDelta = right.evidence.length - left.evidence.length;
      if (evidenceDelta !== 0) {
        return evidenceDelta;
      }

      return left.channel.localeCompare(right.channel);
    });
}

export function displayNotifyChannel(channel: string): string {
  return displayChannelNames[channel] ?? channel;
}
