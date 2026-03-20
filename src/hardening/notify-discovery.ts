import path from "node:path";

import JSON5 from "json5";
import YAML from "yaml";

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

const structuredConfigExtensions = new Set([".json", ".yaml", ".yml"]);
const targetPropertyNames = ["target", "recipient", "destination", "to", "chat_id", "room_id", "channel_id"];
const accountPropertyNames = ["account", "account_name", "profile"];
const channelPropertyNames = ["channel", "type", "provider", "service", "platform"];
const routeContainerPattern =
  /(notify|notification|notifications|route|routes|channel|channels|chat|chats|alert|alerts|relay|reminder|reminders|delivery|deliveries)/i;

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

function normalizeChannelValue(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }

  for (const channel of SUPPORTED_OPENCLAW_NOTIFY_CHANNELS) {
    if (normalized === channel) {
      return channel;
    }
  }

  if (normalized === "google-chat" || normalized === "google_chat") {
    return "googlechat";
  }

  if (
    normalized === "microsoft-teams" ||
    normalized === "microsoft_teams" ||
    normalized === "ms-teams" ||
    normalized === "ms_teams" ||
    normalized === "teams"
  ) {
    return "msteams";
  }

  return undefined;
}

function parseStructuredConfig(filePath: string, content: string): unknown {
  const extension = path.extname(filePath).toLowerCase();
  if (!structuredConfigExtensions.has(extension)) {
    return undefined;
  }

  try {
    if (extension === ".json") {
      return JSON5.parse(content) as unknown;
    }

    return YAML.parse(content) as unknown;
  } catch {
    return undefined;
  }
}

function extractStringPropertyCandidates(
  source: Record<string, unknown>,
  propertyNames: string[]
): string[] {
  return uniqueStrings(
    propertyNames.flatMap((name) => {
      const value = source[name];
      return typeof value === "string" ? [value] : [];
    })
  );
}

function registerStructuredHit(
  channel: string,
  fileLabel: string,
  contextLabel: string | undefined,
  targetHints: string[],
  accountHints: string[],
  matches: Map<string, Set<string>>,
  targets: Map<string, Set<string>>,
  accounts: Map<string, Set<string>>
): void {
  const evidence = matches.get(channel) ?? new Set<string>();
  evidence.add(contextLabel ? `${fileLabel}（${contextLabel}）` : fileLabel);
  matches.set(channel, evidence);

  const targetBucket = targets.get(channel) ?? new Set<string>();
  for (const candidate of targetHints) {
    targetBucket.add(candidate);
  }
  targets.set(channel, targetBucket);

  const accountBucket = accounts.get(channel) ?? new Set<string>();
  for (const candidate of accountHints) {
    accountBucket.add(candidate);
  }
  accounts.set(channel, accountBucket);
}

function traverseStructuredNotifyConfig(
  value: unknown,
  state: {
    fileLabel: string;
    path: string[];
    inheritedChannel?: string;
    matches: Map<string, Set<string>>;
    targets: Map<string, Set<string>>;
    accounts: Map<string, Set<string>>;
  }
): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      traverseStructuredNotifyConfig(item, {
        ...state,
        path: [...state.path, `[${index}]`]
      })
    );
    return;
  }

  if (!value || typeof value !== "object") {
    return;
  }

  const record = value as Record<string, unknown>;
  const pathLabel = state.path.join(" › ");
  const contextLabel = pathLabel || undefined;

  const explicitChannel = uniqueStrings(
    channelPropertyNames.flatMap((name) => {
      const detected = normalizeChannelValue(record[name]);
      return detected ? [detected] : [];
    })
  )[0];

  const pathChannels = state.path
    .map((segment) => normalizeChannelValue(segment.replace(/^\[(\d+)\]$/, "")))
    .filter((segment): segment is string => Boolean(segment));
  const inheritedChannel = explicitChannel ?? pathChannels.at(-1) ?? state.inheritedChannel;

  const targetHints = extractStringPropertyCandidates(record, targetPropertyNames);
  const accountHints = extractStringPropertyCandidates(record, accountPropertyNames);

  if (inheritedChannel && (targetHints.length > 0 || accountHints.length > 0)) {
    registerStructuredHit(
      inheritedChannel,
      state.fileLabel,
      contextLabel,
      targetHints,
      accountHints,
      state.matches,
      state.targets,
      state.accounts
    );
  }

  for (const [key, child] of Object.entries(record)) {
    const normalizedKeyChannel = normalizeChannelValue(key);
    const childPath = [...state.path, key];
    const childInheritedChannel = normalizedKeyChannel ?? inheritedChannel;

    if (normalizedKeyChannel) {
      const childTargets =
        typeof child === "string"
          ? extractTargetCandidates(normalizedKeyChannel, child)
          : [];
      const childAccounts =
        typeof child === "string"
          ? extractAccountCandidates(child)
          : [];

      if (childTargets.length > 0 || childAccounts.length > 0) {
        registerStructuredHit(
          normalizedKeyChannel,
          state.fileLabel,
          childPath.join(" › "),
          childTargets,
          childAccounts,
          state.matches,
          state.targets,
          state.accounts
        );
      }
    }

    const shouldDescend =
      normalizedKeyChannel !== undefined ||
      routeContainerPattern.test(key) ||
      inheritedChannel !== undefined;

    if (shouldDescend) {
      traverseStructuredNotifyConfig(child, {
        ...state,
        path: childPath,
        inheritedChannel: childInheritedChannel
      });
    }
  }
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

    const structured = parseStructuredConfig(file.relativePath, file.content);
    if (structured !== undefined) {
      traverseStructuredNotifyConfig(structured, {
        fileLabel,
        path: [],
        matches,
        targets,
        accounts
      });
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

export async function detectLikelyNotifyChannelsForTargets(
  targets: string[]
): Promise<LikelyNotifyChannel[]> {
  const merged = new Map<
    string,
    {
      evidence: Set<string>;
      target?: string;
      account?: string;
    }
  >();

  for (const target of targets) {
    let channels: LikelyNotifyChannel[] = [];

    try {
      channels = await detectLikelyNotifyChannels(target);
    } catch {
      continue;
    }

    for (const channel of channels) {
      const current = merged.get(channel.channel) ?? {
        evidence: new Set<string>()
      };

      for (const item of channel.evidence) {
        current.evidence.add(item);
      }

      if (!current.target && channel.target) {
        current.target = channel.target;
      }

      if (!current.account && channel.account) {
        current.account = channel.account;
      }

      merged.set(channel.channel, current);
    }
  }

  return [...merged.entries()]
    .map(([channel, value]) => ({
      channel,
      evidence: [...value.evidence].slice(0, 2),
      target: value.target,
      account: value.account
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
