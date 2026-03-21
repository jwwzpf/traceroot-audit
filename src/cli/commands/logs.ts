import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { Command, Option } from "commander";

import { appendAuditEvents, readAuditEvents } from "../../audit/store";
import {
  loadAuditReviewState,
  saveAuditReviewState
} from "../../audit/review-state";
import {
  discoverHostNativeRuntimeFeeds,
  discoverRuntimeEventFeeds,
  readRecentRuntimeFeedEvents,
  readTodaysRuntimeFeedEvents
} from "../../audit/feeds";
import { loadWatchStatusSession } from "../../audit/status";
import type { AuditEvent, AuditSeverity } from "../../audit/types";
import {
  actionLabel,
  actionLabelWithSubject,
  actionObjectSentence,
  actionSubjectLabel,
  summarizeActionLabels,
  actionTriggerSourceLabel,
  actionTriggerSentence
} from "../../audit/presentation";
import {
  loadAggregatedAuditCoverage,
  loadAuditCoverageSnapshot
} from "../../hardening/audit-coverage";
import { loadHardeningProfile } from "../../hardening/profile";
import {
  workflowScopeNoteForAction,
  workflowScopeUserWarningForAction,
  type HardeningIntentId
} from "../../hardening/profiles";
import { discoverHost } from "../../core/discovery";
import {
  loadRecentDoctorContext,
  recentTargetLabel
} from "../../hardening/recent-target";
import { displayUserPath } from "../../utils/paths";

import type { CliRuntime } from "../index";

interface LogsOptions {
  target?: string;
  severity?: AuditSeverity;
  today?: boolean;
  limit: string;
  tail?: boolean;
  interval: string;
  all?: boolean;
}

function isWorthReview(event: AuditEvent): boolean {
  return event.severity !== "safe";
}

type TimelineEntry = {
  primary: AuditEvent;
  related: AuditEvent[];
};

type OpenMatter = {
  kind: "action-open" | "action-failed" | "boundary" | "finding" | "risk" | "surface";
  severity: AuditSeverity;
  headline: string;
  note: string;
  priority: number;
  timestamp: string;
};

type SettledAction = {
  severity: AuditSeverity;
  actionLabel: string;
  count: number;
  note: string;
};

type DailyVerdict = {
  headline: string;
  note: string;
};

function severityIcon(severity: AuditSeverity): string {
  switch (severity) {
    case "critical":
      return "🚨";
    case "high-risk":
      return "🛑";
    case "risky":
      return "⚠️";
    case "safe":
    default:
      return "🟢";
  }
}

function severityRank(severity: AuditSeverity): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high-risk":
      return 3;
    case "risky":
      return 2;
    case "safe":
    default:
      return 1;
  }
}

function formatTimestamp(value: string): string {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("en-GB", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function relativeTimeFromNow(value: string): string | null {
  const timestamp = new Date(value).getTime();

  if (Number.isNaN(timestamp)) {
    return null;
  }

  const diffMs = Math.max(Date.now() - timestamp, 0);
  const minute = 60_000;
  const hour = 60 * minute;

  if (diffMs < minute) {
    return "刚刚";
  }

  if (diffMs < hour) {
    return `约 ${Math.round(diffMs / minute)} 分钟前`;
  }

  if (diffMs < 24 * hour) {
    return `约 ${Math.round(diffMs / hour)} 小时前`;
  }

  return `约 ${Math.round(diffMs / (24 * hour))} 天前`;
}

async function renderWatchStatusSummary(options: {
  target?: string;
  hostScope?: boolean;
}): Promise<string[] | null> {
  const session = await loadWatchStatusSession({
    scope: options.hostScope ? "host" : "target",
    target: options.hostScope ? null : options.target
  });

  if (!session) {
    return null;
  }

  const relativeTime = relativeTimeFromNow(session.lastHeartbeatAt);
  if (!relativeTime) {
    return null;
  }

  const heartbeatAgeMs = Date.now() - new Date(session.lastHeartbeatAt).getTime();
  const stale = heartbeatAgeMs > 15 * 60_000;
  const lines = [
    "💓 陪跑状态：",
    stale
      ? `- 最近一次报平安：${relativeTime}（看起来这次陪跑可能已经停下来了）`
      : `- 最近一次报平安：${relativeTime}（看起来它还在继续陪跑）`
  ];

  if (session.lastAttention) {
    let attentionLine = session.lastAttention.message;

    if (session.lastAttention.category === "action-event" && session.lastAttention.action) {
      const actor = actorLabel({
        timestamp: session.lastAttention.timestamp,
        severity: session.lastAttention.severity,
        category: session.lastAttention.category,
        source: "runtime-feed",
        target: session.lastAttention.target ?? null,
        message: session.lastAttention.message,
        runtime: session.lastAttention.runtime,
        action: session.lastAttention.action,
        status: session.lastAttention.status
      });
      const label = actionLabel(session.lastAttention.action);

      if (session.lastAttention.status === "succeeded") {
        attentionLine = `${actor} 已完成：${label}`;
      } else if (session.lastAttention.status === "failed") {
        attentionLine = `${actor} 没有完成：${label}`;
      } else {
        attentionLine = `${actor} 正在尝试：${label}`;
      }
    }

    lines.push(`- 最近一次值得你看一眼的是：${attentionLine}`);
    const triggerContext = actionTriggerSourceLabel({
      timestamp: session.lastAttention.timestamp,
      severity: session.lastAttention.severity,
      category: session.lastAttention.category,
      source: "runtime-feed",
      target: session.lastAttention.target ?? null,
      message: session.lastAttention.message,
      runtime: session.lastAttention.runtime,
      action: session.lastAttention.action,
      status: session.lastAttention.status,
      evidence: {
        channel: session.lastAttention.channel,
        sender: session.lastAttention.sender
      }
    });

    if (triggerContext) {
      lines.push(`- 触发来源：${triggerContext}`);
    }
  }

  lines.push("");
  return lines;
}

function categoryLabel(event: AuditEvent): string {
  switch (event.category) {
    case "watch-started":
      return "开始陪跑";
    case "watch-heartbeat":
      return "陪跑心跳";
    case "risk-change":
      return "风险变化";
    case "finding-change":
      return "发现变化";
    case "boundary-drift":
      return "边界漂移";
    case "surface-change":
      return "入口变化";
    case "action-event":
      return "Agent 动作";
    default:
      return event.category;
  }
}

function actorLabel(event: AuditEvent): string {
  const runtime = event.runtime?.trim();

  if (runtime) {
    const normalized = runtime.toLowerCase();

    if (normalized === "openclaw") {
      return "OpenClaw 运行时";
    }

    if (normalized === "claw") {
      return "Claw 运行时";
    }

    if (normalized === "lobster") {
      return "Lobster 运行时";
    }

    if (normalized === "mcp") {
      return "MCP 服务";
    }

    return runtime;
  }

  if (event.target) {
    return path.basename(event.target);
  }

  return "这个 agent";
}

function eventHeadline(event: AuditEvent): string {
  if (event.category === "action-event") {
    const label = actionLabelWithSubject(event);

    switch (event.status) {
      case "attempted":
        return `Agent 开始尝试：${label}`;
      case "succeeded":
        return `Agent 已完成：${label}`;
      case "failed":
        return `Agent 没有完成：${label}`;
      default:
        return `Agent 触发了一个动作：${label}`;
    }
  }

  switch (event.category) {
    case "watch-started":
      return "TraceRoot 已经开始陪跑这个 agent";
    case "watch-heartbeat":
      return "TraceRoot 还在继续陪跑";
    case "risk-change":
      return "整体风险出现了变化";
    case "finding-change":
      return "TraceRoot 发现了新的风险信号";
    case "boundary-drift":
      return "当前运行态重新变宽了";
    case "surface-change":
      return "机器上的 agent 入口有变化";
    default:
      return categoryLabel(event);
  }
}

function eventTimeMs(event: AuditEvent): number {
  const value = new Date(event.timestamp).getTime();
  return Number.isNaN(value) ? 0 : value;
}

function elapsedLabel(startTimestamp: string, endTimestamp: string): string | undefined {
  const start = new Date(startTimestamp).getTime();
  const end = new Date(endTimestamp).getTime();

  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) {
    return undefined;
  }

  const diffMs = end - start;
  const seconds = Math.max(1, Math.round(diffMs / 1000));

  if (seconds < 60) {
    return `大约 ${seconds} 秒`;
  }

  const minutes = Math.round(seconds / 60);
  return `大约 ${minutes} 分钟`;
}

function canFoldIntoOneIncident(first: AuditEvent, next: AuditEvent): boolean {
  if (first.category !== "action-event" || next.category !== "action-event") {
    return false;
  }

  if (first.status !== "attempted") {
    return false;
  }

  if (!(next.status === "succeeded" || next.status === "failed")) {
    return false;
  }

  if (
    first.action !== next.action ||
    first.runtime !== next.runtime ||
    first.target !== next.target
  ) {
    return false;
  }

  return Math.abs(eventTimeMs(next) - eventTimeMs(first)) <= 2 * 60 * 1000;
}

function buildTimelineEntries(eventsAscending: AuditEvent[]): TimelineEntry[] {
  const entries: TimelineEntry[] = [];

  for (let index = 0; index < eventsAscending.length; index += 1) {
    const current = eventsAscending[index]!;
    const next = eventsAscending[index + 1];

    if (next && canFoldIntoOneIncident(current, next)) {
      entries.push({
        primary: next,
        related: [current]
      });
      index += 1;
      continue;
    }

    entries.push({
      primary: current,
      related: []
    });
  }

  return entries;
}

function looksLikeGenericRuntimeNarration(message: string): boolean {
  const normalized = message
    .trim()
    .replace(/^[^:：]+(?:刚提到|报告这个动作已经完成|报告这个动作没有成功|刚刚报告了一个动作)[:：]\s*/u, "");
  return [
    /^agent is attempting to /i,
    /^agent attempted to /i,
    /^agent started /i,
    /^agent began /i,
    /^agent completed /i,
    /^agent finished /i,
    /^agent succeeded /i,
    /^agent failed /i,
    /^agent triggered /i
  ].some((pattern) => pattern.test(normalized));
}

function eventDetail(event: AuditEvent): string | undefined {
  if (!event.message) {
    return undefined;
  }

  if (event.category !== "action-event") {
    return event.message;
  }

  if (!looksLikeGenericRuntimeNarration(event.message)) {
    return event.message;
  }

  switch (event.status) {
    case "attempted":
      return "这个动作刚刚开始，TraceRoot 已经先把它记进审计时间线里。";
    case "succeeded":
      return "这个动作已经执行完成，TraceRoot 也已经把它记下来了。";
    case "failed":
      return "这次动作没有完成，不过 TraceRoot 已经把整个尝试过程记下来了。";
    default:
      return "TraceRoot 已经把这次动作记进审计时间线里。";
  }
}

function timelineHeadline(entry: TimelineEntry): string {
  if (entry.related.length === 0) {
    return eventHeadline(entry.primary);
  }

  const actor = actorLabel(entry.primary);
  const label = actionLabel(entry.primary.action);

  if (entry.primary.status === "succeeded") {
    return `${actor} 已完成：${label}`;
  }

  if (entry.primary.status === "failed") {
    return `${actor} 没有完成：${label}`;
  }

  return eventHeadline(entry.primary);
}

function timelineDetail(entry: TimelineEntry): string | undefined {
  if (entry.related.length === 0) {
    return eventDetail(entry.primary);
  }

  const attempt = entry.related[0];
  const duration = attempt ? elapsedLabel(attempt.timestamp, entry.primary.timestamp) : undefined;

  if (entry.primary.status === "succeeded") {
    return duration
      ? `TraceRoot 看到这个动作先被触发，随后在${duration}后执行完成。`
      : "TraceRoot 看到这个动作先被触发，随后已经执行完成。";
  }

  if (entry.primary.status === "failed") {
    return duration
      ? `TraceRoot 看到这个动作先被触发，不过在${duration}后还是没有完成。`
      : "TraceRoot 看到这个动作先被触发，不过最后没有完成。";
  }

  return eventDetail(entry.primary);
}

function openMatterPriority(entry: TimelineEntry): number {
  const event = entry.primary;

  if (event.category === "action-event") {
    if (event.status === "failed") {
      return 40;
    }

    if (event.status === "attempted") {
      return 35;
    }
  }

  if (event.category === "boundary-drift") {
    return 30;
  }

  if (event.category === "finding-change") {
    return 20;
  }

  if (event.category === "risk-change") {
    return 15;
  }

  if (event.category === "surface-change") {
    return 10;
  }

  return 0;
}

function summarizeOpenMatters(
  timelineEntries: TimelineEntry[],
  approvedIntentIds: HardeningIntentId[] = []
): OpenMatter[] {
  const matters: OpenMatter[] = [];

  for (const entry of timelineEntries) {
    const event = entry.primary;

    if (event.severity === "safe") {
      continue;
    }

    if (event.category === "action-event") {
      const label = actionLabelWithSubject(event);

      if (event.status === "failed") {
        matters.push({
          kind: "action-failed",
          severity: event.severity,
          headline: `${label} 这次没有完成`,
          priority: openMatterPriority(entry),
          timestamp: event.timestamp,
          note: event.recommendation
            ? `TraceRoot 建议你先看一眼：${event.recommendation}`
            : "这类动作虽然没有完成，但通常值得确认会不会重试，或者有没有留下半完成状态。"
        });
        continue;
      }

      if (event.status === "attempted") {
        const scopeWarning = workflowScopeUserWarningForAction(
          event.action,
          approvedIntentIds
        );
        matters.push({
          kind: "action-open",
          severity: event.severity,
          headline: `${label} 刚刚开始了，但还没看到它收住`,
          priority: openMatterPriority(entry),
          timestamp: event.timestamp,
          note:
            scopeWarning ??
            actionTriggerSentence(event) ??
            "TraceRoot 已经先把这一步记住了，你可以继续盯一下它后面有没有真的完成。"
        });
        continue;
      }
    }

    if (event.category === "boundary-drift") {
      matters.push({
        kind: "boundary",
        severity: event.severity,
        headline: "当前运行态比你批准的边界更宽",
        priority: openMatterPriority(entry),
        timestamp: event.timestamp,
        note: event.recommendation
          ? `TraceRoot 建议你先做：${event.recommendation}`
          : "这通常意味着 agent 现在拿到的能力，比你原本批准的那套还要多。"
      });
      continue;
    }

    if (event.category === "finding-change") {
      matters.push({
        kind: "finding",
        severity: event.severity,
        headline: "今天又冒出了新的风险信号",
        priority: openMatterPriority(entry),
        timestamp: event.timestamp,
        note:
          event.recommendation ??
          "TraceRoot 觉得这里值得回头看一眼，确认是不是新出现的高风险入口或动作。"
      });
      continue;
    }

    if (event.category === "risk-change") {
      matters.push({
        kind: "risk",
        severity: event.severity,
        headline: "整体风险刚刚又变高了",
        priority: openMatterPriority(entry),
        timestamp: event.timestamp,
        note:
          event.recommendation ??
          "这说明当前运行态的风险面又往上走了一步，值得确认最近变了什么。"
      });
      continue;
    }

    if (event.category === "surface-change") {
      matters.push({
        kind: "surface",
        severity: event.severity,
        headline: "机器上的 agent 入口今天有变化",
        priority: openMatterPriority(entry),
        timestamp: event.timestamp,
        note:
          event.recommendation ??
          "如果这不是你预期中的变化，最好回头看看是不是多了新的运行入口。"
      });
    }
  }

  return matters
    .sort((left, right) => {
      const severityDelta = severityRank(right.severity) - severityRank(left.severity);
      if (severityDelta !== 0) {
        return severityDelta;
      }

      const priorityDelta = right.priority - left.priority;
      if (priorityDelta !== 0) {
        return priorityDelta;
      }

      return right.timestamp.localeCompare(left.timestamp);
    })
    .slice(0, 3);
}

function summarizeSettledActions(timelineEntries: TimelineEntry[]): SettledAction[] {
  const settled = new Map<
    string,
    { severity: AuditSeverity; actionLabel: string; count: number }
  >();

  for (const entry of timelineEntries) {
    const event = entry.primary;

    if (
      event.category !== "action-event" ||
      event.status !== "succeeded" ||
      event.severity === "safe"
    ) {
      continue;
    }

    const label = actionLabel(event.action);
    const existing = settled.get(label) ?? {
      severity: event.severity,
      actionLabel: label,
      count: 0
    };

    existing.count += 1;
    if (severityRank(event.severity) > severityRank(existing.severity)) {
      existing.severity = event.severity;
    }

    settled.set(label, existing);
  }

  return [...settled.values()]
    .sort((left, right) => {
      const severityDelta = severityRank(right.severity) - severityRank(left.severity);
      if (severityDelta !== 0) {
        return severityDelta;
      }

      return right.count - left.count;
    })
    .slice(0, 3)
    .map((entry) => ({
      ...entry,
      note:
        entry.count > 1
          ? `今天这类高风险动作已经走完了 ${entry.count} 次，至少从时间线上看，目前没有卡在半路。`
          : "这类高风险动作今天已经顺利走完，至少从时间线上看，目前没有卡在半路。"
    }));
}

function summarizeDailyVerdict(options: {
  openMatters: OpenMatter[];
  settledActions: SettledAction[];
  summary: ReturnType<typeof summarizeEvents>;
}): DailyVerdict {
  const { openMatters, settledActions, summary } = options;

  if (openMatters.length > 0) {
    const topActionMatter = openMatters.find(
      (matter) => matter.kind === "action-open" || matter.kind === "action-failed"
    );

    if (topActionMatter) {
      return {
        headline: `今天还有 ${openMatters.length} 件事没收住，最该先盯的是「${topActionMatter.headline}」`,
        note: topActionMatter.note
      };
    }

    if (settledActions.length > 0) {
      const topAction = settledActions[0]!;
      return {
        headline: `今天已经发生过高风险动作，最该先回看的是「${topAction.actionLabel}」`,
        note: `${topAction.actionLabel} 今天至少已经顺利走完了；不过与此同时，TraceRoot 看到运行态还有一些边界和风险信号没有完全收住。`
      };
    }

    const topMatter = openMatters[0]!;
    return {
      headline: `今天还有 ${openMatters.length} 件事没收住，最该先盯的是「${topMatter.headline}」`,
      note: topMatter.note
    };
  }

  if (settledActions.length > 0) {
    const topAction = settledActions[0]!;
    return {
      headline: "今天出现过高风险动作，但目前看起来都已经收住了",
      note: `${topAction.actionLabel} 是今天最值得回头确认的一类动作，至少从时间线上看，它目前已经走完了。`
    };
  }

  if (summary.boundaryEvents > 0 || summary.driftEvents > 0) {
    return {
      headline: "今天主要是边界和风险信号有变化，还没看到高风险动作失控",
      note: "TraceRoot 目前主要在盯运行态有没有重新变宽，以及新的风险入口有没有冒出来。"
    };
  }

  if (summary.actionEvents > 0) {
    return {
      headline: "今天 agent 有动作记录，但目前没有需要立刻打断你的事情",
      note: "TraceRoot 已经把这些动作记进审计时间线里了；如果你想回看来龙去脉，直接往下看今天的记录就行。"
    };
  }

  return {
    headline: "今天目前还比较平稳，TraceRoot 正在继续陪跑",
    note: "只要有新的高风险动作、边界漂移或风险变化冒出来，TraceRoot 就会把它提到最前面。"
  };
}

function summarizeEvents(
  events: AuditEvent[],
  approvedIntentIds: HardeningIntentId[] = []
): {
  critical: number;
  highRisk: number;
  risky: number;
  safe: number;
  actionEvents: number;
  boundaryEvents: number;
  driftEvents: number;
  latestAttention: AuditEvent | null;
  attentionActions: Array<{
    actionLabel: string;
    count: number;
    failed: number;
    severity: AuditSeverity;
  }>;
  attentionActors: Array<{
    actorLabel: string;
    count: number;
    severity: AuditSeverity;
    actions: string[];
  }>;
  attentionSources: Array<{
    sourceLabel: string;
    count: number;
    severity: AuditSeverity;
    actions: string[];
  }>;
  attentionTargets: Array<{
    targetLabel: string;
    targetPath: string;
    count: number;
    severity: AuditSeverity;
    actions: string[];
  }>;
} {
  let critical = 0;
  let highRisk = 0;
  let risky = 0;
  let safe = 0;
  let actionEvents = 0;
  let boundaryEvents = 0;
  let driftEvents = 0;
  let latestAttention: AuditEvent | null = null;
  const attentionActions = new Map<
    string,
    { actionLabel: string; count: number; failed: number; severity: AuditSeverity }
  >();
  const attentionSubjects = new Map<
    string,
    { subjectLabel: string; count: number; severity: AuditSeverity; actions: Set<string> }
  >();
  const attentionActors = new Map<
    string,
    { actorLabel: string; count: number; severity: AuditSeverity; actions: Set<string> }
  >();
  const attentionSources = new Map<
    string,
    { sourceLabel: string; count: number; severity: AuditSeverity; actions: Set<string> }
  >();
  const attentionTargets = new Map<
    string,
    { targetLabel: string; targetPath: string; count: number; severity: AuditSeverity; actions: Set<string> }
  >();

  const severityWeight = (severity: AuditSeverity): number => {
    if (severity === "critical") return 4;
    if (severity === "high-risk") return 3;
    if (severity === "risky") return 2;
    return 1;
  };

  const attentionCategoryWeight = (event: AuditEvent): number => {
    if (event.category === "action-event") {
      return 4;
    }

    if (event.category === "boundary-drift") {
      return 3;
    }

    if (event.category === "risk-change" || event.category === "finding-change") {
      return 2;
    }

    if (event.category === "surface-change") {
      return 1;
    }

    return 0;
  };

  const attentionPrimaryPriority = (event: AuditEvent): number => {
    if (
      event.category === "action-event" &&
      workflowScopeNoteForAction(event.action, approvedIntentIds)
    ) {
      return 60;
    }

    if (event.category === "action-event") {
      return 50;
    }

    if (event.category === "boundary-drift") {
      return 30;
    }

    if (event.category === "risk-change" || event.category === "finding-change") {
      return 20;
    }

    if (event.category === "surface-change") {
      return 10;
    }

    return 0;
  };

  for (const event of events) {
    if (event.severity === "critical") critical += 1;
    else if (event.severity === "high-risk") highRisk += 1;
    else if (event.severity === "risky") risky += 1;
    else safe += 1;

    if (event.category === "action-event") {
      actionEvents += 1;

      if (event.severity !== "safe") {
        const label = actionLabel(event.action);
        const existing = attentionActions.get(label) ?? {
          actionLabel: label,
          count: 0,
          failed: 0,
          severity: event.severity
        };

        existing.count += 1;
        if (event.status === "failed") {
          existing.failed += 1;
        }
        if (event.severity === "critical") {
          existing.severity = "critical";
        } else if (event.severity === "high-risk" && existing.severity !== "critical") {
          existing.severity = "high-risk";
        } else if (event.severity === "risky" && existing.severity === "safe") {
          existing.severity = "risky";
        }

        attentionActions.set(label, existing);

        const subject = actionSubjectLabel(event);
        if (subject) {
          const subjectEntry = attentionSubjects.get(subject) ?? {
            subjectLabel: subject,
            count: 0,
            severity: event.severity,
            actions: new Set<string>()
          };

          subjectEntry.count += 1;
          subjectEntry.actions.add(label);
          if (severityWeight(event.severity) > severityWeight(subjectEntry.severity)) {
            subjectEntry.severity = event.severity;
          }

          attentionSubjects.set(subject, subjectEntry);
        }

        const actor = actorLabel(event);
        const actorEntry = attentionActors.get(actor) ?? {
          actorLabel: actor,
          count: 0,
          severity: event.severity,
          actions: new Set<string>()
        };

        actorEntry.count += 1;
        actorEntry.actions.add(label);
        if (severityWeight(event.severity) > severityWeight(actorEntry.severity)) {
          actorEntry.severity = event.severity;
        }

        attentionActors.set(actor, actorEntry);

        const sourceLabel = actionTriggerSourceLabel(event);
        if (sourceLabel) {
          const sourceEntry = attentionSources.get(sourceLabel) ?? {
            sourceLabel,
            count: 0,
            severity: event.severity,
            actions: new Set<string>()
          };

          sourceEntry.count += 1;
          sourceEntry.actions.add(label);
          if (severityWeight(event.severity) > severityWeight(sourceEntry.severity)) {
            sourceEntry.severity = event.severity;
          }

          attentionSources.set(sourceLabel, sourceEntry);
        }

        if (event.target) {
          const targetLabel = displayUserPath(event.target);
          const targetEntry = attentionTargets.get(event.target) ?? {
            targetLabel,
            targetPath: event.target,
            count: 0,
            severity: event.severity,
            actions: new Set<string>()
          };

          targetEntry.count += 1;
          targetEntry.actions.add(label);
          if (severityWeight(event.severity) > severityWeight(targetEntry.severity)) {
            targetEntry.severity = event.severity;
          }

          attentionTargets.set(event.target, targetEntry);
        }
      }
    }

    if (event.category === "boundary-drift") {
      boundaryEvents += 1;
      driftEvents += 1;
    }

    if (
      event.category === "risk-change" ||
      event.category === "finding-change" ||
      event.category === "surface-change"
    ) {
      driftEvents += 1;
    }

    if (event.severity !== "safe") {
      if (!latestAttention) {
        latestAttention = event;
      } else {
        const primaryDelta =
          attentionPrimaryPriority(event) - attentionPrimaryPriority(latestAttention);
        if (primaryDelta > 0) {
          latestAttention = event;
          continue;
        }

        if (primaryDelta < 0) {
          continue;
        }

        const nextScore =
          severityWeight(event.severity) * 10 + attentionCategoryWeight(event);
        const currentScore =
          severityWeight(latestAttention.severity) * 10 + attentionCategoryWeight(latestAttention);

        if (nextScore > currentScore || (nextScore === currentScore && event.timestamp >= latestAttention.timestamp)) {
          latestAttention = event;
        }
      }
    }
  }

  return {
    critical,
    highRisk,
    risky,
    safe,
    actionEvents,
    boundaryEvents,
    driftEvents,
    latestAttention,
    attentionActions: [...attentionActions.values()]
      .sort((left, right) => {
        return (
          severityWeight(right.severity) - severityWeight(left.severity) ||
          right.count - left.count ||
          right.failed - left.failed
        );
      })
      .slice(0, 3),
    attentionSubjects: [...attentionSubjects.values()]
      .sort((left, right) => {
        return (
          severityWeight(right.severity) - severityWeight(left.severity) ||
          right.count - left.count ||
          right.actions.size - left.actions.size
        );
      })
      .slice(0, 4)
      .map((entry) => ({
        subjectLabel: entry.subjectLabel,
        count: entry.count,
        severity: entry.severity,
        actions: [...entry.actions]
      })),
    attentionActors: [...attentionActors.values()]
      .sort((left, right) => {
        return (
          severityWeight(right.severity) - severityWeight(left.severity) ||
          right.count - left.count ||
          right.actions.size - left.actions.size
        );
      })
      .slice(0, 3)
      .map((entry) => ({
        actorLabel: entry.actorLabel,
        count: entry.count,
        severity: entry.severity,
        actions: [...entry.actions]
      })),
    attentionSources: [...attentionSources.values()]
      .sort((left, right) => {
        return (
          severityWeight(right.severity) - severityWeight(left.severity) ||
          right.count - left.count ||
          right.actions.size - left.actions.size
        );
      })
      .slice(0, 3)
      .map((entry) => ({
        sourceLabel: entry.sourceLabel,
        count: entry.count,
        severity: entry.severity,
        actions: [...entry.actions]
      })),
    attentionTargets: [...attentionTargets.values()]
      .sort((left, right) => {
        return (
          severityWeight(right.severity) - severityWeight(left.severity) ||
          right.count - left.count ||
          right.actions.size - left.actions.size
        );
      })
      .slice(0, 3)
      .map((entry) => ({
        targetLabel: entry.targetLabel,
        targetPath: entry.targetPath,
        count: entry.count,
        severity: entry.severity,
        actions: [...entry.actions]
      }))
  };
}

function eventKey(event: AuditEvent): string {
  return [
    event.timestamp,
    event.source,
    event.category,
    event.status ?? "",
    event.action ?? "",
    event.target ?? "",
    event.message
  ].join("::");
}

function eventDisplayScore(event: AuditEvent): number {
  let score = 0;

  if (event.recommendation) score += 4;
  if (actionTriggerSourceLabel(event)) score += 3;
  if (actionObjectSentence(event)) score += 3;
  if (typeof event.evidence?.feedPath === "string" && event.evidence.feedPath.trim().length > 0) {
    score += 2;
  }
  if (event.message.trim().length > 0) score += Math.min(event.message.trim().length, 120) / 120;

  return score;
}

function eventDisplayTimeBucket(event: AuditEvent): string {
  const bucketMs = event.category === "action-event" ? 5_000 : 1_000;
  const value = new Date(event.timestamp).getTime();
  if (Number.isNaN(value)) {
    return event.timestamp;
  }

  const bucket = Math.floor(value / bucketMs) * bucketMs;
  return new Date(bucket).toISOString();
}

function eventDisplayKey(event: AuditEvent): string {
  if (event.category === "action-event") {
    return [
      eventDisplayTimeBucket(event),
      event.category,
      event.status ?? "",
      event.action ?? "",
      event.runtime ?? "",
      event.target ?? "",
      actionTriggerSourceLabel(event) ?? "",
      actionObjectSentence(event) ?? "",
      event.severity
    ].join("::");
  }

  return [
    eventDisplayTimeBucket(event),
    event.category,
    event.target ?? "",
    event.message,
    event.severity
  ].join("::");
}

function dedupeEventsForDisplay(events: AuditEvent[]): AuditEvent[] {
  const deduped = new Map<string, AuditEvent>();

  for (const event of events) {
    const key = eventDisplayKey(event);
    const existing = deduped.get(key);

    if (!existing || eventDisplayScore(event) > eventDisplayScore(existing)) {
      deduped.set(key, event);
    }
  }

  return [...deduped.values()].sort((left, right) => right.timestamp.localeCompare(left.timestamp));
}

function renderTimelineEntry(
  entry: TimelineEntry,
  approvedIntentIds: HardeningIntentId[] = []
): string[] {
  const headline = timelineHeadline(entry);
  const lines = [
    `${severityIcon(entry.primary.severity)} [${formatTimestamp(entry.primary.timestamp)}] ${headline}`
  ];

  const detail = timelineDetail(entry);
  if (detail && detail !== headline) {
    lines.push(`   📝 ${detail}`);
  }

  const triggerContext = actionTriggerSourceLabel(entry.primary);
  if (triggerContext) {
    lines.push(`   🗣️ 触发来源: ${triggerContext}`);
  }

  const actionObject = actionObjectSentence(entry.primary);
  if (actionObject) {
    lines.push(`   🎯 ${actionObject}`);
  }

  if (entry.primary.target) {
    lines.push(`   📍 发生在: ${displayUserPath(entry.primary.target)}`);
  }

  const feedPath =
    typeof entry.primary.evidence?.feedPath === "string" &&
    entry.primary.evidence.feedPath.trim().length > 0
      ? displayUserPath(entry.primary.evidence.feedPath)
      : undefined;
  if (feedPath) {
    lines.push(`   🧷 来源日志: ${feedPath}`);
  }

  if (entry.primary.recommendation) {
    lines.push(`   🔧 TraceRoot 建议先做: ${entry.primary.recommendation}`);
  }

  const workflowScopeNote = workflowScopeNoteForAction(
    entry.primary.action,
    approvedIntentIds
  );
  if (workflowScopeNote) {
    lines.push(`   🚧 ${workflowScopeUserWarningForAction(entry.primary.action, approvedIntentIds) ?? workflowScopeNote}`);
  }

  return lines;
}

function normalizeTargetFilter(target?: string): string | undefined {
  if (!target) {
    return undefined;
  }

  return path.resolve(target);
}

async function renderAuditCoverageSummary(target?: string): Promise<string[] | null> {
  if (!target) {
    return null;
  }

  const coverage = await loadAuditCoverageSnapshot(target);
  if (!coverage.snapshot) {
    return null;
  }

  const lines = [
    "🎬 当前动作审计覆盖：",
    `- 现在已经盯住：${summarizeActionLabels(coverage.snapshot.coveredActions)}。`,
    `- 已经自动接好 ${coverage.snapshot.installedEntrypointCount} 个常见动作入口。`
  ];

  if (coverage.snapshot.installedEntrypointLabels.length > 0) {
    lines.push(
      `- 已接好的重点入口：${coverage.snapshot.installedEntrypointLabels.slice(0, 3).join("、")}${
        coverage.snapshot.installedEntrypointLabels.length > 3
          ? `，以及另外 ${coverage.snapshot.installedEntrypointLabels.length - 3} 个入口`
          : ""
      }。`
    );
  }

  if (coverage.snapshot.pendingActions.length > 0) {
    lines.push(
      `- 还有 ${coverage.snapshot.pendingActions.length} 类高风险动作暂时还没完全接上，TraceRoot 会继续从运行时事件里补上这层视角。`
    );
  }

  lines.push("");
  return lines;
}

async function renderHostAuditCoverageSummary(): Promise<string[] | null> {
  const discovery = await discoverHost({ includeCwd: false });
  const coverage = await loadAggregatedAuditCoverage(discovery.candidates);
  const runtimeFeeds = new Map<string, true>();

  for (const candidate of discovery.candidates) {
    const feeds = await discoverRuntimeEventFeeds(candidate.absolutePath);
    for (const feed of feeds) {
      runtimeFeeds.set(feed.absolutePath, true);
    }
  }

  const nativeFeedDiscovery = await discoverHostNativeRuntimeFeeds(discovery.homeDir);
  for (const feed of nativeFeedDiscovery.feeds) {
    runtimeFeeds.set(feed.absolutePath, true);
  }

  if (coverage.surfaceCount === 0 && runtimeFeeds.size === 0) {
    return null;
  }

  const lines = ["🎬 当前整机动作审计覆盖："];

  if (coverage.surfaceCount > 0) {
    lines.push(
      `- 这台机器上已经有 ${coverage.surfaceCount} 个入口被接进了动作审计。`,
      `- 现在已经盯住：${summarizeActionLabels(coverage.coveredActions)}。`,
      `- 已经自动接好 ${coverage.installedEntrypointCount} 个常见动作入口。`
    );

    if (coverage.installedEntrypointLabels.length > 0) {
      lines.push(
        `- 已接好的重点入口：${coverage.installedEntrypointLabels.slice(0, 3).join("、")}${
          coverage.installedEntrypointLabels.length > 3
            ? `，以及另外 ${coverage.installedEntrypointLabels.length - 3} 个入口`
            : ""
        }。`
      );
    }

    if (coverage.pendingActions.length > 0) {
      lines.push(
        `- 还有 ${coverage.pendingActions.length} 类高风险动作暂时还没完全接上，TraceRoot 也会继续通过原生运行时事件把这些动作记进时间线。`
      );
    }
  } else {
    lines.push(
      "- 这台机器上暂时还没看到已经自动接好的动作入口。",
      "- TraceRoot 这次主要还是靠原生运行时事件入口继续陪跑。"
    );
  }

  if (runtimeFeeds.size > 0) {
    lines.push(`- 另外还在继续听 ${runtimeFeeds.size} 个运行时事件入口。`);
  }

  lines.push("");
  return lines;
}

async function backfillRuntimeFeedEvents(options: {
  target?: string;
  today?: boolean;
  hostScope?: boolean;
}): Promise<number> {
  const feedMap = new Map<string, Awaited<ReturnType<typeof discoverRuntimeEventFeeds>>[number]>();

  if (options.hostScope) {
    const discovery = await discoverHost({ includeCwd: false });
    for (const candidate of discovery.candidates) {
      const feeds = await discoverRuntimeEventFeeds(candidate.absolutePath);
      for (const feed of feeds) {
        feedMap.set(feed.absolutePath, feed);
      }
    }

    const nativeFeedDiscovery = await discoverHostNativeRuntimeFeeds(discovery.homeDir);
    for (const feed of nativeFeedDiscovery.feeds) {
      feedMap.set(feed.absolutePath, feed);
    }
  } else if (options.target) {
    const feeds = await discoverRuntimeEventFeeds(options.target);
    for (const feed of feeds) {
      feedMap.set(feed.absolutePath, feed);
    }
  } else {
    return 0;
  }

  const feeds = [...feedMap.values()];
  if (feeds.length === 0) {
    return 0;
  }

  const feedEvents = options.today
    ? await readTodaysRuntimeFeedEvents({
        feeds,
        targetRoot: options.target ?? process.cwd()
      })
    : await readRecentRuntimeFeedEvents({
        feeds,
        targetRoot: options.target ?? process.cwd()
      });

  if (feedEvents.length === 0) {
    return 0;
  }

  const existingEvents = await readAuditEvents({
    target: options.hostScope ? undefined : options.target,
    today: options.today
  });
  const existingKeys = new Set(existingEvents.events.map(eventKey));
  const freshEvents = feedEvents.filter((event) => !existingKeys.has(eventKey(event)));

  if (freshEvents.length === 0) {
    return 0;
  }

  await appendAuditEvents(freshEvents);
  return freshEvents.length;
}

async function printLogs(
  runtime: CliRuntime,
  options: {
    target?: string;
    severity?: AuditSeverity;
    today?: boolean;
    limit?: number;
    header?: boolean;
    hostScope?: boolean;
  }
): Promise<AuditEvent[]> {
  const backfilledFeedEvents = await backfillRuntimeFeedEvents({
    target: options.target,
    today: options.today,
    hostScope: options.hostScope
  });
  const reviewState = await loadAuditReviewState({
    scope: options.hostScope ? "host" : "target",
    target: options.hostScope ? null : options.target
  });
  const query = {
    target: options.target,
    severity: options.severity,
    today: options.today
  } as const;
  const fullResult = await readAuditEvents(query);
  const dedupedEvents = dedupeEventsForDisplay(fullResult.events);
  const result = {
    ...fullResult,
    events:
      typeof options.limit === "number" && options.limit > 0
        ? dedupedEvents.slice(0, options.limit)
        : dedupedEvents
  };
  const eventsAscending = [...result.events].reverse();
  const totalMatchingEvents = dedupedEvents.length;
  const timelineEntries = buildTimelineEntries(eventsAscending);
  const hardeningProfileResult =
    options.target && !options.hostScope
      ? await loadHardeningProfile(options.target)
      : { profile: null, profilePath: null };
  const approvedIntentIds =
    hardeningProfileResult.profile?.selectedIntents.map(
      (intent) => intent.id as HardeningIntentId
    ) ?? [];
  const outsideWorkflowTodayCount =
    approvedIntentIds.length > 0
      ? eventsAscending.filter((event) =>
          Boolean(workflowScopeNoteForAction(event.action, approvedIntentIds))
        ).length
      : 0;

  if (options.header !== false) {
    const summary = summarizeEvents(eventsAscending, approvedIntentIds);
    const openMatters = summarizeOpenMatters(timelineEntries, approvedIntentIds);
    const settledActions = summarizeSettledActions(timelineEntries);
    const dailyVerdict = summarizeDailyVerdict({
      openMatters,
      settledActions,
      summary
    });
    const freshSinceLastReview = reviewState
      ? (
          await readAuditEvents({
            target: options.target,
            severity: options.severity,
            today: options.today,
            since: reviewState.lastReviewedAt
          })
        ).events.filter(isWorthReview)
      : [];
    const watchStatusLines = await renderWatchStatusSummary({
      target: options.target,
      hostScope: options.hostScope
    });
    const coverageLines = options.hostScope
      ? await renderHostAuditCoverageSummary()
      : await renderAuditCoverageSummary(options.target);
    const lines = [
      "TraceRoot Audit Logs",
      "====================",
      "",
      `🗂 审计日志位置: ${displayUserPath(result.paths.eventsPath)}`
    ];

    if (options.hostScope) {
      lines.push("🖥 正在查看: 整机陪跑时间线");
    } else if (options.target) {
      lines.push(`🎯 正在查看: ${displayUserPath(options.target)}`);
    }

    if (options.severity) {
      lines.push(`🚦 风险过滤: ${options.severity}`);
    }

    if (options.today) {
      lines.push("📅 时间范围: 今天");
    }

    if (backfilledFeedEvents > 0) {
      lines.push(
        `🧲 TraceRoot 这次还顺手从原生运行时日志里补回了 ${backfilledFeedEvents} 条今天的动作记录。`
      );
    }

    if (watchStatusLines) {
      lines.push("", ...watchStatusLines);
    }

    if (coverageLines) {
      lines.push("", ...coverageLines);
    }

    lines.push(
      `📚 本次显示 ${eventsAscending.length} 条审计记录`,
      `🧾 对你来说更像 ${timelineEntries.length} 件完整的事`,
      `🧮 风险概览: 🚨 ${summary.critical} / 🛑 ${summary.highRisk} / ⚠️ ${summary.risky} / 🟢 ${summary.safe}`,
      `🎬 动作记录: ${summary.actionEvents} 条`,
      `🧱 边界与漂移: ${summary.boundaryEvents} 条边界漂移，${summary.driftEvents} 条整体变化`,
      ""
    );

    lines.push(
      "🩺 今天的审计结论：",
      `- ${dailyVerdict.headline}`,
      `- ${dailyVerdict.note}`,
      ""
    );

    const partialView =
      Boolean(options.severity) ||
      (typeof options.limit === "number" && totalMatchingEvents > options.limit);

    if (partialView) {
      lines.push(
        "🧠 这次你看的还是一部分记录。",
        "   TraceRoot 还会继续保留“上次没看完”的提醒，等你真正把这段时间线看完整再替你消掉它。",
        ""
      );
    }

    if (outsideWorkflowTodayCount > 0) {
      lines.push(
        "🚧 这条时间线里还有一些动作看起来不是你刚才让 agent 做的事：",
        `- 今天已经出现了 ${outsideWorkflowTodayCount} 条这类记录`,
        ""
      );
    }

    if (reviewState && freshSinceLastReview.length > 0) {
      const newSummary = summarizeEvents(freshSinceLastReview, approvedIntentIds);
      const outsideWorkflowCount =
        approvedIntentIds.length > 0
          ? freshSinceLastReview.filter((event) =>
              Boolean(workflowScopeNoteForAction(event.action, approvedIntentIds))
            ).length
          : 0;
      lines.push("🆕 自从你上次回来看这条时间线以后：");
      lines.push(
        `- 又发生了 ${freshSinceLastReview.length} 条值得留意的记录`,
        `- 里面最值得先看的是：${newSummary.latestAttention ? eventHeadline(newSummary.latestAttention) : "有新的风险变化"}`
      );
      if (outsideWorkflowCount > 0) {
        lines.push(`- 其中有 ${outsideWorkflowCount} 条看起来已经不是你让 agent 做的事`);
      }

      if (newSummary.attentionActions.length > 0) {
        lines.push(
          `- 最常冒出来的是：${newSummary.attentionActions
            .slice(0, 2)
            .map((item) => item.actionLabel)
            .join("、")}`
        );
      }

      lines.push("");
    }

    if (openMatters.length > 0) {
      lines.push("🚨 今天还没收住的事情：");
      for (const matter of openMatters) {
        lines.push(`- ${severityIcon(matter.severity)} ${matter.headline}`);
        lines.push(`  ${matter.note}`);
      }
      lines.push("");
    } else if (eventsAscending.length > 0) {
      lines.push(
        "🫶 今天暂时没有“还没收住”的高风险事情。",
        "   这代表目前看起来没有哪一步正卡在半路上，也没有哪块边界正在明显外扩。",
        ""
      );
    }

    if (settledActions.length > 0) {
      lines.push("✅ 今天已经收住的高风险动作：");
      for (const action of settledActions) {
        lines.push(`- ${severityIcon(action.severity)} ${action.actionLabel}：已经走完 ${action.count} 次`);
        lines.push(`  ${action.note}`);
      }
      lines.push("");
    }

    if (summary.latestAttention) {
      lines.push("👀 当前最值得注意的事情：");
      lines.push(`- ${eventHeadline(summary.latestAttention)}`);
      const triggerContext = actionTriggerSourceLabel(summary.latestAttention);
      if (triggerContext) {
        lines.push(`- 触发来源：${triggerContext}`);
      }
      const detail = eventDetail(summary.latestAttention);
      if (detail && detail !== eventHeadline(summary.latestAttention)) {
        lines.push(`- 说明：${detail}`);
      }
      const workflowScopeNote = workflowScopeNoteForAction(
        summary.latestAttention.action,
        approvedIntentIds
      );
      if (workflowScopeNote) {
        lines.push(
          `- 🚧 ${workflowScopeUserWarningForAction(summary.latestAttention.action, approvedIntentIds) ?? workflowScopeNote}`
        );
      }
      if (summary.latestAttention.recommendation) {
        lines.push(`- 建议：${summary.latestAttention.recommendation}`);
      }
      lines.push("");
    }

    if (summary.attentionActions.length > 0) {
      lines.push("🔥 今天最值得留意的动作：");
      for (const action of summary.attentionActions) {
        const prefix = severityIcon(action.severity);
        const failureSuffix = action.failed > 0 ? `，其中 ${action.failed} 次没有完成` : "";
        lines.push(`- ${prefix} ${action.actionLabel}：出现了 ${action.count} 次${failureSuffix}`);
      }
      lines.push("");
    } else if (summary.actionEvents === 0) {
      lines.push(
        "🫶 今天还没有触发值得单独提醒的 agent 动作。",
        "   TraceRoot 目前主要在盯边界有没有重新变宽，以及新的风险信号有没有冒出来。",
        ""
      );
    }

    if (summary.attentionSubjects.length > 0) {
      lines.push("🧩 今天 agent 真正碰到的关键对象：");
      for (const subject of summary.attentionSubjects) {
        const prefix = severityIcon(subject.severity);
        lines.push(
          `- ${prefix} ${subject.subjectLabel}：被碰了 ${subject.count} 次（${subject.actions.slice(0, 2).join("、")}）`
        );
      }
      lines.push("");
    }

    if (summary.attentionActors.length > 0) {
      lines.push("🧭 今天这些 agent 最值得你看一眼：");
      for (const actor of summary.attentionActors) {
        const prefix = severityIcon(actor.severity);
        lines.push(
          `- ${prefix} ${actor.actorLabel}：出现了 ${actor.count} 次值得留意的动作（${actor.actions.slice(0, 2).join("、")}）`
        );
      }
      lines.push("");
    }

    if (summary.attentionTargets.length > 0) {
      lines.push("📍 今天最值得回头看的位置：");
      for (const target of summary.attentionTargets) {
        const prefix = severityIcon(target.severity);
        lines.push(
          `- ${prefix} ${target.targetLabel}：出现了 ${target.count} 次值得留意的动作（${target.actions.slice(0, 2).join("、")}）`
        );
      }
      lines.push("   如果你之后只想回看某一个位置的完整轨迹，可以直接运行：traceroot-audit logs <那个路径>");
      lines.push("");
    }

    if (summary.attentionSources.length > 0) {
      lines.push("📬 今天最值得留意的触发入口：");
      for (const source of summary.attentionSources) {
        const prefix = severityIcon(source.severity);
        lines.push(
          `- ${prefix} ${source.sourceLabel}：触发了 ${source.count} 次值得留意的动作（${source.actions.slice(0, 2).join("、")}）`
        );
      }
      lines.push("");
    }

    lines.push("📘 最近发生的事：", "");

    runtime.io.stdout(`${lines.join("\n")}\n`);
  }

  if (eventsAscending.length === 0) {
    runtime.io.stdout(
      "🟢 这条时间线里还没有符合条件的审计记录。\n先运行 `traceroot-audit doctor --watch`，TraceRoot 才会开始陪跑并留下本地审计轨迹。\n"
    );
    return [];
  }

  for (const entry of timelineEntries) {
    runtime.io.stdout(`${renderTimelineEntry(entry, approvedIntentIds).join("\n")}\n`);
  }

  const shouldMarkReviewed =
    !options.severity &&
    !(typeof options.limit === "number" && totalMatchingEvents > options.limit);

  if (shouldMarkReviewed) {
    await saveAuditReviewState({
      scope: options.hostScope ? "host" : "target",
      target: options.hostScope ? null : options.target
    });
  }

  return eventsAscending;
}

export function registerLogsCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("logs")
    .description("Review the local runtime audit timeline that TraceRoot recorded on this machine.")
    .argument("[target]", "target path to filter logs for")
    .option("--target <path>", "same as the positional target filter")
    .addOption(
      new Option("--severity <severity>", "show only one severity level").choices([
        "safe",
        "risky",
        "high-risk",
        "critical"
      ])
    )
    .option("--today", "show only events from today")
    .addOption(
      new Option("--limit <count>", "number of recent events to show")
        .default("20")
    )
    .option("--tail", "keep polling and print new events as they arrive")
    .option("--all", "show the full machine-wide audit timeline instead of resuming the last doctor target")
    .addOption(
      new Option("--interval <seconds>", "when used with --tail, seconds between refreshes")
        .default("2")
    )
    .action(async (targetArg: string | undefined, options: LogsOptions) => {
      let target = normalizeTargetFilter(options.target ?? targetArg);
      let hostScope = false;
      if (!target && !options.all) {
        const recentContext = await loadRecentDoctorContext();
        if (recentContext?.scope === "host") {
          hostScope = true;
          runtime.io.stdout("🧠 TraceRoot 先帮你继续看上次整机陪跑的时间线。\n\n");
        } else {
          const recentTarget = recentContext?.scope === "target"
            ? recentContext.targetPath
            : await loadRecentDoctorTarget();
          if (recentTarget) {
            target = normalizeTargetFilter(recentTarget);
            runtime.io.stdout(
              `🧠 TraceRoot 先帮你继续看上次陪跑的 target：${recentTargetLabel(recentTarget)}。\n\n`
            );
          }
        }
      }
      const limit = Number.parseInt(options.limit, 10);
      const intervalSeconds = Number.parseInt(options.interval, 10);
      const tailHardeningProfileResult =
        target && !hostScope
          ? await loadHardeningProfile(target)
          : { profile: null, profilePath: null };
      const tailApprovedIntentIds =
        tailHardeningProfileResult.profile?.selectedIntents.map(
          (intent) => intent.id as HardeningIntentId
        ) ?? [];

      if (!Number.isInteger(limit) || limit <= 0) {
        runtime.io.stderr("`--limit` must be a positive integer.\n");
        runtime.exitCode = 1;
        return;
      }

      if (!Number.isInteger(intervalSeconds) || intervalSeconds <= 0) {
        runtime.io.stderr("`--interval` must be a positive integer number of seconds.\n");
        runtime.exitCode = 1;
        return;
      }

      const initialEvents = await printLogs(runtime, {
        target,
        severity: options.severity,
        today: options.today,
        limit,
        hostScope
      });

      if (!options.tail) {
        return;
      }

      runtime.io.stdout(
        `\n💓 实时查看已开启。TraceRoot 每 ${intervalSeconds}s 会刷新一次新的审计事件，按 Ctrl+C 可以停止。\n\n`
      );

      const seen = new Set(initialEvents.map(eventKey));

      while (true) {
        await sleep(intervalSeconds * 1000);
        const result = await readAuditEvents({
          target,
          severity: options.severity,
          today: options.today
        });
        const nextEvents = [...result.events]
          .reverse()
          .filter((event) => !seen.has(eventKey(event)));

        for (const event of nextEvents) {
          runtime.io.stdout(
            `${renderTimelineEntry({ primary: event, related: [] }, tailApprovedIntentIds).join("\n")}\n`
          );
          seen.add(eventKey(event));
        }
      }
    });
}
