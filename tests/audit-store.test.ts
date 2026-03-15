import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { appendAuditEvents, readAuditEvents, resolveAuditPaths } from "../src/audit/store";
import type { AuditEvent } from "../src/audit/types";

function createEvent(index: number): AuditEvent {
  return {
    timestamp: new Date(Date.UTC(2026, 2, 15, 10, 0, index)).toISOString(),
    severity: index % 2 === 0 ? "high-risk" : "risky",
    category: "action-event",
    source: "runtime-feed",
    target: "/tmp/openclaw",
    message: `Entry #${String(index).padStart(2, "0")}`,
    runtime: "openclaw",
    action: "send-email",
    status: "attempted"
  };
}

describe("audit store retention", () => {
  it("keeps only the newest events when the local audit file grows beyond the configured limit", async () => {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "traceroot-audit-store-"));

    try {
      const events = Array.from({ length: 12 }, (_, index) => createEvent(index + 1));

      await appendAuditEvents(events, tempHome, {
        maxBytes: 1600,
        trimToBytes: 1200,
        maxEvents: 12,
        trimToEvents: 4
      });

      const { events: storedEvents } = await readAuditEvents({
        homeDir: tempHome,
        limit: 20
      });
      const fileContent = await readFile(resolveAuditPaths(tempHome).eventsPath, "utf8");

      expect(storedEvents).toHaveLength(4);
      expect(storedEvents.map((event) => event.message)).toEqual([
        "Entry #12",
        "Entry #11",
        "Entry #10",
        "Entry #09"
      ]);
      expect(fileContent).not.toContain("Entry #01");
      expect(Buffer.byteLength(fileContent, "utf8")).toBeLessThanOrEqual(1200);
    } finally {
      await rm(tempHome, { recursive: true, force: true });
    }
  });
});
