import { appendFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  createRuntimeFeedCursor,
  readNewRuntimeFeedEvents,
  type RuntimeEventFeed
} from "../src/audit/feeds";

function createFeed(rootDir: string, absolutePath: string): RuntimeEventFeed {
  return {
    absolutePath,
    displayPath: absolutePath,
    rootDir,
    kind: "generic-jsonl"
  };
}

describe("runtime feed cursor", () => {
  it("buffers an unfinished line and only emits the action after the line becomes complete", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-feed-cursor-"));

    try {
      const feedPath = path.join(tempDir, "runtime-events.jsonl");
      const feed = createFeed(tempDir, feedPath);
      await writeFile(feedPath, "", "utf8");

      const cursor = await createRuntimeFeedCursor([feed]);

      await appendFile(
        feedPath,
        '{"event":{"type":"send-email","status":"attempted","runtime":"openclaw","target":"mailer.ts","message":"Agent is attempting to send an external email."}}',
        "utf8"
      );

      const firstRead = await readNewRuntimeFeedEvents({
        feeds: [feed],
        cursor,
        targetRoot: tempDir
      });

      expect(firstRead).toHaveLength(0);

      await appendFile(
        feedPath,
        '\n{"event":{"type":"delete-files","status":"attempted","runtime":"openclaw","target":"cleanup.ts","message":"Agent is attempting to delete files."}}\n',
        "utf8"
      );

      const secondRead = await readNewRuntimeFeedEvents({
        feeds: [feed],
        cursor,
        targetRoot: tempDir
      });

      expect(secondRead).toHaveLength(2);
      expect(secondRead[0]?.action).toBe("send-email");
      expect(secondRead[1]?.action).toBe("delete-files");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("recovers cleanly when a runtime feed is truncated and starts again", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "traceroot-feed-rotation-"));

    try {
      const feedPath = path.join(tempDir, "runtime-events.jsonl");
      const feed = createFeed(tempDir, feedPath);
      await writeFile(feedPath, "", "utf8");

      const cursor = await createRuntimeFeedCursor([feed]);

      await appendFile(
        feedPath,
        '{"event":{"type":"send-email","status":"attempted","runtime":"openclaw","target":"mailer.ts","message":"Agent is attempting to send an external email."}}\n',
        "utf8"
      );

      const firstRead = await readNewRuntimeFeedEvents({
        feeds: [feed],
        cursor,
        targetRoot: tempDir
      });

      expect(firstRead).toHaveLength(1);
      expect(firstRead[0]?.action).toBe("send-email");

      await writeFile(
        feedPath,
        '{"event":{"type":"delete-files","status":"attempted","runtime":"openclaw","target":"cleanup.ts","message":"Agent is attempting to delete files."}}\n',
        "utf8"
      );

      const secondRead = await readNewRuntimeFeedEvents({
        feeds: [feed],
        cursor,
        targetRoot: tempDir
      });

      expect(secondRead).toHaveLength(1);
      expect(secondRead[0]?.action).toBe("delete-files");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
