import path from "node:path";

import { describe, expect, it } from "vitest";

import { loadManifest } from "../src/manifest/loader";

describe("loadManifest", () => {
  it("loads a JSON manifest", async () => {
    const result = await loadManifest(path.resolve("examples/safe-skill"));

    expect(result.manifest?.name).toBe("safe-skill");
    expect(result.manifestPath).toBe("traceroot.manifest.json");
  });

  it("loads a YAML manifest", async () => {
    const result = await loadManifest(path.resolve("examples/exposed-runtime"));

    expect(result.manifest?.name).toBe("exposed-runtime");
    expect(result.manifestPath).toBe("traceroot.manifest.yaml");
  });
});
