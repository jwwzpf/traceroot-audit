import type { HardeningCurrentState, SecretExposure } from "./analysis";
import type { SavedHardeningProfile } from "./profile";
import type { SupportedCapability } from "./profiles";

export interface BoundaryViolation {
  code:
    | "unexpected-capabilities"
    | "public-exposure"
    | "missing-confirmation"
    | "secret-exposure";
  severity: "critical" | "high" | "medium";
  title: string;
  message: string;
  recommendation: string;
  fingerprint: string;
}

export interface BoundaryStatus {
  aligned: boolean;
  violations: BoundaryViolation[];
}

function formatCapabilityList(capabilities: SupportedCapability[]): string {
  return capabilities.join(", ");
}

function reviewSecretVariables(exposures: SecretExposure[]): string[] {
  return exposures
    .filter((entry) => entry.action === "review" || entry.action === "remove")
    .map((entry) => entry.variable)
    .sort();
}

export function evaluateBoundaryStatus(
  profile: SavedHardeningProfile,
  currentState: HardeningCurrentState
): BoundaryStatus {
  const violations: BoundaryViolation[] = [];
  const approvedCapabilities = new Set(profile.recommendedCapabilities);
  const unexpectedCapabilities = currentState.currentCapabilities.filter(
    (capability) => !approvedCapabilities.has(capability)
  );

  if (unexpectedCapabilities.length > 0) {
    const severity: BoundaryViolation["severity"] =
      unexpectedCapabilities.includes("shell") ||
      unexpectedCapabilities.includes("payments")
        ? "critical"
        : unexpectedCapabilities.includes("filesystem") ||
            unexpectedCapabilities.includes("browser")
          ? "high"
          : "medium";

    violations.push({
      code: "unexpected-capabilities",
      severity,
      title: "当前权限比你批准的更宽",
      message: `这个 runtime 现在仍然带着你刚才没有批准的能力：${formatCapabilityList(unexpectedCapabilities)}。`,
      recommendation: `如果当前工作流根本不需要这些能力，就把它们关掉或移出：${formatCapabilityList(unexpectedCapabilities)}。`,
      fingerprint: `unexpected-capabilities:${formatCapabilityList(unexpectedCapabilities)}`
    });
  }

  const expectsLocalhostOnly =
    profile.selectedPolicies?.exposureMode === "localhost-only" ||
    profile.recommendedManifest.safeguards?.includes("localhost_only_runtime") === true;
  if (expectsLocalhostOnly && currentState.publicExposureDetected) {
    violations.push({
      code: "public-exposure",
      severity: "critical",
      title: "这个 runtime 现在仍然可能被别的机器访问",
      message:
        "你批准的是“只在本机运行”，但当前配置看起来仍然能从局域网或其他机器打进来。",
      recommendation:
        "把 runtime 收回到 localhost，并移除不必要的对外端口或公开接口。",
      fingerprint: "public-exposure"
    });
  }

  const expectsConfirmation = profile.recommendedManifest.confirmation_required === true;
  const currentConfirmation = currentState.manifest?.confirmation_required;
  if (expectsConfirmation && currentConfirmation !== true) {
    violations.push({
      code: "missing-confirmation",
      severity: "high",
      title: "高风险动作还没有真正卡住确认步骤",
      message:
        "你批准的边界要求外发或副作用动作先确认，但当前 manifest 还没有把这个保护真正打开。",
      recommendation:
        "应用 TraceRoot 生成的 hardened manifest，或者在当前 manifest 里把 `confirmation_required` 打开。",
      fingerprint: "missing-confirmation"
    });
  }

  const unexpectedSecrets = reviewSecretVariables(currentState.secretExposure);
  if (unexpectedSecrets.length > 0) {
    const preview = unexpectedSecrets.slice(0, 4).join(", ");
    violations.push({
      code: "secret-exposure",
      severity: unexpectedSecrets.length >= 3 ? "high" : "medium",
      title: "还有一些和当前工作流无关的 secrets 仍然暴露着",
      message:
        unexpectedSecrets.length === 1
          ? `当前 runtime 仍然能看到一个和你刚批准的工作流无关的 secret：${preview}。`
          : `当前 runtime 仍然能看到 ${unexpectedSecrets.length} 个和你刚批准的工作流无关的 secrets：${preview}${unexpectedSecrets.length > 4 ? ", ..." : ""}。`,
      recommendation:
        "把和当前工作流无关的 secrets 挪出 runtime 环境变量，只留下真正需要的那几项。",
      fingerprint: `secret-exposure:${unexpectedSecrets.join(",")}`
    });
  }

  return {
    aligned: violations.length === 0,
    violations
  };
}

export interface BoundaryDiff {
  changed: boolean;
  newViolations: BoundaryViolation[];
  resolvedViolations: BoundaryViolation[];
}

export function diffBoundaryStatus(
  previous: BoundaryStatus,
  current: BoundaryStatus
): BoundaryDiff {
  const previousMap = new Map(
    previous.violations.map((violation) => [violation.fingerprint, violation])
  );
  const currentMap = new Map(
    current.violations.map((violation) => [violation.fingerprint, violation])
  );

  const newViolations = current.violations.filter(
    (violation) => !previousMap.has(violation.fingerprint)
  );
  const resolvedViolations = previous.violations.filter(
    (violation) => !currentMap.has(violation.fingerprint)
  );

  return {
    changed: newViolations.length > 0 || resolvedViolations.length > 0,
    newViolations,
    resolvedViolations
  };
}
