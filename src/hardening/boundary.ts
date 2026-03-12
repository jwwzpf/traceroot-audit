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
      title: "More power than approved",
      message: `This runtime currently exposes capabilities beyond the profile you approved: ${formatCapabilityList(unexpectedCapabilities)}.`,
      recommendation: `Remove or disable these capabilities unless this workflow truly needs them: ${formatCapabilityList(unexpectedCapabilities)}.`,
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
      title: "Public or network exposure is still possible",
      message:
        "The approved profile expects a localhost-only runtime, but the current target still looks reachable from other machines.",
      recommendation:
        "Bind the runtime to localhost only and remove unnecessary published ports or public interfaces.",
      fingerprint: "public-exposure"
    });
  }

  const expectsConfirmation = profile.recommendedManifest.confirmation_required === true;
  const currentConfirmation = currentState.manifest?.confirmation_required;
  if (expectsConfirmation && currentConfirmation !== true) {
    violations.push({
      code: "missing-confirmation",
      severity: "high",
      title: "Approval guard is not being enforced",
      message:
        "The approved profile requires explicit confirmation for side-effecting actions, but the active manifest does not currently enforce that guard.",
      recommendation:
        "Apply the hardened manifest or set `confirmation_required: true` in the active runtime manifest.",
      fingerprint: "missing-confirmation"
    });
  }

  const unexpectedSecrets = reviewSecretVariables(currentState.secretExposure);
  if (unexpectedSecrets.length > 0) {
    const preview = unexpectedSecrets.slice(0, 4).join(", ");
    violations.push({
      code: "secret-exposure",
      severity: unexpectedSecrets.length >= 3 ? "high" : "medium",
      title: "Unrelated secrets are still visible",
      message:
        unexpectedSecrets.length === 1
          ? `This runtime still exposes a secret outside the workflows you approved: ${preview}.`
          : `This runtime still exposes ${unexpectedSecrets.length} secrets outside the workflows you approved: ${preview}${unexpectedSecrets.length > 4 ? ", ..." : ""}.`,
      recommendation:
        "Move unrelated secrets out of the agent runtime env and keep only the credentials required for the approved workflows.",
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
