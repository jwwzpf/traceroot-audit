import { c001PublicRuntimeExposureRule } from "./C001_public_runtime_exposure";
import { c002RemoteFetchExecuteRule } from "./C002_remote_fetch_execute";
import { c003UntrustedShellNetworkFilesystemRule } from "./C003_untrusted_shell_network_filesystem";
import { c004DestructiveWithoutSafeguardsRule } from "./C004_destructive_without_safeguards";
import { h001MissingTrustMetadataRule } from "./H001_missing_trust_metadata";
import { h002OverbroadPermissionDeclarationRule } from "./H002_overbroad_permission_declaration";
import { h004HardcodedExternalEndpointsRule } from "./H004_hardcoded_external_endpoints";
import { h006MissingIdempotencyDeclarationRule } from "./H006_missing_idempotency_declaration";
import { h007MissingInterruptContractRule } from "./H007_missing_interrupt_contract";

import type { Rule } from "./types";

export const builtInRules: Rule[] = [
  c001PublicRuntimeExposureRule,
  c002RemoteFetchExecuteRule,
  c003UntrustedShellNetworkFilesystemRule,
  c004DestructiveWithoutSafeguardsRule,
  h001MissingTrustMetadataRule,
  h002OverbroadPermissionDeclarationRule,
  h004HardcodedExternalEndpointsRule,
  h006MissingIdempotencyDeclarationRule,
  h007MissingInterruptContractRule
];

export const builtInRuleMap = new Map(
  builtInRules.map((rule) => [rule.id, rule] as const)
);
