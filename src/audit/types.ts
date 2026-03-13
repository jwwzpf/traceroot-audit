export type AuditSeverity = "safe" | "risky" | "high-risk" | "critical";

export type AuditCategory =
  | "watch-started"
  | "watch-heartbeat"
  | "risk-change"
  | "finding-change"
  | "boundary-drift"
  | "surface-change"
  | "action-event";

export interface AuditEvent {
  timestamp: string;
  severity: AuditSeverity;
  category: AuditCategory;
  source: "doctor-watch" | "guard-watch" | "host-watch" | "tap-wrapper" | "runtime-feed";
  target: string | null;
  message: string;
  runtime?: string;
  surfaceKind?: "host" | "runtime" | "skill" | "project";
  action?: string;
  status?:
    | "started"
    | "observed"
    | "changed"
    | "resolved"
    | "attempted"
    | "succeeded"
    | "failed";
  evidence?: Record<string, unknown>;
  recommendation?: string;
}
