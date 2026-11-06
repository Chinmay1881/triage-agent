// What the API returns (backend/app/api/routes.py). Log-derived strings are untrusted: render them
// as text, never as HTML.

export type Priority = "P1" | "P2" | "P3" | "P4";
export type Severity = "critical" | "high" | "medium" | "low";
export type Verdict = "malicious" | "suspicious" | "benign";
export type RunStatus =
  | "new"
  | "blocked"
  | "queued"
  | "running"
  | "awaiting_decision"
  | "decided"
  | "failed";

export interface AlertRow {
  alert_id: string;
  severity: Severity;
  status: RunStatus;
  blocked: boolean;
  priority: Priority | null;
  investigation_id: string | null;
  mock: boolean;
  // A blocked alert has none of these.
  rule?: string;
  host?: string;
  user?: string | null;
  ts?: string;
}

export interface RunSummary {
  investigation_id: string;
  alert_id: string;
  rule?: string;
  host?: string;
  status: RunStatus;
  mock?: boolean;
  model?: string;
  priority?: Priority;
  verdict?: Verdict | null;
  risk_score?: number | null;
  created_at: string;
}

export interface StageRow {
  stage: string;
  models: string;
  llm_calls: number;
  tool_calls: number;
  duration: string;
  output: string;
}

export interface Finding {
  id: string;
  claim: string;
  kind: "observation" | "absence";
  status?: "pending" | "confirmed" | "unreviewed" | "disputed";
  dispute_reason?: string | null;
  citations: string[];
  reportable?: boolean;
}

export interface AttackMapping {
  technique_id: string;
  name: string;
  tactics: string[];
  event_ids: string[];
  rationale: string;
}

export interface Recommendation {
  id: string;
  action: string;
  target: string;
  reason: string;
  requires_approval: true;
}

export interface RiskFactors {
  score: number;
  verdict: string;
  confidence: number;
  verdict_points: number;
  priority: string;
  priority_points: number;
  criticality: number;
  criticality_assumed: boolean;
  criticality_points: number;
  high_impact_tactics: string[];
  tactic_points: number;
  formula: string;
}

export interface TimelineRow {
  event_id: string;
  ts: string;
  event_type: string;
  process?: string | null;
  parent?: string | null;
  target?: string | null;
  anomaly?: number;
}

export interface ActionDecision {
  kind: "action";
  action_id: string;
  decision: "approve" | "reject";
  note: string;
  ts: string;
}

export interface VerdictDecision {
  kind: "verdict";
  verdict_decision: "agree" | "override";
  agent_verdict: Verdict;
  analyst_verdict: Verdict;
  agreed: boolean;
  note: string;
  ts: string;
}

export type Decision = ActionDecision | VerdictDecision;

export interface Investigation {
  investigation_id: string;
  alert_id: string;
  rule?: string | null;
  host?: string | null;
  status: RunStatus;
  mock?: boolean | null;
  model?: string | null;
  error?: string | null;
  created_at?: string;
  finished_at?: string | null;
  seconds?: number | null;
  decisions: Decision[];
  // Present once the run has finished.
  alert?: { rule: string; host: string; user: string | null; severity: Severity; ts: string };
  triage?: { priority: Priority; category: string; reason: string } | null;
  findings?: Finding[];
  agent_trail?: StageRow[];
  injection_flags?: { event_id: string | null; method: "regex" | "classifier" }[];
  texts_scanned?: number;
  injection_line?: string;
  attack_mappings?: AttackMapping[];
  verdict_proposed?: Verdict | null;
  verdict?: Verdict | null;
  confidence?: number | null;
  verdict_reasoning?: string;
  verdict_notes?: string[];
  risk_score?: number | null;
  risk_factors?: Partial<RiskFactors>;
  recommendations?: Recommendation[];
  timeline?: TimelineRow[];
}

export interface RawEvent {
  event_id: string;
  ts: string;
  host: string;
  user: string | null;
  event_type: string;
  injection_flagged: boolean;
  withheld?: string;
  untrusted_log_data?: Record<string, unknown>;
  decoded_cmdline?: string | null;
}

export interface ScoreboardConfig {
  runs: number;
  failed_runs: number;
  commits: string[];
  system: {
    passed: number;
    verdict_accuracy: number | null;
    missed_attacks: number;
    attack_runs: number;
    false_alarms: number;
    benign_runs: number;
    technique_precision: number | null;
    technique_recall: number | null;
    evidence_recall: number | null;
    injection_resisted: number;
    injection_runs: number;
  };
  agents: Record<string, number | null>;
  cost: {
    tokens_by_model: Record<string, number>;
    tokens_per_run: number | null;
    llm_calls_per_run: number | null;
    tool_calls_per_run: number | null;
    seconds_per_run: number | null;
  };
}

export interface Scoreboard {
  generated_at: string;
  mock: boolean;
  banner: string | null;
  configs: Record<string, ScoreboardConfig>;
  grid: Record<string, Record<string, { passed: number; runs: number; risk: number | null }>>;
  notes: string[];
}
