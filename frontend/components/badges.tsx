import { cn } from "@/lib/utils";
import type { Finding, Priority, RunStatus, Severity, Verdict } from "@/lib/types";

// Every status color lives here, so "red only for P1 and critical" holds in one place.
const CHIP = "inline-flex items-center whitespace-nowrap rounded border px-1.5 py-px text-xs";
const RED = "border-red-500/60 bg-red-500/15 text-red-300";
const AMBER = "border-amber-500/50 bg-amber-500/10 text-amber-300";
const BLUE = "border-sky-500/40 bg-sky-500/10 text-sky-300";
const GREEN = "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
const QUIET = "border-border bg-muted text-muted-foreground";

function Chip({ tone, children, title }: { tone: string; children: React.ReactNode; title?: string }) {
  return (
    <span className={cn(CHIP, tone)} title={title}>
      {children}
    </span>
  );
}

const PRIORITY_TONE: Record<Priority, string> = { P1: RED, P2: AMBER, P3: BLUE, P4: QUIET };
const SEVERITY_TONE: Record<Severity, string> = {
  critical: RED,
  high: AMBER,
  medium: BLUE,
  low: QUIET,
};

export function PriorityBadge({ priority }: { priority: Priority | null | undefined }) {
  if (!priority) return <span className="text-muted-foreground">-</span>;
  return <Chip tone={PRIORITY_TONE[priority]}>{priority}</Chip>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Chip tone={SEVERITY_TONE[severity]}>{severity}</Chip>;
}

const STATUS: Record<RunStatus, { label: string; tone: string }> = {
  new: { label: "new", tone: QUIET },
  blocked: { label: "blocked in dev", tone: QUIET },
  queued: { label: "queued", tone: BLUE },
  running: { label: "running", tone: BLUE },
  awaiting_decision: { label: "awaiting decision", tone: AMBER },
  decided: { label: "decided", tone: GREEN },
  failed: { label: "failed", tone: AMBER },
};

export function StatusChip({ status }: { status: RunStatus }) {
  const { label, tone } = STATUS[status];
  return <Chip tone={tone}>{label}</Chip>;
}

const FINDING_TONE: Record<NonNullable<Finding["status"]>, string> = {
  pending: QUIET,
  confirmed: GREEN,
  unreviewed: BLUE,
  disputed: AMBER,
};

export function FindingStatusChip({ status }: { status: Finding["status"] }) {
  return <Chip tone={FINDING_TONE[status ?? "pending"]}>{status ?? "pending"}</Chip>;
}

// A malicious verdict is amber, not red: red is kept for P1 and critical.
const VERDICT_TONE: Record<Verdict, string> = {
  malicious: AMBER,
  suspicious: BLUE,
  benign: GREEN,
};

export function VerdictBadge({ verdict }: { verdict: Verdict | null | undefined }) {
  if (!verdict) return <Chip tone={QUIET}>no verdict</Chip>;
  return <Chip tone={VERDICT_TONE[verdict]}>{verdict}</Chip>;
}

export function MockChip() {
  return <Chip tone={AMBER}>mock</Chip>;
}

export function InjectionBadge({ flags }: { flags: number }) {
  return (
    <Chip tone={flags ? AMBER : GREEN}>
      {flags ? `injection: ${flags} flag${flags === 1 ? "" : "s"}` : "injection: none flagged"}
    </Chip>
  );
}
