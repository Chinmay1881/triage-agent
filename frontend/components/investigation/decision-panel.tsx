"use client";

import { useState } from "react";

import { ErrorBanner, Panel } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ApiError, decideAction, decideVerdict } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type {
  ActionDecision,
  Investigation,
  Recommendation,
  Verdict,
  VerdictDecision,
} from "@/lib/types";

const VERDICTS: Verdict[] = ["malicious", "suspicious", "benign"];

function errorText(exc: unknown): string {
  return exc instanceof ApiError ? exc.message : "The decision could not be recorded.";
}

function Decided({ title, note, ts }: { title: string; note: string; ts: string }) {
  return (
    <div>
      <p>
        <span className="font-medium">{title}</span>
        <span className="text-xs text-muted-foreground"> {formatTime(ts)} UTC</span>
      </p>
      {note && <p className="break-words text-xs text-muted-foreground">Note: {note}</p>}
    </div>
  );
}

function VerdictDecisionForm({ view, onDecided }: { view: Investigation; onDecided: () => void }) {
  const decided = view.decisions.find((d): d is VerdictDecision => d.kind === "verdict");
  const [mode, setMode] = useState<"agree" | "override">("agree");
  const [override, setOverride] = useState<Verdict | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (decided) {
    const title = decided.agreed
      ? `Agreed: ${decided.analyst_verdict}`
      : `Overrode ${decided.agent_verdict} to ${decided.analyst_verdict}`;
    return <Decided title={title} note={decided.note} ts={decided.ts} />;
  }

  const options = VERDICTS.filter((v) => v !== view.verdict);
  const chosen = mode === "override" ? (override ?? options[0]) : null;
  const needsNote = mode === "override" && !note.trim();

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await decideVerdict(view.investigation_id, chosen, note.trim());
      onDecided();
    } catch (exc) {
      setError(errorText(exc));
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1" role="radiogroup" aria-label="Verdict decision">
        <Button
          size="xs"
          role="radio"
          aria-checked={mode === "agree"}
          variant={mode === "agree" ? "secondary" : "ghost"}
          onClick={() => setMode("agree")}
        >
          Agree with {view.verdict}
        </Button>
        <Button
          size="xs"
          role="radio"
          aria-checked={mode === "override"}
          variant={mode === "override" ? "secondary" : "ghost"}
          onClick={() => setMode("override")}
        >
          Override
        </Button>
        {mode === "override" && (
          <select
            aria-label="Analyst verdict"
            className="h-6 rounded border bg-background px-1 text-xs"
            value={chosen ?? ""}
            onChange={(event) => setOverride(event.target.value as Verdict)}
          >
            {options.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        )}
      </div>
      <Textarea
        aria-label="Verdict note"
        className="min-h-12 text-xs"
        placeholder={mode === "override" ? "Why you are overriding (required)" : "Note (optional)"}
        value={note}
        onChange={(event) => setNote(event.target.value)}
      />
      {error && <ErrorBanner message={error} />}
      <Button size="xs" disabled={busy || needsNote} onClick={submit}>
        Record verdict decision
      </Button>
    </div>
  );
}

function ActionRow({
  view,
  action,
  onDecided,
}: {
  view: Investigation;
  action: Recommendation;
  onDecided: () => void;
}) {
  const decided = view.decisions.find(
    (d): d is ActionDecision => d.kind === "action" && d.action_id === action.id,
  );
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function decide(decision: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      await decideAction(view.investigation_id, action.id, decision, note.trim());
      onDecided();
    } catch (exc) {
      setError(errorText(exc));
      setBusy(false);
    }
  }

  return (
    <li className="space-y-1.5 py-2 first:pt-0 last:pb-0" data-action={action.id}>
      <p className="break-words">
        <span className="font-mono text-xs text-muted-foreground">{action.id}</span>{" "}
        <span className="font-medium">{action.action}</span> <span>{action.target}</span>
      </p>
      <p className="break-words text-xs text-muted-foreground">{action.reason}</p>
      {decided ? (
        <Decided
          title={decided.decision === "approve" ? "Approved" : "Rejected"}
          note={decided.note}
          ts={decided.ts}
        />
      ) : (
        <div className="flex items-center gap-1">
          <input
            aria-label={`Note for ${action.id}`}
            className="h-6 min-w-0 flex-1 rounded border bg-background px-1.5 text-xs"
            placeholder="Note (optional)"
            value={note}
            onChange={(event) => setNote(event.target.value)}
          />
          <Button size="xs" variant="outline" disabled={busy} onClick={() => decide("approve")}>
            Approve
          </Button>
          <Button size="xs" variant="ghost" disabled={busy} onClick={() => decide("reject")}>
            Reject
          </Button>
        </div>
      )}
      {error && <ErrorBanner message={error} />}
    </li>
  );
}

export function DecisionPanel({
  view,
  open,
  onDecided,
}: {
  view: Investigation;
  open: boolean;
  onDecided: () => void;
}) {
  if (!open) {
    return (
      <Panel title="Analyst decision">
        <p className="text-muted-foreground">Decisions open when the run has finished.</p>
      </Panel>
    );
  }
  const actions = view.recommendations ?? [];
  return (
    <Panel
      title="Analyst decision"
      aside={
        view.status === "decided" && (
          <span className="text-xs text-muted-foreground">complete, read-only</span>
        )
      }
    >
      <VerdictDecisionForm view={view} onDecided={onDecided} />
      <div className="mt-3 border-t pt-2">
        <h3 className="text-xs font-semibold text-muted-foreground">Recommended actions</h3>
        <p className="mb-2 text-xs text-muted-foreground">
          Approving records your decision. Nothing is executed.
        </p>
        {actions.length === 0 ? (
          <p className="text-muted-foreground">No actions were recommended.</p>
        ) : (
          <ul className="divide-y">
            {actions.map((action) => (
              <ActionRow key={action.id} view={view} action={action} onDecided={onDecided} />
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}
