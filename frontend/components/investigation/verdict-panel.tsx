import { VerdictBadge } from "@/components/badges";
import { Panel } from "@/components/states";
import { attackUrl } from "@/lib/format";
import type { AttackMapping, Investigation, RiskFactors, Verdict } from "@/lib/types";
import type { StreamState } from "@/lib/useInvestigationStream";

const ARC_RADIUS = 42;
const ARC_LENGTH = Math.PI * ARC_RADIUS;

// A semicircle. It stops at amber: red is kept for P1 and critical.
function RiskGauge({ score }: { score: number }) {
  const tone = score >= 60 ? "stroke-amber-400" : score >= 30 ? "stroke-sky-400" : "stroke-emerald-400";
  return (
    <svg viewBox="0 0 100 56" className="h-16 w-28 shrink-0" role="img" aria-label={`Risk ${score} of 100`}>
      <path
        d="M 8 50 A 42 42 0 0 1 92 50"
        fill="none"
        strokeWidth="8"
        className="stroke-muted"
      />
      <path
        d="M 8 50 A 42 42 0 0 1 92 50"
        fill="none"
        strokeWidth="8"
        className={tone}
        strokeDasharray={`${(Math.min(score, 100) / 100) * ARC_LENGTH} ${ARC_LENGTH}`}
      />
      <text x="50" y="47" textAnchor="middle" className="fill-foreground text-[20px] font-semibold">
        {score}
      </text>
    </svg>
  );
}

function RiskBreakdown({ risk }: { risk: RiskFactors }) {
  const rows: [string, string, number][] = [
    ["Verdict", `${risk.verdict}, ${risk.confidence.toFixed(2)}`, risk.verdict_points],
    ["Priority", risk.priority, risk.priority_points],
    [
      "Asset criticality",
      `${risk.criticality}${risk.criticality_assumed ? " (assumed)" : ""}`,
      risk.criticality_points,
    ],
    ["High-impact tactics", risk.high_impact_tactics.join(", ") || "none", risk.tactic_points],
  ];
  return (
    <table className="w-full text-xs">
      <tbody>
        {rows.map(([part, input, points]) => (
          <tr key={part}>
            <td className="py-0.5 pr-2 text-muted-foreground">{part}</td>
            <td className="py-0.5 pr-2">{input}</td>
            <td className="py-0.5 text-right">{points}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TechniqueChips({ mappings }: { mappings: Pick<AttackMapping, "technique_id">[] }) {
  if (mappings.length === 0) {
    return <p className="text-xs text-muted-foreground">No techniques mapped.</p>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {mappings.map((mapping) => {
        const full = mapping as Partial<AttackMapping>;
        return (
          <a
            key={mapping.technique_id}
            href={attackUrl(mapping.technique_id)}
            target="_blank"
            rel="noreferrer"
            title={full.rationale}
            className="rounded border px-1.5 py-px text-xs hover:border-primary hover:text-primary"
          >
            <span className="font-mono">{mapping.technique_id}</span>
            {full.name ? ` ${full.name}` : ""}
          </a>
        );
      })}
    </div>
  );
}

export function VerdictPanel({
  view,
  stream,
  streaming,
}: {
  view: Investigation;
  stream: StreamState;
  streaming: boolean;
}) {
  const verdict: Verdict | null | undefined = streaming ? stream.verdict?.verdict : view.verdict;
  const confidence = streaming ? stream.verdict?.confidence : view.confidence;
  const notes = (streaming ? stream.verdict?.notes : view.verdict_notes) ?? [];
  const mappings = streaming ? stream.mappings : (view.attack_mappings ?? []);
  const risk =
    !streaming && view.risk_factors?.score !== undefined ? (view.risk_factors as RiskFactors) : null;

  return (
    <Panel title="Verdict and risk">
      {verdict === undefined || verdict === null ? (
        <p className="text-muted-foreground">
          {streaming ? "Waiting for the verdict." : "This run has no verdict."}
        </p>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            {risk && <RiskGauge score={risk.score} />}
            <div className="min-w-0 space-y-1">
              <div className="flex items-center gap-2">
                <VerdictBadge verdict={verdict} />
                {confidence !== null && confidence !== undefined && (
                  <span className="text-xs text-muted-foreground">
                    confidence {confidence.toFixed(2)}
                  </span>
                )}
              </div>
              {!streaming && view.verdict_reasoning && (
                <p className="break-words">{view.verdict_reasoning}</p>
              )}
            </div>
          </div>
          {notes.map((note) => (
            <p key={note} className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs text-amber-200">
              Code rule: {note}
            </p>
          ))}
          {risk && <RiskBreakdown risk={risk} />}
        </div>
      )}
      <div className="mt-3 space-y-1.5 border-t pt-2">
        <h3 className="text-xs font-semibold text-muted-foreground">ATT&amp;CK techniques</h3>
        <TechniqueChips mappings={mappings} />
      </div>
      {!streaming && view.injection_line && (
        <p className="mt-3 border-t pt-2 text-xs text-muted-foreground">{view.injection_line}</p>
      )}
    </Panel>
  );
}
