import { Check, Circle, LoaderCircle } from "lucide-react";

import { Panel } from "@/components/states";
import type { Investigation, StageRow } from "@/lib/types";
import { STAGES, type StreamState } from "@/lib/useInvestigationStream";

const CONNECTION_LABEL: Record<string, string> = {
  connecting: "connecting",
  live: "live",
  reconnecting: "reconnecting",
};

export function AgentTrail({
  view,
  stream,
  streaming,
}: {
  view: Investigation;
  stream: StreamState;
  streaming: boolean;
}) {
  // While a stream runs its rows tick in; otherwise the stored trail has the final numbers.
  const stored = Object.fromEntries((view.agent_trail ?? []).map((row) => [row.stage, row]));
  const rows: Record<string, StageRow> = streaming ? stream.stages : { ...stored, ...stream.stages };
  const final = streaming ? {} : stored;

  return (
    <Panel
      title="Agent trail"
      aside={
        streaming && (
          <span
            className={
              stream.connection === "reconnecting"
                ? "text-xs text-amber-300"
                : "text-xs text-muted-foreground"
            }
          >
            {CONNECTION_LABEL[stream.connection]}
          </span>
        )
      }
    >
      <ol className="space-y-3">
        {STAGES.map((stage) => {
          const row = final[stage] ?? rows[stage];
          const active = streaming && stream.active === stage && !stream.stages[stage];
          return (
            <li key={stage} className="flex gap-2" data-stage={stage} data-done={Boolean(row)}>
              <span className="mt-0.5 shrink-0">
                {row ? (
                  <Check className="size-3.5 text-emerald-400" aria-label="done" />
                ) : active ? (
                  <LoaderCircle className="size-3.5 animate-spin text-sky-300" aria-label="running" />
                ) : (
                  <Circle className="size-3.5 text-muted-foreground/50" aria-label="waiting" />
                )}
              </span>
              <div className="min-w-0">
                <p className={row || active ? "font-medium" : "text-muted-foreground"}>{stage}</p>
                {row && (
                  <>
                    <p className="text-foreground/90">{row.output}</p>
                    <p className="text-xs text-muted-foreground">
                      {row.models !== "none" && `${row.models}, `}
                      {row.llm_calls} LLM, {row.tool_calls} tools, {row.duration}
                    </p>
                  </>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}
