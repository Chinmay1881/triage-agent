import { FindingStatusChip } from "@/components/badges";
import { EmptyState, Panel } from "@/components/states";
import type { Finding, Investigation } from "@/lib/types";
import type { StreamState } from "@/lib/useInvestigationStream";

const EVENT = /^evt_\d+$/;

function Citation({ citation, onOpen }: { citation: string; onOpen: (id: string) => void }) {
  if (!EVENT.test(citation)) {
    return (
      <span
        className="rounded bg-muted px-1.5 py-px font-mono text-xs text-muted-foreground"
        title="A tool result, not a single event"
      >
        {citation}
      </span>
    );
  }
  return (
    <button
      type="button"
      onClick={() => onOpen(citation)}
      className="rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-px font-mono text-xs text-sky-300 hover:border-sky-400 hover:bg-sky-500/20"
    >
      {citation}
    </button>
  );
}

export function FindingsPanel({
  view,
  stream,
  streaming,
  onOpenEvent,
}: {
  view: Investigation;
  stream: StreamState;
  streaming: boolean;
  onOpenEvent: (id: string) => void;
}) {
  const all: Finding[] = streaming ? stream.findings : (view.findings ?? []);
  // Disputed findings never reach the report, so they stay out of the list too.
  const shown = all.filter((f) => f.status !== "disputed");
  const disputed = all.length - shown.length;

  return (
    <Panel
      title="Findings"
      aside={<span className="text-xs text-muted-foreground">{shown.length}</span>}
    >
      {shown.length === 0 ? (
        <EmptyState
          title={streaming ? "No findings yet." : "No findings reached this report."}
          hint={streaming ? "They appear as the investigator records them." : undefined}
        />
      ) : (
        <ul className="divide-y">
          {shown.map((finding) => (
            <li key={finding.id} className="space-y-1.5 py-2 first:pt-0 last:pb-0">
              <div className="flex items-start gap-2">
                <span className="mt-px font-mono text-xs text-muted-foreground">{finding.id}</span>
                <p className="min-w-0 flex-1 break-words">{finding.claim}</p>
                <FindingStatusChip status={finding.status} />
              </div>
              <div className="flex flex-wrap gap-1 pl-6">
                {finding.citations.map((citation) => (
                  <Citation key={citation} citation={citation} onOpen={onOpenEvent} />
                ))}
              </div>
            </li>
          ))}
        </ul>
      )}
      {disputed > 0 && (
        <p className="mt-2 text-xs text-muted-foreground">
          {disputed} disputed finding{disputed === 1 ? "" : "s"} left out.
        </p>
      )}
    </Panel>
  );
}
