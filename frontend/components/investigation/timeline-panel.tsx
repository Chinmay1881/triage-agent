import { EmptyState, Panel } from "@/components/states";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatTime } from "@/lib/format";
import type { TimelineRow } from "@/lib/types";

function Anomaly({ percentile }: { percentile?: number }) {
  if (percentile === undefined) return null;
  return (
    <span className="flex items-center gap-1.5" title="Baseline percentile: how unusual, not how bad">
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-muted">
        <span
          className="block h-full bg-primary"
          style={{ width: `${Math.min(percentile, 100)}%` }}
        />
      </span>
      {percentile}
    </span>
  );
}

export function TimelinePanel({
  rows,
  onOpenEvent,
}: {
  rows: TimelineRow[];
  onOpenEvent: (id: string) => void;
}) {
  return (
    <Panel title="Key event timeline">
      {rows.length === 0 ? (
        <EmptyState title="No events yet." hint="The timeline is built when the report is written." />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time (UTC)</TableHead>
              <TableHead>Event</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Anomaly</TableHead>
              <TableHead>Process</TableHead>
              <TableHead>Parent</TableHead>
              <TableHead>Target</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.event_id}>
                <TableCell className="font-mono text-xs whitespace-nowrap">
                  {formatTime(row.ts)}
                </TableCell>
                <TableCell>
                  <button
                    type="button"
                    className="font-mono text-xs text-sky-300 hover:underline"
                    onClick={() => onOpenEvent(row.event_id)}
                  >
                    {row.event_id}
                  </button>
                </TableCell>
                <TableCell className="text-xs">{row.event_type}</TableCell>
                <TableCell className="text-xs">
                  <Anomaly percentile={row.anomaly} />
                </TableCell>
                <TableCell className="text-xs">{row.process}</TableCell>
                <TableCell className="text-xs">{row.parent}</TableCell>
                <TableCell className="max-w-md truncate font-mono text-xs" title={row.target ?? ""}>
                  {row.target}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}
