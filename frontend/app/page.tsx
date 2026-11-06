"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";

import {
  MockChip,
  PriorityBadge,
  SeverityBadge,
  StatusChip,
  VerdictBadge,
} from "@/components/badges";
import { EmptyState, ErrorBanner, LoadingRows, Panel } from "@/components/states";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError, listAlerts, listRuns, startInvestigation } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { AlertRow, RunStatus, RunSummary } from "@/lib/types";

const PRIORITY_RANK = { P1: 0, P2: 1, P3: 2, P4: 3 };
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const ACTIVE: RunStatus[] = ["queued", "running"];
const REFRESH_MS = 2000;

function queueOrder(a: AlertRow, b: AlertRow): number {
  const priority = (row: AlertRow) => (row.priority ? PRIORITY_RANK[row.priority] : 4);
  return (
    priority(a) - priority(b) ||
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    a.alert_id.localeCompare(b.alert_id)
  );
}

export default function AlertQueuePage() {
  const router = useRouter();
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [nextAlerts, nextRuns] = await Promise.all([listAlerts(), listRuns()]);
      setAlerts(nextAlerts);
      setRuns(nextRuns);
      setError(null);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "The alert queue could not be loaded.");
    }
  }, []);

  const anyActive = useMemo(
    () => (alerts ?? []).some((row) => ACTIVE.includes(row.status)),
    [alerts],
  );

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    const refresh = anyActive ? window.setInterval(load, REFRESH_MS) : null;
    return () => {
      window.clearTimeout(first);
      if (refresh !== null) window.clearInterval(refresh);
    };
  }, [load, anyActive]);

  async function investigate(alertId: string) {
    setStarting(alertId);
    try {
      const { investigation_id } = await startInvestigation(alertId);
      router.push(`/investigations/${investigation_id}?watch=1`);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "The investigation could not be started.");
      setStarting(null);
    }
  }

  const ordered = useMemo(() => [...(alerts ?? [])].sort(queueOrder), [alerts]);

  return (
    <div className="space-y-3">
      {error && <ErrorBanner message={error} onRetry={load} />}
      <Panel title="Alert queue" aside={alerts && <Count value={alerts.length} />}>
        {alerts === null && !error && <LoadingRows />}
        {alerts?.length === 0 && (
          <EmptyState title="No alerts loaded." hint="Run python tasks.py seed, then refresh." />
        )}
        {ordered.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Priority</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Alert</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Time (UTC)</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {ordered.map((row) => (
                <TableRow key={row.alert_id}>
                  <TableCell>
                    <PriorityBadge priority={row.priority} />
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={row.severity} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">{row.alert_id}</TableCell>
                  <TableCell className="max-w-96 truncate" title={row.rule}>
                    {row.blocked ? <Hidden /> : row.rule}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {row.blocked ? <Hidden /> : row.host}
                  </TableCell>
                  <TableCell>{row.blocked ? <Hidden /> : (row.user ?? "-")}</TableCell>
                  <TableCell className="font-mono text-xs whitespace-nowrap">
                    {row.ts ? formatTime(row.ts) : <Hidden />}
                  </TableCell>
                  <TableCell>
                    <span className="flex items-center gap-1">
                      <StatusChip status={row.status} />
                      {row.mock && <MockChip />}
                    </span>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    {row.investigation_id && (
                      <Link
                        className={buttonVariants({ size: "xs", variant: "ghost" })}
                        href={`/investigations/${row.investigation_id}`}
                      >
                        Open
                      </Link>
                    )}
                    {!row.blocked && (
                      <Button
                        className="ml-1"
                        size="xs"
                        variant="outline"
                        disabled={starting !== null || ACTIVE.includes(row.status)}
                        onClick={() => investigate(row.alert_id)}
                      >
                        {row.investigation_id ? "Run again" : "Investigate"}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>

      <Panel title="Past investigations" aside={<Count value={runs.length} />}>
        {runs.length === 0 ? (
          <EmptyState
            title="No investigations yet."
            hint="Finished runs stay here, and can be reopened and replayed."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Started (UTC)</TableHead>
                <TableHead>Alert</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>Model</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Status</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((run) => (
                <TableRow key={run.investigation_id}>
                  <TableCell className="font-mono text-xs whitespace-nowrap">
                    {formatTime(run.created_at)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{run.alert_id}</TableCell>
                  <TableCell className="max-w-96 truncate" title={run.rule}>
                    {run.rule ?? "-"}
                  </TableCell>
                  <TableCell>{run.mock ? <MockChip /> : (run.model ?? "-")}</TableCell>
                  <TableCell>
                    {run.verdict ? <VerdictBadge verdict={run.verdict} /> : "-"}
                  </TableCell>
                  <TableCell>{run.risk_score ?? "-"}</TableCell>
                  <TableCell>
                    <StatusChip status={run.status} />
                  </TableCell>
                  <TableCell className="text-right">
                    <Link
                      className={buttonVariants({ size: "xs", variant: "ghost" })}
                      href={`/investigations/${run.investigation_id}`}
                    >
                      Open
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>
    </div>
  );
}

function Hidden() {
  return <span className="text-muted-foreground">hidden</span>;
}

function Count({ value }: { value: number }) {
  return <span className="text-xs text-muted-foreground">{value}</span>;
}
