"use client";

import { useCallback, useEffect, useState } from "react";

import { EmptyState, ErrorBanner, LoadingRows, Panel } from "@/components/states";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError, getScoreboard } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { Scoreboard, ScoreboardConfig } from "@/lib/types";

const AGENT_ROWS: [string, string, string, string?][] = [
  ["Sentinel-Triage", "Priority ROC-AUC, attacks vs false alarms", "triage_priority_auc"],
  ["CyberIntel-Agent", "Share of indicators looked up", "intel_indicator_share"],
  ["CyberIntel-Agent", "known_bad found", "intel_known_bad_found", "intel_known_bad"],
  ["CyberIntel-Agent", "Runs with a known_bad indicator", "known_bad_runs"],
  ["Investigator-Agent", "Budget used (mean share)", "investigator_budget_share"],
  ["Investigator-Agent", "Findings per run", "investigator_findings"],
  ["Investigator-Agent", "Grounding: findings dropped", "investigator_findings_dropped"],
  ["Investigator-Agent", "Grounding: citations removed", "investigator_citations_removed"],
  ["Reviewer-Agent", "Disputes", "reviewer_disputes"],
  ["Reviewer-Agent", "Unreviewed", "reviewer_unreviewed"],
  ["Reviewer-Agent", "Reopens", "reviewer_reopens"],
  ["Report stage", "Validator refusals", "report_validator_refusals"],
  ["Report stage", "Actions dropped", "report_actions_dropped"],
  ["Report stage", "Downgrades to suspicious", "report_downgrades"],
];

const show = (value: number | null | undefined) => value ?? "n/a";

function configRows(c: ScoreboardConfig): [string, React.ReactNode][] {
  const s = c.system;
  const tokens = Object.entries(c.cost.tokens_by_model)
    .map(([model, count]) => `${model} ${count.toLocaleString("en-US")}`)
    .join(", ");
  return [
    ["Runs (failed)", `${c.runs} (${c.failed_runs})`],
    ["Passed", `${s.passed} of ${c.runs}`],
    ["Verdict accuracy", show(s.verdict_accuracy)],
    ["Missed attacks", `${s.missed_attacks} of ${s.attack_runs}`],
    ["False alarms", `${s.false_alarms} of ${s.benign_runs}`],
    ["Technique precision", show(s.technique_precision)],
    ["Technique recall", show(s.technique_recall)],
    ["Evidence recall", show(s.evidence_recall)],
    ["Injection resisted", `${s.injection_resisted} of ${s.injection_runs}`],
    ["Tokens counted", tokens || "none"],
    ["Tokens per run", show(c.cost.tokens_per_run)],
    ["LLM calls per run", show(c.cost.llm_calls_per_run)],
    ["Tool calls per run", show(c.cost.tool_calls_per_run)],
    ["Seconds per run", show(c.cost.seconds_per_run)],
  ];
}

function PassCell({ cell }: { cell?: { passed: number; runs: number; risk: number | null } }) {
  if (!cell) return <span className="text-muted-foreground">not run</span>;
  const pass = cell.passed === cell.runs;
  return (
    <span className="flex items-center gap-2">
      <span
        className={
          pass
            ? "rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 text-xs text-emerald-300"
            : "rounded border border-amber-500/50 bg-amber-500/10 px-1.5 text-xs text-amber-300"
        }
      >
        {pass ? "PASS" : "FAIL"}
        {cell.runs > 1 ? ` ${cell.passed}/${cell.runs}` : ""}
      </span>
      <span className="text-xs text-muted-foreground">risk {show(cell.risk)}</span>
    </span>
  );
}

export default function EvalsPage() {
  const [board, setBoard] = useState<Scoreboard | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setBoard(await getScoreboard());
      setError(null);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "The scoreboard could not be loaded.");
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    return () => window.clearTimeout(first);
  }, [load]);

  if (error) return <ErrorBanner message={error} onRetry={load} />;
  if (board === undefined) return <LoadingRows rows={10} />;
  if (board === null || Object.keys(board.configs).length === 0) {
    return (
      <EmptyState
        title="No eval results yet."
        hint="Run evals/run.py, then evals/report.py, and refresh."
      />
    );
  }

  const names = Object.keys(board.configs);
  const columns = [...new Set(Object.values(board.grid).flatMap((row) => Object.keys(row)))].sort();

  return (
    <div className="space-y-3">
      {board.mock && (
        <div
          role="status"
          className="rounded border border-amber-500/60 bg-amber-500/15 px-3 py-1.5 text-amber-200"
        >
          <strong>SCRIPTED MODEL.</strong> These runs used a mock that follows a fixed rule, with no
          Groq call. They show that the harness works, and say nothing about how good the agent is.
          Token counts are estimates of input size.
        </div>
      )}
      <p className="text-xs text-muted-foreground">Generated {formatTime(board.generated_at)} UTC.</p>

      <div className="grid items-start gap-3 md:grid-cols-2">
        {names.map((name) => (
          <Panel key={name} title={name}>
            <Table>
              <TableBody>
                {configRows(board.configs[name]).map(([metric, value]) => (
                  <TableRow key={metric}>
                    <TableCell className="text-muted-foreground">{metric}</TableCell>
                    <TableCell className="whitespace-normal">{value}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>
        ))}
      </div>

      <Panel title="Per scenario">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Scenario</TableHead>
              {columns.map((column) => (
                <TableHead key={column}>{column}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {Object.entries(board.grid).map(([scenario, row]) => (
              <TableRow key={scenario}>
                <TableCell className="font-mono text-xs">{scenario}</TableCell>
                {columns.map((column) => (
                  <TableCell key={column}>
                    <PassCell cell={row[column]} />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>

      <Panel title="Per agent">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Agent</TableHead>
              <TableHead>Metric</TableHead>
              {names.map((name) => (
                <TableHead key={name}>{name}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {AGENT_ROWS.map(([agent, metric, key, whole]) => (
              <TableRow key={key}>
                <TableCell>{agent}</TableCell>
                <TableCell className="text-muted-foreground">{metric}</TableCell>
                {names.map((name) => {
                  const values = board.configs[name].agents;
                  return (
                    <TableCell key={name}>
                      {show(values[key])}
                      {whole ? ` of ${show(values[whole])}` : ""}
                    </TableCell>
                  );
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>

      <Panel title="Notes" aside={<span className="text-xs text-muted-foreground">{board.notes.length}</span>}>
        {board.notes.length === 0 ? (
          <p className="text-muted-foreground">No failures.</p>
        ) : (
          <ul className="space-y-1 text-xs">
            {board.notes.map((note) => (
              <li key={note} className="break-words">
                {note}
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
