"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { InjectionBadge, PriorityBadge, SeverityBadge, StatusChip } from "@/components/badges";
import { AgentTrail } from "@/components/investigation/agent-trail";
import { DecisionPanel } from "@/components/investigation/decision-panel";
import { EventDrawer } from "@/components/investigation/event-drawer";
import { FindingsPanel } from "@/components/investigation/findings-panel";
import { ReportView } from "@/components/investigation/report-view";
import { TimelinePanel } from "@/components/investigation/timeline-panel";
import { VerdictPanel } from "@/components/investigation/verdict-panel";
import { ErrorBanner, LoadingRows, MockBanner } from "@/components/states";
import { Button } from "@/components/ui/button";
import { ApiError, getInvestigation } from "@/lib/api";
import type { Investigation } from "@/lib/types";
import { useInvestigationStream } from "@/lib/useInvestigationStream";

const ACTIVE = ["queued", "running"];

export default function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const [view, setView] = useState<Investigation | null>(null);
  const [error, setError] = useState<{ message: string; missing: boolean } | null>(null);
  const [openEvent, setOpenEvent] = useState<string | null>(null);
  const [reportVersion, setReportVersion] = useState(0);
  const [replaying, setReplaying] = useState(false);

  const load = useCallback(async () => {
    try {
      const next = await getInvestigation(id);
      setView(next);
      setError(null);
      setReportVersion((version) => version + 1);
      return next;
    } catch (exc) {
      const missing = exc instanceof ApiError && exc.status === 404;
      const message = exc instanceof ApiError ? exc.message : "The investigation failed to load.";
      setError({ message, missing });
      return null;
    }
  }, [id]);

  const { stream, start } = useInvestigationStream(id, load);

  // A run still going, including after a refresh mid-run, follows the stream from its first event.
  // So does one just started from the queue (?watch), since a scripted run can finish before this
  // page has loaded. Any other finished run shows its stored state at once, and Replay streams it.
  useEffect(() => {
    let cancelled = false;
    getInvestigation(id)
      .then((first) => {
        if (cancelled) return;
        setView(first);
        setReportVersion((version) => version + 1);
        const watch = new URLSearchParams(window.location.search).has("watch");
        if (watch) window.history.replaceState(null, "", window.location.pathname);
        if (watch || ACTIVE.includes(first.status)) start();
      })
      .catch((exc) => {
        if (cancelled) return;
        const missing = exc instanceof ApiError && exc.status === 404;
        const message = exc instanceof ApiError ? exc.message : "The investigation failed to load.";
        setError({ message, missing });
      });
    return () => {
      cancelled = true;
    };
  }, [id, start]);

  if (error && !view) {
    return (
      <div className="space-y-3">
        <ErrorBanner message={error.message} onRetry={error.missing ? undefined : load} />
        <Link className="text-primary underline" href="/">
          Back to the alert queue
        </Link>
      </div>
    );
  }
  if (!view) return <LoadingRows rows={10} />;

  const streaming = ["connecting", "live", "reconnecting"].includes(stream.connection);
  // While a stream plays, everything after the trail waits for it, even if the run is already done.
  const finished = !streaming && (view.status === "awaiting_decision" || view.status === "decided");
  const flags = view.injection_flags?.length ?? 0;
  const status = streaming && !replaying ? "running" : view.status;

  return (
    <div className="space-y-3">
      {view.mock && <MockBanner />}
      {error && <ErrorBanner message={error.message} onRetry={load} />}
      <header className="flex flex-wrap items-center gap-2">
        <h1 className="text-base font-semibold">{view.alert?.rule ?? view.rule ?? view.alert_id}</h1>
        <span className="font-mono text-xs text-muted-foreground">
          {view.alert_id} on {view.alert?.host ?? view.host ?? "-"}
          {view.alert?.user ? `, ${view.alert.user}` : ""}
        </span>
        {view.alert && <SeverityBadge severity={view.alert.severity} />}
        <PriorityBadge priority={view.triage?.priority} />
        <StatusChip status={status} />
        {finished && <InjectionBadge flags={flags} />}
        <span className="ml-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground">{view.model}</span>
          {(finished || replaying) && (
            <Button
              size="xs"
              variant="outline"
              disabled={streaming}
              onClick={() => {
                setReplaying(true);
                start();
              }}
            >
              {streaming ? "Replaying" : "Replay run"}
            </Button>
          )}
        </span>
      </header>

      {view.status === "failed" && (
        <ErrorBanner message={`This run failed: ${view.error ?? "no reason recorded"}.`} />
      )}
      {stream.error && <ErrorBanner message={`The run reported: ${stream.error}`} />}

      <div className="grid items-start gap-3 xl:grid-cols-[minmax(250px,3fr)_minmax(340px,5fr)_minmax(320px,4fr)] lg:grid-cols-[minmax(240px,1fr)_2fr]">
        <AgentTrail view={view} stream={stream} streaming={streaming} />
        <FindingsPanel
          view={view}
          stream={stream}
          streaming={streaming}
          onOpenEvent={setOpenEvent}
        />
        <div className="space-y-3 lg:col-span-2 xl:col-span-1">
          <VerdictPanel view={view} stream={stream} streaming={streaming} />
          <DecisionPanel view={view} open={finished} onDecided={load} />
        </div>
      </div>

      <TimelinePanel rows={streaming ? [] : (view.timeline ?? [])} onOpenEvent={setOpenEvent} />
      <ReportView id={id} alertId={view.alert_id} finished={finished} version={reportVersion} />
      <EventDrawer id={id} eventId={openEvent} onClose={() => setOpenEvent(null)} />
    </div>
  );
}
