"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { eventsUrl } from "./api";
import type { AttackMapping, Finding, StageRow, Verdict } from "./types";

export const STAGES = [
  "Sentinel-Triage",
  "CyberIntel-Agent",
  "Investigator-Agent",
  "Reviewer-Agent",
  "Report & Human Review",
];

const EVENT_KINDS = [
  "handoff",
  "stage_done",
  "finding_added",
  "mapping_checked",
  "verdict",
  "report_ready",
  "error",
  "done",
] as const;

// Long enough to see each stage tick in when a scripted run finishes in a second or two.
const STAGE_PACE_MS = 450;
const RECONNECT_MS = 3000;

export type Connection = "idle" | "connecting" | "live" | "reconnecting" | "finished";

export interface StreamState {
  connection: Connection;
  active: string | null;
  stages: Record<string, StageRow>;
  findings: Finding[];
  mappings: Pick<AttackMapping, "technique_id">[];
  verdict: { verdict: Verdict | null; confidence: number | null; notes: string[] } | null;
  error: string | null;
}

const EMPTY: StreamState = {
  connection: "idle",
  active: null,
  stages: {},
  findings: [],
  mappings: [],
  verdict: null,
  error: null,
};

interface StreamEvent {
  seq: number;
  kind: (typeof EVENT_KINDS)[number];
  data: unknown;
}

function apply(state: StreamState, event: StreamEvent): StreamState {
  const { kind, data } = event;
  switch (kind) {
    case "handoff": {
      const { to } = data as { to: string };
      return { ...state, active: STAGES.includes(to) ? to : null };
    }
    case "stage_done": {
      const row = data as StageRow;
      return { ...state, stages: { ...state.stages, [row.stage]: row } };
    }
    case "finding_added":
      return { ...state, findings: [...state.findings, data as Finding] };
    case "mapping_checked": {
      const { techniques } = data as { techniques: string[] };
      return { ...state, mappings: techniques.map((technique_id) => ({ technique_id })) };
    }
    case "verdict":
      return { ...state, verdict: data as StreamState["verdict"] };
    case "error":
      return { ...state, error: (data as { message: string }).message };
    default:
      return state;
  }
}

/**
 * Follows a run over SSE. EventSource sends Last-Event-ID itself when it reconnects, so a dropped
 * stream resumes in place. If the browser gives up (the API restarted), or the page was refreshed,
 * a new connection replays from the start, and events already seen are ignored by seq. Stored
 * events make a finished run replayable the same way.
 */
export function useInvestigationStream(id: string, onDone: () => void) {
  const [state, setState] = useState<StreamState>(EMPTY);
  const source = useRef<EventSource | null>(null);
  const retry = useRef<number | null>(null);
  const timer = useRef<number | null>(null);
  const queue = useRef<StreamEvent[]>([]);
  const lastSeq = useRef(0);
  const closed = useRef(false);
  const notify = useRef(onDone);

  useEffect(() => {
    notify.current = onDone;
  }, [onDone]);

  const stop = useCallback(() => {
    source.current?.close();
    source.current = null;
    if (retry.current !== null) window.clearTimeout(retry.current);
    if (timer.current !== null) window.clearInterval(timer.current);
    retry.current = null;
    timer.current = null;
  }, []);

  // One tick shows everything up to and including the next finished stage.
  const drain = useCallback(() => {
    const events = queue.current;
    if (events.length === 0) return;
    const stageAt = events.findIndex((e) => e.kind === "stage_done");
    const batch = events.splice(0, stageAt === -1 ? events.length : stageAt + 1);
    setState((current) => batch.reduce(apply, current));
    if (batch.some((e) => e.kind === "done")) {
      stop();
      setState((current) => ({ ...current, connection: "finished", active: null }));
      notify.current();
    }
  }, [stop]);

  const connect = useCallback(function open() {
    source.current?.close();
    const es = new EventSource(eventsUrl(id));
    source.current = es;
    es.onopen = () => setState((current) => ({ ...current, connection: "live" }));
    es.onerror = () => {
      setState((current) => ({ ...current, connection: "reconnecting" }));
      if (es.readyState === EventSource.CLOSED && !closed.current) {
        retry.current = window.setTimeout(open, RECONNECT_MS);
      }
    };
    for (const kind of EVENT_KINDS) {
      es.addEventListener(kind, (message: MessageEvent<string>) => {
        // A dropped connection also fires "error", as a plain event with no data: onerror has it.
        if (typeof message.data !== "string") return;
        const seq = Number(message.lastEventId);
        if (seq <= lastSeq.current) return;
        lastSeq.current = seq;
        queue.current.push({ seq, kind, data: JSON.parse(message.data) });
        // The terminal event closes the connection here, or the browser would reconnect.
        if (kind === "done") {
          closed.current = true;
          es.close();
        }
      });
    }
  }, [id]);

  const start = useCallback(() => {
    stop();
    queue.current = [];
    lastSeq.current = 0;
    closed.current = false;
    setState({ ...EMPTY, connection: "connecting", active: STAGES[0] });
    connect();
    timer.current = window.setInterval(drain, STAGE_PACE_MS);
  }, [connect, drain, stop]);

  useEffect(() => stop, [stop]);

  return { stream: state, start };
}
