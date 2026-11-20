import type {
  AlertRow,
  Investigation,
  RawEvent,
  RunSummary,
  Scoreboard,
  Verdict,
} from "./types";

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
  }
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, { cache: "no-store", ...init });
  } catch {
    throw new ApiError(`Can't reach the API at ${API_URL}. Is python tasks.py dev-api running?`, null);
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = body?.detail;
    const message = typeof detail === "string" ? detail : detail?.[0]?.msg;
    throw new ApiError(message ?? `The API answered ${response.status}.`, response.status);
  }
  return response;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await request(path, init)).json() as Promise<T>;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return json<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export const getMeta = () => json<{ mock: boolean }>("/meta");
export const listAlerts = () => json<AlertRow[]>("/alerts");
export const listRuns = () => json<RunSummary[]>("/investigations");
export const getInvestigation = (id: string) => json<Investigation>(`/investigations/${id}`);
export const getRawEvent = (id: string, eventId: string) =>
  json<RawEvent>(`/investigations/${id}/raw-event/${eventId}`);

export const startInvestigation = (alertId: string) =>
  post<{ investigation_id: string }>("/investigations", { alert_id: alertId });

export const getReport = async (id: string) =>
  (await request(`/investigations/${id}/report.md`)).text();

export const decideAction = (
  id: string,
  actionId: string,
  decision: "approve" | "reject",
  note: string,
) => post(`/investigations/${id}/decision`, { action_id: actionId, decision, note });

export const decideVerdict = (id: string, override: Verdict | null, note: string) =>
  post(`/investigations/${id}/decision`, {
    verdict_decision: override ? "override" : "agree",
    ...(override ? { override_verdict: override } : {}),
    note,
  });

export async function getScoreboard(): Promise<Scoreboard | null> {
  const latest = await json<{ scoreboard?: { results: Scoreboard } }>(
    "/evals/latest?kind=scoreboard",
  );
  return latest.scoreboard?.results ?? null;
}

export const eventsUrl = (id: string) => `${API_URL}/investigations/${id}/events`;
