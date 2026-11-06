/** "2026-10-06 09:55:12": always UTC, the time the logs and the report use. */
export function formatTime(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toISOString().slice(0, 19).replace("T", " ");
}

export function attackUrl(techniqueId: string): string {
  return `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/`;
}
