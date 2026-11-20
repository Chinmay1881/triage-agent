"use client";

import { useEffect, useState } from "react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { EmptyState, ErrorBanner, LoadingRows, Panel } from "@/components/states";
import { Button } from "@/components/ui/button";
import { ApiError, getReport } from "@/lib/api";

const ATTACK_SITE = "https://attack.mitre.org/";

// The report holds log text, which could carry Markdown of its own. react-markdown renders no raw
// HTML, and these keep the rest inert: only our own ATT&CK links are links, and images never load.
const SAFE: Components = {
  a: ({ href, children }) =>
    href?.startsWith(ATTACK_SITE) ? (
      <a href={href} target="_blank" rel="noreferrer">
        {children}
      </a>
    ) : (
      <span>{children}</span>
    ),
  img: ({ alt }) => <span>{alt}</span>,
};

type Loaded = { version: number; text: string | null; error: string | null };

export function ReportView({
  id,
  alertId,
  finished,
  version,
}: {
  id: string;
  alertId: string;
  finished: boolean;
  version: number;
}) {
  const [loaded, setLoaded] = useState<Loaded | null>(null);

  useEffect(() => {
    if (!finished) return;
    let cancelled = false;
    getReport(id)
      .then((text) => {
        if (!cancelled) setLoaded({ version, text, error: null });
      })
      .catch((exc) => {
        if (cancelled) return;
        const error = exc instanceof ApiError ? exc.message : "The report could not be loaded.";
        setLoaded((current) => ({ version, text: current?.text ?? null, error }));
      });
    return () => {
      cancelled = true;
    };
  }, [id, finished, version]);

  function download() {
    if (!loaded?.text) return;
    const url = URL.createObjectURL(new Blob([loaded.text], { type: "text/markdown" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${alertId}_report.md`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Panel
      title="Report"
      aside={
        <Button size="xs" variant="outline" disabled={!loaded?.text} onClick={download}>
          Download Markdown
        </Button>
      }
    >
      {!finished && (
        <EmptyState title="No report yet." hint="It is written when the run finishes." />
      )}
      {finished && !loaded && <LoadingRows />}
      {loaded?.error && <ErrorBanner message={loaded.error} />}
      {finished && loaded?.text && (
        <article className="report" data-testid="report">
          <Markdown remarkPlugins={[remarkGfm]} components={SAFE}>
            {loaded.text}
          </Markdown>
        </article>
      )}
    </Panel>
  );
}
