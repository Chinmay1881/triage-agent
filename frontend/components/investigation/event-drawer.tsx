"use client";

import { useEffect, useState } from "react";

import { ErrorBanner, LoadingRows } from "@/components/states";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ApiError, getRawEvent } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { RawEvent } from "@/lib/types";

type Loaded = { eventId: string; event: RawEvent | null; error: string | null };

export function EventDrawer({
  id,
  eventId,
  onClose,
}: {
  id: string;
  eventId: string | null;
  onClose: () => void;
}) {
  const [loaded, setLoaded] = useState<Loaded | null>(null);

  useEffect(() => {
    if (!eventId) return;
    let cancelled = false;
    getRawEvent(id, eventId)
      .then((event) => {
        if (!cancelled) setLoaded({ eventId, event, error: null });
      })
      .catch((exc) => {
        if (cancelled) return;
        const error = exc instanceof ApiError ? exc.message : "The event could not be loaded.";
        setLoaded({ eventId, event: null, error });
      });
    return () => {
      cancelled = true;
    };
  }, [id, eventId]);

  const current = loaded?.eventId === eventId ? loaded : null;
  const event = current?.event;

  return (
    <Sheet open={eventId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full gap-0 sm:max-w-xl">
        <SheetHeader className="border-b p-3">
          <SheetTitle className="font-mono text-sm">{eventId}</SheetTitle>
          {event && (
            <p className="text-xs text-muted-foreground">
              {event.event_type} on {event.host}, {formatTime(event.ts)} UTC
            </p>
          )}
        </SheetHeader>
        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3">
          {!current && <LoadingRows rows={5} />}
          {current?.error && <ErrorBanner message={current.error} />}
          {event?.injection_flagged && (
            <p className="rounded border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-amber-200">
              This event has an injection flag, so its log text isn&apos;t shown. {event.withheld}
            </p>
          )}
          {event?.decoded_cmdline && (
            <section>
              <h3 className="mb-1 text-xs font-semibold text-muted-foreground">
                Decoded command line
              </h3>
              <pre className="rounded bg-muted p-2 font-mono text-xs break-all whitespace-pre-wrap">
                {event.decoded_cmdline}
              </pre>
            </section>
          )}
          {event?.untrusted_log_data && (
            <section>
              <h3 className="mb-1 text-xs font-semibold text-muted-foreground">
                Raw event (untrusted log data)
              </h3>
              <pre className="rounded bg-muted p-2 font-mono text-xs break-all whitespace-pre-wrap">
                {JSON.stringify(event.untrusted_log_data, null, 2)}
              </pre>
            </section>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
