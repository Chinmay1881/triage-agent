import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex items-center gap-3 rounded border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-amber-200"
    >
      <span className="min-w-0 flex-1">{message}</span>
      {onRetry && (
        <Button size="xs" variant="outline" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="rounded border border-dashed px-4 py-6 text-center">
      <p>{title}</p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function LoadingRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-1.5" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-6 w-full" />
      ))}
    </div>
  );
}

export function MockBanner() {
  return (
    <div
      role="status"
      className="rounded border border-amber-500/60 bg-amber-500/15 px-3 py-1.5 font-medium text-amber-200"
    >
      MOCK MODEL: results are scripted
    </div>
  );
}

export function Panel({
  title,
  aside,
  children,
}: {
  title: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded border bg-card">
      <header className="flex min-h-8 items-center gap-2 border-b px-3 py-1">
        <h2 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
          {title}
        </h2>
        {aside && <div className="ml-auto flex items-center gap-2">{aside}</div>}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}
