"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { getMeta } from "@/lib/api";
import { cn } from "@/lib/utils";

const LINKS = [
  { href: "/", label: "Alert queue" },
  { href: "/evals", label: "Evals" },
];

type Mode = "checking" | "mock" | "live" | "offline";

const MODE_LABEL: Record<Mode, string> = {
  checking: "",
  mock: "API: mock model",
  live: "API: live model",
  offline: "API: unreachable",
};

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [mode, setMode] = useState<Mode>("checking");

  useEffect(() => {
    getMeta()
      .then((meta) => setMode(meta.mock ? "mock" : "live"))
      .catch(() => setMode("offline"));
  }, [pathname]);

  return (
    <>
      <header className="sticky top-0 z-40 flex h-10 items-center gap-5 border-b bg-background px-4">
        <span className="font-semibold tracking-tight">Triage console</span>
        <nav className="flex items-center gap-1">
          {LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={cn(
                "rounded px-2 py-1 text-muted-foreground hover:text-foreground",
                pathname === link.href && "bg-accent text-foreground",
              )}
            >
              {link.label}
            </Link>
          ))}
        </nav>
        <span
          className={cn(
            "ml-auto text-xs text-muted-foreground",
            mode === "mock" && "text-amber-300",
          )}
        >
          {MODE_LABEL[mode]}
        </span>
      </header>
      <main className="mx-auto w-full max-w-[1600px] px-4 py-3">{children}</main>
    </>
  );
}
