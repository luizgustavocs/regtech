"use client";

import { useState } from "react";

export function CopyButton({
  text,
  label = "Copiar",
  variant = "ghost",
}: {
  text: string;
  label?: string;
  variant?: "ghost" | "solid";
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard API can be blocked (iframes, old browsers); fall back to a hidden textarea.
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  const base = "no-print inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition";
  const styles =
    variant === "solid"
      ? "bg-accent text-accent-ink hover:opacity-90"
      : "border border-line bg-surface text-ink hover:bg-subtle";

  return (
    <button type="button" onClick={copy} className={`${base} ${styles}`} aria-live="polite">
      {copied ? "Copiado ✓" : label}
    </button>
  );
}
