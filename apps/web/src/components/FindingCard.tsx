"use client";

import {
  buildPrompt,
  FIX_TARGET_LABEL,
  orderSnippets,
  OWASP,
  SEVERITY_LABEL,
  type Report,
  type ResolvedFinding,
  type Severity,
} from "@regtech/core";
import { useState } from "react";
import { CopyButton } from "./CopyButton";

export const SEV_TEXT: Record<Severity, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
};

const SEV_BAR: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide ${SEV_TEXT[severity]}`}>
      <span className={`size-2 rounded-full ${SEV_BAR[severity]}`} aria-hidden />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function FindingCard({
  r,
  report,
  index,
  defaultOpen,
}: {
  r: ResolvedFinding;
  report: Report;
  index: number;
  defaultOpen?: boolean;
}) {
  const snippets = orderSnippets(r, report.stack);
  const [tab, setTab] = useState(0);
  const prompt = buildPrompt(r, report);

  return (
    <details open={defaultOpen} className="group relative overflow-hidden rounded-2xl border border-line bg-surface">
      <span className={`absolute inset-y-0 left-0 w-1 ${SEV_BAR[r.severity]}`} aria-hidden />
      <summary className="flex cursor-pointer items-start gap-4 px-5 py-4 pl-6 hover:bg-subtle/60">
        <span className="mt-0.5 font-mono text-sm text-muted">{String(index).padStart(2, "0")}</span>
        <span className="flex-1">
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <SeverityBadge severity={r.severity} />
            <span className="text-xs text-muted">~{r.effort}</span>
          </span>
          <span className="mt-1 block font-medium leading-snug">{r.title}</span>
        </span>
        <span className="mt-1 text-muted transition group-open:rotate-180" aria-hidden>
          ▾
        </span>
      </summary>

      <div className="space-y-5 border-t border-line px-6 py-5 text-[15px] leading-relaxed">
        <section>
          <h4 className="mb-1 text-sm font-semibold">O que é isso?</h4>
          <p className="text-muted">{r.analogy}</p>
        </section>

        <section>
          <h4 className="mb-1 text-sm font-semibold">O que pode acontecer</h4>
          <p className="text-muted">{r.risk}</p>
        </section>

        <section>
          <h4 className="mb-2 text-sm font-semibold">Como corrigir</h4>
          <ol className="list-decimal space-y-1.5 pl-5 text-muted marker:text-ink">
            {r.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </section>

        <section className="rounded-xl border border-line bg-subtle p-4">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h4 className="text-sm font-semibold">Prompt pronto para a sua IA</h4>
              <p className="text-xs text-muted">Cole no Cursor, Lovable, Bolt, v0, Copilot ou Claude Code.</p>
            </div>
            <CopyButton text={prompt} label="Copiar prompt" variant="solid" />
          </div>
          <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded-lg bg-surface p-3 font-mono text-xs leading-relaxed text-muted">
            {prompt}
          </pre>
        </section>

        {snippets.length > 0 && (
          <section>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <h4 className="text-sm font-semibold">Ou faça você mesmo</h4>
              <CopyButton text={snippets[tab]?.[1] ?? ""} />
            </div>
            <div className="no-print mb-2 flex flex-wrap gap-1" role="tablist">
              {snippets.map(([target], i) => (
                <button
                  key={target}
                  type="button"
                  role="tab"
                  aria-selected={tab === i}
                  onClick={() => setTab(i)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium ${
                    tab === i ? "bg-accent text-accent-ink" : "text-muted hover:bg-subtle"
                  }`}
                >
                  {FIX_TARGET_LABEL[target]}
                </button>
              ))}
            </div>
            <pre className="overflow-auto rounded-lg border border-line bg-subtle p-3 font-mono text-xs leading-relaxed">
              {snippets[tab]?.[1]}
            </pre>
          </section>
        )}

        {r.lgpd && (
          <section className="rounded-xl border border-line p-4">
            <h4 className="mb-1 text-sm font-semibold">E a LGPD?</h4>
            <p className="text-sm text-muted">{r.lgpd}</p>
          </section>
        )}

        <details className="text-sm">
          <summary className="cursor-pointer text-muted hover:text-ink">Detalhes técnicos</summary>
          <dl className="mt-3 grid gap-x-4 gap-y-1 sm:grid-cols-[max-content_1fr]">
            <dt className="text-muted">Nome técnico</dt>
            <dd>{r.technicalName}</dd>
            <dt className="text-muted">OWASP Top 10:2025</dt>
            <dd>
              {r.owasp} — {OWASP[r.owasp].name}
            </dd>
            {r.cwe && (
              <>
                <dt className="text-muted">CWE</dt>
                <dd>
                  <a
                    className="underline underline-offset-2"
                    href={`https://cwe.mitre.org/data/definitions/${r.cwe}.html`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    CWE-{r.cwe}
                  </a>
                </dd>
              </>
            )}
          </dl>
          {r.finding.evidence.length > 0 && (
            <ul className="mt-3 space-y-1 break-all font-mono text-xs text-muted">
              {r.finding.evidence.map((e, i) => (
                <li key={i}>• {e}</li>
              ))}
            </ul>
          )}
        </details>
      </div>
    </details>
  );
}
