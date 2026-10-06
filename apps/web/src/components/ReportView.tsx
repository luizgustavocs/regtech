"use client";

import {
  buildFixPlanPrompt,
  computeScore,
  OWASP,
  OWASP_IDS,
  PASSED_LABEL,
  resolveFinding,
  sortFindings,
  STACK_LABEL,
  type Grade,
  type Report,
} from "@regtech/core";
import { download, reportToMarkdown } from "@/lib/markdown";
import { CopyButton } from "./CopyButton";
import { FindingCard } from "./FindingCard";

const GRADE_COLOR: Record<Grade, string> = {
  A: "text-ok",
  B: "text-ok",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

function hostOf(target: string) {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}

export function ReportView({ report, onReset }: { report: Report; onReset: () => void }) {
  const score = computeScore(report.findings);
  const items = sortFindings(report.findings.map(resolveFinding));
  const actionable = items.filter((r) => r.severity !== "info");
  const tips = items.filter((r) => r.severity === "info");
  const plan = buildFixPlanPrompt(report);
  const affected = new Set(actionable.map((r) => r.owasp));

  return (
    <div className="space-y-8">
      {/* Resumo */}
      <section className="rounded-3xl border border-line bg-surface p-6 sm:p-8">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
          <div className="flex items-center gap-5">
            <div
              className={`grid size-24 shrink-0 place-items-center rounded-full border-4 border-current ${GRADE_COLOR[score.grade]}`}
              aria-label={`Nota ${score.grade}`}
            >
              <span className="text-5xl font-semibold leading-none">{score.grade}</span>
            </div>
            <div className="sm:hidden">
              <div className="text-sm text-muted">{score.value}/100</div>
            </div>
          </div>
          <div className="flex-1">
            <p className="text-sm text-muted">
              {report.source === "zap" ? "Relatório do ZAP traduzido" : "Raio-X de"}{" "}
              <span className="font-medium text-ink break-all">{hostOf(report.finalUrl ?? report.target)}</span>
              <span className="hidden sm:inline"> · {score.value}/100</span>
            </p>
            <h2 className="mt-1 text-xl font-semibold leading-snug sm:text-2xl">{score.headline}</h2>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm">
              {(["critical", "high", "medium", "low"] as const).map((s) =>
                score.counts[s] ? (
                  <span key={s} className="text-muted">
                    <strong className="text-ink">{score.counts[s]}</strong>{" "}
                    {{ critical: "urgente", high: "alta", medium: "média", low: "baixa" }[s]}
                  </span>
                ) : null,
              )}
              {report.passed.length > 0 && (
                <span className="text-muted">
                  <strong className="text-ok">{report.passed.length}</strong> verificações ok
                </span>
              )}
            </div>
            {report.stack.length > 0 && (
              <div className="mt-3 flex flex-wrap items-center gap-1.5">
                <span className="text-xs text-muted">Detectamos:</span>
                {report.stack.map((s) => (
                  <span key={s} className="rounded-full bg-subtle px-2.5 py-0.5 text-xs font-medium">
                    {STACK_LABEL[s]}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="no-print mt-6 flex flex-wrap gap-2 border-t border-line pt-5">
          {plan && <CopyButton text={plan} label="Copiar plano completo para a IA" variant="solid" />}
          <button
            type="button"
            onClick={() => download(`raio-x-${hostOf(report.target)}.md`, reportToMarkdown(report))}
            className="rounded-lg border border-line bg-surface px-3 py-1.5 text-sm font-medium hover:bg-subtle"
          >
            Baixar .md
          </button>
          <button
            type="button"
            onClick={() => window.print()}
            className="rounded-lg border border-line bg-surface px-3 py-1.5 text-sm font-medium hover:bg-subtle"
          >
            Imprimir / PDF
          </button>
          <button
            type="button"
            onClick={onReset}
            className="ml-auto rounded-lg px-3 py-1.5 text-sm font-medium text-muted hover:bg-subtle hover:text-ink"
          >
            Nova análise
          </button>
        </div>
      </section>

      {/* Plano de ação */}
      {actionable.length > 0 && (
        <section>
          <h3 className="mb-1 text-lg font-semibold">O que corrigir, na ordem</h3>
          <p className="mb-4 text-sm text-muted">
            Abra cada item para entender o problema e copiar um prompt pronto para a sua ferramenta de IA.
          </p>
          <div className="space-y-3">
            {actionable.map((r, i) => (
              <FindingCard key={r.id} r={r} report={report} index={i + 1} defaultOpen={i === 0} />
            ))}
          </div>
        </section>
      )}

      {tips.length > 0 && (
        <section>
          <h3 className="mb-4 text-lg font-semibold">Dicas</h3>
          <div className="space-y-3">
            {tips.map((r, i) => (
              <FindingCard key={r.id} r={r} report={report} index={actionable.length + i + 1} />
            ))}
          </div>
        </section>
      )}

      {/* O que está certo */}
      {report.passed.length > 0 && (
        <section className="rounded-2xl border border-line bg-surface p-6">
          <h3 className="mb-3 text-lg font-semibold">O que já está certo</h3>
          <ul className="grid gap-2 sm:grid-cols-2">
            {report.passed.map((id) => {
              const label = PASSED_LABEL[id];
              if (!label) return null;
              return (
                <li key={id} className="flex gap-2 text-sm text-muted">
                  <span className="text-ok" aria-hidden>
                    ✓
                  </span>
                  <span>{label}</span>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* Cobertura OWASP */}
      <section className="rounded-2xl border border-line bg-surface p-6">
        <h3 className="text-lg font-semibold">OWASP Top 10:2025 — o que esta análise cobre</h3>
        <p className="mb-4 mt-1 text-sm text-muted">
          Nenhuma ferramenta automática vê tudo. Aqui está, com honestidade, o que foi e o que não foi possível verificar.
        </p>
        <ul className="divide-y divide-line">
          {OWASP_IDS.map((id) => {
            const cat = OWASP[id];
            const covered = report.coverage.includes(id);
            const hit = affected.has(id);
            return (
              <li key={id} className="flex flex-col gap-1 py-3 sm:flex-row sm:items-start sm:gap-4">
                <span className="w-44 shrink-0 text-sm">
                  <span className="font-mono text-muted">{id}</span> <span className="font-medium">{cat.name}</span>
                </span>
                <span className="flex-1 text-sm text-muted">{cat.plain}</span>
                <span
                  className={`shrink-0 text-xs font-semibold ${
                    hit ? "text-sev-high" : covered ? "text-ok" : "text-muted"
                  }`}
                >
                  {hit ? "Problemas encontrados" : covered ? "Verificado" : "Fora do alcance"}
                </span>
              </li>
            );
          })}
        </ul>
      </section>

      {report.notes.length > 0 && (
        <section className="text-sm text-muted">
          <ul className="space-y-1">
            {report.notes.map((n) => (
              <li key={n}>• {n}</li>
            ))}
          </ul>
          <p className="mt-3">
            Gerado em {new Date(report.generatedAt).toLocaleString("pt-BR")}
            {report.durationMs ? ` em ${(report.durationMs / 1000).toFixed(1)}s` : ""}. Nada foi armazenado.
          </p>
        </section>
      )}
    </div>
  );
}
