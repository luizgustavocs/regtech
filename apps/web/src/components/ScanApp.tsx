"use client";

import { parseZapReport, ZapParseError, type Report } from "@regtech/core";
import { useEffect, useRef, useState } from "react";
import { ReportView } from "./ReportView";

type Mode = "url" | "zap";

const PROGRESS = [
  "Abrindo o seu site como um visitante…",
  "Conferindo o cadeado (HTTPS)…",
  "Lendo os cabeçalhos de proteção…",
  "Procurando chaves esquecidas no JavaScript…",
  "Conferindo bibliotecas desatualizadas…",
  "Traduzindo tudo para português claro…",
];

export function ScanApp() {
  const [mode, setMode] = useState<Mode>("url");
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const topRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!loading) return;
    setStep(0);
    const t = setInterval(() => setStep((s) => Math.min(s + 1, PROGRESS.length - 1)), 1600);
    return () => clearInterval(t);
  }, [loading]);

  function show(r: Report) {
    setReport(r);
    requestAnimationFrame(() => topRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  async function runScan(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim() || loading) return;
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json().catch(() => ({ error: "Resposta inesperada do servidor." }));
      if (!res.ok) throw new Error(data.error ?? "Não foi possível analisar o site.");
      show(data as Report);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Não foi possível analisar o site.");
    } finally {
      setLoading(false);
    }
  }

  async function readZap(file: File | undefined) {
    if (!file) return;
    setError(null);
    if (file.size > 25_000_000) {
      setError("Arquivo grande demais (máx. 25 MB).");
      return;
    }
    try {
      show(parseZapReport(await file.text()));
    } catch (err) {
      setError(err instanceof ZapParseError ? err.message : "Não consegui ler esse arquivo.");
    }
  }

  function reset() {
    setReport(null);
    setError(null);
    if (fileRef.current) fileRef.current.value = "";
    requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: "smooth" }));
  }

  return (
    <div ref={topRef} className="scroll-mt-6">
      {!report && (
        <div className="no-print rounded-3xl border border-line bg-surface p-2 shadow-sm">
          <div className="flex gap-1 p-1" role="tablist">
            {(
              [
                ["url", "Analisar um site"],
                ["zap", "Traduzir relatório do ZAP"],
              ] as const
            ).map(([m, label]) => (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={mode === m}
                onClick={() => {
                  setMode(m);
                  setError(null);
                }}
                className={`flex-1 rounded-xl px-3 py-2 text-sm font-medium transition ${
                  mode === m ? "bg-subtle text-ink" : "text-muted hover:text-ink"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {mode === "url" ? (
            <form onSubmit={runScan} className="p-3 sm:p-4">
              <label htmlFor="url" className="sr-only">
                Endereço do site
              </label>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  id="url"
                  type="text"
                  inputMode="url"
                  autoComplete="url"
                  autoFocus
                  placeholder="meuapp.vercel.app"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={loading}
                  className="min-w-0 flex-1 rounded-xl border border-line bg-bg px-4 py-3 text-base outline-none placeholder:text-muted/70 focus:border-ink disabled:opacity-60"
                />
                <button
                  type="submit"
                  disabled={loading || !url.trim()}
                  className="rounded-xl bg-accent px-6 py-3 font-medium text-accent-ink transition hover:opacity-90 disabled:opacity-40"
                >
                  {loading ? "Analisando…" : "Fazer Raio-X"}
                </button>
              </div>
              <p className="mt-3 text-xs text-muted" aria-live="polite">
                {loading
                  ? PROGRESS[step]
                  : "Olhamos só o que qualquer visitante vê ao abrir a página. Leva uns 10 a 30 segundos. Nada é armazenado."}
              </p>
            </form>
          ) : (
            <div className="p-3 sm:p-4">
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  readZap(e.dataTransfer.files[0]);
                }}
                className={`flex w-full flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-10 text-center transition ${
                  dragging ? "border-ink bg-subtle" : "border-line hover:bg-subtle/60"
                }`}
              >
                <span className="font-medium">Arraste o relatório JSON do ZAP aqui</span>
                <span className="mt-1 text-sm text-muted">ou clique para escolher o arquivo</span>
              </button>
              <input
                ref={fileRef}
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={(e) => readZap(e.target.files?.[0])}
              />
              <details className="mt-3 text-sm text-muted">
                <summary className="cursor-pointer hover:text-ink">Como gerar esse arquivo no ZAP?</summary>
                <ol className="mt-2 list-decimal space-y-1 pl-5">
                  <li>No ZAP, depois de analisar o seu site, abra o menu Report → Generate Report.</li>
                  <li>Em Template, escolha “Traditional JSON Report”.</li>
                  <li>Gere o arquivo e arraste-o para cá.</li>
                </ol>
                <p className="mt-2">
                  O arquivo é lido no seu próprio navegador e não é enviado para nenhum servidor.
                </p>
              </details>
            </div>
          )}

          {error && (
            <p role="alert" className="mx-3 mb-3 rounded-xl bg-sev-critical/10 px-4 py-3 text-sm text-sev-critical sm:mx-4">
              {error}
            </p>
          )}
        </div>
      )}

      {report && <ReportView report={report} onReset={reset} />}
    </div>
  );
}
