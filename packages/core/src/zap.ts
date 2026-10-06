import { owaspForCwe, OWASP_IDS } from "./owasp.ts";
import type { Finding, Report, Severity } from "./types.ts";

/** ZAP plugin id → knowledge-base issue id. Anything not listed falls back to a CWE-based explanation. */
const PLUGIN_TO_ISSUE: Record<string, string> = {
  "10038": "missing-csp",
  "10055": "weak-csp",
  "10020": "missing-clickjacking",
  "10021": "missing-nosniff",
  "10035": "missing-hsts",
  "10036": "server-version-leak",
  "10037": "server-version-leak",
  "10010": "cookie-insecure",
  "10011": "cookie-insecure",
  "10054": "cookie-insecure",
  "90033": "cookie-insecure",
  "10098": "cors-misconfig",
  "40040": "cors-misconfig",
  "10202": "csrf",
  "20012": "csrf",
  "10003": "vulnerable-library",
  "10017": "missing-sri",
  "10040": "mixed-content",
  "10041": "form-over-http",
  "10042": "form-over-http",
  "40012": "xss",
  "40014": "xss",
  "40016": "xss",
  "40017": "xss",
  "40026": "xss",
  "40018": "sqli",
  "40019": "sqli",
  "40020": "sqli",
  "40021": "sqli",
  "40022": "sqli",
  "40024": "sqli",
  "40027": "sqli",
  "90018": "sqli",
  "90020": "injection-other",
  "90019": "injection-other",
  "90021": "injection-other",
  "90023": "injection-other",
  "90025": "injection-other",
  "90035": "injection-other",
  "90036": "injection-other",
  "40003": "injection-other",
  "40043": "injection-other",
  "40045": "injection-other",
  "20019": "open-redirect",
  "10028": "open-redirect",
  "6": "path-traversal",
  "7": "path-traversal",
  "40034": "exposed-env",
  "40035": "exposed-file",
  "40032": "exposed-file",
  "40028": "exposed-file",
  "40029": "exposed-file",
  "10045": "exposed-file",
  "0": "directory-listing",
  "10033": "directory-listing",
  "10062": "pii-disclosure",
  "90022": "verbose-errors",
  "10023": "verbose-errors",
  "10027": "info-leak-comments",
  "10063": "missing-permissions-policy",
  "10105": "secret-in-js",
};

const RISK_TO_SEVERITY: Record<string, Severity> = { "0": "info", "1": "low", "2": "medium", "3": "high" };

interface ZapInstance {
  uri?: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
}

interface ZapAlert {
  pluginid?: string;
  alertRef?: string;
  alert?: string;
  name?: string;
  riskcode?: string;
  confidence?: string;
  desc?: string;
  solution?: string;
  cweid?: string;
  instances?: ZapInstance[];
  count?: string;
}

interface ZapSite {
  "@name"?: string;
  alerts?: ZapAlert[];
}

export class ZapParseError extends Error {}

function stripHtml(s: string | undefined): string {
  return (s ?? "")
    .replace(/<\/p>\s*<p>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .trim();
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Parses a ZAP "Traditional JSON" report (Report → Generate Report, or zap-baseline.py -J). */
export function parseZapReport(raw: string): Report {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new ZapParseError("O arquivo não é um JSON válido. Exporte o relatório do ZAP no formato \"Traditional JSON\".");
  }

  const sites = (data as { site?: ZapSite[] | ZapSite })?.site;
  if (!sites) {
    throw new ZapParseError("Não encontrei a lista de sites no arquivo. Ele foi gerado pelo ZAP no formato \"Traditional JSON\"?");
  }
  const siteList = Array.isArray(sites) ? sites : [sites];

  const findings: Finding[] = [];
  const byKey = new Map<string, Finding>();

  for (const site of siteList) {
    for (const a of site.alerts ?? []) {
      const pluginId = String(a.pluginid ?? "");
      // Some ZAP ids carry a variant suffix ("10020-1"); the base id is what we map.
      const baseId = String(a.alertRef ?? pluginId).split("-")[0];
      const issueId = PLUGIN_TO_ISSUE[baseId] ?? PLUGIN_TO_ISSUE[pluginId] ?? `zap-${pluginId || "alert"}`;
      const severity: Severity = RISK_TO_SEVERITY[String(a.riskcode)] ?? "info";
      const name = a.alert ?? a.name ?? "Alerta do ZAP";

      const evidence = (a.instances ?? []).slice(0, 8).map((inst) => {
        const parts = [inst.method, inst.uri].filter(Boolean).join(" ");
        const extra = [
          inst.param ? `parâmetro: ${inst.param}` : "",
          inst.evidence ? `evidência: ${truncate(inst.evidence, 160)}` : "",
          inst.attack ? `ataque: ${truncate(inst.attack, 120)}` : "",
        ]
          .filter(Boolean)
          .join(" · ");
        return extra ? `${parts} (${extra})` : parts;
      });
      const total = Number(a.count ?? a.instances?.length ?? 0);
      if (total > evidence.length) evidence.push(`… e mais ${total - evidence.length} ocorrência(s)`);
      evidence.unshift(`ZAP: ${name} (plugin ${pluginId}${a.cweid ? `, CWE-${a.cweid}` : ""}, confiança ${a.confidence ?? "?"})`);

      // Merge alerts that map to the same issue+severity (e.g. three different cookie alerts).
      const key = `${issueId}:${severity}`;
      const existing = byKey.get(key);
      if (existing) {
        existing.evidence.push(...evidence);
        continue;
      }

      const f: Finding = {
        issueId,
        severity,
        evidence,
        source: "zap",
        override: issueId.startsWith("zap-")
          ? {
              title: name,
              technicalName: name,
              description: truncate(stripHtml(a.desc), 600),
              solution: truncate(stripHtml(a.solution), 600),
              cwe: a.cweid && a.cweid !== "-1" ? a.cweid : undefined,
              owasp: owaspForCwe(a.cweid),
            }
          : undefined,
      };
      byKey.set(key, f);
      findings.push(f);
    }
  }

  const target = siteList.map((s) => s["@name"]).filter(Boolean).join(", ") || "relatório importado";
  const program = (data as Record<string, unknown>)["@programName"] ?? "ZAP";
  const version = (data as Record<string, unknown>)["@version"];

  return {
    target,
    generatedAt: new Date().toISOString(),
    source: "zap",
    stack: [],
    findings,
    passed: [],
    coverage: OWASP_IDS.filter((id) => id !== "A06" && id !== "A09"),
    notes: [
      `Relatório importado do ${String(program)}${version ? ` ${String(version)}` : ""}. A análise foi feita no seu navegador; o arquivo não foi enviado para nenhum servidor.`,
    ],
  };
}
