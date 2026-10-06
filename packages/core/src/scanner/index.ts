import type { Finding, Report, Severity, StackTag } from "../types.ts";
import { normalizeTarget, safeGet, ScanError, tryGet, type FetchedPage } from "./net.ts";
import { findSecrets, type SupabaseSignals } from "./secrets.ts";

export { ScanError } from "./net.ts";

const MAX_SCRIPTS = 12;
const MAX_SCRIPT_BYTES = 2_500_000;

/** Every check this scanner runs; anything not reported as a finding is listed as passed. */
const CHECKED = [
  "no-https",
  "http-no-redirect",
  "tls-invalid",
  "missing-hsts",
  "missing-csp",
  "weak-csp",
  "missing-clickjacking",
  "missing-nosniff",
  "missing-referrer-policy",
  "missing-permissions-policy",
  "server-version-leak",
  "cookie-insecure",
  "cors-misconfig",
  "mixed-content",
  "form-over-http",
  "secret-in-js",
  "supabase-service-role",
  "vulnerable-library",
  "missing-sri",
  "exposed-sourcemap",
  "directory-listing",
  "verbose-errors",
];

class Findings {
  list: Finding[] = [];
  add(issueId: string, severity: Severity, evidence: string[]) {
    const existing = this.list.find((f) => f.issueId === issueId);
    if (existing) {
      existing.evidence.push(...evidence);
      if (rank(severity) < rank(existing.severity)) existing.severity = severity;
      return;
    }
    this.list.push({ issueId, severity, evidence, source: "scan" });
  }
}

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const rank = (s: Severity) => ORDER.indexOf(s);

// ───────────── header checks ─────────────

function metaContent(html: string, attr: "http-equiv" | "name", value: string): string | null {
  const re = new RegExp(`<meta[^>]+${attr}\\s*=\\s*["']?${value}["']?[^>]*>`, "i");
  const tag = html.match(re)?.[0];
  return tag?.match(/content\s*=\s*["']([^"']*)["']/i)?.[1] ?? null;
}

function checkHeaders(page: FetchedPage, isHttps: boolean, out: Findings) {
  const h = page.headers;
  const csp = h.get("content-security-policy") ?? metaContent(page.body, "http-equiv", "content-security-policy");

  if (isHttps && !h.get("strict-transport-security")) {
    out.add("missing-hsts", "low", ["Cabeçalho Strict-Transport-Security ausente na resposta."]);
  }

  if (!csp) {
    out.add("missing-csp", "medium", ["Nenhum Content-Security-Policy no cabeçalho nem em <meta http-equiv>."]);
  } else {
    const scriptSrc =
      csp.match(/script-src(?:-elem)?\s+([^;]+)/i)?.[1] ?? csp.match(/default-src\s+([^;]+)/i)?.[1] ?? "";
    const problems: string[] = [];
    const usesNonceOrHash = /'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(scriptSrc);
    if (/'unsafe-inline'/.test(scriptSrc) && !usesNonceOrHash) problems.push("script-src permite 'unsafe-inline'");
    if (/'unsafe-eval'/.test(scriptSrc)) problems.push("script-src permite 'unsafe-eval'");
    if (/(^|\s)(\*|https?:|data:)(\s|$)/.test(scriptSrc)) problems.push("script-src aceita qualquer origem (*, https: ou data:)");
    if (!scriptSrc) problems.push("política não define script-src nem default-src");
    if (problems.length) out.add("weak-csp", "low", [...problems, `CSP atual: ${csp.slice(0, 300)}`]);
  }

  const xfo = h.get("x-frame-options");
  const frameAncestors = /frame-ancestors/i.test(h.get("content-security-policy") ?? "");
  if (!xfo && !frameAncestors) {
    out.add("missing-clickjacking", "medium", ["Sem X-Frame-Options e sem frame-ancestors na CSP."]);
  }

  if ((h.get("x-content-type-options") ?? "").toLowerCase() !== "nosniff") {
    out.add("missing-nosniff", "low", ["X-Content-Type-Options ausente ou diferente de nosniff."]);
  }

  if (!h.get("referrer-policy") && !metaContent(page.body, "name", "referrer")) {
    out.add("missing-referrer-policy", "low", ["Referrer-Policy ausente (cabeçalho e meta)."]);
  }

  if (!h.get("permissions-policy")) {
    out.add("missing-permissions-policy", "info", ["Permissions-Policy ausente."]);
  }

  const leaks: string[] = [];
  for (const name of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]) {
    const v = h.get(name);
    if (v && (/\d/.test(v) || name !== "server")) leaks.push(`${name}: ${v}`);
  }
  // Platform-set headers like "x-powered-by: Next.js" without a version are low value; keep only versioned ones or language runtimes.
  const meaningful = leaks.filter((l) => /\d/.test(l) || /php|asp\.net|express/i.test(l));
  if (meaningful.length) out.add("server-version-leak", "low", meaningful);

  const acao = h.get("access-control-allow-origin");
  const acac = (h.get("access-control-allow-credentials") ?? "").toLowerCase() === "true";
  if (acao === "*" && acac) {
    out.add("cors-misconfig", "high", ["Access-Control-Allow-Origin: * junto com Access-Control-Allow-Credentials: true."]);
  } else if (acao === "null") {
    out.add("cors-misconfig", "medium", ["Access-Control-Allow-Origin: null (aceita origens sandbox/arquivos locais)."]);
  }
}

// ───────────── cookies ─────────────

const SESSION_NAME = /sess|token|auth|sid|jwt|login|remember|csrf|xsrf|sb-|supabase|next-auth|__secure|__host/i;

function checkCookies(cookies: string[], isHttps: boolean, out: Findings) {
  for (const c of cookies) {
    const [pair, ...attrs] = c.split(";").map((s) => s.trim());
    const name = pair.split("=")[0];
    const lower = attrs.map((a) => a.toLowerCase());
    const missing: string[] = [];
    if (isHttps && !lower.includes("secure")) missing.push("Secure");
    if (!lower.includes("httponly")) missing.push("HttpOnly");
    if (!lower.some((a) => a.startsWith("samesite"))) missing.push("SameSite");
    if (!missing.length) continue;
    const isSession = SESSION_NAME.test(name);
    // HttpOnly alone is often intentionally absent on non-session cookies (consent, theme).
    if (!isSession && missing.length === 1 && missing[0] === "HttpOnly") continue;
    out.add("cookie-insecure", isSession ? "medium" : "low", [`Cookie "${name}" sem: ${missing.join(", ")}`]);
  }
}

// ───────────── HTML content ─────────────

function attrValues(html: string, tag: string, attr: string): Array<{ value: string; tag: string }> {
  const re = new RegExp(`<${tag}\\b[^>]*>`, "gi");
  const out: Array<{ value: string; tag: string }> = [];
  for (const m of html.matchAll(re)) {
    const v = m[0].match(new RegExp(`\\s${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
    const value = v?.[1] ?? v?.[2] ?? v?.[3];
    if (value) out.push({ value, tag: m[0] });
  }
  return out;
}

function checkHtml(page: FetchedPage, isHttps: boolean, out: Findings) {
  const html = page.body;

  if (isHttps) {
    const mixed = new Set<string>();
    for (const [tag, attr] of [
      ["script", "src"],
      ["iframe", "src"],
      ["img", "src"],
      ["link", "href"],
      ["source", "src"],
      ["video", "src"],
      ["audio", "src"],
    ] as const) {
      for (const { value, tag: raw } of attrValues(html, tag, attr)) {
        if (tag === "link" && !/rel\s*=\s*["']?(stylesheet|preload|icon|modulepreload)/i.test(raw)) continue;
        if (/^http:\/\//i.test(value)) mixed.add(`<${tag}> ${value}`);
      }
    }
    if (mixed.size) {
      const anyActive = [...mixed].some((m) => /^<(script|iframe|link)>/.test(m));
      out.add("mixed-content", anyActive ? "medium" : "low", [...mixed].slice(0, 10));
    }
  }

  const httpForms = attrValues(html, "form", "action").filter((f) => /^http:\/\//i.test(f.value));
  if (httpForms.length) out.add("form-over-http", "high", httpForms.map((f) => `<form action="${f.value}">`));
  if (!isHttps && /<input[^>]+type\s*=\s*["']?password/i.test(html)) {
    out.add("form-over-http", "high", ["Página sem HTTPS contém campo de senha."]);
  }

  if (/<title>\s*Index of \//i.test(html)) out.add("directory-listing", "medium", [`${page.url} lista os arquivos da pasta.`]);

  if (page.status >= 500) {
    const trace = html.match(
      /(Traceback \(most recent call last\)|at [\w.$<>]+ \([^)]*:\d+:\d+\)|Fatal error:.+ on line \d+|Exception in thread|SQLSTATE\[|Microsoft OLE DB|Whitelabel Error Page|DEBUG = True|Stack trace:)/,
    );
    if (trace) out.add("verbose-errors", "medium", [`HTTP ${page.status} com detalhe interno: ${trace[0].slice(0, 160)}`]);
  }
}

// ───────────── scripts / libraries ─────────────

const VERSIONED_CDN = /(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|ajax\.googleapis\.com|cdn\.bootcdn\.net)/i;

function cmp(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

function checkLibraries(label: string, code: string, found: Map<string, string>) {
  const probes: Array<{ lib: string; re: RegExp; vulnerable: (v: string) => string | null }> = [
    {
      lib: "jQuery",
      re: /jquery[.-]?(?:v|-)?(\d+\.\d+\.\d+)(?:\.min)?\.js|jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/i,
      vulnerable: (v) => (cmp(v, "3.5.0") < 0 ? "versões < 3.5.0 têm XSS conhecidos (CVE-2020-11022/11023)" : null),
    },
    {
      lib: "AngularJS",
      re: /angular(?:\.min)?\.js[^"']*?(1\.\d+\.\d+)|AngularJS v(1\.\d+\.\d+)/i,
      vulnerable: () => "AngularJS 1.x não recebe mais correções de segurança desde 2022",
    },
    {
      lib: "Bootstrap",
      re: /bootstrap(?:@|\/|-)(\d+\.\d+\.\d+)|Bootstrap v(\d+\.\d+\.\d+)/i,
      vulnerable: (v) =>
        (v.startsWith("3.") && cmp(v, "3.4.1") < 0) || (v.startsWith("4.") && cmp(v, "4.3.1") < 0)
          ? "versão com XSS conhecido (CVE-2019-8331)"
          : null,
    },
    {
      lib: "Lodash",
      re: /lodash(?:@|\/|\.js[^"']*?)(\d+\.\d+\.\d+)|lodash\.com.{0,40}?VERSION\s*=\s*['"](\d+\.\d+\.\d+)/i,
      vulnerable: (v) => (cmp(v, "4.17.21") < 0 ? "versões < 4.17.21 têm prototype pollution/injeção de comando" : null),
    },
    {
      lib: "Moment.js",
      re: /moment(?:@|\/|\.js[^"']*?)(\d+\.\d+\.\d+)|\/\/! moment\.js\s*\/\/! version : (\d+\.\d+\.\d+)/i,
      vulnerable: (v) => (cmp(v, "2.29.4") < 0 ? "versões < 2.29.4 têm ReDoS/path traversal conhecidos" : null),
    },
  ];
  for (const p of probes) {
    const m = code.match(p.re);
    const v = m?.slice(1).find(Boolean);
    if (!v) continue;
    const why = p.vulnerable(v);
    if (why) found.set(`${p.lib} ${v}`, `${p.lib} ${v} (${label}): ${why}`);
  }
}

function sameSite(a: URL, b: URL): boolean {
  const base = (h: string) => h.split(".").slice(-2).join(".");
  return base(a.hostname) === base(b.hostname);
}

// ───────────── stack detection ─────────────

function detectStack(page: FetchedPage, code: string): StackTag[] {
  const h = page.headers;
  const html = page.body;
  const tags = new Set<StackTag>();
  const server = (h.get("server") ?? "").toLowerCase();
  const powered = (h.get("x-powered-by") ?? "").toLowerCase();

  if (h.get("x-vercel-id") || server.includes("vercel")) tags.add("vercel");
  if (h.get("x-nf-request-id") || server.includes("netlify")) tags.add("netlify");
  if (h.get("cf-ray") || server.includes("cloudflare")) tags.add("cloudflare");
  if (server.includes("nginx")) tags.add("nginx");
  if (server.includes("apache")) tags.add("apache");
  if (powered.includes("next.js") || /\/_next\/static\/|__NEXT_DATA__|self\.__next_f/.test(html)) tags.add("nextjs");
  if (powered.includes("express")) tags.add("express");
  if (powered.includes("php") || /\.php\b/.test(page.url)) tags.add("php");
  if (/wp-content\/|wp-includes\//.test(html)) tags.add("wordpress");
  if (/\/assets\/index-[\w-]+\.js|type="module" crossorigin src="\/assets\//.test(html)) tags.add("vite");
  if (/data-reactroot|react-dom|__reactContainer|_reactListening/.test(html + code.slice(0, 200_000))) tags.add("react");
  if (/gpteng\.co|lovable\.(app|dev)|lovable-tagger/i.test(html + code.slice(0, 200_000))) tags.add("lovable");
  if (/bolt\.new|stackblitz/i.test(html)) tags.add("bolt");
  if (/\.supabase\.co\b|sb_publishable_/.test(code)) tags.add("supabase");
  if (/firebaseio\.com|firebaseapp\.com|firebasestorage\.googleapis/.test(code)) tags.add("firebase");
  if (tags.has("nextjs")) tags.add("react");
  return [...tags];
}

// ───────────── orchestration ─────────────

async function fetchMain(target: URL, explicitScheme: boolean, out: Findings, notes: string[]) {
  try {
    return await safeGet(target);
  } catch (err) {
    if (!(err instanceof ScanError) || target.protocol !== "https:") throw err;
    if (err.code === "TLS") {
      out.add("tls-invalid", "high", [err.message]);
    } else if ((err.code !== "UNREACHABLE" && err.code !== "TIMEOUT") || explicitScheme) {
      throw err;
    }
    // HTTPS failed: look at the plain-HTTP version so the rest of the report still helps.
    const http = new URL(target);
    http.protocol = "http:";
    const page = await safeGet(http);
    notes.push("A versão HTTPS não respondeu corretamente; analisamos a versão http://.");
    return page;
  }
}

export async function scan(input: string): Promise<Report> {
  const started = Date.now();
  const explicitScheme = /^https?:\/\//i.test(input.trim());
  const target = normalizeTarget(input);
  const out = new Findings();
  const notes: string[] = [];

  const page = await fetchMain(target, explicitScheme, out, notes);
  const finalUrl = new URL(page.url);
  const isHttps = finalUrl.protocol === "https:";

  if (page.status >= 400 && page.status !== 401 && page.status !== 403 && page.status < 500) {
    notes.push(`A página respondeu com HTTP ${page.status}; alguns resultados podem não representar o site real.`);
  }
  if (page.status === 401 || page.status === 403) {
    notes.push(`A página respondeu com HTTP ${page.status} (acesso restrito ou proteção anti-robô). Só conseguimos ver o que é público.`);
  }

  if (!isHttps) {
    out.add("no-https", "critical", [`O endereço final é ${page.url} (sem HTTPS).`, ...page.redirects]);
  } else {
    // Does http:// send people to https://?
    const http = new URL(finalUrl.origin);
    http.protocol = "http:";
    try {
      const r = await safeGet(http, { maxRedirects: 0, maxBytes: 1, timeoutMs: 6_000 });
      const loc = r.headers.get("location") ?? "";
      const redirectsToHttps = r.status >= 300 && r.status < 400 && /^https:\/\//i.test(new URL(loc, http).href);
      if (!redirectsToHttps) {
        out.add("http-no-redirect", "medium", [`GET ${http.href} → HTTP ${r.status}${loc ? ` (Location: ${loc})` : ""}, sem redirecionar para https://`]);
      }
    } catch {
      // Port 80 closed is fine: nobody can be served over plain HTTP.
    }
  }

  checkHeaders(page, isHttps, out);
  checkCookies(page.setCookies, isHttps, out);
  checkHtml(page, isHttps, out);

  // Scripts the page loads, exactly as a visitor's browser would.
  const scripts = attrValues(page.body, "script", "src")
    .map((s) => {
      try {
        return { url: new URL(s.value, finalUrl), tag: s.tag };
      } catch {
        return null;
      }
    })
    .filter((s): s is { url: URL; tag: string } => s !== null && /^https?:$/.test(s.url.protocol));

  const libs = new Map<string, string>();
  const noSri: string[] = [];
  for (const s of scripts) {
    checkLibraries(s.url.href, s.url.href, libs);
    if (!sameSite(s.url, finalUrl) && VERSIONED_CDN.test(s.url.hostname) && !/\sintegrity\s*=/i.test(s.tag)) {
      noSri.push(s.url.href);
    }
  }
  if (noSri.length) out.add("missing-sri", "low", noSri.slice(0, 10));

  const own = scripts.filter((s) => sameSite(s.url, finalUrl)).slice(0, MAX_SCRIPTS);
  const bodies = await Promise.all(own.map((s) => tryGet(s.url, MAX_SCRIPT_BYTES)));

  const supabase: SupabaseSignals = { projectUrls: new Set(), anonKey: false };
  const secretEvidence = new Map<string, string[]>();
  const sourceMaps: string[] = [];
  const sources: Array<{ label: string; code: string }> = [
    { label: "HTML da página", code: page.body },
    ...bodies.flatMap((b, i) => (b && b.status < 400 ? [{ label: own[i].url.href, code: b.body }] : [])),
  ];

  for (const { label, code } of sources) {
    for (const hit of findSecrets(code, supabase)) {
      const list = secretEvidence.get(hit.issueId) ?? [];
      list.push(`${hit.kind} em ${label}: ${hit.masked}`);
      secretEvidence.set(hit.issueId, list);
    }
    checkLibraries(label, code.slice(0, 4_000), libs);
    const map = code.match(/\/\/[#@] sourceMappingURL=(?!data:)(\S+\.map)\s*$/m);
    if (map && label !== "HTML da página") sourceMaps.push(`${label} referencia ${map[1]}`);
  }

  for (const [issueId, evidence] of secretEvidence) {
    const severity: Severity = issueId === "google-api-key" ? "low" : "critical";
    out.add(issueId, severity, evidence);
  }
  if (libs.size) out.add("vulnerable-library", "medium", [...libs.values()]);
  if (sourceMaps.length) out.add("exposed-sourcemap", "low", sourceMaps.slice(0, 5));

  const allCode = sources.map((s) => s.code).join("\n");
  const stack = detectStack(page, allCode);

  if ((supabase.projectUrls.size || supabase.anonKey) && !secretEvidence.has("supabase-service-role")) {
    out.add("supabase-check-rls", "info", [
      ...[...supabase.projectUrls].map((u) => `Projeto Supabase usado pelo site: ${u}`),
      "A chave anon/publishable é pública por design; a proteção dos dados depende do RLS.",
    ]);
  }

  if (own.length < scripts.filter((s) => sameSite(s.url, finalUrl)).length) {
    notes.push(`Analisamos os primeiros ${MAX_SCRIPTS} arquivos JavaScript do site.`);
  }
  notes.push(
    "Análise passiva: olhamos só o que qualquer visitante recebe ao abrir a página. Falhas que exigem testes ativos (injeção, controle de acesso) precisam do OWASP ZAP — importe o relatório na aba ao lado.",
  );

  const reported = new Set(out.list.map((f) => f.issueId));
  // Don't celebrate checks that didn't really apply (e.g. "CSP is not weak" when there is no CSP).
  const notApplicable = new Set<string>();
  if (!isHttps) notApplicable.add("missing-hsts").add("http-no-redirect");
  if (reported.has("missing-csp")) notApplicable.add("weak-csp");
  if (!stack.includes("supabase")) notApplicable.add("supabase-service-role");
  if (page.setCookies.length === 0) notApplicable.add("cookie-insecure");
  if (!scripts.some((s) => VERSIONED_CDN.test(s.url.hostname))) notApplicable.add("missing-sri");
  return {
    target: target.href,
    finalUrl: page.url,
    generatedAt: new Date().toISOString(),
    source: "scan",
    stack,
    findings: out.list,
    passed: CHECKED.filter((id) => !reported.has(id) && !notApplicable.has(id)),
    coverage: ["A01", "A02", "A03", "A04", "A07", "A08", "A10"],
    notes,
    durationMs: Date.now() - started,
  };
}
