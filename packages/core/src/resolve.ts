import { getIssue, type Issue } from "./knowledge.ts";
import { OWASP } from "./owasp.ts";
import type { Finding, FixTarget, Severity, StackTag } from "./types.ts";

export interface ResolvedFinding extends Issue {
  finding: Finding;
  severity: Severity;
}

/** Merges a finding with its knowledge entry; ZAP alerts without one get a generic, category-level explanation. */
export function resolveFinding(f: Finding): ResolvedFinding {
  const base = getIssue(f.issueId);
  if (base) return { ...base, severity: f.severity, finding: f };

  const o = f.override ?? {};
  const owasp = o.owasp ?? "A02";
  const cat = OWASP[owasp];
  return {
    id: f.issueId,
    owasp,
    cwe: o.cwe,
    severity: f.severity,
    effort: "variável",
    title: o.title ?? o.technicalName ?? "Alerta do scanner",
    technicalName: o.technicalName ?? "Alerta",
    analogy: `Este alerta pertence à categoria "${cat.name}": ${cat.plain}`,
    risk: o.description ?? "Veja os detalhes técnicos abaixo.",
    steps: o.solution ? [o.solution] : ["Use o prompt abaixo com a sua IA para entender e corrigir este alerta."],
    aiTask: `O OWASP ZAP gerou o alerta "${o.technicalName ?? f.issueId}". Explique em linguagem simples o que ele significa no meu projeto, diga se é um falso positivo provável e, se for real, corrija.${o.solution ? ` Sugestão do ZAP: ${o.solution}` : ""}`,
    finding: f,
  };
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Urgente",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  info: "Dica",
};

export function sortFindings<T extends { severity: Severity }>(items: T[]): T[] {
  return [...items].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

export const STACK_LABEL: Record<StackTag, string> = {
  nextjs: "Next.js",
  react: "React",
  vite: "Vite",
  vercel: "Vercel",
  netlify: "Netlify",
  cloudflare: "Cloudflare",
  supabase: "Supabase",
  firebase: "Firebase",
  lovable: "Lovable",
  bolt: "Bolt",
  wordpress: "WordPress",
  php: "PHP",
  express: "Express/Node",
  nginx: "Nginx",
  apache: "Apache",
};

export const FIX_TARGET_LABEL: Record<FixTarget, string> = {
  nextjs: "Next.js",
  vercel: "Vercel",
  netlify: "Netlify",
  express: "Express/Node",
  nginx: "Nginx",
  apache: "Apache",
  supabase: "Supabase (SQL)",
  firebase: "Firebase",
  generic: "Outros",
};

/** Snippet tabs ordered so the user's own stack comes first. */
export function orderSnippets(issue: Issue, stack: StackTag[]): Array<[FixTarget, string]> {
  const entries = Object.entries(issue.snippets ?? {}) as Array<[FixTarget, string]>;
  const preferred: FixTarget[] = [];
  for (const s of stack) {
    if (s === "nextjs") preferred.push("nextjs");
    if (s === "vercel") preferred.push("vercel");
    if (s === "netlify") preferred.push("netlify");
    if (s === "express") preferred.push("express");
    if (s === "nginx") preferred.push("nginx");
    if (s === "apache" || s === "php" || s === "wordpress") preferred.push("apache");
    if (s === "supabase") preferred.push("supabase");
    if (s === "firebase") preferred.push("firebase");
  }
  const rank = (t: FixTarget) => {
    const i = preferred.indexOf(t);
    return i === -1 ? 100 : i;
  };
  return entries.sort((a, b) => rank(a[0]) - rank(b[0]));
}

/** Plain-language phrasing for checks that came back clean ("o que já está certo"). */
export const PASSED_LABEL: Record<string, string> = {
  "no-https": "O site usa HTTPS (cadeado)",
  "http-no-redirect": "Quem entra por http:// é levado para https://",
  "tls-invalid": "O certificado HTTPS é válido",
  "missing-hsts": "O navegador é instruído a usar sempre HTTPS",
  "missing-csp": "Existe uma política de scripts (CSP)",
  "weak-csp": "A política de scripts não está frouxa",
  "missing-clickjacking": "O site não pode ser embutido escondido em outro",
  "missing-nosniff": "O navegador não \"adivinha\" o tipo dos arquivos",
  "missing-referrer-policy": "Endereços completos não vazam para outros sites",
  "missing-permissions-policy": "Câmera, microfone e localização estão restritos",
  "server-version-leak": "O servidor não anuncia versões de software",
  "cookie-insecure": "Os cookies têm as travas de segurança",
  "cors-misconfig": "Outros sites não conseguem ler as respostas da API",
  "mixed-content": "Nada é carregado de endereços sem cadeado",
  "form-over-http": "Formulários enviam dados com criptografia",
  "secret-in-js": "Nenhuma chave secreta encontrada no código público",
  "supabase-service-role": "A chave-mestra do Supabase não está exposta",
  "vulnerable-library": "Nenhuma biblioteca com falha conhecida detectada",
  "missing-sri": "Scripts de CDN têm verificação de integridade",
  "exposed-sourcemap": "O código-fonte original não está publicado",
  "directory-listing": "Pastas do servidor não listam seus arquivos",
  "verbose-errors": "Nenhum erro técnico exposto na página",
};
