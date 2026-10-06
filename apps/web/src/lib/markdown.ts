import {
  buildFixPlanPrompt,
  buildPrompt,
  computeScore,
  OWASP,
  resolveFinding,
  SEVERITY_LABEL,
  sortFindings,
  STACK_LABEL,
  type Report,
} from "@regtech/core";

export function reportToMarkdown(report: Report): string {
  const score = computeScore(report.findings);
  const items = sortFindings(report.findings.map(resolveFinding));
  const lines: string[] = [];

  lines.push(`# Raio-X de segurança — ${report.target}`);
  lines.push("");
  lines.push(`Gerado em ${new Date(report.generatedAt).toLocaleString("pt-BR")} · Nota **${score.grade}** (${score.value}/100)`);
  if (report.stack.length) lines.push(`Stack detectada: ${report.stack.map((s) => STACK_LABEL[s]).join(", ")}`);
  lines.push("");
  lines.push(`> ${score.headline}`);
  lines.push("");

  items.forEach((r, i) => {
    lines.push(`## ${i + 1}. [${SEVERITY_LABEL[r.severity]}] ${r.title}`);
    lines.push("");
    lines.push(`*${r.technicalName} — OWASP ${r.owasp} (${OWASP[r.owasp].name})${r.cwe ? ` · CWE-${r.cwe}` : ""} · esforço: ${r.effort}*`);
    lines.push("");
    lines.push(`**O que é:** ${r.analogy}`);
    lines.push("");
    lines.push(`**O que pode acontecer:** ${r.risk}`);
    lines.push("");
    lines.push("**Como corrigir:**");
    r.steps.forEach((s) => lines.push(`- ${s}`));
    if (r.lgpd) {
      lines.push("");
      lines.push(`**LGPD:** ${r.lgpd}`);
    }
    lines.push("");
    lines.push("**Prompt para a sua IA:**");
    lines.push("");
    lines.push("```text");
    lines.push(buildPrompt(r, report));
    lines.push("```");
    lines.push("");
  });

  const plan = buildFixPlanPrompt(report);
  if (plan) {
    lines.push("## Plano completo para a IA");
    lines.push("");
    lines.push("```text");
    lines.push(plan);
    lines.push("```");
    lines.push("");
  }

  if (report.notes.length) {
    lines.push("## Observações");
    report.notes.forEach((n) => lines.push(`- ${n}`));
  }
  return lines.join("\n");
}

export function download(filename: string, content: string, type = "text/markdown") {
  const url = URL.createObjectURL(new Blob([content], { type: `${type};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
