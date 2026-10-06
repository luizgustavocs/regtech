import { OWASP } from "./owasp.ts";
import { resolveFinding, sortFindings, STACK_LABEL, SEVERITY_LABEL, type ResolvedFinding } from "./resolve.ts";
import type { Report, StackTag } from "./types.ts";

function stackText(stack: StackTag[]): string {
  if (stack.length === 0) return "uma stack que não consegui identificar (me pergunte se precisar)";
  return stack.map((s) => STACK_LABEL[s]).join(", ");
}

const RULES = `Regras:
- Faça a menor mudança possível e não quebre o que já funciona.
- Mostre quais arquivos mudar e o código completo de cada trecho alterado.
- Se algo precisar ser feito fora do código (painel da hospedagem, Supabase, trocar uma chave), me diga o passo a passo.
- Nunca escreva chaves, senhas ou tokens reais no código.
- No final, me diga como eu testo que ficou corrigido.`;

/** A prompt the user can paste into Cursor, Lovable, Bolt, Copilot, Claude Code... */
export function buildPrompt(r: ResolvedFinding, report: Pick<Report, "target" | "stack">): string {
  const cat = OWASP[r.owasp];
  const evidence = r.finding.evidence.length
    ? r.finding.evidence.slice(0, 12).map((e) => `- ${e}`).join("\n")
    : "- (sem evidência adicional)";

  return `Preciso corrigir um problema de segurança no meu projeto.

Contexto: o site ${report.target} usa ${stackText(report.stack)}.
Problema: ${r.technicalName} — OWASP Top 10:2025 ${r.owasp} (${cat.name})${r.cwe ? `, CWE-${r.cwe}` : ""}.
Em palavras simples: ${r.title}.

Evidência encontrada por um scanner externo:
${evidence}

O que eu preciso: ${r.aiTask}

${RULES}`;
}

/** One prompt with every fix, most urgent first — for "fix it all" sessions. */
export function buildFixPlanPrompt(report: Report): string {
  const items = sortFindings(report.findings.map(resolveFinding)).filter((r) => r.severity !== "info");
  if (items.length === 0) return "";

  const list = items
    .map((r, i) => {
      const ev = r.finding.evidence.slice(0, 5).map((e) => `   - ${e}`).join("\n");
      return `${i + 1}. [${SEVERITY_LABEL[r.severity]}] ${r.technicalName} (OWASP ${r.owasp})
   ${r.aiTask}${ev ? `\n   Evidência:\n${ev}` : ""}`;
    })
    .join("\n\n");

  return `Um scanner de segurança analisou meu site ${report.target} (stack: ${stackText(report.stack)}) e encontrou os problemas abaixo, do mais urgente para o menos urgente.

Corrija um por vez, nessa ordem. Antes de começar cada item, me diga em uma frase o que vai fazer; depois de terminar, me diga como testar. Se um item depender de algo que só eu posso fazer (painel, trocar chave), pare e me peça.

${list}

${RULES}`;
}
