import type { Finding, Severity } from "./types.ts";

const PENALTY: Record<Severity, number> = { critical: 35, high: 15, medium: 7, low: 2, info: 0 };

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface Score {
  value: number;
  grade: Grade;
  headline: string;
  counts: Record<Severity, number>;
}

export function computeScore(findings: Finding[]): Score {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  // The same issue reported several times (e.g. many ZAP instances) only costs once.
  const seen = new Set<string>();
  let value = 100;
  for (const f of findings) {
    counts[f.severity]++;
    const key = `${f.issueId}:${f.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    value -= PENALTY[f.severity];
  }
  value = Math.max(0, value);
  if (counts.critical > 0) value = Math.min(value, 39);
  else if (counts.high > 0) value = Math.min(value, 69);

  const grade: Grade = value >= 90 ? "A" : value >= 75 ? "B" : value >= 60 ? "C" : value >= 40 ? "D" : "F";

  let headline: string;
  if (counts.critical > 0) {
    headline =
      counts.critical === 1
        ? "Tem 1 problema urgente. Pare o que está fazendo e resolva este primeiro."
        : `Tem ${counts.critical} problemas urgentes. Resolva estes antes de qualquer outra coisa.`;
  } else if (counts.high > 0) {
    headline = `Nada catastrófico, mas ${counts.high === 1 ? "1 problema importante precisa" : `${counts.high} problemas importantes precisam`} de atenção esta semana.`;
  } else if (counts.medium + counts.low > 0) {
    headline = "Base boa. Faltam alguns ajustes de configuração que levam poucos minutos.";
  } else {
    headline = "Nenhum problema encontrado no que conseguimos ver de fora. Ótimo trabalho!";
  }

  return { value, grade, headline, counts };
}
