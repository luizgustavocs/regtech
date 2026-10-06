export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** OWASP Top 10:2025 */
export type OwaspId =
  | "A01"
  | "A02"
  | "A03"
  | "A04"
  | "A05"
  | "A06"
  | "A07"
  | "A08"
  | "A09"
  | "A10";

export type StackTag =
  | "nextjs"
  | "react"
  | "vite"
  | "vercel"
  | "netlify"
  | "cloudflare"
  | "supabase"
  | "firebase"
  | "lovable"
  | "bolt"
  | "wordpress"
  | "php"
  | "express"
  | "nginx"
  | "apache";

/** Where a fix snippet applies. Hosting/server layer for headers, framework layer for code. */
export type FixTarget =
  | "nextjs"
  | "vercel"
  | "netlify"
  | "express"
  | "nginx"
  | "apache"
  | "supabase"
  | "firebase"
  | "generic";

export interface Finding {
  /** Knowledge-base issue id (see knowledge.ts). */
  issueId: string;
  severity: Severity;
  /** Technical evidence, shown under "detalhes técnicos" and fed into the AI prompt. */
  evidence: string[];
  source: "scan" | "zap";
  /** Overrides used when a ZAP alert has no dedicated knowledge entry. */
  override?: {
    title?: string;
    technicalName?: string;
    description?: string;
    solution?: string;
    cwe?: string;
    owasp?: OwaspId;
  };
}

export interface Report {
  target: string;
  finalUrl?: string;
  generatedAt: string;
  source: "scan" | "zap";
  stack: StackTag[];
  findings: Finding[];
  /** Issue ids that were checked and came back clean. */
  passed: string[];
  /** OWASP categories this report could actually inspect. */
  coverage: OwaspId[];
  notes: string[];
  durationMs?: number;
}
