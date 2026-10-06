export interface SecretHit {
  kind: string;
  issueId: "secret-in-js" | "supabase-service-role" | "google-api-key";
  masked: string;
}

const PATTERNS: Array<{ kind: string; issueId: SecretHit["issueId"]; re: RegExp }> = [
  { kind: "Anthropic API key", issueId: "secret-in-js", re: /\bsk-ant-[a-z]+\d{2}-[A-Za-z0-9_-]{80,}/g },
  { kind: "OpenAI API key", issueId: "secret-in-js", re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/g },
  { kind: "OpenAI API key (legada)", issueId: "secret-in-js", re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g },
  { kind: "Stripe secret key", issueId: "secret-in-js", re: /\b[sr]k_live_[A-Za-z0-9]{20,}/g },
  { kind: "AWS access key", issueId: "secret-in-js", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: "GitHub token", issueId: "secret-in-js", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/g },
  { kind: "Slack token", issueId: "secret-in-js", re: /\bxox[abpr]-[A-Za-z0-9-]{20,}/g },
  { kind: "SendGrid API key", issueId: "secret-in-js", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { kind: "Groq API key", issueId: "secret-in-js", re: /\bgsk_[A-Za-z0-9]{48,}/g },
  { kind: "Hugging Face token", issueId: "secret-in-js", re: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { kind: "xAI API key", issueId: "secret-in-js", re: /\bxai-[A-Za-z0-9]{70,}/g },
  { kind: "Chave privada", issueId: "secret-in-js", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { kind: "Supabase secret key", issueId: "supabase-service-role", re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g },
  { kind: "Google API key", issueId: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

/** Never return a usable secret: just enough to recognise which key it is. */
export function mask(value: string): string {
  if (value.startsWith("-----BEGIN")) return value;
  return `${value.slice(0, 8)}…(${value.length} caracteres)`;
}

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const part = jwt.split(".")[1];
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export interface SupabaseSignals {
  projectUrls: Set<string>;
  anonKey: boolean;
}

export function findSecrets(code: string, supabase: SupabaseSignals): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();

  for (const p of PATTERNS) {
    for (const m of code.matchAll(p.re)) {
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      hits.push({ kind: p.kind, issueId: p.issueId, masked: mask(m[0]) });
    }
  }

  for (const m of code.matchAll(JWT_RE)) {
    if (seen.has(m[0])) continue;
    seen.add(m[0]);
    const payload = decodeJwtPayload(m[0]);
    if (!payload || payload.iss !== "supabase") continue;
    if (payload.role === "service_role") {
      hits.push({ kind: "Supabase service_role key", issueId: "supabase-service-role", masked: mask(m[0]) });
    } else if (payload.role === "anon") {
      supabase.anonKey = true;
    }
  }

  for (const m of code.matchAll(/https:\/\/([a-z0-9]{15,30})\.supabase\.co\b/g)) {
    supabase.projectUrls.add(m[0]);
  }
  if (/\bsb_publishable_[A-Za-z0-9_-]{20,}/.test(code)) supabase.anonKey = true;

  return hits;
}
