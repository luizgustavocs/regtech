import { scan, ScanError } from "@regtech/core/scanner";
import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";

// Best-effort, per-instance limit. No database on purpose: nothing about a scan is stored.
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 5;
const hits = new Map<string, number[]>();

function limited(ip: string): boolean {
  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < WINDOW_MS);
  if (hits.size > 5_000) hits.clear();
  // Rejected attempts don't count, otherwise impatient retries would keep someone locked out.
  if (recent.length >= MAX_PER_WINDOW) return true;
  recent.push(now);
  hits.set(ip, recent);
  return false;
}

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "anon";
  if (limited(ip)) {
    return NextResponse.json({ error: "Muitas análises em sequência. Espere um minuto e tente de novo." }, { status: 429 });
  }

  let url: unknown;
  try {
    ({ url } = await req.json());
  } catch {
    return NextResponse.json({ error: "Requisição inválida." }, { status: 400 });
  }
  if (typeof url !== "string" || url.length > 2048) {
    return NextResponse.json({ error: "Informe o endereço do site." }, { status: 400 });
  }

  try {
    const report = await scan(url);
    return NextResponse.json(report, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    if (err instanceof ScanError) {
      const status = err.code === "INVALID_URL" || err.code === "BLOCKED" ? 400 : 502;
      return NextResponse.json({ error: err.message }, { status });
    }
    console.error("scan failed", err);
    return NextResponse.json({ error: "Algo deu errado na análise. Tente novamente." }, { status: 500 });
  }
}
