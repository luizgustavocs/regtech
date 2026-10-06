import dns from "node:dns";
import net from "node:net";
import { Agent, fetch, type Response } from "undici";

export type ScanErrorCode = "INVALID_URL" | "BLOCKED" | "UNREACHABLE" | "TIMEOUT" | "TLS";

export class ScanError extends Error {
  readonly code: ScanErrorCode;
  constructor(message: string, code: ScanErrorCode) {
    super(message);
    this.code = code;
  }
}

// Private, loopback, link-local, CGNAT, multicast and cloud-metadata ranges: never fetched (SSRF guard).
const blocked = new net.BlockList();
for (const [addr, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(addr, prefix, "ipv4");
}
for (const [addr, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["64:ff9b::", 96],
  ["2001:db8::", 32],
] as const) {
  blocked.addSubnet(addr, prefix, "ipv6");
}

export function isBlockedIp(ip: string): boolean {
  const mapped = ip.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return blocked.check(mapped[1], "ipv4");
  const family = net.isIP(ip);
  if (family === 4) return blocked.check(ip, "ipv4");
  if (family === 6) return blocked.check(ip, "ipv6");
  return true;
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void;

/** DNS lookup that refuses internal addresses at connect time, so DNS rebinding can't sneak past the URL check. */
function safeLookup(hostname: string, options: dns.LookupOptions, callback: LookupCb) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, []);
    const list = addresses as dns.LookupAddress[];
    if (list.length === 0 || list.some((a) => isBlockedIp(a.address))) {
      const e = new Error(`Endereço interno bloqueado: ${hostname}`) as NodeJS.ErrnoException;
      e.code = "EBLOCKED";
      return callback(e, []);
    }
    if (options.all) callback(null, list);
    else callback(null, list[0].address, list[0].family);
  });
}

const agent = new Agent({
  connect: { lookup: safeLookup as never, timeout: 6_000, rejectUnauthorized: true, autoSelectFamily: true },
  headersTimeout: 8_000,
  bodyTimeout: 8_000,
});

const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);
const UA = "RaioX-SecurityCheck/1.0 (+passive scan; https://github.com/luizgustavolab/regtech)";

export function normalizeTarget(input: string): URL {
  let raw = input.trim();
  if (!raw) throw new ScanError("Informe o endereço do site.", "INVALID_URL");
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ScanError("Esse endereço não parece válido. Exemplo: meusite.com.br", "INVALID_URL");
  }
  assertPublicUrl(url);
  url.hash = "";
  return url;
}

export function assertPublicUrl(url: URL): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScanError("Só analisamos endereços http:// ou https://.", "INVALID_URL");
  }
  if (url.username || url.password) throw new ScanError("Remova usuário/senha do endereço.", "INVALID_URL");
  if (!ALLOWED_PORTS.has(url.port)) throw new ScanError("Porta não permitida.", "BLOCKED");
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new ScanError("Endereços internos ou privados não podem ser analisados.", "BLOCKED");
    return;
  }
  if (!host.includes(".") || /(^|\.)(localhost|local|internal|intranet|lan|home|corp)$/.test(host)) {
    throw new ScanError("Endereços internos ou privados não podem ser analisados.", "BLOCKED");
  }
}

export interface FetchedPage {
  url: string;
  status: number;
  headers: Headers;
  setCookies: string[];
  body: string;
  redirects: string[];
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  const buf = new Uint8Array(Math.min(size, maxBytes));
  let off = 0;
  for (const c of chunks) {
    const take = Math.min(c.byteLength, buf.byteLength - off);
    buf.set(c.subarray(0, take), off);
    off += take;
    if (off >= buf.byteLength) break;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

function mapError(err: unknown, url: URL): ScanError {
  const e = err as { code?: string; cause?: { code?: string; message?: string }; name?: string };
  const code = e.cause?.code ?? e.code ?? "";
  if (code === "EBLOCKED") return new ScanError("Endereços internos ou privados não podem ser analisados.", "BLOCKED");
  if (e.name === "TimeoutError" || /TIMEOUT/i.test(code)) return new ScanError(`${url.host} demorou demais para responder.`, "TIMEOUT");
  if (/CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(code)) return new ScanError(`O certificado HTTPS de ${url.host} é inválido.`, "TLS");
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new ScanError(`Não encontramos o domínio ${url.host}. Confira se digitou certo.`, "UNREACHABLE");
  return new ScanError(`Não foi possível conectar em ${url.host}.`, "UNREACHABLE");
}

/** GET with manual redirects (each hop re-validated), size cap and timeout. */
export async function safeGet(
  start: URL,
  opts: { maxBytes?: number; maxRedirects?: number; timeoutMs?: number; accept?: string } = {},
): Promise<FetchedPage> {
  const { maxBytes = 1_500_000, maxRedirects = 5, timeoutMs = 10_000, accept = "text/html,*/*;q=0.8" } = opts;
  let url = start;
  const redirects: string[] = [];

  for (let hop = 0; hop <= maxRedirects; hop++) {
    assertPublicUrl(url);
    let res: Response;
    try {
      res = await fetch(url, {
        dispatcher: agent,
        redirect: "manual",
        headers: { "user-agent": UA, accept, "accept-language": "pt-BR,pt;q=0.9,en;q=0.8" },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw mapError(err, url);
    }

    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location && hop < maxRedirects) {
      await res.body?.cancel().catch(() => {});
      redirects.push(`${res.status} ${url.href} → ${location}`);
      url = new URL(location, url);
      continue;
    }

    const body = await readCapped(res, maxBytes).catch(() => "");
    return {
      url: url.href,
      status: res.status,
      headers: res.headers as unknown as Headers,
      setCookies: res.headers.getSetCookie?.() ?? [],
      body,
      redirects,
    };
  }
  throw new ScanError("O site redireciona vezes demais.", "UNREACHABLE");
}

/** Fetches a resource the page itself references (scripts), as a browser would. Never throws. */
export async function tryGet(url: URL, maxBytes: number): Promise<FetchedPage | null> {
  try {
    return await safeGet(url, { maxBytes, maxRedirects: 2, timeoutMs: 8_000, accept: "*/*" });
  } catch {
    return null;
  }
}
