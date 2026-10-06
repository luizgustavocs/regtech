import assert from "node:assert/strict";
import { test } from "node:test";
import { buildFixPlanPrompt, buildPrompt } from "./prompt.ts";
import { resolveFinding } from "./resolve.ts";
import { isBlockedIp, normalizeTarget } from "./scanner/net.ts";
import { findSecrets } from "./scanner/secrets.ts";
import { computeScore } from "./score.ts";
import { parseZapReport, ZapParseError } from "./zap.ts";

test("SSRF guard blocks internal addresses", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "::1", "fd00::1", "::ffff:127.0.0.1", "100.64.0.1"]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) assert.equal(isBlockedIp(ip), false, ip);
  for (const u of ["localhost", "http://intranet", "ftp://x.com", "http://a:b@x.com", "http://x.com:22", "https://192.168.0.1"]) {
    assert.throws(() => normalizeTarget(u), u);
  }
  assert.equal(normalizeTarget("meusite.com.br").href, "https://meusite.com.br/");
});

test("secrets are detected and masked, Supabase roles decoded", () => {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = (role: string) => `eyJ${b64({ alg: "HS256" }).slice(3)}.${b64({ iss: "supabase", role })}.c2lnbmF0dXJlc2lnbmF0dXJl`;
  const openai = "sk-proj-" + "a".repeat(48);
  const sb = { projectUrls: new Set<string>(), anonKey: false };
  const hits = findSecrets(`const k="${openai}"; const s="${jwt("service_role")}"; const a="${jwt("anon")}"; fetch("https://abcdefghijklmnopqrst.supabase.co")`, sb);

  assert.deepEqual(hits.map((h) => h.issueId).sort(), ["secret-in-js", "supabase-service-role"]);
  assert.ok(hits.every((h) => !h.masked.includes(openai) && h.masked.includes("…")));
  assert.equal(sb.anonKey, true);
  assert.equal(sb.projectUrls.size, 1);
});

const zapSample = JSON.stringify({
  "@programName": "ZAP",
  "@version": "2.16.0",
  site: [
    {
      "@name": "https://exemplo.com",
      alerts: [
        { pluginid: "10038", alertRef: "10038-1", alert: "CSP Header Not Set", riskcode: "2", confidence: "3", cweid: "693", instances: [{ uri: "https://exemplo.com/", method: "GET" }], count: "3" },
        { pluginid: "10010", alert: "Cookie No HttpOnly Flag", riskcode: "1", cweid: "1004", instances: [{ uri: "https://exemplo.com/", param: "sid" }] },
        { pluginid: "10054", alert: "Cookie without SameSite Attribute", riskcode: "1", cweid: "1275", instances: [] },
        { pluginid: "99999", alert: "Alerta Novo", riskcode: "3", cweid: "79", desc: "<p>Algo &amp; mais</p>", solution: "<p>Corrija</p>", instances: [] },
      ],
    },
  ],
});

test("ZAP report is translated and merged", () => {
  const r = parseZapReport(zapSample);
  assert.equal(r.target, "https://exemplo.com");
  const ids = r.findings.map((f) => f.issueId);
  assert.deepEqual(ids, ["missing-csp", "cookie-insecure", "zap-99999"]);
  assert.ok(r.findings[0].evidence.some((e) => e.includes("mais 2")));

  const unknown = resolveFinding(r.findings[2]);
  assert.equal(unknown.owasp, "A05");
  assert.equal(unknown.risk, "Algo & mais");

  const prompt = buildPrompt(resolveFinding(r.findings[0]), r);
  assert.match(prompt, /OWASP Top 10:2025 A02/);
  assert.match(buildFixPlanPrompt(r), /1\. \[Alta\]/);

  assert.throws(() => parseZapReport("not json"), ZapParseError);
  assert.throws(() => parseZapReport("{}"), ZapParseError);
});

test("score caps grade when something is critical", () => {
  assert.equal(computeScore([]).grade, "A");
  const s = computeScore([{ issueId: "exposed-env", severity: "critical", evidence: [], source: "scan" }]);
  assert.equal(s.grade, "F");
  assert.equal(computeScore([{ issueId: "missing-hsts", severity: "low", evidence: [], source: "scan" }]).grade, "A");
});
