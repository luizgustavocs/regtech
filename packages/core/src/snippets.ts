import type { FixTarget } from "./types.ts";

export type HeaderSet = Array<[name: string, value: string]>;

export const RECOMMENDED_HEADERS = {
  hsts: ["Strict-Transport-Security", "max-age=63072000; includeSubDomains"],
  csp: [
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
  ],
  xfo: ["X-Frame-Options", "DENY"],
  nosniff: ["X-Content-Type-Options", "nosniff"],
  referrer: ["Referrer-Policy", "strict-origin-when-cross-origin"],
  permissions: ["Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"],
} satisfies Record<string, [string, string]>;

/** Ready-to-paste config that adds the given response headers, one variant per hosting/framework. */
export function headerSnippets(headers: HeaderSet): Partial<Record<FixTarget, string>> {
  const js = headers.map(([k, v]) => `      { key: ${JSON.stringify(k)}, value: ${JSON.stringify(v)} },`).join("\n");
  const json = headers
    .map(([k, v]) => `        { "key": ${JSON.stringify(k)}, "value": ${JSON.stringify(v)} }`)
    .join(",\n");

  return {
    nextjs: `// next.config.js (ou next.config.ts)
const nextConfig = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
${js}
        ],
      },
    ];
  },
};

module.exports = nextConfig; // em .ts/.mjs: export default nextConfig`,
    vercel: `// vercel.json (na raiz do projeto) — funciona para qualquer site na Vercel
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
${json}
      ]
    }
  ]
}`,
    netlify: `# arquivo public/_headers (ou na pasta que vai para o deploy)
/*
${headers.map(([k, v]) => `  ${k}: ${v}`).join("\n")}`,
    express: `// npm install helmet — configura quase todos esses cabeçalhos de uma vez
const helmet = require("helmet");
app.use(helmet());

// ou manualmente:
app.use((req, res, next) => {
${headers.map(([k, v]) => `  res.setHeader(${JSON.stringify(k)}, ${JSON.stringify(v)});`).join("\n")}
  next();
});`,
    nginx: `# dentro do bloco server { ... }
${headers.map(([k, v]) => `add_header ${k} "${v.replace(/"/g, '\\"')}" always;`).join("\n")}`,
    apache: `# .htaccess (requer mod_headers)
${headers.map(([k, v]) => `Header always set ${k} "${v.replace(/"/g, '\\"')}"`).join("\n")}`,
  };
}
