# Raio-X: website security in plain language

Free platform that runs a passive security check of a website against the **OWASP Top 10:2025** and explains every finding to non-specialists, with fix steps, a ready-to-use prompt for AI coding tools and the impact under Brazil's data protection law (**LGPD**). It also translates OWASP ZAP reports directly in the browser. **Nothing is stored.**

**Live:** [regtech-virid.vercel.app](https://regtech-virid.vercel.app) · Interface in Portuguese

## Highlights

- **Passive scan** (serverless function on Vercel): HTTPS and certificate, HTTP to HTTPS redirect, security headers (CSP, HSTS, X-Frame-Options), cookies, CORS, mixed content, secret keys exposed in public JavaScript (masked), Supabase `service_role` key, outdated libraries, SRI, source maps and verbose errors.
- **OWASP ZAP report translator:** reads the ZAP *Traditional JSON Report* and explains each alert; the file never leaves the browser.
- **Actionable output:** plain-language analogy, fix steps ordered by urgency with estimated effort, ready-made code for Next.js, Vercel, Netlify, Express, Nginx, Apache or Supabase SQL, LGPD impact and an honest map of what could not be verified.
- **Secure by design:** SSRF protection validated at DNS resolution (against DNS rebinding) and on every redirect, response size limit, timeout, rate limit of 5 scans per minute per IP, masked secrets and a strict nonce-based CSP.

## Tech stack

Next.js 16 (App Router) · TypeScript · Go · pnpm monorepo · Vercel

```
apps/
  web/        Next.js 16: interface and /api/scan route (deployed on Vercel)
  api/        Regulatory correlation engine in Go (not used by web yet)
packages/
  core/       Knowledge base, passive scanner, ZAP parser, prompts and scoring (TypeScript)
```

## Getting started

```bash
pnpm install
pnpm dev        # http://localhost:3000
pnpm test       # tests for packages/core
pnpm build
```

Deploy on Vercel: import the repository, set **Root Directory** to `apps/web` and deploy (no environment variables needed).

## Limitations

Automatic and passive analysis: it does not replace a penetration test. Issues that require active testing (injection, access control) should be checked with OWASP ZAP and imported in the second tab. **Use only on sites you own or are authorised to assess.**

## Author

Luiz Gustavo Costa e Silva · [GitHub](https://github.com/luizgustavocs) · [LinkedIn](https://www.linkedin.com/in/luizgustavocs)

---

## Versão em português

Plataforma gratuita que analisa um site com base no **OWASP Top 10:2025** e explica o resultado
para quem não é especialista (o famoso *vibe coder*). Cada problema vem com:

- uma **analogia do dia a dia** e o que pode acontecer de verdade;
- **passos de correção** em ordem de urgência, com esforço estimado;
- um **prompt pronto** para colar no Cursor, Lovable, Bolt, v0, Copilot ou Claude Code, já com a stack
  detectada (Next.js, Vercel, Supabase…) e a evidência encontrada;
- código pronto para Next.js, Vercel, Netlify, Express, Nginx, Apache ou SQL do Supabase;
- a relação com a **LGPD** quando a falha envolve dados pessoais;
- um mapa honesto do que foi e do que não foi possível verificar.

O relatório pode ser baixado em Markdown ou impresso em PDF. **Nada é armazenado.**

### Dois modos

| Modo | Onde roda | O que faz |
| --- | --- | --- |
| **Analisar um site** | Função serverless na Vercel | Análise **passiva**: abre a página como um visitante e verifica HTTPS/certificado, redirecionamento http→https, cabeçalhos de segurança (CSP, HSTS, X-Frame-Options…), cookies, CORS, conteúdo misto, chaves secretas no JavaScript público (mascaradas), chave `service_role` do Supabase, bibliotecas desatualizadas, SRI, source maps e erros verbosos. |
| **Traduzir relatório do ZAP** | No navegador do usuário | Lê o JSON do OWASP ZAP (*Traditional JSON Report*) e traduz cada alerta. O arquivo nunca sai do navegador. |

### Estrutura do monorepo

```
apps/
  web/        Next.js 16 (App Router): interface + rota /api/scan (deploy na Vercel)
  api/        Motor de correlação regulatória em Go (não usado pelo web; futuro deploy em Render/Railway)
packages/
  core/       Base de conhecimento, scanner passivo, parser do ZAP, prompts e pontuação (TypeScript)
```

### Deploy na Vercel (grátis)

1. Em vercel.com, vá em **Add New… > Project** e importe este repositório.
2. Em **Root Directory**, escolha `apps/web`. O framework (Next.js) e o pnpm são detectados sozinhos.
3. Clique em **Deploy**. Não há variáveis de ambiente.

A rota `/api/scan` usa `maxDuration = 60`, dentro do limite do plano Hobby.

### Desenvolvimento

```bash
pnpm install
pnpm dev        # http://localhost:3000
pnpm test       # testes do packages/core
pnpm build
```

### Segurança da própria plataforma

- Proteção contra SSRF: só `http`/`https`, portas 80/443/8080/8443, bloqueio de IPs privados,
  loopback, link-local e metadados de nuvem, validado também **na resolução DNS** (contra DNS rebinding)
  e a cada redirecionamento.
- Limite de tamanho de resposta, timeout e limite de 5 análises por minuto por IP.
- Chaves encontradas são sempre mascaradas antes de sair do servidor.
- CSP estrita com nonce, HSTS, X-Frame-Options, nosniff, Referrer-Policy e Permissions-Policy.

### Limites

É uma análise automática e passiva: não substitui um pentest. Falhas que exigem testes ativos
(injeção, controle de acesso) devem ser verificadas com o OWASP ZAP e importadas na segunda aba.
Use apenas em sites que são seus ou que você tem autorização para avaliar.
