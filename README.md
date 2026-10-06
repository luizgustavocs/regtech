# Raio-X — segurança do seu site em português claro

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

## Dois modos

| Modo | Onde roda | O que faz |
| --- | --- | --- |
| **Analisar um site** | Função serverless na Vercel | Análise **passiva**: abre a página como um visitante e verifica HTTPS/certificado, redirecionamento http→https, cabeçalhos de segurança (CSP, HSTS, X-Frame-Options…), cookies, CORS, conteúdo misto, chaves secretas no JavaScript público (mascaradas), chave `service_role` do Supabase, bibliotecas desatualizadas, SRI, source maps e erros verbosos. |
| **Traduzir relatório do ZAP** | No navegador do usuário | Lê o JSON do OWASP ZAP (*Traditional JSON Report*) e traduz cada alerta. O arquivo nunca sai do navegador. |

## Estrutura do monorepo

```
apps/
  web/        Next.js 16 (App Router) — interface + rota /api/scan (deploy na Vercel)
  api/        Motor de correlação regulatória em Go (não usado pelo web; futuro deploy em Render/Railway)
packages/
  core/       Base de conhecimento, scanner passivo, parser do ZAP, prompts e pontuação (TypeScript)
```

## Deploy na Vercel (grátis)

1. Em vercel.com → **Add New… → Project**, importe este repositório.
2. Em **Root Directory**, escolha `apps/web`. O framework (Next.js) e o pnpm são detectados sozinhos.
3. Clique em **Deploy**. Não há variáveis de ambiente.

A rota `/api/scan` usa `maxDuration = 60`, dentro do limite do plano Hobby.

## Desenvolvimento

```bash
pnpm install
pnpm dev        # http://localhost:3000
pnpm test       # testes do packages/core
pnpm build
```

## Segurança da própria plataforma

- Proteção contra SSRF: só `http`/`https`, portas 80/443/8080/8443, bloqueio de IPs privados,
  loopback, link-local e metadados de nuvem — validado também **na resolução DNS** (contra DNS rebinding)
  e a cada redirecionamento.
- Limite de tamanho de resposta, timeout e limite de 5 análises por minuto por IP.
- Chaves encontradas são sempre mascaradas antes de sair do servidor.
- CSP estrita com nonce, HSTS, X-Frame-Options, nosniff, Referrer-Policy e Permissions-Policy.

## Limites

É uma análise automática e passiva: não substitui um pentest. Falhas que exigem testes ativos
(injeção, controle de acesso) devem ser verificadas com o OWASP ZAP e importadas na segunda aba.
Use apenas em sites que são seus ou que você tem autorização para avaliar.
