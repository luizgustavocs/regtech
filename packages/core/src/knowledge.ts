import { RECOMMENDED_HEADERS as H, headerSnippets } from "./snippets.ts";
import type { FixTarget, OwaspId, Severity } from "./types.ts";

export interface Issue {
  id: string;
  owasp: OwaspId;
  cwe?: string;
  severity: Severity;
  /** Rough time for someone with an AI assistant to fix it. */
  effort: string;
  /** Plain-language title. Must make sense to someone who never heard of OWASP. */
  title: string;
  technicalName: string;
  /** "É como se..." — an everyday analogy. */
  analogy: string;
  /** What can really happen if nothing is done. */
  risk: string;
  steps: string[];
  /** Instruction given to the user's AI assistant (Cursor, Lovable, Bolt, Copilot...). */
  aiTask: string;
  snippets?: Partial<Record<FixTarget, string>>;
  lgpd?: string;
}

const LGPD_46 =
  "LGPD, art. 46: quem trata dados pessoais precisa adotar medidas de segurança técnicas aptas a proteger esses dados. Uma falha básica e conhecida enfraquece a sua defesa se houver um incidente.";
const LGPD_48 =
  "LGPD, art. 48: se dados pessoais vazarem, você pode ter que comunicar a ANPD e os titulares. Corrigir antes é muito mais barato.";

const ISSUES: Issue[] = [
  // ───────────── Transporte / HTTPS ─────────────
  {
    id: "no-https",
    owasp: "A04",
    cwe: "319",
    severity: "critical",
    effort: "15 min",
    title: "Seu site não usa HTTPS (o cadeado)",
    technicalName: "Cleartext transmission (no TLS)",
    analogy:
      "É como mandar cartas sem envelope: qualquer pessoa no caminho (o Wi-Fi do café, o provedor) pode ler e até alterar o que está escrito.",
    risk: "Senhas, e-mails e dados de formulários trafegam abertos. O navegador ainda mostra \"Não seguro\" para os seus visitantes.",
    steps: [
      "Na Vercel, Netlify e Cloudflare o HTTPS é gratuito e automático: confira se o domínio está configurado no painel da hospedagem.",
      "Em servidor próprio, instale um certificado gratuito do Let's Encrypt (ex.: com o Certbot).",
      "Depois, faça o endereço http:// redirecionar para https://.",
    ],
    aiTask:
      "Me ajude a ativar HTTPS no meu site e a redirecionar todo o tráfego http:// para https://, considerando onde ele está hospedado.",
    lgpd: LGPD_46,
  },
  {
    id: "http-no-redirect",
    owasp: "A04",
    cwe: "319",
    severity: "medium",
    effort: "5 min",
    title: "A versão sem cadeado (http://) do seu site não manda o visitante para a versão segura",
    technicalName: "HTTP to HTTPS redirect missing",
    analogy:
      "Você tem uma porta blindada, mas deixou a porta dos fundos aberta e sem placa indicando a entrada certa.",
    risk: "Quem digitar o endereço sem https, ou clicar num link antigo, navega sem criptografia.",
    steps: [
      "Configure um redirecionamento permanente (301/308) de http:// para https://.",
      "Na Vercel/Netlify isso é automático para domínios configurados no painel; confira se o domínio está lá.",
    ],
    aiTask: "Configure um redirecionamento permanente de http:// para https:// em todas as rotas do meu site.",
    snippets: {
      nginx: `server {
  listen 80;
  server_name seu-dominio.com;
  return 301 https://$host$request_uri;
}`,
      apache: `RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`,
      express: `app.set("trust proxy", 1);
app.use((req, res, next) => {
  if (req.secure) return next();
  res.redirect(308, "https://" + req.headers.host + req.originalUrl);
});`,
    },
  },
  {
    id: "tls-invalid",
    owasp: "A04",
    cwe: "295",
    severity: "high",
    effort: "15 min",
    title: "O certificado de segurança (cadeado) do seu site está com problema",
    technicalName: "Invalid TLS certificate",
    analogy: "É como um documento de identidade vencido ou de outra pessoa: o navegador não confia em quem está do outro lado.",
    risk: "Os visitantes veem um aviso assustador de \"Sua conexão não é particular\" e a maioria vai embora. Quem continua fica vulnerável a interceptação.",
    steps: [
      "Verifique se o certificado expirou ou se foi emitido para outro domínio (ex.: www vs. sem www).",
      "Renove o certificado. Na Vercel/Netlify/Cloudflare, remova e adicione o domínio de novo no painel se a renovação travou.",
    ],
    aiTask: "O certificado TLS do meu site é inválido. Me ajude a descobrir o motivo (expirado, domínio errado, cadeia incompleta) e a corrigir.",
  },
  {
    id: "missing-hsts",
    owasp: "A04",
    cwe: "319",
    severity: "low",
    effort: "5 min",
    title: "O navegador não é instruído a usar sempre a versão segura do seu site",
    technicalName: "Strict-Transport-Security (HSTS) header missing",
    analogy: "É como avisar ao porteiro: \"nunca deixe ninguém entrar pela porta dos fundos, nem se pedirem com jeitinho\".",
    risk: "Num Wi-Fi público, um atacante pode forçar a primeira visita a acontecer sem criptografia e roubar a sessão.",
    steps: ["Adicione o cabeçalho Strict-Transport-Security nas respostas do site (exemplo abaixo)."],
    aiTask: `Adicione o cabeçalho de resposta "${H.hsts[0]}: ${H.hsts[1]}" em todas as rotas do meu site.`,
    snippets: headerSnippets([H.hsts]),
  },
  {
    id: "mixed-content",
    owasp: "A04",
    cwe: "311",
    severity: "medium",
    effort: "15 min",
    title: "Sua página segura carrega arquivos de endereços sem cadeado (http://)",
    technicalName: "Mixed content",
    analogy: "É como trancar a porta da frente, mas deixar uma janela aberta.",
    risk: "Scripts carregados por http:// podem ser trocados por um atacante, que passa a controlar a sua página. O navegador também pode bloquear esses arquivos e quebrar o layout.",
    steps: [
      "Troque todos os links http:// por https:// no código (imagens, scripts, fontes, iframes).",
      "Se o recurso não existir em https, baixe o arquivo e sirva a partir do seu próprio site.",
    ],
    aiTask: "Encontre no meu código todos os recursos carregados com http:// (scripts, imagens, CSS, iframes, fontes) e troque por https:// ou por arquivos locais.",
  },
  {
    id: "form-over-http",
    owasp: "A04",
    cwe: "319",
    severity: "high",
    effort: "5 min",
    title: "Um formulário do seu site envia dados para um endereço sem cadeado",
    technicalName: "Form submits to HTTP endpoint",
    analogy: "É como entregar a senha do banco escrita num cartão-postal.",
    risk: "O que o usuário digita (inclusive senhas) viaja sem criptografia e pode ser lido no caminho.",
    steps: ["Troque o action do formulário para https:// ou para um caminho relativo (ex.: /api/contato)."],
    aiTask: "Encontre formulários cujo action aponta para http:// e troque por https:// ou por um caminho relativo.",
    lgpd: LGPD_46,
  },

  // ───────────── Cabeçalhos de proteção ─────────────
  {
    id: "missing-csp",
    owasp: "A02",
    cwe: "693",
    severity: "medium",
    effort: "1 hora",
    title: "Seu site não tem uma \"lista de convidados\" para scripts",
    technicalName: "Content-Security-Policy (CSP) header missing",
    analogy:
      "É uma festa sem lista na porta: se alguém conseguir colar um script malicioso na sua página, o navegador executa sem questionar.",
    risk: "Torna ataques de XSS (injeção de script) muito mais perigosos: roubo de sessão, redirecionamento para golpes, captura do que o usuário digita.",
    steps: [
      "Comece com o cabeçalho Content-Security-Policy-Report-Only (só observa, não bloqueia) para não quebrar nada.",
      "Abra o site, veja no console do navegador o que seria bloqueado e adicione os domínios legítimos (analytics, fontes, Supabase etc.).",
      "Quando o console estiver limpo, troque para Content-Security-Policy.",
    ],
    aiTask:
      "Crie uma Content-Security-Policy para o meu site. Liste todos os domínios externos que meu código realmente usa (scripts, estilos, fontes, imagens, APIs como Supabase/Firebase/analytics) e monte a política a partir deles. Comece em modo Report-Only e me explique como passar para o modo que bloqueia. Se o framework precisar de nonce para scripts inline (ex.: Next.js), implemente.",
    snippets: headerSnippets([H.csp]),
  },
  {
    id: "weak-csp",
    owasp: "A02",
    cwe: "693",
    severity: "low",
    effort: "1 hora",
    title: "Sua \"lista de convidados\" para scripts deixa entrar quase qualquer um",
    technicalName: "Weak Content-Security-Policy",
    analogy: "A festa tem lista, mas a lista diz \"pode entrar quem quiser\".",
    risk: "A política existe, mas não impede scripts injetados de rodar, então a proteção contra XSS é pequena.",
    steps: [
      "Remova 'unsafe-eval' se possível.",
      "Troque 'unsafe-inline' em script-src por nonces ou hashes.",
      "Evite curingas como * ou https: em script-src.",
    ],
    aiTask: "Minha Content-Security-Policy está fraca (veja a evidência). Endureça a política removendo unsafe-inline/unsafe-eval/curingas de script-src, usando nonce ou hash onde for necessário, sem quebrar o site.",
  },
  {
    id: "missing-clickjacking",
    owasp: "A02",
    cwe: "1021",
    severity: "medium",
    effort: "5 min",
    title: "Outro site pode colocar o seu dentro de uma moldura invisível",
    technicalName: "Clickjacking protection missing (X-Frame-Options / frame-ancestors)",
    analogy:
      "É como alguém colocar um vidro transparente com botões falsos em cima do seu caixa eletrônico: o usuário acha que clica numa coisa e clica em outra.",
    risk: "Um site malicioso pode carregar o seu escondido e enganar usuários logados para clicar em \"excluir conta\", \"transferir\" ou \"dar permissão\".",
    steps: ["Adicione X-Frame-Options: DENY (ou frame-ancestors 'none' na CSP)."],
    aiTask: `Adicione os cabeçalhos "${H.xfo[0]}: ${H.xfo[1]}" e "Content-Security-Policy: frame-ancestors 'none'" (mesclando com a CSP existente, se houver) em todas as rotas.`,
    snippets: headerSnippets([H.xfo]),
  },
  {
    id: "missing-nosniff",
    owasp: "A02",
    cwe: "693",
    severity: "low",
    effort: "5 min",
    title: "O navegador pode \"adivinhar\" o tipo dos seus arquivos",
    technicalName: "X-Content-Type-Options header missing",
    analogy: "É como um segurança que deixa passar uma caixa só porque parece com a encomenda, sem ler a etiqueta.",
    risk: "Um arquivo enviado por usuário (ex.: uma \"imagem\") pode ser executado como script.",
    steps: ["Adicione X-Content-Type-Options: nosniff."],
    aiTask: `Adicione o cabeçalho "${H.nosniff[0]}: ${H.nosniff[1]}" em todas as rotas.`,
    snippets: headerSnippets([H.nosniff]),
  },
  {
    id: "missing-referrer-policy",
    owasp: "A02",
    cwe: "200",
    severity: "low",
    effort: "5 min",
    title: "Seu site conta para outros sites o endereço completo de onde o visitante veio",
    technicalName: "Referrer-Policy header missing",
    analogy: "É como entregar a ficha do paciente inteira quando só precisava dizer de qual hospital ele veio.",
    risk: "Endereços com tokens, e-mails ou IDs (ex.: /reset?token=...) podem vazar para sites externos e ferramentas de analytics.",
    steps: ["Adicione Referrer-Policy: strict-origin-when-cross-origin."],
    aiTask: `Adicione o cabeçalho "${H.referrer[0]}: ${H.referrer[1]}" em todas as rotas.`,
    snippets: headerSnippets([H.referrer]),
    lgpd: "Vazar URLs com e-mail ou identificadores para terceiros pode ser compartilhamento de dado pessoal sem base legal (LGPD, art. 7º).",
  },
  {
    id: "missing-permissions-policy",
    owasp: "A02",
    cwe: "693",
    severity: "info",
    effort: "5 min",
    title: "Você não restringiu o acesso a câmera, microfone e localização",
    technicalName: "Permissions-Policy header missing",
    analogy: "É como deixar as chaves de todos os cômodos penduradas na porta, mesmo dos que você nunca usa.",
    risk: "Se um script de terceiro for comprometido, ele pode tentar usar recursos sensíveis do navegador.",
    steps: ["Adicione Permissions-Policy desligando o que o site não usa."],
    aiTask: `Adicione o cabeçalho "${H.permissions[0]}: ${H.permissions[1]}", liberando apenas os recursos que meu site realmente usa.`,
    snippets: headerSnippets([H.permissions]),
  },
  {
    id: "server-version-leak",
    owasp: "A02",
    cwe: "200",
    severity: "low",
    effort: "5 min",
    title: "Seu servidor anuncia qual software e versão ele usa",
    technicalName: "Server / X-Powered-By version disclosure",
    analogy: "É como colar na porta de casa o modelo exato da sua fechadura.",
    risk: "Facilita para robôs procurarem falhas conhecidas daquela versão específica.",
    steps: [
      "Remova ou esconda os cabeçalhos Server e X-Powered-By.",
      "Mais importante: mantenha o software atualizado.",
    ],
    aiTask: "Remova os cabeçalhos que revelam tecnologia e versão (X-Powered-By, Server com versão) das respostas do meu site.",
    snippets: {
      nextjs: `// next.config.js
module.exports = { poweredByHeader: false };`,
      express: `app.disable("x-powered-by");
// ou use helmet(), que já faz isso`,
      nginx: `# no bloco http { ... }
server_tokens off;`,
      apache: `ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By`,
    },
  },
  {
    id: "cookie-insecure",
    owasp: "A07",
    cwe: "614",
    severity: "medium",
    effort: "15 min",
    title: "Seus cookies estão sem as travas de segurança",
    technicalName: "Cookie without Secure / HttpOnly / SameSite",
    analogy: "O cookie é o crachá do usuário logado. Sem essas travas, é um crachá que qualquer script consegue copiar ou que pode ser usado por outro site.",
    risk: "Um script injetado pode roubar a sessão (sem HttpOnly), o cookie pode vazar numa conexão sem cadeado (sem Secure) ou ser usado por outro site para agir em nome do usuário (sem SameSite).",
    steps: [
      "Cookies de login/sessão: sempre HttpOnly, Secure e SameSite=Lax (ou Strict).",
      "Se o cookie é criado por uma biblioteca (auth, sessão), procure as opções \"secure\", \"httpOnly\" e \"sameSite\" dela.",
    ],
    aiTask: "Encontre onde os cookies listados na evidência são criados e adicione os atributos Secure, HttpOnly (se o JavaScript do navegador não precisar lê-lo) e SameSite=Lax.",
    snippets: {
      express: `res.cookie("session", valor, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
});`,
      nextjs: `// Route Handler / Server Action
import { cookies } from "next/headers";
(await cookies()).set("session", valor, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
});`,
    },
    lgpd: LGPD_46,
  },
  {
    id: "cors-misconfig",
    owasp: "A01",
    cwe: "942",
    severity: "high",
    effort: "15 min",
    title: "Qualquer site do mundo pode ler as respostas da sua API",
    technicalName: "Permissive CORS policy",
    analogy: "É como o banco aceitar ordens de transferência vindas de qualquer agência, até de uma agência falsa montada pelo golpista.",
    risk: "Se um usuário logado visitar um site malicioso, esse site pode chamar a sua API em nome dele e ler os dados que voltarem.",
    steps: [
      "Troque o curinga (*) ou o \"espelhamento\" de origem por uma lista fixa dos seus domínios.",
      "Nunca combine Access-Control-Allow-Credentials: true com origem aberta.",
    ],
    aiTask: "Minha configuração de CORS aceita qualquer origem (veja a evidência). Troque por uma lista explícita dos meus domínios (produção e localhost em desenvolvimento) e não permita credentials para origens desconhecidas.",
    snippets: {
      express: `const cors = require("cors");
app.use(cors({
  origin: ["https://seu-dominio.com"],
  credentials: true,
}));`,
      nextjs: `// Route Handler: só devolva o header para origens conhecidas
const ALLOWED = new Set(["https://seu-dominio.com"]);
const origin = req.headers.get("origin") ?? "";
const headers = ALLOWED.has(origin)
  ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" }
  : {};`,
    },
    lgpd: LGPD_46,
  },

  // ───────────── Arquivos expostos ─────────────
  {
    id: "exposed-env",
    owasp: "A02",
    cwe: "538",
    severity: "critical",
    effort: "1 hora",
    title: "Seu arquivo de senhas (.env) está público na internet",
    technicalName: "Environment file (.env) publicly accessible",
    analogy: "É como deixar o caderninho com todas as senhas da empresa pregado na porta de entrada.",
    risk: "Robôs varrem a internet atrás desse arquivo o tempo todo. Com ele, alguém acessa seu banco de dados, gasta seus créditos de IA, envia e-mails em seu nome e baixa dados de clientes.",
    steps: [
      "URGENTE: considere TODAS as chaves desse arquivo como roubadas. Gere chaves novas em cada serviço (banco, Supabase, OpenAI, Stripe...) e apague as antigas.",
      "Remova o .env da pasta pública / do build e garanta que ele está no .gitignore.",
      "Coloque as variáveis no painel da hospedagem (Vercel/Netlify → Environment Variables).",
    ],
    aiTask:
      "Meu arquivo .env está sendo servido publicamente. 1) Descubra por que ele está acessível (pasta public, configuração do servidor, build copiando arquivos). 2) Corrija para que nunca seja servido. 3) Confira o .gitignore. 4) Me dê uma lista de cada chave que preciso rotacionar e onde fazer isso. NÃO repita os valores das chaves na resposta.",
    snippets: {
      nginx: `# bloqueia qualquer arquivo que começa com ponto (.env, .git...)
location ~ /\\. {
  deny all;
  return 404;
}`,
      apache: `<FilesMatch "^\\.">
  Require all denied
</FilesMatch>`,
    },
    lgpd: LGPD_48,
  },
  {
    id: "exposed-git",
    owasp: "A02",
    cwe: "538",
    severity: "critical",
    effort: "15 min",
    title: "O histórico completo do seu código (.git) pode ser baixado por qualquer pessoa",
    technicalName: "Git repository exposed (.git/)",
    analogy: "É como publicar o projeto inteiro da sua casa, com a localização do cofre e todas as versões antigas das chaves.",
    risk: "Existem ferramentas prontas que reconstroem o código inteiro a partir disso, incluindo senhas que um dia foram commitadas, mesmo que já tenham sido apagadas.",
    steps: [
      "Bloqueie o acesso à pasta .git no servidor (ou não envie essa pasta no deploy).",
      "Procure no histórico do Git por senhas e chaves já commitadas e rotacione todas.",
    ],
    aiTask: "A pasta .git do meu projeto está acessível publicamente. Corrija o deploy/servidor para nunca servir arquivos que começam com ponto, e me ajude a verificar se há segredos no histórico do Git que precisem ser trocados.",
    snippets: {
      nginx: `location ~ /\\.git {
  deny all;
  return 404;
}`,
      apache: `RedirectMatch 404 /\\.git`,
    },
    lgpd: LGPD_48,
  },
  {
    id: "exposed-file",
    owasp: "A02",
    cwe: "538",
    severity: "high",
    effort: "15 min",
    title: "Arquivos internos do servidor estão acessíveis publicamente",
    technicalName: "Sensitive file exposure",
    analogy: "É como deixar documentos da contabilidade em cima do balcão da loja.",
    risk: "Backups de banco, páginas de diagnóstico e arquivos de configuração revelam dados de clientes, senhas e detalhes da sua infraestrutura.",
    steps: [
      "Apague os arquivos listados da pasta pública do servidor.",
      "Se for um backup de banco de dados, trate como vazamento: veja quais dados ele contém.",
    ],
    aiTask: "Os arquivos listados na evidência estão acessíveis publicamente no meu site. Me ajude a removê-los do deploy e a configurar o servidor para nunca servir esse tipo de arquivo (backups, dumps, phpinfo, arquivos de sistema).",
    lgpd: LGPD_48,
  },
  {
    id: "exposed-sourcemap",
    owasp: "A02",
    cwe: "540",
    severity: "low",
    effort: "5 min",
    title: "O código-fonte original do seu front-end está publicado",
    technicalName: "JavaScript source maps publicly accessible",
    analogy: "É entregar, junto com o produto, a receita detalhada com comentários do chef.",
    risk: "Facilita entender a sua lógica, achar rotas escondidas e chaves esquecidas no código. Não é grave sozinho, mas ajuda quem quer atacar.",
    steps: ["Desative a geração de source maps em produção (ou envie-os só para a sua ferramenta de monitoramento de erros)."],
    aiTask: "Desative a publicação de source maps (.map) do JavaScript em produção no meu projeto, mantendo-os em desenvolvimento.",
    snippets: {
      nextjs: `// next.config.js — já é false por padrão; confira se não foi ligado
module.exports = { productionBrowserSourceMaps: false };`,
      generic: `// vite.config.js
export default { build: { sourcemap: false } };`,
    },
  },
  {
    id: "directory-listing",
    owasp: "A01",
    cwe: "548",
    severity: "medium",
    effort: "5 min",
    title: "Qualquer pessoa pode ver a lista de arquivos de uma pasta do seu servidor",
    technicalName: "Directory listing enabled",
    analogy: "É como uma vitrine que mostra também o estoque inteiro dos fundos.",
    risk: "Expõe arquivos que você nem sabia que estavam lá: uploads de usuários, backups, documentos.",
    steps: ["Desative a listagem de diretórios no servidor."],
    aiTask: "Desative a listagem de diretórios (directory listing) no meu servidor.",
    snippets: {
      nginx: `autoindex off;`,
      apache: `Options -Indexes`,
    },
  },

  // ───────────── Segredos e backends ─────────────
  {
    id: "secret-in-js",
    owasp: "A07",
    cwe: "798",
    severity: "critical",
    effort: "1 hora",
    title: "Uma chave secreta está escondida no código que vai para o navegador",
    technicalName: "Hardcoded secret in client-side JavaScript",
    analogy:
      "Tudo o que vai para o navegador é público, como um panfleto. Colocar a chave da API ali é imprimir a senha do cartão de crédito no panfleto.",
    risk: "Qualquer pessoa abre o código do site (F12) e copia a chave. Resultado comum: conta de OpenAI/Anthropic/AWS de milhares de reais em poucas horas, ou acesso total ao banco.",
    steps: [
      "URGENTE: revogue a chave no painel do serviço e gere uma nova.",
      "Mova a chamada desse serviço para o servidor (API route, Edge Function, Server Action). O navegador chama o SEU servidor, que chama o serviço com a chave.",
      "Coloque a chave nova numa variável de ambiente SEM o prefixo público (NEXT_PUBLIC_, VITE_, REACT_APP_ expõem a variável no navegador).",
    ],
    aiTask:
      "Uma chave secreta está no JavaScript que vai para o navegador (veja a evidência). 1) Encontre onde ela é usada. 2) Mova essa chamada para o lado do servidor (API route / server action / edge function, de acordo com meu framework). 3) Leia a chave de uma variável de ambiente sem prefixo público (nada de NEXT_PUBLIC_/VITE_/REACT_APP_). 4) Faça o front-end chamar a nova rota. 5) Me lembre de revogar a chave antiga. Não escreva o valor da chave em nenhum arquivo.",
    lgpd: LGPD_46,
  },
  {
    id: "supabase-service-role",
    owasp: "A07",
    cwe: "798",
    severity: "critical",
    effort: "1 hora",
    title: "A chave-mestra do seu Supabase está no navegador",
    technicalName: "Supabase service_role key exposed client-side",
    analogy:
      "A chave anon do Supabase é a chave da recepção. A service_role é a chave-mestra que abre todas as portas, ignorando todas as regras. Ela está no panfleto.",
    risk: "Qualquer pessoa pode ler, alterar e apagar TODOS os dados de TODAS as tabelas, incluindo dados de usuários. As regras de RLS não valem para essa chave.",
    steps: [
      "URGENTE: no painel do Supabase, gere novas chaves (Settings → API) para invalidar a antiga.",
      "No front-end, use apenas a chave anon/publishable.",
      "Operações que precisam da service_role devem rodar só no servidor (Edge Function, API route).",
    ],
    aiTask:
      "A service_role key do Supabase está no código do navegador. Troque o cliente do front-end para usar a anon/publishable key, mova toda operação que precisava da service_role para o servidor (Supabase Edge Function ou API route), leia a chave de variável de ambiente sem prefixo público e garanta que as tabelas têm RLS. Não escreva o valor da chave em nenhum arquivo.",
    lgpd: LGPD_48,
  },
  {
    id: "supabase-rls-open",
    owasp: "A01",
    cwe: "284",
    severity: "critical",
    effort: "1 hora",
    title: "Tabelas do seu banco (Supabase) podem ser lidas por qualquer pessoa",
    technicalName: "Supabase tables readable with anon key (RLS disabled or permissive)",
    analogy:
      "A chave anon do Supabase é pública por design: a segurança depende das regras de cada tabela (RLS). Sem regras, é um arquivo de clientes aberto na calçada.",
    risk: "Qualquer pessoa, só com o endereço do seu site, consegue baixar o conteúdo dessas tabelas: e-mails, nomes, telefones, pedidos. Este é o vazamento mais comum em apps feitos com IA.",
    steps: [
      "No Supabase, vá em Authentication → Policies (ou Table Editor) e ative RLS em cada tabela listada.",
      "Crie políticas que deixem cada usuário ver só os próprios dados, por exemplo: auth.uid() = user_id.",
      "Tabelas que realmente precisam ser públicas (ex.: lista de produtos) devem ter uma política só de leitura, e nunca colunas sensíveis.",
    ],
    aiTask:
      "As tabelas listadas na evidência do meu Supabase podem ser lidas com a anon key. Escreva as migrations SQL que: 1) ativam Row Level Security em cada uma; 2) criam políticas para que cada usuário só leia/escreva os próprios registros (usando auth.uid()); 3) mantêm leitura pública apenas onde fizer sentido para o produto, me perguntando antes. Depois, ajuste o código do front-end se alguma consulta deixar de funcionar.",
    snippets: {
      supabase: `-- exemplo para uma tabela "profiles" com coluna user_id
alter table public.profiles enable row level security;

create policy "cada um le o proprio perfil"
  on public.profiles for select
  using (auth.uid() = user_id);

create policy "cada um edita o proprio perfil"
  on public.profiles for update
  using (auth.uid() = user_id);`,
    },
    lgpd: LGPD_48,
  },
  {
    id: "supabase-check-rls",
    owasp: "A01",
    cwe: "284",
    severity: "info",
    effort: "15 min",
    title: "Seu site usa Supabase: confira se todas as tabelas têm RLS",
    technicalName: "Supabase detected — verify Row Level Security",
    analogy: "A chave anon que aparece no seu site é como o endereço do prédio: pode ser público. O que protege cada apartamento são as regras de RLS.",
    risk: "Não conseguimos listar suas tabelas de fora, então não dá para garantir. Tabela sem RLS = dados públicos.",
    steps: [
      "No painel do Supabase, abra o Security Advisor (Advisors → Security) e resolva os alertas \"RLS disabled\".",
      "Teste logado como um usuário tentando ler dados de outro.",
    ],
    aiTask: "Liste todas as tabelas do meu projeto Supabase que o front-end usa e confira se cada uma tem RLS ativo e políticas corretas (cada usuário só acessa os próprios dados). Gere as migrations SQL que faltarem.",
  },
  {
    id: "firebase-db-open",
    owasp: "A01",
    cwe: "284",
    severity: "critical",
    effort: "15 min",
    title: "Seu banco do Firebase está aberto para leitura pública",
    technicalName: "Firebase Realtime Database world-readable",
    analogy: "É um arquivo compartilhado com \"qualquer pessoa com o link pode ver\" — e o link está no seu site.",
    risk: "Qualquer pessoa pode baixar o banco inteiro com um único comando.",
    steps: [
      "No console do Firebase → Realtime Database → Regras, troque \".read\": true por regras baseadas em auth.",
      "Use o Simulador de Regras para testar antes de publicar.",
    ],
    aiTask: "Meu Firebase Realtime Database está com leitura pública. Escreva regras de segurança em que cada usuário só lê e escreve nos próprios dados (usando auth.uid), mantendo pública apenas a parte que precisa ser pública, me perguntando antes.",
    snippets: {
      firebase: `{
  "rules": {
    ".read": false,
    ".write": false,
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}`,
    },
    lgpd: LGPD_48,
  },
  {
    id: "google-api-key",
    owasp: "A07",
    cwe: "798",
    severity: "low",
    effort: "5 min",
    title: "Uma chave do Google aparece no código do site — confira se ela está restrita",
    technicalName: "Google API key in client-side code",
    analogy: "Algumas chaves do Google (Maps, Firebase) são feitas para ficar no site, mas precisam de um \"só funciona no meu endereço\".",
    risk: "Sem restrição, outras pessoas usam a sua chave e a conta vem para você. Se ela der acesso a APIs pagas como Gemini, o prejuízo pode ser alto.",
    steps: [
      "No Google Cloud Console → APIs e serviços → Credenciais, restrinja a chave ao seu domínio (referenciadores HTTP).",
      "Restrinja também quais APIs a chave pode usar. Nunca use a mesma chave para APIs de IA no navegador.",
    ],
    aiTask: "Há uma chave de API do Google no meu front-end. Me diga para que ela está sendo usada no código e, se for uma API paga ou de IA (ex.: Gemini), mova a chamada para o servidor. Me lembre de restringir a chave por domínio no Google Cloud Console.",
  },

  // ───────────── Bibliotecas / integridade ─────────────
  {
    id: "vulnerable-library",
    owasp: "A03",
    cwe: "1104",
    severity: "medium",
    effort: "1 hora",
    title: "Seu site usa uma biblioteca antiga com falhas de segurança conhecidas",
    technicalName: "Outdated JavaScript library with known vulnerabilities",
    analogy: "É usar uma fechadura cujo modelo já teve o segredo publicado na internet.",
    risk: "As falhas dessas versões são públicas e há receitas prontas para explorá-las (geralmente XSS).",
    steps: [
      "Atualize a biblioteca para a versão mais recente.",
      "Rode npm audit (ou pnpm audit) no projeto e resolva os alertas.",
    ],
    aiTask: "Atualize as bibliotecas listadas na evidência para versões sem vulnerabilidades conhecidas, ajustando o código onde a atualização quebrar compatibilidade. Depois rode npm audit e resolva o que for alto/crítico.",
  },
  {
    id: "missing-sri",
    owasp: "A08",
    cwe: "353",
    severity: "low",
    effort: "15 min",
    title: "Scripts de outros sites são carregados sem verificação de integridade",
    technicalName: "Third-party script without Subresource Integrity (SRI)",
    analogy: "É aceitar uma encomenda sem conferir o lacre.",
    risk: "Se o CDN de terceiro for invadido, o código malicioso roda no seu site com acesso a tudo que o usuário faz.",
    steps: [
      "Para arquivos de versão fixa em CDN, adicione o atributo integrity=\"sha384-...\" e crossorigin=\"anonymous\".",
      "Ou instale a biblioteca pelo npm e sirva junto com o seu código.",
    ],
    aiTask: "Para os scripts externos listados na evidência, adicione Subresource Integrity (integrity + crossorigin) com o hash correto da versão usada, ou instale a biblioteca via npm e importe localmente.",
  },

  // ───────────── Erros ─────────────
  {
    id: "verbose-errors",
    owasp: "A10",
    cwe: "209",
    severity: "medium",
    effort: "15 min",
    title: "Quando dá erro, seu site mostra detalhes internos do sistema",
    technicalName: "Verbose error messages / stack trace disclosure",
    analogy: "É o atendente que, quando não acha seu pedido, lê em voz alta o manual interno da empresa.",
    risk: "Mensagens de erro técnicas revelam caminhos de arquivos, versões, consultas SQL e às vezes até senhas, ajudando quem quer atacar.",
    steps: [
      "Em produção, mostre uma página de erro genérica (\"Algo deu errado\").",
      "Registre o erro detalhado só nos logs do servidor.",
      "Garanta que o modo debug/desenvolvimento está desligado em produção.",
    ],
    aiTask: "Meu site exibe stack traces/erros detalhados em produção (veja a evidência). Configure tratamento de erros para mostrar mensagem genérica ao usuário, registrar os detalhes só no servidor e garantir que o modo debug está desligado em produção.",
  },

  // ───────────── Vindos do ZAP (ataques ativos) ─────────────
  {
    id: "xss",
    owasp: "A05",
    cwe: "79",
    severity: "high",
    effort: "1 hora",
    title: "Alguém pode injetar código na sua página através de um campo ou link",
    technicalName: "Cross-Site Scripting (XSS)",
    analogy: "É um mural onde qualquer um pode escrever, e o que escrevem vira uma ordem que os visitantes obedecem.",
    risk: "Um link malicioso enviado para um usuário pode roubar a sessão dele, mostrar formulários falsos ou fazer ações em nome dele.",
    steps: [
      "Nunca insira texto do usuário direto no HTML (innerHTML, dangerouslySetInnerHTML, v-html).",
      "Se precisar exibir HTML do usuário, limpe com DOMPurify.",
      "Adicione uma Content-Security-Policy como segunda camada.",
    ],
    aiTask: "O ZAP encontrou XSS no parâmetro/URL da evidência. Encontre no código onde esse valor é colocado na página sem escape (innerHTML, dangerouslySetInnerHTML, v-html, template sem escape) e corrija usando renderização segura ou DOMPurify.",
    lgpd: LGPD_46,
  },
  {
    id: "sqli",
    owasp: "A05",
    cwe: "89",
    severity: "critical",
    effort: "1 hora",
    title: "Alguém pode dar ordens direto para o seu banco de dados através de um campo",
    technicalName: "SQL Injection",
    analogy: "É como se, no formulário de \"nome\", alguém escrevesse \"Maria; e me entregue todos os clientes\" e o sistema obedecesse.",
    risk: "Leitura, alteração ou exclusão de todo o banco de dados, inclusive senhas e dados pessoais.",
    steps: [
      "Nunca monte SQL juntando texto (\"SELECT ... WHERE id = \" + id).",
      "Use consultas parametrizadas ou um ORM (Prisma, Drizzle, query builder do Supabase).",
    ],
    aiTask: "O ZAP encontrou SQL Injection no parâmetro da evidência. Encontre a consulta que usa esse parâmetro e reescreva com consultas parametrizadas/ORM. Procure no projeto outras consultas montadas por concatenação de strings e corrija também.",
    lgpd: LGPD_48,
  },
  {
    id: "injection-other",
    owasp: "A05",
    cwe: "74",
    severity: "high",
    effort: "1 hora",
    title: "Um dado enviado pelo usuário é executado pelo seu servidor",
    technicalName: "Injection (command / template / XML / expression)",
    analogy: "É o sistema confundir um dado (\"o que o cliente escreveu\") com uma ordem (\"o que eu devo fazer\").",
    risk: "Dependendo do tipo, permite executar comandos no servidor, ler arquivos internos ou derrubar o sistema.",
    steps: [
      "Nunca passe entrada do usuário para comandos do sistema, eval, templates ou parsers sem validação.",
      "Valide a entrada contra uma lista do que é permitido.",
    ],
    aiTask: "O ZAP encontrou uma falha de injeção (veja tipo e parâmetro na evidência). Encontre onde esse parâmetro chega ao comando/template/parser e corrija com validação por lista de permitidos e APIs seguras (sem concatenação, sem eval, sem shell).",
  },
  {
    id: "csrf",
    owasp: "A01",
    cwe: "352",
    severity: "medium",
    effort: "1 hora",
    title: "Outro site pode enviar formulários no seu site em nome de um usuário logado",
    technicalName: "Cross-Site Request Forgery (CSRF)",
    analogy: "É alguém preencher um cheque e fazer você assinar sem ler, só porque você estava com a caneta na mão.",
    risk: "Um site malicioso pode fazer o usuário trocar o e-mail, a senha ou fazer compras sem perceber.",
    steps: [
      "Use cookies de sessão com SameSite=Lax ou Strict.",
      "Em formulários que mudam dados, use token anti-CSRF (a maioria dos frameworks tem pronto).",
    ],
    aiTask: "O ZAP indicou formulários sem proteção anti-CSRF. Verifique se os cookies de sessão usam SameSite=Lax/Strict e adicione proteção CSRF (token ou checagem de Origin) nas rotas que alteram dados.",
  },
  {
    id: "open-redirect",
    owasp: "A01",
    cwe: "601",
    severity: "medium",
    effort: "15 min",
    title: "Seu site pode ser usado para mandar pessoas para sites de golpe",
    technicalName: "Open Redirect",
    analogy: "É como um funcionário da sua loja apontar para a loja do golpista e dizer \"é ali, pode confiar\".",
    risk: "Golpistas usam links com o SEU domínio (que parecem confiáveis) para levar vítimas a páginas de phishing.",
    steps: ["Aceite só destinos de redirecionamento de uma lista fixa ou apenas caminhos internos (que começam com /)."],
    aiTask: "O parâmetro de redirecionamento da evidência aceita qualquer URL. Restrinja para aceitar apenas caminhos relativos internos ou domínios de uma lista permitida.",
  },
  {
    id: "path-traversal",
    owasp: "A01",
    cwe: "22",
    severity: "high",
    effort: "1 hora",
    title: "Alguém pode ler arquivos internos do servidor manipulando um endereço",
    technicalName: "Path Traversal",
    analogy: "É pedir \"o documento da gaveta 3\" e receber o documento da gaveta do chefe porque escreveu \"../chefe\".",
    risk: "Leitura de arquivos de configuração, senhas e código-fonte do servidor.",
    steps: ["Nunca monte caminhos de arquivo com entrada do usuário; use IDs e uma tabela de correspondência."],
    aiTask: "O ZAP encontrou path traversal no parâmetro da evidência. Corrija para que a entrada do usuário nunca vire caminho de arquivo diretamente (use IDs ou normalize e valide que o caminho final fica dentro da pasta permitida).",
  },
  {
    id: "pii-disclosure",
    owasp: "A01",
    cwe: "359",
    severity: "high",
    effort: "1 hora",
    title: "Dados pessoais aparecem em respostas do seu site",
    technicalName: "PII disclosure",
    analogy: "É deixar a lista de clientes com CPF visível na tela do caixa.",
    risk: "Vazamento de dados pessoais, o tipo de incidente que a LGPD mais pune.",
    steps: [
      "Revise as respostas da API: devolva só os campos que a tela usa.",
      "Mascare dados sensíveis (ex.: ***.123.456-**).",
    ],
    aiTask: "O ZAP encontrou dados pessoais (CPF, cartão, e-mail etc.) nas respostas listadas na evidência. Ajuste as consultas e respostas da API para devolver só os campos necessários e mascarar dados sensíveis.",
    lgpd: "LGPD, art. 6º, III (necessidade) e art. 46: trate só o mínimo de dados necessário e proteja-os.",
  },
  {
    id: "info-leak-comments",
    owasp: "A02",
    cwe: "615",
    severity: "info",
    effort: "5 min",
    title: "Há comentários no código público que podem revelar informações internas",
    technicalName: "Information disclosure — suspicious comments",
    analogy: "São bilhetinhos internos esquecidos no balcão.",
    risk: "Geralmente inofensivo, mas às vezes revela rotas, nomes de servidores ou TODOs de segurança.",
    steps: ["Revise os trechos da evidência e remova comentários sensíveis do código que vai para produção."],
    aiTask: "Revise os comentários apontados na evidência e remova do código de produção os que revelem informações internas.",
  },
];

export const KNOWLEDGE: Record<string, Issue> = Object.fromEntries(ISSUES.map((i) => [i.id, i]));

export function getIssue(id: string): Issue | undefined {
  return KNOWLEDGE[id];
}
