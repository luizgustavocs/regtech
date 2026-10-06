import { ScanApp } from "@/components/ScanApp";

const FEATURES = [
  {
    title: "Sem jargão",
    text: "Cada problema vem com uma analogia do dia a dia e o que pode acontecer de verdade se ninguém corrigir.",
  },
  {
    title: "Prompt pronto para a IA",
    text: "Copie e cole no Cursor, Lovable, Bolt ou Claude Code. O prompt já leva a sua stack e a evidência encontrada.",
  },
  {
    title: "Em ordem de urgência",
    text: "Você sabe o que resolver hoje e o que pode esperar. Inclui o que já está certo, para não mexer no que funciona.",
  },
  {
    title: "Fala a língua da LGPD",
    text: "Quando a falha envolve dados pessoais, explicamos a relação com a lei.",
  },
];

export default function Home() {
  return (
    <main className="mx-auto max-w-3xl px-4 pb-24 pt-10 sm:pt-16">
      <header className="no-print mb-10 sm:mb-12">
        <div className="mb-8 flex items-center gap-2 text-sm font-semibold tracking-tight">
          <svg viewBox="0 0 32 32" className="size-6" aria-hidden>
            <rect width="32" height="32" rx="8" className="fill-ink" />
            <path
              d="M16 6l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V9z"
              fill="none"
              className="stroke-bg"
              strokeWidth="2"
              strokeLinejoin="round"
            />
          </svg>
          Raio-X
        </div>
        <h1 className="text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">
          Seu site está seguro?
          <br />
          <span className="text-muted">Descubra em português claro.</span>
        </h1>
        <p className="mt-4 max-w-xl text-muted">
          Cole o endereço do seu app. Mostramos o que está exposto com base no OWASP Top 10, explicamos sem
          jargão e entregamos prompts prontos para a sua IA corrigir.
        </p>
      </header>

      <ScanApp />

      <section className="no-print mt-16 grid gap-6 sm:grid-cols-2">
        {FEATURES.map((f) => (
          <div key={f.title}>
            <h2 className="font-medium">{f.title}</h2>
            <p className="mt-1 text-sm text-muted">{f.text}</p>
          </div>
        ))}
      </section>

      <footer className="no-print mt-16 border-t border-line pt-6 text-xs leading-relaxed text-muted">
        Análise automática e passiva: não substitui um pentest. Use apenas em sites que são seus ou que você tem
        autorização para avaliar. Nenhum dado é armazenado.
      </footer>
    </main>
  );
}
