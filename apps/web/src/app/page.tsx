import { DonationBanner } from "@/components/DonationBanner";
import { ScanApp } from "@/components/ScanApp";

const SOCIAL = [
  {
    label: "LinkedIn",
    href: "https://www.linkedin.com/in/luizgustavocs/",
    icon: "M4.98 3.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5zM3 9.75h4v11H3zm6.5 0h3.8v1.6h.06c.53-1 1.83-2.05 3.77-2.05 4.03 0 4.77 2.6 4.77 6v5.45h-4v-4.83c0-1.15-.02-2.63-1.6-2.63-1.6 0-1.85 1.25-1.85 2.55v4.91h-4z",
  },
  {
    label: "GitHub",
    href: "https://github.com/luizgustavocs",
    icon: "M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.56 9.56 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2z",
  },
];

const FEATURES = [
  {
    icon: "M4 6h16M4 12h10M4 18h7",
    title: "Sem jargão",
    text: "Cada problema vem com uma analogia do dia a dia e o que pode acontecer de verdade se ninguém corrigir.",
  },
  {
    icon: "M8 9l-3 3 3 3M16 9l3 3-3 3M13 7l-2 10",
    title: "Prompt pronto para a IA",
    text: "Copie e cole no Cursor, Lovable, Bolt ou Claude Code. O prompt já leva a sua stack e a evidência encontrada.",
  },
  {
    icon: "M4 17l5-5 4 4 7-7M14 9h6v6",
    title: "Em ordem de urgência",
    text: "Você sabe o que resolver hoje e o que pode esperar, e vê o que já está certo para não mexer no que funciona.",
  },
  {
    icon: "M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6z",
    title: "Fala a língua da LGPD",
    text: "Quando a falha envolve dados pessoais, explicamos a relação com a lei.",
  },
];

export default function Home() {
  return (
    <>
      <nav aria-label="Contato" className="no-print mx-auto flex max-w-5xl justify-end gap-1 px-4 pt-4">
        {SOCIAL.map((s) => (
          <a
            key={s.label}
            href={s.href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-medium text-muted transition hover:bg-surface hover:text-ink"
          >
            <svg viewBox="0 0 24 24" className="size-4" fill="currentColor" aria-hidden>
              <path d={s.icon} />
            </svg>
            {s.label}
          </a>
        ))}
      </nav>

      <main className="mx-auto max-w-3xl px-4 pb-24 pt-8 sm:pt-14">
        <section className="no-print mb-10 text-center sm:mb-12">
          <h1 className="text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            Seu site está seguro?
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-base leading-relaxed text-muted text-pretty sm:text-lg">
            Cole o endereço do seu app. Mostramos o que está exposto com base no OWASP Top 10, explicamos sem
            jargão e entregamos prompts prontos para a sua IA corrigir.
          </p>
        </section>

        <ScanApp />

        <section className="no-print mt-20 grid gap-4 sm:grid-cols-2">
          {FEATURES.map((f) => (
            <div key={f.title} className="rounded-2xl border border-line bg-surface p-5">
              <span className="mb-3 grid size-9 place-items-center rounded-lg bg-subtle text-accent">
                <svg viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d={f.icon} />
                </svg>
              </span>
              <h2 className="font-semibold">{f.title}</h2>
              <p className="mt-1 text-sm leading-relaxed text-muted">{f.text}</p>
            </div>
          ))}
        </section>
      </main>

      <footer className="no-print border-t border-line">
        <div className="mx-auto flex max-w-5xl flex-col items-center gap-2 px-4 pb-24 pt-8 text-center text-xs leading-relaxed text-muted">
          <p className="max-w-xl">
            Análise automática e passiva: não substitui um pentest. Use apenas em sites que são seus ou que você tem
            autorização para avaliar. Nenhum dado é armazenado.
          </p>
        </div>
      </footer>

      <DonationBanner />
    </>
  );
}
