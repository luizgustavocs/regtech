import { DonationBanner } from "@/components/DonationBanner";
import { ScanApp } from "@/components/ScanApp";

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
      <main className="mx-auto max-w-3xl px-4 pb-24 pt-14 sm:pt-20">
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
