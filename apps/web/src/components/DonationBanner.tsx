"use client";

import { useEffect, useState } from "react";
import { CopyButton } from "./CopyButton";

const PIX_COPIA_E_COLA =
  "00020126440014br.gov.bcb.pix01226379769@vakinha.com.br5204000053039865802BR5901N6001C62070503***63046A42";

const STORAGE_KEY = "raiox:pix-minimized";

/** Floating Pix donation card. Fixed to the viewport so it stays visible while scrolling. */
export function DonationBanner() {
  // Starts expanded on wide screens and minimized on phones, where it would cover the content.
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let stored: string | null = null;
    try {
      stored = localStorage.getItem(STORAGE_KEY);
    } catch {}
    const wide = window.matchMedia("(min-width: 1360px)").matches;
    setOpen(stored === null ? wide : stored === "0");
  }, []);

  function toggle(next: boolean) {
    setOpen(next);
    try {
      localStorage.setItem(STORAGE_KEY, next ? "0" : "1");
    } catch {}
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => toggle(true)}
        className="no-print fixed bottom-4 right-4 z-50 inline-flex items-center gap-2 rounded-full bg-cta px-4 py-2.5 text-sm font-semibold text-cta-ink shadow-lg transition hover:brightness-110 sm:bottom-6 sm:right-6"
        aria-label="Abrir doação via Pix"
      >
        <HeartIcon />
        Apoie o projeto
      </button>
    );
  }

  return (
    <aside
      aria-label="Doação via Pix"
      className="no-print fixed bottom-4 right-4 z-50 w-[min(15rem,calc(100vw-2rem))] rounded-2xl border border-line bg-surface p-4 shadow-2xl shadow-accent/15 sm:bottom-6 sm:right-6"
    >
      <button
        type="button"
        onClick={() => toggle(false)}
        className="absolute right-2 top-2 grid size-7 place-items-center rounded-full text-muted transition hover:bg-subtle hover:text-ink"
        aria-label="Minimizar"
      >
        <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
          <path d="M6 6l12 12M18 6L6 18" />
        </svg>
      </button>

      <p className="flex items-center gap-2 pr-6 text-sm font-semibold">
        <span className="text-cta">
          <HeartIcon />
        </span>
        Apoie o Raio-X
      </p>
      <p className="mt-2 text-xs leading-relaxed text-muted">
        Se esse projeto contribuiu de alguma forma para a melhoria do seu código, considere realizar uma doação de
        qualquer valor. O projeto é gratuito e continuará sendo.
      </p>

      <div className="mt-3 rounded-xl bg-white p-2">
        {/* Plain <img>: a 7 KB QR code doesn't need the image optimizer. */}
        <img src="/pix.png" alt="QR Code Pix para doação" width={280} height={280} className="mx-auto size-40" />
      </div>

      <div className="mt-3 flex justify-center">
        <CopyButton text={PIX_COPIA_E_COLA} label="Copiar Pix copia e cola" variant="solid" />
      </div>
    </aside>
  );
}

function HeartIcon() {
  return (
    <svg viewBox="0 0 24 24" className="size-4" fill="currentColor" aria-hidden>
      <path d="M12 21s-7.5-4.6-9.6-9.2C.9 8.4 3 4.5 6.8 4.5c2.1 0 3.6 1.1 4.4 2.5.8-1.4 2.3-2.5 4.4-2.5 3.8 0 5.9 3.9 4.4 7.3C19.5 16.4 12 21 12 21z" />
    </svg>
  );
}
