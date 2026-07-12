/// <reference types="astro/client" />

type CloudflareEnv = {
  DB: D1Database;
  NEWS_CACHE: KVNamespace;
  VT_API_KEY: string;
  ABUSEIPDB_API_KEY: string;
  OTX_API_KEY: string;
  SESSION_SECRET: string;
  APP_ENV: string;
};

// Supaya `Astro.locals.runtime.env` punya autocomplete & type-safety
type Runtime = import('@astrojs/cloudflare').Runtime<CloudflareEnv>;

declare namespace App {
  interface Locals extends Runtime {
    // Nanti kita isi `user` di sini setelah middleware auth dibuat,
    // supaya semua halaman bisa tahu siapa yang sedang login.
    user?: { id: number; email: string; role: 'admin' | 'member' } | null;
  }
}
