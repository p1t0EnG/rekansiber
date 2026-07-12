import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

// https://docs.astro.build/en/guides/integrations-guide/cloudflare/
export default defineConfig({
  output: 'server', // wajib 'server' karena kita butuh API routes (login, IOC check) yang jalan di edge
  adapter: cloudflare({
    platformProxy: {
      enabled: true, // bikin D1/KV bindings bisa diakses saat `astro dev` di local
    },
  }),
});
