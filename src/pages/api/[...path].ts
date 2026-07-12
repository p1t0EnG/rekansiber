import type { APIRoute } from 'astro';
import honoApp from '../../server/hono-app';

// File ini menangkap SEMUA request ke /api/* dan meneruskannya ke Hono.
// Jadi semua routing (login, ioc/check, news, dashboard) diatur di
// src/server/hono-app.ts, bukan tersebar di banyak file Astro.
export const ALL: APIRoute = async (context) => {
  const env = context.locals.runtime.env;
  const ctx = context.locals.runtime.ctx;
  return honoApp.fetch(context.request, env, ctx);
};

export const prerender = false;
