import type { Context, Next } from 'hono';
import { getCookie } from 'hono/cookie';
import { getSessionUser, type SessionUser } from './session';

export const SESSION_COOKIE_NAME = 'session';

type Env = { Bindings: { DB: D1Database }; Variables: { user: SessionUser } };

// Middleware proteksi endpoint yang butuh login (dashboard, bulk checking, report, dst).
export async function requireAuth(c: Context<Env>, next: Next) {
  const token = getCookie(c, SESSION_COOKIE_NAME);
  const user = token ? await getSessionUser(c.env.DB, token) : null;

  if (!user) {
    return c.json({ error: 'Belum login' }, 401);
  }

  c.set('user', user);
  await next();
}

// Dipasang setelah requireAuth untuk endpoint yang cuma boleh diakses role tertentu
// (mis. generate report bulanan -- khusus admin).
export function requireRole(role: SessionUser['role']) {
  return async (c: Context<Env>, next: Next) => {
    const user = c.get('user');
    if (user.role !== role) {
      return c.json({ error: 'Khusus admin' }, 403);
    }
    await next();
  };
}
