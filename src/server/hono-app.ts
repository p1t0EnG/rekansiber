import { Hono } from 'hono';
import { setCookie, getCookie, deleteCookie } from 'hono/cookie';
import { isValidIoc } from './ioc/validate';
import { checkIoc } from './ioc/check';
import { checkRateLimit } from './ioc/rate-limit';
import { MAX_BULK_ITEMS, type IocType } from './ioc/types';
import { verifyPassword } from './auth/password';
import { createSession, getSessionUser, deleteSession, type SessionUser } from './auth/session';
import { requireAuth, SESSION_COOKIE_NAME } from './auth/middleware';
import { getDashboardStats } from './dashboard/stats';

// Bindings ini datang dari wrangler.toml (D1, KV) + .dev.vars / dashboard (API keys)
type Bindings = {
  DB: D1Database;
  NEWS_CACHE: KVNamespace;
  VT_API_KEY: string;
  ABUSEIPDB_API_KEY: string;
  OTX_API_KEY: string;
  SESSION_SECRET: string;
};

type Variables = { user: SessionUser };

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>().basePath('/api');

const VALID_TYPES: IocType[] = ['ip', 'domain', 'hash', 'url'];

// --- Health check, buat mastiin deploy berhasil ---
app.get('/health', (c) => c.json({ status: 'ok', time: new Date().toISOString() }));

// --- IOC Checker (publik, tanpa login) ---
app.post('/ioc/check', async (c) => {
  const body = await c.req.json<{ value: string; type: IocType }>().catch(() => null);

  if (!body?.value || !body?.type) {
    return c.json({ error: 'value dan type wajib diisi' }, 400);
  }
  if (!VALID_TYPES.includes(body.type)) {
    return c.json({ error: `type harus salah satu dari: ${VALID_TYPES.join(', ')}` }, 400);
  }
  if (!isValidIoc(body.value, body.type)) {
    return c.json({ error: `Format value tidak valid untuk type ${body.type}` }, 400);
  }

  const clientIp = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rateLimit = await checkRateLimit(c.env.NEWS_CACHE, clientIp);
  if (!rateLimit.allowed) {
    return c.json({ error: 'Terlalu banyak permintaan, coba lagi sebentar lagi' }, 429);
  }

  const { verdict, providers } = await checkIoc(c.env, body.value, body.type);

  await c.env.DB.prepare(
    `INSERT INTO ioc_checks (user_id, ioc_value, ioc_type, source, verdict, result_summary)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(null, body.value, body.type, 'public', verdict, JSON.stringify(providers))
    .run();

  return c.json({ value: body.value, type: body.type, verdict, providers });
});

// --- Bulk IOC Checker (tim SOC, butuh login) ---
// Upload banyak IOC sekaligus (type sudah dideteksi otomatis di frontend), diproses
// paralel, disimpan ke ioc_checks dengan source: 'soc' + user_id anggota yang login.
app.post('/ioc/bulk-check', requireAuth, async (c) => {
  const body = await c.req.json<{ items: { value: string; type: IocType }[] }>().catch(() => null);

  if (!body?.items || !Array.isArray(body.items) || body.items.length === 0) {
    return c.json({ error: 'items wajib diisi (array of {value, type})' }, 400);
  }
  if (body.items.length > MAX_BULK_ITEMS) {
    return c.json({ error: `Maksimal ${MAX_BULK_ITEMS} IOC per batch` }, 400);
  }

  const user = c.get('user');

  const results = await Promise.all(
    body.items.map(async (item) => {
      if (!item?.value || !VALID_TYPES.includes(item.type) || !isValidIoc(item.value, item.type)) {
        return {
          value: item?.value ?? '',
          type: item?.type ?? null,
          verdict: 'unknown' as const,
          error: 'Format tidak valid',
          providers: [],
        };
      }

      const { verdict, providers } = await checkIoc(c.env, item.value, item.type);

      await c.env.DB.prepare(
        `INSERT INTO ioc_checks (user_id, ioc_value, ioc_type, source, verdict, result_summary)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(user.id, item.value, item.type, 'soc', verdict, JSON.stringify(providers))
        .run();

      return { value: item.value, type: item.type, verdict, providers };
    }),
  );

  return c.json({ results });
});

// --- Berita CVE & Ransomware (dibaca dari cache KV, diisi oleh Cron Trigger) ---
// TODO tahap coding berikutnya: bikin Worker terpisah dengan `scheduled()` handler
// yang fetch RSS TheHackerNews / RansomHub tiap beberapa jam lalu simpan ke KV.
app.get('/news/cve', async (c) => {
  const cached = await c.env.NEWS_CACHE.get('cve-latest', 'json');
  return c.json(cached ?? { items: [], message: 'Belum ada data cache' });
});

// --- Auth: login tim SOC ---
// Akun tim dibuat lewat `npm run user:create -- <email> <password> "<nama>" <role>`,
// bukan lewat form publik -- lihat scripts/create-user.mjs.
app.post('/auth/login', async (c) => {
  const body = await c.req.json<{ email: string; password: string }>().catch(() => null);

  if (!body?.email || !body?.password) {
    return c.json({ error: 'email dan password wajib diisi' }, 400);
  }

  const user = await c.env.DB.prepare(
    'SELECT id, email, password_hash, full_name, role FROM users WHERE email = ?',
  )
    .bind(body.email)
    .first<{ id: number; email: string; password_hash: string; full_name: string; role: 'admin' | 'member' }>();

  if (!user || !(await verifyPassword(body.password, user.password_hash))) {
    return c.json({ error: 'Email atau password salah' }, 401);
  }

  const { token, expiresAt } = await createSession(c.env.DB, user.id);
  setCookie(c, SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
    expires: expiresAt,
  });

  return c.json({ user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role } });
});

app.post('/auth/logout', async (c) => {
  const token = getCookie(c, SESSION_COOKIE_NAME);
  if (token) await deleteSession(c.env.DB, token);
  deleteCookie(c, SESSION_COOKIE_NAME, { path: '/' });
  return c.json({ message: 'Logout berhasil' });
});

app.get('/auth/me', async (c) => {
  const token = getCookie(c, SESSION_COOKIE_NAME);
  const user = token ? await getSessionUser(c.env.DB, token) : null;
  return c.json({ user });
});

// --- Dashboard: statistik pengecekan per anggota tim (butuh login) ---
app.get('/dashboard/stats', requireAuth, async (c) => {
  const stats = await getDashboardStats(c.env.DB);
  return c.json(stats);
});

export default app;
export type AppType = typeof app;
