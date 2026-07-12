import { Hono, type Context } from 'hono';
import { setCookie, getCookie, deleteCookie } from 'hono/cookie';
import { isValidIoc } from './ioc/validate';
import { checkIoc } from './ioc/check';
import { checkRateLimit } from './ioc/rate-limit';
import { MAX_BULK_ITEMS, type IocType } from './ioc/types';
import { hashPassword, verifyPassword } from './auth/password';
import { createSession, getSessionUser, deleteSession, type SessionUser } from './auth/session';
import { requireAuth, requireRole, SESSION_COOKIE_NAME } from './auth/middleware';
import { getUserPasswordHash, updateUserPassword } from './auth/user';
import { getDashboardStats } from './dashboard/stats';
import { getMonthlyStats, buildMonthlyReportPdf, buildMonthlyReportXlsx } from './reports/monthly';
import {
  listPhishingReports,
  getPhishingReport,
  createPhishingReport,
  updatePhishingReportStatus,
  type PhishingReportStatus,
} from './phishing/reports';
import { generatePhishingReportTemplate } from './phishing/template';

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
type AppEnv = { Bindings: Bindings; Variables: Variables };

const app = new Hono<AppEnv>().basePath('/api');

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

// --- Berita CVE & Ransomware (dibaca dari cache KV, diisi oleh worker terpisah news-cron/) ---
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

// Ganti password sendiri (admin maupun member) -- supaya admin tidak perlu
// reset-in password anggota tim satu-satu lewat wrangler d1 execute.
app.post('/auth/change-password', requireAuth, async (c) => {
  const body = await c.req.json<{ current_password: string; new_password: string }>().catch(() => null);

  if (!body?.current_password || !body?.new_password) {
    return c.json({ error: 'Password saat ini dan password baru wajib diisi' }, 400);
  }
  if (body.new_password.length < 8) {
    return c.json({ error: 'Password baru minimal 8 karakter' }, 400);
  }

  const user = c.get('user');
  const currentHash = await getUserPasswordHash(c.env.DB, user.id);
  if (!currentHash || !(await verifyPassword(body.current_password, currentHash))) {
    return c.json({ error: 'Password saat ini salah' }, 401);
  }

  const newHash = await hashPassword(body.new_password);
  await updateUserPassword(c.env.DB, user.id, newHash);

  return c.json({ message: 'Password berhasil diganti' });
});

// --- Dashboard: statistik pengecekan per anggota tim (butuh login) ---
// Member cuma lihat aktivitas sendiri, admin lihat seluruh tim.
app.get('/dashboard/stats', requireAuth, async (c) => {
  const user = c.get('user');
  const stats = await getDashboardStats(c.env.DB, user.role === 'admin' ? undefined : user.id);
  return c.json(stats);
});

// --- Report bulanan (PDF/Excel rekap per anggota, butuh login) ---
const YEAR_MONTH_RE = /^\d{4}-\d{2}$/;

function resolveReportMonth(c: Context<AppEnv>): string | null {
  const month = c.req.query('month') ?? new Date().toISOString().slice(0, 7);
  return YEAR_MONTH_RE.test(month) ? month : null;
}

app.get('/reports/monthly.pdf', requireAuth, requireRole('admin'), async (c) => {
  const month = resolveReportMonth(c);
  if (!month) {
    return c.json({ error: 'Parameter month harus format YYYY-MM' }, 400);
  }

  const rows = await getMonthlyStats(c.env.DB, month);
  const pdfBytes = await buildMonthlyReportPdf(month, rows);

  return c.body(pdfBytes as Uint8Array<ArrayBuffer>, 200, {
    'Content-Type': 'application/pdf',
    'Content-Disposition': `attachment; filename="report-bulanan-${month}.pdf"`,
  });
});

app.get('/reports/monthly.xlsx', requireAuth, requireRole('admin'), async (c) => {
  const month = resolveReportMonth(c);
  if (!month) {
    return c.json({ error: 'Parameter month harus format YYYY-MM' }, 400);
  }

  const rows = await getMonthlyStats(c.env.DB, month);
  const xlsxBytes = buildMonthlyReportXlsx(month, rows);

  return c.body(xlsxBytes as Uint8Array<ArrayBuffer>, 200, {
    'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'Content-Disposition': `attachment; filename="report-bulanan-${month}.xlsx"`,
  });
});

// --- Template report phishing ke hosting provider (tim SOC, butuh login) ---
// App cuma generate teks template-nya -- pengiriman email tetap manual lewat
// email client masing-masing analyst, lalu status di-update di sini.
const PHISHING_STATUSES: PhishingReportStatus[] = ['draft', 'sent', 'resolved'];

app.get('/phishing-reports', requireAuth, async (c) => {
  const reports = await listPhishingReports(c.env.DB);
  return c.json({ reports });
});

app.post('/phishing-reports', requireAuth, async (c) => {
  const body = await c.req
    .json<{ target_domain: string; hosting_email?: string; notes?: string }>()
    .catch(() => null);

  if (!body?.target_domain?.trim()) {
    return c.json({ error: 'target_domain wajib diisi' }, 400);
  }

  const user = c.get('user');
  const id = await createPhishingReport(
    c.env.DB,
    user.id,
    body.target_domain.trim(),
    body.hosting_email?.trim() || null,
    body.notes?.trim() || null,
  );

  return c.json({ id }, 201);
});

app.patch('/phishing-reports/:id', requireAuth, async (c) => {
  const id = Number(c.req.param('id'));
  const body = await c.req.json<{ status: PhishingReportStatus }>().catch(() => null);

  if (!Number.isInteger(id) || !body?.status || !PHISHING_STATUSES.includes(body.status)) {
    return c.json({ error: `status harus salah satu dari: ${PHISHING_STATUSES.join(', ')}` }, 400);
  }

  const existing = await getPhishingReport(c.env.DB, id);
  if (!existing) {
    return c.json({ error: 'Report tidak ditemukan' }, 404);
  }

  await updatePhishingReportStatus(c.env.DB, id, body.status);
  return c.json({ message: 'Status diperbarui' });
});

app.get('/phishing-reports/:id/template', requireAuth, async (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id)) {
    return c.json({ error: 'id tidak valid' }, 400);
  }

  const report = await getPhishingReport(c.env.DB, id);
  if (!report) {
    return c.json({ error: 'Report tidak ditemukan' }, 404);
  }

  return c.text(generatePhishingReportTemplate(report));
});

export default app;
export type AppType = typeof app;
