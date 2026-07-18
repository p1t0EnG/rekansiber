/// <reference types="@cloudflare/workers-types" />

// Worker terpisah -- satu-satunya tugasnya jalan tiap 6 jam (lihat wrangler.toml),
// fetch RSS berita CVE/ransomware, lalu simpan ringkasannya ke KV NEWS_CACHE
// yang juga dibaca oleh project utama (Astro) lewat GET /api/news/cve.

export interface Env {
  NEWS_CACHE: KVNamespace;
}

interface NewsItem {
  title: string;
  link: string;
  pubDate: string;
  source: string;
}

// RansomHub itu nama grup ransomware (situs kebocoran korban), bukan sumber berita --
// dipakai BleepingComputer (kategori ransomware kuat) sebagai gantinya untuk berita ransomware.
//
// Tiap feed boleh punya beberapa URL kandidat, dicoba berurutan sampai ada yang
// menghasilkan item. BleepingComputer memblokir fetch dari IP Cloudflare Workers
// (feed-nya balas halaman challenge "Just a moment..."), jadi kandidat kedua
// mengambil artikel BC terbaru lewat Bing News RSS (Google News juga blokir IP
// Workers dengan halaman "Sorry...", FeedBurner mirror-nya sudah lama basi).
const FEEDS: { urls: string[]; source: string }[] = [
  { urls: ['https://feeds.feedburner.com/TheHackersNews'], source: 'The Hacker News' },
  {
    urls: [
      'https://www.bleepingcomputer.com/feed/',
      'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=rss',
    ],
    source: 'BleepingComputer',
  },
];

const MAX_ITEMS_PER_FEED = 15;
// Berita lama tetap disimpan sampai 7 hari (digabung dengan hasil fetch baru tiap
// refresh, dedupe per link), supaya halaman Berita tidak "kehilangan" berita
// kemarin setiap cache di-overwrite. Cap total sebagai pengaman ukuran KV.
const NEWS_RETENTION_DAYS = 7;
const MAX_RETAINED_ITEMS = 150;

function decodeEntities(str: string): string {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&nbsp;/g, ' ');
}

function extractTag(itemXml: string, tag: string): string {
  const cdataMatch = itemXml.match(new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>`));
  if (cdataMatch) return cdataMatch[1].trim();

  const plainMatch = itemXml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`));
  return plainMatch ? decodeEntities(plainMatch[1].trim()) : '';
}

// Link dari Bing News berupa redirect apiclick.aspx?...&url=<artikel asli> --
// ambil URL artikel aslinya supaya user langsung ke sumbernya.
function unwrapAggregatorLink(link: string): string {
  if (!link.includes('bing.com/news/apiclick')) return link;
  try {
    const direct = new URL(link).searchParams.get('url');
    return direct && /^https?:\/\//.test(direct) ? direct : link;
  } catch {
    return link;
  }
}

function parseRss(xml: string, source: string): NewsItem[] {
  const itemMatches = xml.match(/<item>[\s\S]*?<\/item>/g) ?? [];
  const items: NewsItem[] = [];

  for (const itemXml of itemMatches.slice(0, MAX_ITEMS_PER_FEED)) {
    // Item dari agregator kadang diberi suffix " - NamaSumber" di judulnya --
    // dibuang karena kolom sumber sudah ditampilkan terpisah di halaman Berita.
    const title = extractTag(itemXml, 'title').replace(new RegExp(` - ${source}$`), '');
    const link = unwrapAggregatorLink(extractTag(itemXml, 'link'));
    const pubDate = extractTag(itemXml, 'pubDate');
    if (title && link) {
      items.push({ title, link, pubDate, source });
    }
  }

  return items;
}

async function fetchFeed(feed: { urls: string[]; source: string }): Promise<NewsItem[]> {
  for (const url of feed.urls) {
    try {
      const res = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; RekanSiberNewsBot/1.0)',
          Accept: 'application/rss+xml, application/xml, text/xml',
        },
      });
      if (!res.ok) continue;
      const items = parseRss(await res.text(), feed.source);
      if (items.length > 0) return items;
    } catch {
      // coba URL kandidat berikutnya
    }
  }
  return [];
}

async function updateNewsCache(env: Env): Promise<number> {
  const perFeed = await Promise.all(FEEDS.map(fetchFeed));
  const fresh = perFeed.flat();

  const existing = (await env.NEWS_CACHE.get('cve-latest', 'json')) as { items?: NewsItem[] } | null;
  const cutoff = Date.now() - NEWS_RETENTION_DAYS * 24 * 60 * 60 * 1000;

  // Gabung cache lama + hasil baru: dedupe per link (item baru menang), buang
  // yang lebih tua dari masa retensi atau tanggalnya tidak bisa diparse.
  const byLink = new Map<string, NewsItem>();
  for (const item of [...(existing?.items ?? []), ...fresh]) {
    const time = new Date(item.pubDate).getTime();
    if (Number.isNaN(time) || time < cutoff) continue;
    byLink.set(item.link, item);
  }

  const items = [...byLink.values()]
    .sort((a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime())
    .slice(0, MAX_RETAINED_ITEMS);

  await env.NEWS_CACHE.put('cve-latest', JSON.stringify({ items, updatedAt: new Date().toISOString() }));
  return items.length;
}

// --- Ransomware Watch: daftar korban terbaru dari ransomware.live ---
// API publiknya bisa diakses tanpa API key; hanya field yang dibutuhkan halaman
// /ransomware-watch yang disimpan (claim_url onion & screenshot sengaja dibuang).
const RANSOMWARE_API = 'https://api.ransomware.live/v2/recentvictims';
const MAX_VICTIMS = 50;

interface RansomVictim {
  victim: string;
  group: string;
  activity: string;
  country: string;
  attackdate: string;
  url: string;
}

async function updateRansomwareCache(env: Env): Promise<number> {
  try {
    const res = await fetch(RANSOMWARE_API, {
      headers: { 'User-Agent': 'RekanSiberNewsBot/1.0', Accept: 'application/json' },
    });
    if (!res.ok) return -1;

    const raw = (await res.json()) as Array<Record<string, unknown>>;
    const victims: RansomVictim[] = raw
      .map((v) => ({
        victim: typeof v.victim === 'string' ? v.victim : '',
        group: typeof v.group === 'string' ? v.group : '',
        activity: typeof v.activity === 'string' && v.activity !== 'Not Found' ? v.activity : '',
        country: typeof v.country === 'string' ? v.country.toUpperCase() : '',
        attackdate: typeof v.attackdate === 'string' ? v.attackdate : typeof v.discovered === 'string' ? v.discovered : '',
        url: typeof v.url === 'string' && v.url.startsWith('https://www.ransomware.live/') ? v.url : '',
      }))
      .filter((v) => v.victim && v.group)
      .sort((a, b) => new Date(b.attackdate).getTime() - new Date(a.attackdate).getTime())
      .slice(0, MAX_VICTIMS);

    if (victims.length === 0) return -1;
    await env.NEWS_CACHE.put('ransomware-latest', JSON.stringify({ victims, updatedAt: new Date().toISOString() }));
    return victims.length;
  } catch {
    return -1;
  }
}

async function refreshAll(env: Env): Promise<{ news: number; victims: number }> {
  const [news, victims] = await Promise.all([updateNewsCache(env), updateRansomwareCache(env)]);
  return { news, victims };
}

// Jeda minimal antar refresh manual, biar endpoint /refresh tidak bisa
// dipakai menghajar upstream (RSS & ransomware.live) berulang-ulang.
const MANUAL_REFRESH_COOLDOWN_MS = 15 * 60 * 1000;

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(refreshAll(env));
  },

  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/refresh') {
      const last = Number((await env.NEWS_CACHE.get('last-manual-refresh')) ?? 0);
      const now = Date.now();
      if (now - last < MANUAL_REFRESH_COOLDOWN_MS) {
        const waitMin = Math.ceil((MANUAL_REFRESH_COOLDOWN_MS - (now - last)) / 60000);
        return Response.json({ error: `Baru saja di-refresh, coba lagi ${waitMin} menit lagi` }, { status: 429 });
      }
      await env.NEWS_CACHE.put('last-manual-refresh', String(now));
      const counts = await refreshAll(env);
      return Response.json({ message: 'Cache diperbarui', ...counts });
    }

    return Response.json({ worker: 'rekansiber-news-cron', endpoints: ['/refresh'] });
  },
} satisfies ExportedHandler<Env>;
