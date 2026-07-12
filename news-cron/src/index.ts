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
const FEEDS: { url: string; source: string }[] = [
  { url: 'https://feeds.feedburner.com/TheHackersNews', source: 'The Hacker News' },
  { url: 'https://www.bleepingcomputer.com/feed/', source: 'BleepingComputer' },
];

const MAX_ITEMS_PER_FEED = 15;
const MAX_TOTAL_ITEMS = 30;

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

function parseRss(xml: string, source: string): NewsItem[] {
  const itemMatches = xml.match(/<item>[\s\S]*?<\/item>/g) ?? [];
  const items: NewsItem[] = [];

  for (const itemXml of itemMatches.slice(0, MAX_ITEMS_PER_FEED)) {
    const title = extractTag(itemXml, 'title');
    const link = extractTag(itemXml, 'link');
    const pubDate = extractTag(itemXml, 'pubDate');
    if (title && link) {
      items.push({ title, link, pubDate, source });
    }
  }

  return items;
}

async function fetchFeed(feed: { url: string; source: string }): Promise<NewsItem[]> {
  try {
    const res = await fetch(feed.url, { headers: { 'User-Agent': 'RekanSiberNewsBot/1.0' } });
    if (!res.ok) return [];
    return parseRss(await res.text(), feed.source);
  } catch {
    return [];
  }
}

async function updateNewsCache(env: Env): Promise<void> {
  const perFeed = await Promise.all(FEEDS.map(fetchFeed));
  const items = perFeed
    .flat()
    .sort((a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime())
    .slice(0, MAX_TOTAL_ITEMS);

  await env.NEWS_CACHE.put('cve-latest', JSON.stringify({ items, updatedAt: new Date().toISOString() }));
}

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(updateNewsCache(env));
  },
} satisfies ExportedHandler<Env>;
