// Rate limit sederhana berbasis fixed window per menit, disimpan di KV NEWS_CACHE
// dengan prefix terpisah (`ratelimit:`) supaya tidak bentrok dengan cache berita.
const MAX_REQUESTS_PER_MINUTE = 10;

export async function checkRateLimit(
  kv: KVNamespace,
  clientIp: string,
): Promise<{ allowed: boolean; remaining: number }> {
  const bucket = Math.floor(Date.now() / 60_000);
  const key = `ratelimit:ioc:${clientIp}:${bucket}`;

  const current = Number((await kv.get(key)) ?? '0');
  if (current >= MAX_REQUESTS_PER_MINUTE) {
    return { allowed: false, remaining: 0 };
  }

  // expirationTtl minimum di Cloudflare KV adalah 60 detik, cukup untuk 1 window
  await kv.put(key, String(current + 1), { expirationTtl: 60 });
  return { allowed: true, remaining: MAX_REQUESTS_PER_MINUTE - current - 1 };
}
