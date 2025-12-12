import Fastify from 'fastify';
import fetch from 'node-fetch';
const fastify = Fastify({ logger: true });

const VT_KEY = process.env.VT_KEY;
const ABUSE_KEY = process.env.ABUSEIPDB_KEY;
const OTX_KEY = process.env.OTX_KEY;
const MX_KEY = process.env.MXTOOLBOX_KEY;

fastify.get('/health', async () => ({ status: 'ok' }));

fastify.get('/ioc/check', async (req, reply) => {
  const ioc = req.query.ioc;
  if (!ioc) return reply.status(400).send({ error: 'ioc required' });

  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(ioc);
  const type = isIp ? 'ip' : (ioc.includes('.') ? 'domain' : 'hash');

  const vt = (async () => {
    if (!VT_KEY) return { error: 'VT_KEY not configured' };
    try {
      const r = await fetch(`https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(ioc)}`, {
        headers: { 'x-apikey': VT_KEY }
      });
      return await r.json();
    } catch (e) { return { error: e.message }; }
  })();

  const abuse = (async () => {
    if (!ABUSE_KEY || !isIp) return { error: 'no-key-or-not-ip' };
    try {
      const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`, {
        headers: { 'Key': ABUSE_KEY, 'Accept': 'application/json' }
      });
      return await r.json();
    } catch (e) { return { error: e.message }; }
  })();

  const [vtRes, abuseRes] = await Promise.all([vt, abuse]);
  return { ioc, type, results: { virustotal: vtRes, abuseipdb: abuseRes } };
});

const start = async () => {
  await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
};
start();
