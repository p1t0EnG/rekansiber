// backend/server.js
import Fastify from "fastify";
import fastifyCors from "@fastify/cors";
import fetch from "node-fetch";

const PORT = process.env.PORT || 3000;
const app = Fastify({ logger: true });

// Read keys from env
const VT_KEY = process.env.VT_KEY || "";
const ABUSE_KEY = process.env.ABUSEIPDB_KEY || "";
const OTX_KEY = process.env.OTX_KEY || "";
const MX_KEY = process.env.MXTOOLBOX_KEY || "";

// CORS config - allow your Pages domain(s)
// For testing you can set origin: true (allow all), but in production limit to your pages domain.
await app.register(fastifyCors, {
  origin: (origin, cb) => {
    // Allow requests with no origin (e.g. curl, server-to-server)
    if (!origin) return cb(null, true);
    // whitelist typical Pages domain - change to your actual domain
    const whitelist = [
      "https://rasecurity.pages.dev",
      "https://rasecurity.pages.dev/ioc",
      "http://localhost:5173",
      "http://localhost:3000"
    ];
    if (whitelist.indexOf(origin) !== -1) cb(null, true);
    else {
      // for development you can allow all by using cb(null, true)
      cb(null, true);
    }
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
});

// Basic health route
app.get("/health", async () => ({ status: "ok", ts: Date.now() }));

// Helper: detect IOC type
function detectIOC(ioc) {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const hashRegex = /^[A-Fa-f0-9]{32,64}$/;
  if (ipRegex.test(ioc)) return "ip";
  if (domainRegex.test(ioc)) return "domain";
  if (hashRegex.test(ioc)) return "hash";
  return "unknown";
}

// ========= Provider wrappers (return JSON or {error:...}) =========
async function callVirusTotal(ioc) {
  if (!VT_KEY) return { error: "VT_KEY not configured" };
  try {
    // Using search endpoint for flexible ioc queries (ip/domain/hash)
    const url = `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(ioc)}`;
    const r = await fetch(url, { headers: { "x-apikey": VT_KEY } });
    const json = await r.json();
    return { status: r.status, body: json };
  } catch (e) {
    return { error: e.message };
  }
}

async function callAbuseIPDB(ioc) {
  // AbuseIPDB only for IP checks
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(ioc);
  if (!isIp) return { error: "abuseipdb: only supports IP addresses" };
  if (!ABUSE_KEY) return { error: "ABUSEIPDB_KEY not configured" };
  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}&maxAgeInDays=90`;
    const r = await fetch(url, { headers: { "Key": ABUSE_KEY, "Accept": "application/json" } });
    const json = await r.json();
    return { status: r.status, body: json };
  } catch (e) {
    return { error: e.message };
  }
}

async function callOTX(ioc) {
  if (!OTX_KEY) return { error: "OTX_KEY not configured" };
  try {
    // AlienVault OTX IPv4 example; for domains/hashes endpoints differ
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(ioc);
    const base = "https://otx.alienvault.com/api/v1";
    const url = isIp ? `${base}/indicators/IPv4/${encodeURIComponent(ioc)}/general` : `${base}/indicators/hostname/${encodeURIComponent(ioc)}/general`;
    const r = await fetch(url, { headers: { "X-OTX-API-KEY": OTX_KEY } });
    const json = await r.json();
    return { status: r.status, body: json };
  } catch (e) {
    return { error: e.message };
  }
}

async function callMXToolbox(ioc) {
  if (!MX_KEY) return { error: "MXTOOLBOX_KEY not configured" };
  try {
    // MXToolbox has different endpoints; here we try a generic lookup for ip/domain
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(ioc);
    const url = isIp
      ? `https://api.mxtoolbox.com/api/v1/lookup/ip/${encodeURIComponent(ioc)}`
      : `https://api.mxtoolbox.com/api/v1/lookup/mx/${encodeURIComponent(ioc)}`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${MX_KEY}` } });
    const json = await r.json();
    return { status: r.status, body: json };
  } catch (e) {
    return { error: e.message };
  }
}

// MAIN IOC CHECK endpoint
app.get("/ioc/check", async (req, reply) => {
  const ioc = req.query.ioc;
  if (!ioc) return reply.code(400).send({ error: "Missing query param 'ioc'" });

  const type = detectIOC(ioc);

  // Run providers in parallel but don't fail all if one errors
  const vtP = callVirusTotal(ioc);
  const abuseP = callAbuseIPDB(ioc);
  const otxP = callOTX(ioc);
  const mxP = callMXToolbox(ioc);

  const [vt, abuse, otx, mx] = await Promise.all([vtP, abuseP, otxP, mxP]);

  return reply.send({
    ioc,
    type,
    results: { virustotal: vt, abuseipdb: abuse, otx: otx, mxtoolbox: mx },
    ts: Date.now()
  });
});

// ======= Dashboard mock endpoints (for secdashboard.html) =======
app.get("/api/metrics", async (req) => {
  // Accept ?range=1h|6h|24h|7d
  const range = req.query.range || "24h";
  // Return mock metrics (replace with real aggregation)
  const labels = Array.from({ length: 24 }, (_, i) => `${i}:00`);
  const series = labels.map((_, i) => Math.max(0, Math.round(20 + 40 * Math.sin(i / 3) + (Math.random() * 12))));
  return {
    totalAlerts: series.reduce((a, b) => a + b, 0),
    openIncidents: Math.floor(Math.random() * 12) + 1,
    avgMTTD: Math.round(5 + Math.random() * 20),
    threatScore: Math.round(20 + Math.random() * 70),
    timeline: { labels, series }
  };
});

app.get("/api/alerts", async (req) => {
  const now = Date.now();
  const items = Array.from({ length: 10 }, (_, i) => ({
    time: new Date(now - i * 600000).toISOString(),
    source: `192.0.2.${20 + i}`,
    type: ["ip", "domain", "hash"][Math.floor(Math.random() * 3)],
    severity: ["low", "medium", "high", "critical"][Math.floor(Math.random() * 4)],
    details: `Demo alert id=${1000 + i}`
  }));
  return items;
});

app.get("/api/top_offenders", async () => {
  return [
    { source: "203.0.113.5", count: 129, last: new Date().toISOString() },
    { source: "198.51.100.22", count: 89, last: new Date().toISOString() },
    { source: "8.8.8.8", count: 44, last: new Date().toISOString() }
  ];
});

app.get("/api/distribution", async () => {
  return { labels: ["malicious", "suspicious", "phishing", "benign"], values: [45, 20, 10, 25] };
});

// Start server
const start = async () => {
  try {
    await app.listen({ port: Number(PORT), host: "0.0.0.0" });
    app.log.info(`Server listening on port ${PORT}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};
start();
