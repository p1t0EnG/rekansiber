export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const ioc = url.searchParams.get("ioc");

  if (!ioc) {
    return json({ error: "IOC parameter is required" }, 400);
  }

  const type = detectIOCType(ioc);

  // === FETCH RAW DATA (placeholder – sudah kamu punya / mock dulu) ===
  const vt = await fetchVirusTotal(ioc, type, env);
  const abuse = await fetchAbuseIPDB(ioc, env);
  const otx = await fetchOTX(ioc, env);
  const mx = await fetchMXToolbox(ioc, type, env);

  // === NORMALIZATION (STRICT) ===
  const normalized = {
    virustotal: normalizeVT(vt.malicious || 0, vt.total || 90),
    abuseipdb: normalizeAbuse(abuse.score || 0, abuse.reports || 0),
    otx: normalizeOTX(otx.pulses || 0),
    mxtoolbox: normalizeMX(mx.blacklisted || false)
  };

  return json({
    ioc,
    type,
    timestamp: new Date().toISOString(),
    raw: { vt, abuse, otx, mx },
    normalized
  });
}

/* =======================
   NORMALIZATION FUNCTIONS
   ======================= */

function normalizeVT(malicious, total = 90) {
  if (malicious <= 1) return 0;
  if (malicious <= 10) return 25;
  if (malicious <= 25) return 50;
  if (malicious <= 50) return 75;
  return 100;
}

function normalizeAbuse(score, reports) {
  let base;
  if (score === 0) base = 0;
  else if (score <= 10) base = 25;
  else if (score <= 30) base = 50;
  else if (score <= 60) base = 75;
  else base = 100;

  // escalation
  if (score > 0 && reports >= 10) {
    base = Math.min(base + 25, 100);
  }

  return base;
}

function normalizeOTX(pulses) {
  if (pulses === 0) return 0;
  if (pulses <= 3) return 25;
  if (pulses <= 10) return 50;
  if (pulses <= 25) return 75;
  return 100;
}

function normalizeMX(blacklisted) {
  return blacklisted ? 50 : 0;
}

/* =======================
   HELPERS
   ======================= */

function detectIOCType(ioc) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
  if (/^[a-fA-F0-9]{32,64}$/.test(ioc)) return "hash";
  return "domain";
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

/* =======================
   MOCK FETCHERS (AMAN)
   Ganti dengan real API nanti
   ======================= */

async function fetchVirusTotal(ioc, type, env) {
  return { malicious: 0, total: 90 };
}

async function fetchAbuseIPDB(ioc, env) {
  return { score: 0, reports: 0 };
}

async function fetchOTX(ioc, env) {
  return { pulses: 0 };
}

async function fetchMXToolbox(ioc, type, env) {
  return { blacklisted: false };
}
