export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const ioc = url.searchParams.get("ioc");

  if (!ioc) {
    return json({ error: "IOC parameter is required" }, 400);
  }

  const type = detectIOCType(ioc);

  const results = {
    virustotal: null,
    abuseipdb: null,
    otx: null,
    mxtoolbox: null
  };

  // Parallel enrichment
  await Promise.all([
    fetchVirusTotal(ioc, type, env).then(r => results.virustotal = r),
    fetchAbuseIPDB(ioc, type, env).then(r => results.abuseipdb = r),
    fetchOTX(ioc, type, env).then(r => results.otx = r),
    fetchMXToolbox(ioc, type, env).then(r => results.mxtoolbox = r)
  ]);

  return json({
    ioc,
    type,
    timestamp: new Date().toISOString(),
    results
  });
}

/* ================= HELPERS ================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

function detectIOCType(ioc) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
  if (/^[a-f0-9]{32,64}$/i.test(ioc)) return "hash";
  return "domain";
}

/* ================= PROVIDERS ================= */

async function fetchVirusTotal(ioc, type, env) {
  if (!env.VT_API_KEY) return { error: "VT key missing" };

  const map = { ip: "ip_addresses", domain: "domains", hash: "files" };
  const url = `https://www.virustotal.com/api/v3/${map[type]}/${ioc}`;

  try {
    const res = await fetch(url, {
      headers: { "x-apikey": env.VT_API_KEY }
    });
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

async function fetchAbuseIPDB(ioc, type, env) {
  if (type !== "ip") return { skipped: "Not IP" };
  if (!env.ABUSEIPDB_API_KEY) return { error: "AbuseIPDB key missing" };

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`;

  try {
    const res = await fetch(url, {
      headers: {
        Key: env.ABUSEIPDB_API_KEY,
        Accept: "application/json"
      }
    });
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

async function fetchOTX(ioc, type, env) {
  if (!env.OTX_API_KEY) return { error: "OTX key missing" };

  const base = "https://otx.alienvault.com/api/v1/indicators";
  const map = { ip: "IPv4", domain: "domain", hash: "file" };
  const url = `${base}/${map[type]}/${ioc}/general`;

  try {
    const res = await fetch(url, {
      headers: { "X-OTX-API-KEY": env.OTX_API_KEY }
    });
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

async function fetchMXToolbox(ioc, type, env) {
  return { info: "MXToolbox integration placeholder" };
}
