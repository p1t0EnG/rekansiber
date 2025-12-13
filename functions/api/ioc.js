export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const ioc = url.searchParams.get("ioc");

  if (!ioc) {
    return json({ error: "IOC parameter is required" }, 400);
  }

  const type = detectIOCType(ioc);

  try {
    const results = {};

    // VirusTotal
    if (env.VT_KEY) {
      results.virustotal = await queryVirusTotal(ioc, type, env.VT_KEY);
    }

    // AbuseIPDB (IP only)
    if (type === "ip" && env.ABUSEIPDB_KEY) {
      results.abuseipdb = await queryAbuseIPDB(ioc, env.ABUSEIPDB_KEY);
    }

    // AlienVault OTX
    if (env.OTX_KEY) {
      results.otx = await queryOTX(ioc, type, env.OTX_KEY);
    }

    // MXToolbox (domain only)
    if (type === "domain" && env.MXTOOLBOX_KEY) {
      results.mxtoolbox = await queryMXToolbox(ioc, env.MXTOOLBOX_KEY);
    }

    return json({
      ioc,
      type,
      timestamp: new Date().toISOString(),
      results
    });

  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

/* =========================
   Helper Functions
========================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

function detectIOCType(ioc) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
  if (/^[a-fA-F0-9]{32,64}$/.test(ioc)) return "hash";
  return "domain";
}

/* === API Calls === */

async function queryVirusTotal(ioc, type, key) {
  const map = {
    ip: `ip_addresses/${ioc}`,
    domain: `domains/${ioc}`,
    hash: `files/${ioc}`
  };

  const res = await fetch(
    `https://www.virustotal.com/api/v3/${map[type]}`,
    { headers: { "x-apikey": key } }
  );

  return res.ok ? await res.json() : { error: "VirusTotal error" };
}

async function queryAbuseIPDB(ip, key) {
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
    {
      headers: {
        Key: key,
        Accept: "application/json"
      }
    }
  );

  return res.ok ? await res.json() : { error: "AbuseIPDB error" };
}

async function queryOTX(ioc, type, key) {
  const map = {
    ip: `IPv4/${ioc}/general`,
    domain: `domain/${ioc}/general`,
    hash: `file/${ioc}/general`
  };

  const res = await fetch(
    `https://otx.alienvault.com/api/v1/indicators/${map[type]}`,
    { headers: { "X-OTX-API-KEY": key } }
  );

  return res.ok ? await res.json() : { error: "OTX error" };
}

async function queryMXToolbox(domain, key) {
  const res = await fetch(
    `https://api.mxtoolbox.com/api/v1/lookup/dns/${domain}`,
    { headers: { Authorization: key } }
  );

  return res.ok ? await res.json() : { error: "MXToolbox error" };
}
