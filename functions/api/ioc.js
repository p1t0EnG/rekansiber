export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const ioc = url.searchParams.get("ioc");

  if (!ioc) {
    return json({ error: "IOC parameter is required" }, 400);
  }

  const type = detectIOCType(ioc);

  if (type !== "ip") {
    return json({ error: "Only IP IOC supported for now" }, 400);
  }

  try {
    const vt = await queryVirusTotal(ioc, env.VT_API_KEY);
    const abuse = await queryAbuseIPDB(ioc, env.ABUSE_API_KEY);

    const verdictData = verdictEngine(vt, abuse);
    const confidence = confidenceEngine(vt, abuse);
    const explanation = explanationEngine(vt, abuse, verdictData.verdict);

    return json({
      ioc,
      type,
      sources: {
        virustotal: vt,
        abuseipdb: abuse
      },
      verdict: verdictData.verdict,
      risk_score: verdictData.score,
      confidence,
      explanation,
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

/* ---------------- HELPERS ---------------- */

function detectIOCType(ioc) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ioc) ? "ip" : "unknown";
}

/* ----------- VIRUSTOTAL ----------- */
async function queryVirusTotal(ip, apiKey) {
  const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
    headers: { "x-apikey": apiKey }
  });

  const data = await res.json();
  const stats = data.data.attributes.last_analysis_stats;

  return {
    malicious: stats.malicious,
    suspicious: stats.suspicious,
    harmless: stats.harmless,
    reputation: data.data.attributes.reputation
  };
}

/* ----------- ABUSEIPDB ----------- */
async function queryAbuseIPDB(ip, apiKey) {
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
    {
      headers: {
        Key: apiKey,
        Accept: "application/json"
      }
    }
  );

  const data = await res.json();
  const d = data.data;

  return {
    abuseScore: d.abuseConfidenceScore,
    reports: d.totalReports,
    country: d.countryCode
  };
}

/* ----------- VERDICT ENGINE ----------- */
function verdictEngine(vt, abuse) {
  const vtDetections = vt.malicious + vt.suspicious;
  let score = 0;
  let verdict = "CLEAN";

  // VirusTotal strict rules
  if (vtDetections === 0) score += 0;
  else if (vtDetections === 1) score += 10;
  else if (vtDetections <= 10) score += 30;
  else if (vtDetections <= 25) score += 60;
  else score += 90;

  // AbuseIPDB strict rules
  if (abuse.abuseScore === 0) score += 0;
  else if (abuse.abuseScore <= 25) score += 20;
  else if (abuse.abuseScore <= 50) score += 40;
  else score += 70;

  if (score >= 80) verdict = "MALICIOUS";
  else if (score >= 40) verdict = "SUSPICIOUS";
  else verdict = "CLEAN";

  return { verdict, score };
}

/* ----------- CONFIDENCE ENGINE ----------- */
function confidenceEngine(vt, abuse) {
  if (vt.harmless > 70 && abuse.abuseScore === 0) return "HIGH";
  if (vt.harmless > 40) return "MEDIUM";
  return "LOW";
}

/* ----------- EXPLANATION ENGINE ----------- */
function explanationEngine(vt, abuse, verdict) {
  const reasons = [];

  reasons.push(
    `${vt.malicious + vt.suspicious}/${vt.malicious + vt.suspicious + vt.harmless} VirusTotal engines flagged this IP`
  );

  reasons.push(`AbuseIPDB confidence score is ${abuse.abuseScore}`);

  reasons.push(`Final verdict classified as ${verdict}`);

  return reasons;
}

/* ----------- RESPONSE HELPER ----------- */
function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
