export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const ioc = url.searchParams.get("ioc");

  if (!ioc) return json({ error: "IOC is required" }, 400);

  const type = detectIOCType(ioc);

  // === MOCK DATA (AMAN, STABIL) ===
  const vt = { malicious: 2, total: 90 };
  const abuse = { score: 5, reports: 3 };
  const otx = { pulses: 0 };
  const mx = { blacklisted: false };

  // === NORMALIZATION ===
  const normalized = {
    virustotal: normalizeVT(vt.malicious),
    abuseipdb: normalizeAbuse(abuse.score, abuse.reports),
    otx: normalizeOTX(otx.pulses),
    mxtoolbox: normalizeMX(mx.blacklisted)
  };

  // === FUSION SCORE ===
  const score = Math.round(
    normalized.virustotal * 0.4 +
    normalized.abuseipdb * 0.3 +
    normalized.otx * 0.2 +
    normalized.mxtoolbox * 0.1
  );

  // === VERDICT ===
  const verdict = finalVerdict(score);

  // === CONFIDENCE ===
  const confidence = calculateConfidence(vt, abuse, otx, mx);

  // === EXPLANATION ===
  const explanation = {
    summary: `IOC diklasifikasikan sebagai ${verdict} berdasarkan korelasi multi-source threat intelligence`,
    details: [
      vt.malicious > 0
        ? `VirusTotal mendeteksi ${vt.malicious}/${vt.total} vendor`
        : "VirusTotal tidak mendeteksi malicious activity",
      abuse.score > 0
        ? `AbuseIPDB mencatat abuse score ${abuse.score}% (${abuse.reports} laporan)`
        : "AbuseIPDB tidak mencatat abuse",
      otx.pulses > 0
        ? `OTX menemukan ${otx.pulses} pulse`
        : "OTX tidak menemukan pulse",
      mx.blacklisted
        ? "MXToolbox mendeteksi blacklist"
        : "MXToolbox tidak mendeteksi blacklist"
    ]
  };

  return json({
    ioc,
    type,
    verdict,
    confidence,
    score,
    normalized,
    explanation,
    timestamp: new Date().toISOString()
  });
}

/* ================= HELPERS ================= */

function detectIOCType(ioc) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
  if (/^[a-fA-F0-9]{32,64}$/.test(ioc)) return "hash";
  return "domain";
}

function normalizeVT(m) {
  if (m <= 1) return 0;
  if (m <= 10) return 25;
  if (m <= 25) return 50;
  if (m <= 50) return 75;
  return 100;
}

function normalizeAbuse(score, reports) {
  let base = score === 0 ? 0 : score <= 10 ? 25 : score <= 30 ? 50 : score <= 60 ? 75 : 100;
  if (score > 0 && reports >= 10) base = Math.min(base + 25, 100);
  return base;
}

function normalizeOTX(p) {
  return p === 0 ? 0 : p <= 3 ? 25 : p <= 10 ? 50 : p <= 25 ? 75 : 100;
}

function normalizeMX(b) {
  return b ? 50 : 0;
}

function finalVerdict(score) {
  if (score === 0) return "CLEAN";
  if (score <= 25) return "LOW RISK";
  if (score <= 50) return "SUSPICIOUS";
  if (score <= 75) return "HIGH RISK";
  return "MALICIOUS";
}

function calculateConfidence(vt, abuse, otx, mx) {
  let signals = 0;
  if (vt.malicious > 0) signals++;
  if (abuse.score > 0) signals++;
  if (otx.pulses > 0) signals++;
  if (mx.blacklisted) signals++;

  return signals >= 3 ? "HIGH" : signals === 2 ? "MEDIUM" : "LOW";
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
