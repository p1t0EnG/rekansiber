export async function onRequest(context) {
  const { request, env } = context;

  try {
    const url = new URL(request.url);
    const ioc = url.searchParams.get("ioc");

    if (!ioc) {
      return new Response(JSON.stringify({ error: "IOC required" }), { status: 400 });
    }

    /* ==========================
       VIRUSTOTAL
    ========================== */
    let vt = { malicious: 0, total: 0, verdict: "LOW" };

    try {
      const vtRes = await fetch(
        `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`,
        {
          headers: {
            "x-apikey": env.VT_KEY
          }
        }
      );
      const vtJson = await vtRes.json();
      const stats = vtJson.data.attributes.last_analysis_stats;
      vt.malicious = stats.malicious || 0;
      vt.total = Object.values(stats).reduce((a, b) => a + b, 0);
      vt.verdict = vt.malicious >= 5 ? "HIGH" : vt.malicious > 0 ? "MEDIUM" : "LOW";
    } catch (_) {}

    /* ==========================
       ABUSEIPDB
    ========================== */
    let abuse = { score: 0, verdict: "LOW" };

    try {
      const abuseRes = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`,
        {
          headers: {
            Key: env.ABUSEIPDB_KEY,
            Accept: "application/json"
          }
        }
      );
      const abuseJson = await abuseRes.json();
      abuse.score = abuseJson.data.abuseConfidenceScore || 0;
      abuse.verdict = abuse.score >= 50 ? "HIGH" : abuse.score >= 10 ? "MEDIUM" : "LOW";
    } catch (_) {}

    /* ==========================
       ALIENVAULT OTX (FIXED)
    ========================== */
    let otx = { pulses: 0, verdict: "LOW" };

    try {
      const otxRes = await fetch(
        `https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general`,
        {
          headers: {
            "X-OTX-API-KEY": env.OTX_KEY
          }
        }
      );
      const otxJson = await otxRes.json();
      otx.pulses = otxJson.pulse_info?.count || 0;
      otx.verdict = otx.pulses >= 20 ? "HIGH" : otx.pulses > 0 ? "MEDIUM" : "LOW";
    } catch (_) {}

    /* ==========================
       RESPONSE (NO FINAL VERDICT)
    ========================== */
    return new Response(
      JSON.stringify({
        ioc,
        timestamp: new Date().toISOString(),
        sources: {
          virustotal: vt,
          abuseipdb: abuse,
          otx: otx
        }
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
