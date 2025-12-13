export async function onRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const ioc = url.searchParams.get("ioc");

    if (!ioc) {
      return new Response(JSON.stringify({ error: "IOC is required" }), { status: 400 });
    }

    /* =========================
       VIRUSTOTAL
    ========================= */
    const vtRes = await fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`,
      {
        headers: { "x-apikey": env.VT_KEY }
      }
    );
    const vtJson = vtRes.ok ? await vtRes.json() : null;

    const vtMalicious =
      vtJson?.data?.attributes?.last_analysis_stats?.malicious || 0;
    const vtTotal =
      Object.values(
        vtJson?.data?.attributes?.last_analysis_stats || {}
      ).reduce((a, b) => a + b, 0);

    /* =========================
       ABUSEIPDB
    ========================= */
    const abuseRes = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`,
      {
        headers: {
          Key: env.ABUSEIPDB_KEY,
          Accept: "application/json"
        }
      }
    );
    const abuseJson = abuseRes.ok ? await abuseRes.json() : null;
    const abuseScore = abuseJson?.data?.abuseConfidenceScore ?? 0;

    /* =========================
       OTX (FIXED — PULSE COUNT)
    ========================= */
    const otxRes = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general`,
      {
        headers: {
          "X-OTX-API-KEY": env.OTX_KEY
        }
      }
    );
    const otxJson = otxRes.ok ? await otxRes.json() : null;
    const otxPulses = otxJson?.pulse_info?.count ?? 0;

    /* =========================
       VERDICT PER TOOL
    ========================= */
    const vtVerdict =
      vtMalicious >= 10 ? "HIGH" :
      vtMalicious >= 3  ? "MEDIUM" : "LOW";

    const abuseVerdict =
      abuseScore >= 80 ? "HIGH" :
      abuseScore >= 30 ? "MEDIUM" : "LOW";

    const otxVerdict =
      otxPulses >= 20 ? "HIGH" :
      otxPulses >= 5  ? "MEDIUM" : "LOW";

    /* =========================
       FINAL RESPONSE
    ========================= */
    return new Response(JSON.stringify({
      ioc,
      timestamp: new Date().toISOString(),

      virustotal: {
        verdict: vtVerdict,
        malicious: vtMalicious,
        total: vtTotal
      },

      abuseipdb: {
        verdict: abuseVerdict,
        score: abuseScore
      },

      otx: {
        verdict: otxVerdict,
        pulses: otxPulses
      }
    }), {
      headers: { "Content-Type": "application/json" }
    });

  } catch (err) {
    return new Response(JSON.stringify({
      error: "Backend error",
      message: err.message
    }), { status: 500 });
  }
}
