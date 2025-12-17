export async function onRequest(context) {
  const { request, env } = context;

  try {
    const url = new URL(request.url);
    const ioc = url.searchParams.get("ioc");

    if (!ioc) {
      return new Response(JSON.stringify({ error: "IOC required" }), { status: 400 });
    }

    /* =====================
       VIRUSTOTAL
    ===================== */
    let vt = { malicious: 0, total: 0, verdict: "LOW", link: "" };

    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ioc}`, {
        headers: { "x-apikey": env.VT_KEY }
      });
      const j = await res.json();
      const s = j.data.attributes.last_analysis_stats;
      vt.malicious = s.malicious || 0;
      vt.total = Object.values(s).reduce((a, b) => a + b, 0);
      vt.verdict = vt.malicious >= 5 ? "HIGH" : vt.malicious > 0 ? "MEDIUM" : "LOW";
      vt.link = `https://www.virustotal.com/gui/ip-address/${ioc}`;
    } catch {}

    /* =====================
       ABUSEIPDB
    ===================== */
    let abuse = { score: 0, verdict: "LOW", country: "N/A", type: "Unknown", isp: "Unknown", link: "" };

    try {
      const res = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`,
        {
          headers: {
            Key: env.ABUSEIPDB_KEY,
            Accept: "application/json"
          }
        }
      );
      const j = await res.json();
      abuse.score   = data.abuseConfidenceScore || 0;
      abuse.country = data.countryCode || "N/A";
      abuse.type    = data.usageType || "Unknown";
      abuse.isp     = data.isp || "Unknown";
      /* abuse.totalReports = j.data.totalReports || 0; */

      abuse.verdict = abuse.score >= 50 ? "HIGH" : abuse.score >= 10 ? "MEDIUM" : "LOW";
      abuse.link = `https://www.abuseipdb.com/check/${ioc}`;
    } catch {}

    /* =====================
       OTX (FIXED & TAGS)
    ===================== */
    let otx = { pulses: 0, verdict: "LOW", tags: [], link: "" };

    try {
      const res = await fetch(
        `https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general`,
        { headers: { "X-OTX-API-KEY": env.OTX_KEY } }
      );
      const j = await res.json();
      otx.pulses = j.pulse_info?.count || 0;
      otx.tags = [...new Set((j.pulse_info?.pulses || []).flatMap(p => p.tags || []))];
      otx.verdict = otx.pulses >= 20 ? "HIGH" : otx.pulses > 0 ? "MEDIUM" : "LOW";
      otx.link = `https://otx.alienvault.com/indicator/ip/${ioc}`;
    } catch {}

    /* =====================
       MXTOOLBOX
    ===================== */
    let mxtoolbox = { listed: false, verdict: "LOW", link: "" };

    try {
      const res = await fetch(
        `https://api.mxtoolbox.com/api/v1/lookup/ip/${ioc}`,
        { headers: { Authorization: env.MXTOOLBOX_KEY } }
      );
      const j = await res.json();
      mxtoolbox.listed = j.Failed && j.Failed.length > 0;
      mxtoolbox.verdict = mxtoolbox.listed ? "HIGH" : "LOW";
      mxtoolbox.link = `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${ioc}`;
    } catch {}

    return new Response(
      JSON.stringify({
        ioc,
        timestamp: new Date().toISOString(),
        sources: { virustotal: vt, abuseipdb: abuse, otx, mxtoolbox }
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
