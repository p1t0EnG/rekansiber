export async function onRequest(context) {
  const { request, env } = context;

  try {
    const url = new URL(request.url);
    const ioc = url.searchParams.get("ioc");

    if (!ioc) {
      return new Response(
        JSON.stringify({ error: "IOC parameter is required" }),
        { status: 400 }
      );
    }

    /* =============================
       VIRUSTOTAL (STEP B)
    ============================== */
    let vtMalicious = 0;
    let vtTotal = 0;

    if (env.VT_KEY) {
      const vtRes = await fetch(
        `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`,
        {
          headers: {
            "x-apikey": env.VT_KEY
          }
        }
      );

      if (vtRes.ok) {
        const vtJson = await vtRes.json();
        const stats =
          vtJson?.data?.attributes?.last_analysis_stats || {};

        vtMalicious = stats.malicious || 0;
        vtTotal = Object.values(stats).reduce(
          (a, b) => a + b,
          0
        );
      }
    }

    function verdictFromVT(malicious) {
      if (malicious <= 1) return "CLEAN";
      if (malicious <= 10) return "LOW";
      if (malicious <= 30) return "MEDIUM";
      return "HIGH";
    }

    const vtVerdict = verdictFromVT(vtMalicious);

    /* =============================
       ABUSEIPDB (STEP C)
    ============================== */
    let abuseScore = 0;

    if (env.ABUSEIPDB_KEY) {
      const abuseRes = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`,
        {
          headers: {
            Key: env.ABUSEIPDB_KEY,
            Accept: "application/json"
          }
        }
      );

      if (abuseRes.ok) {
        const abuseJson = await abuseRes.json();
        abuseScore =
          abuseJson?.data?.abuseConfidenceScore || 0;
      }
    }

    function verdictFromAbuse(score) {
      if (score === 0) return "CLEAN";
      if (score <= 10) return "LOW";
      if (score <= 40) return "MEDIUM";
      return "HIGH";
    }

    const abuseVerdict = verdictFromAbuse(abuseScore);

    /* =============================
       FINAL FUSION VERDICT
    ============================== */
    const verdicts = [vtVerdict, abuseVerdict];

    const finalVerdict = verdicts.includes("HIGH")
      ? "HIGH"
      : verdicts.includes("MEDIUM")
      ? "MEDIUM"
      : verdicts.includes("LOW")
      ? "LOW"
      : "CLEAN";

    const confidence =
      finalVerdict === "CLEAN"
        ? "HIGH"
        : finalVerdict === "LOW"
        ? "MEDIUM"
        : "HIGH";

    /* =============================
       FINAL RESPONSE
    ============================== */
    const response = {
      ioc,
      verdict: finalVerdict,
      confidence,
      timestamp: new Date().toISOString(),
      sources: {
        virustotal: {
          malicious: vtMalicious,
          total: vtTotal
        },
        abuseipdb: {
          score: abuseScore
        }
      },
      explanation: {
        summary:
          finalVerdict === "CLEAN"
            ? "IOC not detected as malicious by VirusTotal or AbuseIPDB."
            : "IOC shows risk indicators from threat intelligence sources.",
        details: [
          `VirusTotal: ${vtMalicious}/${vtTotal} detections`,
          `AbuseIPDB score: ${abuseScore}`
        ]
      }
    };

    return new Response(JSON.stringify(response, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: "Unhandled backend error",
        message: err.message
      }),
      { status: 500 }
    );
  }
}
