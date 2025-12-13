export async function onRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const ioc = url.searchParams.get("ioc");

    if (!ioc) {
      return new Response(
        JSON.stringify({ error: "IOC parameter is required" }),
        { status: 400 }
      );
    }

    // ===== SAFETY CHECK (BIAR TIDAK 500) =====
    if (!env.VT_API_KEY || !env.ABUSEIPDB_API_KEY) {
      return new Response(
        JSON.stringify({
          error: "API keys not configured",
          hint: "Check Cloudflare Pages → Settings → Variables"
        }),
        { status: 500 }
      );
    }

    // ===== MOCK RESPONSE (BIAR FRONTEND JALAN DULU) =====
    // NANTI BARU KITA AKTIFKAN VT / OTX / MX
    const response = {
      ioc,
      verdict: "CLEAN",
      confidence: "HIGH",
      timestamp: new Date().toISOString(),
      sources: {
        virustotal: { malicious: 0, total: 94 },
        abuseipdb: { score: 0 },
        otx: { pulses: 0 },
        mxtoolbox: { blacklisted: false }
      },
      explanation: {
        summary: "IOC not detected as malicious by any intelligence source.",
        details: [
          "VirusTotal reports 0 detections",
          "AbuseIPDB score is 0",
          "No OTX pulses found",
          "MXToolbox shows no blacklist"
        ]
      }
    };

    return new Response(JSON.stringify(response), {
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
