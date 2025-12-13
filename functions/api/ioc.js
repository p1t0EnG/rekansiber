export async function onRequestGet({ request }) {
  try {
    const url = new URL(request.url);
    const ioc = url.searchParams.get("ioc");

    if (!ioc) {
      return new Response(
        JSON.stringify({ error: "IOC parameter is required" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    /**
     * === MOCK RESPONSE (AMAN, STABIL, TIDAK PAKAI API DULU) ===
     * Kita pastikan frontend + routing + history + verdict engine JALAN
     * API eksternal kita sambungkan SETELAH ini stabil
     */
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
        summary: "IOC is not detected as malicious by any intelligence source.",
        details: [
          "VirusTotal: 0/94 detections",
          "AbuseIPDB score is 0",
          "No OTX pulses found",
          "MXToolbox shows no blacklist"
        ]
      }
    };

    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });

  } catch (err) {
    return new Response(
      JSON.stringify({
        error: "Unhandled backend error",
        message: err.message
      }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
