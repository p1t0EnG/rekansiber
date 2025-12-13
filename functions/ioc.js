export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const ioc = url.searchParams.get("ioc");

  if (!ioc) {
    return new Response(JSON.stringify({ error: "IOC required" }), { status: 400 });
  }

  const headers = { "Content-Type": "application/json" };

  try {
    const vt = await fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`,
      { headers: { "x-apikey": env.VT_KEY } }
    );

    const abuse = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}`,
      {
        headers: {
          Key: env.ABUSEIPDB_KEY,
          Accept: "application/json"
        }
      }
    );

    return new Response(
      JSON.stringify({
        virustotal: await vt.json(),
        abuseipdb: await abuse.json()
      }),
      { headers }
    );
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}
