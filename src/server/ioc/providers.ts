import type { IocType, ProviderResult, Verdict } from './types';

// VirusTotal v3 butuh id url dalam bentuk base64url tanpa padding
function urlToVtId(url: string): string {
  return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function checkVirusTotal(value: string, type: IocType, apiKey: string): Promise<ProviderResult> {
  const pathByType: Record<IocType, string> = {
    ip: `ip_addresses/${value}`,
    domain: `domains/${value}`,
    hash: `files/${value}`,
    url: `urls/${urlToVtId(value)}`,
  };

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/${pathByType[type]}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (res.status === 404) {
      return { name: 'VirusTotal', verdict: 'clean', detail: 'Belum pernah dilaporkan (tidak ada data)' };
    }
    if (!res.ok) {
      return { name: 'VirusTotal', verdict: 'unknown', detail: `API error (${res.status})` };
    }

    const data = await res.json<any>();
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return { name: 'VirusTotal', verdict: 'unknown', detail: 'Data analisis tidak tersedia' };
    }

    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    const verdict: Verdict = stats.malicious > 0 ? 'malicious' : stats.suspicious > 0 ? 'suspicious' : 'clean';
    return {
      name: 'VirusTotal',
      verdict,
      detail: `${stats.malicious} malicious, ${stats.suspicious} suspicious dari ${total} engine`,
    };
  } catch {
    return { name: 'VirusTotal', verdict: 'unknown', detail: 'Gagal menghubungi VirusTotal' };
  }
}

// AbuseIPDB cuma berlaku untuk IP -- return null kalau type lain (dianggap "tidak berlaku")
export async function checkAbuseIPDB(value: string, type: IocType, apiKey: string): Promise<ProviderResult | null> {
  if (type !== 'ip') return null;

  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`,
      { headers: { Key: apiKey, Accept: 'application/json' } },
    );

    if (!res.ok) {
      return { name: 'AbuseIPDB', verdict: 'unknown', detail: `API error (${res.status})` };
    }

    const data = await res.json<any>();
    const score = data?.data?.abuseConfidenceScore ?? 0;
    const totalReports = data?.data?.totalReports ?? 0;
    const verdict: Verdict = score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : 'clean';
    return {
      name: 'AbuseIPDB',
      verdict,
      detail: `Skor abuse ${score}/100 dari ${totalReports} laporan`,
    };
  } catch {
    return { name: 'AbuseIPDB', verdict: 'unknown', detail: 'Gagal menghubungi AbuseIPDB' };
  }
}

const OTX_TYPE_MAP: Record<IocType, string> = {
  ip: 'IPv4',
  domain: 'domain',
  url: 'url',
  hash: 'file',
};

export async function checkOTX(value: string, type: IocType, apiKey: string): Promise<ProviderResult> {
  try {
    const otxType = OTX_TYPE_MAP[type];
    const indicator = type === 'url' ? encodeURIComponent(value) : value;
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/${otxType}/${indicator}/general`, {
      headers: { 'X-OTX-API-KEY': apiKey },
    });

    if (!res.ok) {
      return { name: 'OTX', verdict: 'unknown', detail: `API error (${res.status})` };
    }

    const data = await res.json<any>();
    const count = data?.pulse_info?.count ?? 0;
    const verdict: Verdict = count >= 5 ? 'malicious' : count >= 1 ? 'suspicious' : 'clean';
    return { name: 'OTX', verdict, detail: `Muncul di ${count} threat pulse` };
  } catch {
    return { name: 'OTX', verdict: 'unknown', detail: 'Gagal menghubungi OTX' };
  }
}
