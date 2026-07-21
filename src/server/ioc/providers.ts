import type { IocType, ProviderResult, Verdict } from './types';

// VirusTotal v3 butuh id url dalam bentuk base64url tanpa padding
function urlToVtId(url: string): string {
  return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// VT/OTX tidak punya lookup alamat email -- yang dicek reputasi DOMAIN-nya
// (bagian setelah '@'), yang biasanya justru sinyal paling berguna.
export function emailDomain(value: string): string {
  return value.split('@')[1] ?? '';
}

export async function checkVirusTotal(value: string, type: IocType, apiKey: string): Promise<ProviderResult> {
  const pathByType: Record<IocType, string> = {
    ip: `ip_addresses/${value}`,
    domain: `domains/${value}`,
    hash: `files/${value}`,
    url: `urls/${urlToVtId(value)}`,
    email: `domains/${emailDomain(value)}`,
  };

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/${pathByType[type]}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (res.status === 404) {
      return { name: 'VirusTotal', verdict: 'clean', detail: 'Belum pernah dilaporkan (tidak ada data)' };
    }
    if (!res.ok) {
      return { name: 'VirusTotal', verdict: 'unknown', detail: `API error (${res.status})`, error: true };
    }

    const data = await res.json<any>();
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return { name: 'VirusTotal', verdict: 'unknown', detail: 'Data analisis tidak tersedia', error: true };
    }

    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    const verdict: Verdict = stats.malicious > 0 ? 'malicious' : stats.suspicious > 0 ? 'suspicious' : 'clean';
    return {
      name: 'VirusTotal',
      verdict,
      detail: `${stats.malicious} malicious, ${stats.suspicious} suspicious dari ${total} engine`,
    };
  } catch {
    return { name: 'VirusTotal', verdict: 'unknown', detail: 'Gagal menghubungi VirusTotal', error: true };
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
      return { name: 'AbuseIPDB', verdict: 'unknown', detail: `API error (${res.status})`, error: true };
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
    return { name: 'AbuseIPDB', verdict: 'unknown', detail: 'Gagal menghubungi AbuseIPDB', error: true };
  }
}

const OTX_TYPE_MAP: Record<IocType, string> = {
  ip: 'IPv4',
  domain: 'domain',
  url: 'url',
  hash: 'file',
  email: 'domain',
};

export async function checkOTX(value: string, type: IocType, apiKey: string): Promise<ProviderResult> {
  try {
    const otxType = OTX_TYPE_MAP[type];
    const lookupValue = type === 'email' ? emailDomain(value) : value;
    const indicator = type === 'url' ? encodeURIComponent(lookupValue) : lookupValue;
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/${otxType}/${indicator}/general`, {
      headers: { 'X-OTX-API-KEY': apiKey },
    });

    if (!res.ok) {
      return { name: 'OTX', verdict: 'unknown', detail: `API error (${res.status})`, error: true };
    }

    const data = await res.json<any>();
    const count = data?.pulse_info?.count ?? 0;
    // Nama pulse paling atas dari OTX (pulse = laporan komunitas berisi kumpulan IOC
    // terkait satu kampanye/ancaman) -- konteks cepat kenapa IOC ini ditandai.
    const topPulseRaw = data?.pulse_info?.pulses?.[0]?.name;
    const topPulse =
      typeof topPulseRaw === 'string' && topPulseRaw.trim()
        ? topPulseRaw.trim().slice(0, 80) + (topPulseRaw.trim().length > 80 ? '...' : '')
        : null;
    const verdict: Verdict = count >= 5 ? 'malicious' : count >= 1 ? 'suspicious' : 'clean';
    return {
      name: 'OTX',
      verdict,
      detail: `Muncul di ${count} threat pulse${topPulse ? ` -- pulse teratas: "${topPulse}"` : ''}`,
    };
  } catch {
    return { name: 'OTX', verdict: 'unknown', detail: 'Gagal menghubungi OTX', error: true };
  }
}

// MXToolbox: khusus IOC email -- cek apakah domain pengirim terdaftar di
// blacklist/RBL email. Return null untuk type lain (dianggap "tidak berlaku").
export async function checkMxToolbox(
  value: string,
  type: IocType,
  apiKey: string | undefined,
): Promise<ProviderResult | null> {
  if (type !== 'email') return null;

  const domain = emailDomain(value);
  if (!domain) return null;

  if (!apiKey) {
    return {
      name: 'MXToolbox',
      verdict: 'unknown',
      detail: 'API key MXToolbox belum dikonfigurasi (set MXTOOLBOX_API_KEY)',
    };
  }

  try {
    const res = await fetch(`https://mxtoolbox.com/api/v1/Lookup/blacklist/?argument=${encodeURIComponent(domain)}`, {
      headers: { Authorization: apiKey, Accept: 'application/json' },
    });

    if (!res.ok) {
      return { name: 'MXToolbox', verdict: 'unknown', detail: `API error (${res.status})`, error: true };
    }

    const data = await res.json<any>();
    const failed: { Name?: string }[] = Array.isArray(data?.Failed) ? data.Failed : [];
    const passed: { Name?: string }[] = Array.isArray(data?.Passed) ? data.Passed : [];
    const total = failed.length + passed.length;

    if (total === 0) {
      return { name: 'MXToolbox', verdict: 'unknown', detail: `Tidak ada data blacklist untuk ${domain}` };
    }

    const verdict: Verdict = failed.length >= 2 ? 'malicious' : failed.length === 1 ? 'suspicious' : 'clean';
    const listedNames = failed
      .map((f) => f.Name)
      .filter(Boolean)
      .slice(0, 3)
      .join(', ');
    return {
      name: 'MXToolbox',
      verdict,
      detail:
        `Domain ${domain} terdaftar di ${failed.length} dari ${total} blacklist` +
        (listedNames ? ` (${listedNames})` : ''),
    };
  } catch {
    return { name: 'MXToolbox', verdict: 'unknown', detail: 'Gagal menghubungi MXToolbox', error: true };
  }
}
