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

// Palo Alto Threat Vault. Dua jenis lookup yang dipakai di sini:
//   - hash file (MD5/SHA-256) -> /threats, metadata signature antivirus + verdict WildFire
//   - alamat IP               -> /ip-feed, keanggotaan di IP feed Threat Prevention
// SHA-1 serta domain/URL tidak didukung API-nya -> return null supaya kartunya
// tidak muncul sama sekali, bukan muncul kosong. Butuh langganan Threat
// Prevention/ATP aktif; tanpa API key hasilnya ditandai "belum dikonfigurasi"
// (bukan error provider).
const THREAT_VAULT_BASE = 'https://api.threatvault.paloaltonetworks.com/service/v1';
const TV_NAME = 'Threat Vault';

export async function checkThreatVault(
  value: string,
  type: IocType,
  apiKey: string | undefined,
): Promise<ProviderResult | null> {
  if (type !== 'hash' && type !== 'ip') return null;

  // 32 hex = MD5, 64 hex = SHA-256. SHA-1 (40) tidak didukung endpoint /threats.
  const hashParam = value.length === 32 ? 'md5' : value.length === 64 ? 'sha256' : null;
  if (type === 'hash' && !hashParam) return null;

  if (!apiKey) {
    return {
      name: TV_NAME,
      verdict: 'unknown',
      detail: 'API key Threat Vault belum dikonfigurasi (set THREATVAULT_API_KEY)',
    };
  }

  const url =
    type === 'hash'
      ? `${THREAT_VAULT_BASE}/threats?${hashParam}=${encodeURIComponent(value)}`
      : `${THREAT_VAULT_BASE}/ip-feed?ipaddr=${encodeURIComponent(value)}`;

  try {
    const res = await fetch(url, { headers: { 'X-API-KEY': apiKey, Accept: 'application/json' } });

    // Hash tanpa signature dijawab 404 -- wajar, bukan kegagalan. Endpoint
    // /ip-feed tidak pernah 404: IP yang bersih tetap 200 dengan name: null.
    if (res.status === 404 && type === 'hash') {
      return { name: TV_NAME, verdict: 'clean', detail: 'Tidak ada signature antivirus yang cocok' };
    }
    if (res.status === 401 || res.status === 403) {
      return {
        name: TV_NAME,
        verdict: 'unknown',
        detail: `API key ditolak (${res.status}) -- cek key dan status langganan`,
        error: true,
      };
    }
    if (!res.ok) {
      return { name: TV_NAME, verdict: 'unknown', detail: `API error (${res.status})`, error: true };
    }

    const data = await res.json<any>();

    // FAIL-SAFE: hanya simpulkan sesuatu kalau responsnya memang BERBENTUK hasil
    // yang kita kenali. Struktur tak dikenali -> unknown, jangan tebak clean,
    // supaya IOC berbahaya tidak pernah lolos dianggap aman.
    if (!data || typeof data !== 'object' || data.success !== true) {
      return {
        name: TV_NAME,
        verdict: 'unknown',
        detail: 'Format respons Threat Vault tidak dikenali -- cek manual di portal',
        error: true,
      };
    }

    return type === 'hash' ? readHashResult(data) : readIpFeedResult(data);
  } catch {
    return { name: TV_NAME, verdict: 'unknown', detail: 'Gagal menghubungi Threat Vault', error: true };
  }
}

// Bentuk respons /threats (diverifikasi langsung ke API):
//   { success, count, data: { fileinfo: [ { type, family, platform, wildfire_verdict,
//     signatures: { antivirus: [ { name, severity } ] } } ] } }
function readHashResult(data: any): ProviderResult {
  const files: any[] = Array.isArray(data?.data?.fileinfo) ? data.data.fileinfo : [];
  if (files.length === 0) {
    return { name: TV_NAME, verdict: 'clean', detail: 'Tidak ada signature antivirus yang cocok' };
  }

  const file = files[0] ?? {};
  const wildfire = typeof file.wildfire_verdict === 'string' ? file.wildfire_verdict.toLowerCase() : '';
  const avSignatures: any[] = Array.isArray(file?.signatures?.antivirus) ? file.signatures.antivirus : [];

  // wildfire_verdict adalah penilaian resmi Palo Alto; kalau tidak ada, adanya
  // signature antivirus sendiri sudah menandakan file dikenali berbahaya.
  const verdict: Verdict =
    wildfire === 'malicious' || wildfire === 'phishing'
      ? 'malicious'
      : wildfire === 'grayware'
        ? 'suspicious'
        : wildfire === 'benign'
          ? 'clean'
          : avSignatures.length > 0
            ? 'malicious'
            : 'unknown';

  const descriptor = [file.type, file.family].filter((x) => typeof x === 'string' && x.trim()).join('/');
  const sigName = typeof avSignatures[0]?.name === 'string' ? avSignatures[0].name : '';
  const detail = [
    descriptor || 'Sampel dikenali',
    file.platform ? `(${file.platform})` : '',
    wildfire ? `-- WildFire: ${wildfire}` : '',
    avSignatures.length ? `-- ${avSignatures.length} signature AV${sigName ? `: ${sigName}` : ''}` : '',
  ]
    .filter(Boolean)
    .join(' ');

  return { name: TV_NAME, verdict, detail };
}

// Bentuk respons /ip-feed (diverifikasi langsung ke API):
//   { success, count, data: [ { ipaddr, name, status, release, geo, asn } ] }
// `name` = nama IP feed Threat Prevention yang memuat IP ini, atau null kalau
// tidak terdaftar (status "N/A"). geo/asn selalu terisi dan tetap berguna
// sebagai konteks walau IP-nya bersih.
function readIpFeedResult(data: any): ProviderResult {
  const rows: any[] = Array.isArray(data?.data) ? data.data : [];
  if (rows.length === 0) {
    return { name: TV_NAME, verdict: 'unknown', detail: 'Tidak ada data IP feed untuk alamat ini' };
  }

  const row = rows[0] ?? {};
  const feed = typeof row.name === 'string' && row.name.trim() ? row.name.trim() : '';
  const context = [row.geo, row.asn].filter((x) => typeof x === 'string' && x.trim()).join(' -- ');

  if (!feed) {
    return {
      name: TV_NAME,
      verdict: 'clean',
      detail: ['Tidak terdaftar di IP feed Threat Prevention', context].filter(Boolean).join(' -- '),
    };
  }

  // "Known malicious" = sudah terbukti jahat. "High risk" / "Bulletproof hosting"
  // = lingkungan berisiko -- belum tentu IP-nya sendiri sedang menyerang, jadi
  // ditandai suspicious supaya analyst tetap memeriksa, bukan langsung memblokir.
  const verdict: Verdict = feed.toLowerCase().includes('malicious') ? 'malicious' : 'suspicious';

  return {
    name: TV_NAME,
    verdict,
    detail: [`Terdaftar di "${feed}"`, context].filter(Boolean).join(' -- '),
  };
}
