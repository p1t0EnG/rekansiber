// Cari kontak abuse untuk domain phishing lewat RDAP (WHOIS modern berbasis JSON,
// bisa dipanggil dari Workers runtime tanpa socket WHOIS port 43):
//   1. RDAP domain  -> registrar + email abuse registrar
//   2. DNS-over-HTTPS -> IP hosting yang dipakai domain
//   3. RDAP IP      -> organisasi hosting + email abuse network (mis. Hostinger)
// Email abuse hosting-lah yang paling relevan untuk laporan takedown situs phishing.

export interface AbuseLookupResult {
  domain: string;
  ip: string | null;
  registrarName: string | null;
  registrarAbuseEmails: string[];
  hostingName: string | null;
  hostingAbuseEmails: string[];
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown;
  entities?: RdapEntity[];
}

const FETCH_HEADERS = {
  Accept: 'application/rdap+json, application/json',
  'User-Agent': 'RekanSiberAbuseLookup/1.0',
};

function vcardValues(vcardArray: unknown, field: 'email' | 'fn'): string[] {
  const items = Array.isArray(vcardArray) && Array.isArray(vcardArray[1]) ? vcardArray[1] : [];
  return items
    .filter((i: unknown): i is [string, unknown, string, string] => Array.isArray(i) && i[0] === field && typeof i[3] === 'string')
    .map((i) => i[3].trim())
    .filter(Boolean);
}

function collectAbuseEmails(entities: RdapEntity[] | undefined, out: Set<string>): void {
  for (const entity of entities ?? []) {
    if (entity.roles?.includes('abuse')) {
      for (const email of vcardValues(entity.vcardArray, 'email')) out.add(email.toLowerCase());
    }
    collectAbuseEmails(entity.entities, out);
  }
}

function findEntityName(entities: RdapEntity[] | undefined, role: string): string | null {
  for (const entity of entities ?? []) {
    if (entity.roles?.includes(role)) {
      const [name] = vcardValues(entity.vcardArray, 'fn');
      if (name) return name;
    }
    const nested = findEntityName(entity.entities, role);
    if (nested) return nested;
  }
  return null;
}

async function fetchJson(url: string): Promise<any | null> {
  try {
    const res = await fetch(url, { headers: FETCH_HEADERS });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// RDAP registry hanya kenal domain terdaftar (registrable), bukan subdomain --
// kalau lookup subdomain gagal, coba lagi dengan label paling kiri dibuang
// (mis. login.bank-abc.xyz -> bank-abc.xyz).
async function fetchDomainRdap(host: string): Promise<{ data: any; domain: string } | null> {
  let candidate = host.replace(/^www\./i, '');
  while (candidate.split('.').length >= 2) {
    const data = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(candidate)}`);
    if (data) return { data, domain: candidate };
    const labels = candidate.split('.');
    if (labels.length <= 2) break;
    candidate = labels.slice(1).join('.');
  }
  return null;
}

// Resolve A record via DNS-over-HTTPS (butuh header Accept application/dns-json)
async function resolveIp(host: string): Promise<string | null> {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { Accept: 'application/dns-json' },
    });
    if (!res.ok) return null;
    const json = await res.json<any>();
    const answer = (json?.Answer ?? []).find((ans: any) => ans.type === 1 && typeof ans.data === 'string');
    return answer?.data ?? null;
  } catch {
    return null;
  }
}

export async function lookupAbuseContacts(host: string): Promise<AbuseLookupResult> {
  const result: AbuseLookupResult = {
    domain: host,
    ip: null,
    registrarName: null,
    registrarAbuseEmails: [],
    hostingName: null,
    hostingAbuseEmails: [],
  };

  const [domainRdap, ip] = await Promise.all([fetchDomainRdap(host), resolveIp(host)]);

  if (domainRdap) {
    result.domain = domainRdap.domain;
    result.registrarName = findEntityName(domainRdap.data?.entities, 'registrar');
    const emails = new Set<string>();
    collectAbuseEmails(domainRdap.data?.entities, emails);
    result.registrarAbuseEmails = [...emails];
  }

  if (ip) {
    result.ip = ip;
    const ipRdap = await fetchJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
    if (ipRdap) {
      result.hostingName =
        (typeof ipRdap.name === 'string' && ipRdap.name) || findEntityName(ipRdap.entities, 'registrant') || null;
      const emails = new Set<string>();
      collectAbuseEmails(ipRdap.entities, emails);
      result.hostingAbuseEmails = [...emails];
    }
  }

  return result;
}
