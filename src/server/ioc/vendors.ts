import type { IocType } from './types';

// Pivot lookup ke portal vendor. Ini SENGAJA bukan integrasi API:
//  - Cisco Talos tidak punya API reputasi publik, dan ToS-nya melarang scraping.
//  - Symantec Site Review tidak punya API publik (dikonfirmasi KB Broadcom 175706),
//    dan penggunaan otomatis melanggar acceptable use policy mereka.
//  - Akamai hanya menyediakan lookup IOC di dalam produk ETP / Secure Internet Access.
//  - Palo Alto Threat Vault punya API, tapi butuh langganan Threat Prevention/ATP
//    dan cakupannya hash + CVE (bukan IP/domain/URL).
// Jadi di sini kita bantu analyst berpindah cepat ke portal resminya, bukan
// mengotomatiskan pengambilan datanya.

export interface VendorLookup {
  id: string;
  name: string;
  /** Apa yang bisa dicek di portal ini */
  checks: string;
  /** Tipe IOC yang didukung portal tsb */
  supports: IocType[];
  /** true = nilai sudah terisi otomatis lewat URL; false = perlu ditempel manual */
  autofill: boolean;
  /** Catatan penting (mis. butuh akun / batasan kebijakan) */
  note?: string;
  /** Halaman lookup. value sudah di-encode saat autofill. */
  buildUrl: (value: string) => string;
}

const VENDORS: VendorLookup[] = [
  {
    id: 'talos-rep',
    name: 'Cisco Talos — Reputation Center',
    checks: 'Reputasi IP, domain, dan URL',
    supports: ['ip', 'domain', 'url'],
    autofill: true,
    note: 'Data Talos disegarkan tiap 3 jam.',
    buildUrl: (v) => `https://www.talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}`,
  },
  {
    id: 'talos-file',
    name: 'Cisco Talos — File Reputation',
    checks: 'Reputasi hash file',
    supports: ['hash'],
    autofill: false,
    note: 'Hanya menerima SHA-256, satu hash per pencarian.',
    buildUrl: () => 'https://www.talosintelligence.com/sha_searches',
  },
  {
    id: 'symantec-sitereview',
    name: 'Symantec Site Review (Broadcom)',
    checks: 'Kategori URL/domain di WebFilter',
    supports: ['domain', 'url'],
    autofill: false,
    note: 'Broadcom melarang pengecekan otomatis, jadi nilainya ditempel manual.',
    buildUrl: () => 'https://sitereview.bluecoat.com/',
  },
  {
    id: 'pan-urlfiltering',
    name: 'Palo Alto — Test A Site (PAN-DB)',
    checks: 'Kategori URL/domain di PAN-DB',
    supports: ['domain', 'url'],
    autofill: false,
    note: 'Padanan Site Review untuk firewall Palo Alto kita.',
    buildUrl: () => 'https://urlfiltering.paloaltonetworks.com/',
  },
  {
    id: 'pan-threatvault',
    name: 'Palo Alto — Threat Vault',
    checks: 'Metadata signature untuk hash file',
    supports: ['hash'],
    autofill: false,
    note: 'Butuh akun Palo Alto dengan langganan Threat Prevention/ATP aktif.',
    buildUrl: () => 'https://threatvault.paloaltonetworks.com/',
  },
  {
    id: 'akamai',
    name: 'Akamai — Control Center',
    checks: 'Lookup IOC domain/IP (ETP / Secure Internet Access)',
    supports: ['ip', 'domain', 'url'],
    autofill: false,
    note: 'Akamai tidak punya lookup publik -- butuh akun ETP / Secure Internet Access.',
    buildUrl: () => 'https://control.akamai.com/',
  },
];

export function vendorsFor(type: IocType): VendorLookup[] {
  return VENDORS.filter((v) => v.supports.includes(type));
}

export const ALL_VENDORS = VENDORS;
