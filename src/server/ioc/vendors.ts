import type { IocType } from './types';

// Daftar vendor di halaman Vendor Lookup. Sebagian besar hanya PIVOT ke portal
// resmi vendor, bukan integrasi API -- itu batasan lisensi, bukan teknis:
//  - Cisco Talos tidak punya API reputasi publik, dan ToS-nya melarang scraping.
//  - Symantec Site Review tidak punya API publik (dikonfirmasi KB Broadcom 175706),
//    dan penggunaan otomatis melanggar acceptable use policy mereka.
//  - Akamai hanya menyediakan lookup IOC di dalam produk ETP / Secure Internet Access.
// Satu-satunya yang punya API terbuka adalah Palo Alto Threat Vault (`liveApi`),
// untuk hash file dan alamat IP -- hasilnya ditampilkan langsung di kartunya.

export interface VendorLookup {
  id: string;
  name: string;
  /** Apa yang bisa dicek di portal ini */
  checks: string;
  /** Tipe IOC yang didukung portal tsb */
  supports: IocType[];
  /** true = nilai sudah terisi otomatis lewat URL; false = perlu ditempel manual */
  autofill: boolean;
  /** true = hasilnya diambil langsung lewat API dan ditampilkan di kartu */
  liveApi?: boolean;
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
    checks: 'Signature antivirus untuk hash file, dan keanggotaan IP feed Threat Prevention',
    supports: ['hash', 'ip'],
    autofill: false,
    liveApi: true,
    note: 'Hasil di bawah diambil langsung lewat API. Buka portal untuk detail signature lengkap, riwayat rilis, dan CVE terkait.',
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
