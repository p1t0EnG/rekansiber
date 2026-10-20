import type { IocType } from './types';

// Daftar vendor di halaman Vendor Lookup. Sebagian besar hanya PIVOT ke portal
// resmi vendor, bukan integrasi API -- itu batasan lisensi, bukan teknis:
//  - Cisco Talos tidak punya API reputasi publik, dan ToS-nya melarang scraping.
//  - Symantec Site Review tidak punya API publik (dikonfirmasi KB Broadcom 175706),
//    dan penggunaan otomatis melanggar acceptable use policy mereka.
//  - Zscaler menyediakan lookup publik satu per satu; pengecekan massal lewat
//    API-nya butuh tenant ZIA sendiri (lihat catatan tiap entri).
// Satu-satunya yang punya API terbuka tanpa lisensi tambahan adalah Palo Alto
// Threat Vault (`liveApi`), untuk hash file dan alamat IP -- hasilnya tampil
// langsung di kartunya. Akamai dikeluarkan sementara atas permintaan tim
// (status langganannya belum jelas).

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
  /**
   * Penyaring tambahan khusus mode massal. Sebagian portal lebih sempit dari
   * `supports` -- mis. Talos File Reputation hanya menerima SHA-256, jadi daftar
   * yang disalin untuk portal itu tidak boleh ikut membawa MD5.
   * Tanpa ini, seluruh tipe di `supports` dianggap cocok.
   */
  accepts?: (value: string, type: IocType) => boolean;
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
    accepts: (value, type) => type === 'hash' && value.length === 64,
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
    id: 'zscaler-sitereview',
    name: 'Zscaler — Site Review',
    checks: 'Kategori URL/domain di cloud Zscaler',
    supports: ['domain', 'url'],
    autofill: false,
    note: 'Lookup publik, satu per satu. Pengecekan massal lewat API butuh tenant ZIA (endpoint urlLookup, maks 100 URL sekali panggil).',
    buildUrl: () => 'https://sitereview.zscaler.com/',
  },
  {
    id: 'zscaler-zulu',
    name: 'Zscaler — Zulu URL Risk Analyzer',
    checks: 'Skor risiko konten dan reputasi satu URL',
    supports: ['url'],
    autofill: false,
    note: 'Menganalisis isi halaman dan reputasinya, lalu memberi skor risiko.',
    buildUrl: () => 'https://zulu.zscaler.com/',
  },
];

export function vendorsFor(type: IocType): VendorLookup[] {
  return VENDORS.filter((v) => v.supports.includes(type));
}

export const ALL_VENDORS = VENDORS;
