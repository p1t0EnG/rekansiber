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
  /**
   * Merek induk. Mode massal menampilkan SATU KOLOM per merek, jadi beberapa
   * entri yang semereknya (mis. Talos Reputation Center untuk IP/domain/URL dan
   * Talos File Reputation untuk hash) berbagi kolom yang sama dan dipilih
   * menurut tipe IOC barisnya.
   */
  brand: string;
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
    brand: 'Cisco Talos',
    name: 'Cisco Talos — Reputation Center',
    checks: 'Reputasi IP, domain, dan URL',
    supports: ['ip', 'domain', 'url'],
    autofill: true,
    note: 'Data Talos disegarkan tiap 3 jam.',
    buildUrl: (v) => `https://www.talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}`,
  },
  {
    id: 'talos-file',
    brand: 'Cisco Talos',
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
    brand: 'Symantec',
    name: 'Symantec Site Review (Broadcom)',
    checks: 'Kategori URL/domain di WebFilter',
    supports: ['domain', 'url'],
    autofill: false,
    note: 'Broadcom melarang pengecekan otomatis, jadi nilainya ditempel manual.',
    buildUrl: () => 'https://sitereview.bluecoat.com/',
  },
  {
    id: 'pan-urlfiltering',
    brand: 'Palo Alto',
    name: 'Palo Alto — Test A Site (PAN-DB)',
    checks: 'Kategori URL/domain di PAN-DB',
    supports: ['domain', 'url'],
    autofill: false,
    note: 'Padanan Site Review untuk firewall Palo Alto kita.',
    buildUrl: () => 'https://urlfiltering.paloaltonetworks.com/',
  },
  {
    id: 'pan-threatvault',
    brand: 'Palo Alto',
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
    brand: 'Zscaler',
    name: 'Zscaler — Site Review',
    checks: 'Kategori URL/domain di database filtering Zscaler',
    supports: ['domain', 'url'],
    autofill: false,
    note: 'Lookup DATABASE -- menunjukkan kategori yang sudah Zscaler tetapkan (mis. Phishing, Malicious Content). Cepat, dan inilah yang dipakai gateway Zscaler untuk memblokir. Pakai ini lebih dulu.',
    buildUrl: () => 'https://sitereview.zscaler.com/',
  },
  {
    id: 'zscaler-urlanalysis',
    brand: 'Zscaler',
    name: 'Zscaler — URL Analysis (Zulu)',
    checks: 'Analisis risiko langsung terhadap isi halaman',
    supports: ['url'],
    autofill: false,
    // Rumah Zulu yang masih dirawat ada di ThreatLabz; domain lama
    // zulu.zscaler.com masih hidup tapi footer-nya berhenti di 2024.
    note: 'Analisis LANGSUNG -- halamannya benar-benar dibuka dan diperiksa saat itu juga (isi halaman, pola URL, reputasi IP/DNS), lalu diberi skor 0-100 dan verdict Benign/Suspicious/Malicious. Pakai ini kalau Site Review bilang belum terkategori tapi kamu masih curiga, mis. URL phishing yang baru dibuat. Lebih lambat, bisa 20 detik lebih.',
    buildUrl: () => 'https://threatlabz.zscaler.com/tool/url-analysis',
  },
];

export function vendorsFor(type: IocType): VendorLookup[] {
  return VENDORS.filter((v) => v.supports.includes(type));
}

/**
 * Urutan kolom di mode massal. Palo Alto didahulukan karena cuma dia yang
 * dijawab otomatis -- kolom yang paling berguna dibaca lebih dulu.
 */
export const VENDOR_BRANDS = ['Palo Alto', 'Cisco Talos', 'Zscaler', 'Symantec'] as const;

/**
 * Entri merek tertentu yang menangani satu IOC. Mengembalikan null kalau merek
 * itu memang tidak punya portal untuk tipe tsb -- mis. Zscaler tidak melayani
 * hash, jadi selnya dibiarkan kosong, bukan diisi tautan yang menyesatkan.
 */
export function vendorForBrand(brand: string, value: string, type: IocType): VendorLookup | null {
  return (
    VENDORS.find(
      (v) => v.brand === brand && v.supports.includes(type) && (!v.accepts || v.accepts(value, type)),
    ) ?? null
  );
}

export const ALL_VENDORS = VENDORS;
