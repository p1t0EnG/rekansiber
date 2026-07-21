export type IocType = 'ip' | 'domain' | 'hash' | 'url' | 'email';

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

export interface ProviderResult {
  name: string;
  verdict: Verdict;
  detail: string;
  // true kalau provider GAGAL memberi penilaian (network/API error) -- beda dari
  // "tidak ada data" yang wajar (mis. VT 404 = belum pernah dilaporkan). Dipakai
  // aggregate supaya kegagalan tidak menghasilkan verdict "clean" palsu.
  error?: boolean;
}

// Batas jumlah IOC per request bulk checking, biar tidak menghabiskan kuota
// free-tier VirusTotal/AbuseIPDB/OTX sekali jalan.
export const MAX_BULK_ITEMS = 50;
