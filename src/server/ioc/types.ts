export type IocType = 'ip' | 'domain' | 'hash' | 'url';

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

export interface ProviderResult {
  name: string;
  verdict: Verdict;
  detail: string;
}

// Batas jumlah IOC per request bulk checking, biar tidak menghabiskan kuota
// free-tier VirusTotal/AbuseIPDB/OTX sekali jalan.
export const MAX_BULK_ITEMS = 50;
