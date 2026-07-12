export type IocType = 'ip' | 'domain' | 'hash' | 'url';

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

export interface ProviderResult {
  name: string;
  verdict: Verdict;
  detail: string;
}
