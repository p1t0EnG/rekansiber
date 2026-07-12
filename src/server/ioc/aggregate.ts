import type { ProviderResult, Verdict } from './types';

export function aggregateVerdict(results: (ProviderResult | null)[]): Verdict {
  const valid = results.filter((r): r is ProviderResult => r !== null);
  if (valid.some((r) => r.verdict === 'malicious')) return 'malicious';
  if (valid.some((r) => r.verdict === 'suspicious')) return 'suspicious';
  if (valid.some((r) => r.verdict === 'clean')) return 'clean';
  return 'unknown';
}
