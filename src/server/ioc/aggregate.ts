import type { ProviderResult, Verdict } from './types';

export function aggregateVerdict(results: (ProviderResult | null)[]): Verdict {
  const valid = results.filter((r): r is ProviderResult => r !== null);
  // Temuan buruk dari provider mana pun tetap menang, meski provider lain gagal.
  if (valid.some((r) => r.verdict === 'malicious')) return 'malicious';
  if (valid.some((r) => r.verdict === 'suspicious')) return 'suspicious';
  // Kalau ada provider yang GAGAL memberi penilaian (bukan sekadar tidak ada data),
  // hasil "clean" belum konklusif -- jangan tampilkan aman palsu. Tandai unknown
  // supaya analyst tahu harus cek ulang, bukan menyimpulkan IOC aman.
  if (valid.some((r) => r.error)) return 'unknown';
  if (valid.some((r) => r.verdict === 'clean')) return 'clean';
  return 'unknown';
}
