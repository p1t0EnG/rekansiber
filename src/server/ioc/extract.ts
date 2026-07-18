import { isValidIoc } from './validate';

// Ekstraksi IOC dari teks dokumen threat intel (mis. Daily Threat Intel Report .docx).
// Dokumen semacam itu men-defang IOC-nya (contoh: `mora1987[.]work[.]gd`, `hxxps://...`)
// supaya tidak bisa diklik/resolve tanpa sengaja -- jadi sebelum diklasifikasi,
// setiap kandidat harus di-refang dulu.

export interface ExtractedIocs {
  md5: string[];
  sha1: string[];
  sha256: string[];
  ip: string[];
  domain: string[];
  url: string[];
  email: string[];
  other: string[]; // email subject / nama attachment -- tetap IOC, tapi tidak bisa dicek ke provider
  mode: 'section' | 'fulltext';
  total: number;
}

export function refang(s: string): string {
  return s
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{\.\}/g, '.')
    .replace(/\bhxxps:\/\//gi, 'https://')
    .replace(/\bhxxp:\/\//gi, 'http://')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\[@\]/g, '@');
}

const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;

type Bucket = Exclude<keyof ExtractedIocs, 'mode' | 'total'>;

function classifyValue(value: string): { bucket: Bucket; value: string } | null {
  // Buang tanda baca akhir kalimat yang sering nempel di IOC dalam prosa ("...co." dsb.)
  const v = refang(value).replace(/[.,;:]+$/, '').trim();
  if (!v || /^n\/?a$/i.test(v)) return null;

  if (isValidIoc(v, 'hash')) {
    const bucket = v.length === 32 ? 'md5' : v.length === 40 ? 'sha1' : 'sha256';
    return { bucket, value: v.toLowerCase() };
  }
  if (isValidIoc(v, 'url')) return { bucket: 'url', value: v };
  if (EMAIL_RE.test(v)) return { bucket: 'email', value: v.toLowerCase() };
  if (isValidIoc(v, 'ip')) return { bucket: 'ip', value: v };
  if (isValidIoc(v, 'domain')) return { bucket: 'domain', value: v.toLowerCase() };
  return { bucket: 'other', value: v };
}

// Format laporan threat intel: blok IOC diapit header "Indicator of compromise"
// dan section berikutnya (Analyst Opinion / Recommendation / Source / Appendix).
const SECTION_START = /^indicator[s]? of compromise$/i;
const SECTION_END = /^(analyst opinion|recommendation and controls|source|appendix)$/i;
const SUBHEADS = new Set([
  'md5', 'sha-1', 'sha1', 'sha-256', 'sha256', 'domain/ip', 'domain', 'ip',
  'url', 'email address', 'email subject', 'email attachment/link',
]);

function emptyResult(mode: ExtractedIocs['mode']): ExtractedIocs {
  return { md5: [], sha1: [], sha256: [], ip: [], domain: [], url: [], email: [], other: [], mode, total: 0 };
}

function pushUnique(result: ExtractedIocs, seen: Set<string>, bucket: Bucket, value: string): void {
  const key = `${bucket}:${value}`;
  if (seen.has(key)) return;
  seen.add(key);
  result[bucket].push(value);
  result.total++;
}

function stripBullet(line: string): string {
  // Penanda angka ("1. item") hanya di-strip kalau diikuti spasi -- tanpa syarat itu,
  // oktet pertama IP ("195.133.67.35") ikut termakan karena mirip penanda list.
  return line.replace(/^\s*(?:[•▪‣·*-]\s*|\d+[.)]\s+)/, '').trim();
}

function extractFromSections(text: string): ExtractedIocs {
  const result = emptyResult('section');
  const seen = new Set<string>();
  let inSection = false;

  for (const rawLine of text.split('\n')) {
    const line = stripBullet(rawLine);
    if (SECTION_START.test(line)) {
      inSection = true;
      continue;
    }
    if (inSection && SECTION_END.test(line)) {
      inSection = false;
      continue;
    }
    if (!inSection || !line || SUBHEADS.has(line.toLowerCase())) continue;

    const ioc = classifyValue(line);
    if (ioc) pushUnique(result, seen, ioc.bucket, ioc.value);
  }
  return result;
}

// Fallback untuk dokumen tanpa header "Indicator of compromise": pindai seluruh teks.
// Hash & email diambil apa adanya; domain/IP/URL hanya diambil kalau ditulis defanged
// ([.] atau hxxp) -- itu tanda eksplisit "ini IOC", bukan sekadar link/nama file di prosa.
function extractFromFullText(text: string): ExtractedIocs {
  const result = emptyResult('fulltext');
  const seen = new Set<string>();

  for (const match of text.match(/\b[a-f0-9]{64}\b/gi) ?? []) {
    pushUnique(result, seen, 'sha256', match.toLowerCase());
  }
  for (const match of text.match(/\b[a-f0-9]{40}\b/gi) ?? []) {
    pushUnique(result, seen, 'sha1', match.toLowerCase());
  }
  for (const match of text.match(/\b[a-f0-9]{32}\b/gi) ?? []) {
    pushUnique(result, seen, 'md5', match.toLowerCase());
  }
  for (const match of text.match(/\b[a-z0-9._%+-]+(?:@|\[@\])[a-z0-9.\-\[\]]+/gi) ?? []) {
    const ioc = classifyValue(match);
    if (ioc?.bucket === 'email') pushUnique(result, seen, 'email', ioc.value);
  }
  // Token defanged: mengandung [.] atau diawali hxxp(s)
  for (const match of text.match(/\bhxxps?:\/\/\S+|\S*\[\.\]\S*/gi) ?? []) {
    const ioc = classifyValue(match.replace(/[.,;:)\]"']+$/, ''));
    if (ioc && (ioc.bucket === 'ip' || ioc.bucket === 'domain' || ioc.bucket === 'url')) {
      pushUnique(result, seen, ioc.bucket, ioc.value);
    }
  }
  return result;
}

export function extractIocs(text: string): ExtractedIocs {
  const hasIocSections = text.split('\n').some((line) => SECTION_START.test(stripBullet(line)));
  return hasIocSections ? extractFromSections(text) : extractFromFullText(text);
}

export const BUCKET_LABELS: Record<Bucket, string> = {
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  email: 'Email Address',
  other: 'Lainnya (subject/attachment)',
};

export const BUCKET_ORDER: Bucket[] = ['md5', 'sha1', 'sha256', 'ip', 'domain', 'url', 'email', 'other'];

// Nilai yang bisa langsung dicek ke VT/AbuseIPDB/OTX lewat bulk checker
// (email & subject tidak didukung provider, jadi tidak ikut).
export function checkableValues(result: ExtractedIocs): string[] {
  return [...result.md5, ...result.sha1, ...result.sha256, ...result.ip, ...result.domain, ...result.url];
}

export function buildExportText(result: ExtractedIocs, sourceName: string): string {
  let out = `# Rekan Siber - IOC Extractor\n# Sumber: ${sourceName}\n# Diekstrak: ${new Date().toISOString()}\n# Total: ${result.total} IOC\n\n`;
  for (const bucket of BUCKET_ORDER) {
    const values = result[bucket];
    if (!values.length) continue;
    out += `# ${BUCKET_LABELS[bucket]} (${values.length})\n${values.join('\n')}\n\n`;
  }
  return out;
}
