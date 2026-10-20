import type { IocType, ProviderResult, Verdict } from './types';

// Palo Alto Threat Vault -- satu-satunya vendor di halaman Vendor Lookup yang
// punya API terbuka. Mencakup tiga hal yang berguna buat kita:
//   - hash file (MD5/SHA-256) -> signature antivirus + verdict WildFire
//   - alamat IP               -> keanggotaan di IP feed Threat Prevention
//   - CVE                     -> signature vulnerability yang menutup CVE tsb
// Domain, URL, dan SHA-1 TIDAK didukung API-nya.
//
// Bentuk request di bawah ini hasil VERIFIKASI langsung ke API, bukan dari
// dokumentasi: pan.dev mengosongkan bagian request body untuk endpoint batch.
//   GET  /threats?md5= | ?sha256= | ?cve=
//   POST /threats   body {"md5":[...]} ATAU {"sha256":[...]}  <- tidak boleh dicampur
//   GET  /ip-feed?ipaddr=
//   POST /ip-feed   body {"ipaddr":[...]}
//
// Empat perilaku yang menentukan cara kode ini ditulis:
//   1. Batch hash hanya mengembalikan hash yang PUNYA data. Kirim 3, bisa balik 2 --
//      yang hilang berarti tidak ada signature yang cocok (bersih), bukan error.
//   2. md5 kadang dikembalikan HURUF BESAR, jadi pencocokan harus case-insensitive.
//   3. Batch IP mengembalikan SEMUA IP, termasuk yang bersih (name: null).
//   4. Urutan hasil tidak sama dengan urutan kirim -> wajib dipetakan lewat Map.
const BASE = 'https://api.threatvault.paloaltonetworks.com/service/v1';
const TV_NAME = 'Threat Vault';
const BATCH_LIMIT = 100;

const NO_KEY_DETAIL = 'API key Threat Vault belum dikonfigurasi (set THREATVAULT_API_KEY)';

function authHeaders(apiKey: string): Record<string, string> {
  return { 'X-API-KEY': apiKey, Accept: 'application/json' };
}

// --- Pembacaan hasil, dipakai bareng jalur tunggal dan jalur batch ---

// fileinfo: { filetype, sha256, sha1, md5, size, type, family, platform,
//             wildfire_verdict, signatures: { antivirus: [ { name, severity } ] } }
function verdictFromFileInfo(file: any): Verdict {
  const wildfire = typeof file?.wildfire_verdict === 'string' ? file.wildfire_verdict.toLowerCase() : '';
  const avSignatures: any[] = Array.isArray(file?.signatures?.antivirus) ? file.signatures.antivirus : [];

  // wildfire_verdict adalah penilaian resmi Palo Alto; kalau tidak ada, adanya
  // signature antivirus sendiri sudah menandakan file dikenali berbahaya.
  if (wildfire === 'malicious' || wildfire === 'phishing') return 'malicious';
  if (wildfire === 'grayware') return 'suspicious';
  if (wildfire === 'benign') return 'clean';
  return avSignatures.length > 0 ? 'malicious' : 'unknown';
}

function detailFromFileInfo(file: any): string {
  const wildfire = typeof file?.wildfire_verdict === 'string' ? file.wildfire_verdict.toLowerCase() : '';
  const avSignatures: any[] = Array.isArray(file?.signatures?.antivirus) ? file.signatures.antivirus : [];
  const descriptor = [file?.type, file?.family].filter((x) => typeof x === 'string' && x.trim()).join('/');
  const sigName = typeof avSignatures[0]?.name === 'string' ? avSignatures[0].name : '';

  return [
    descriptor || 'Sampel dikenali',
    file?.platform ? `(${file.platform})` : '',
    wildfire ? `-- WildFire: ${wildfire}` : '',
    avSignatures.length ? `-- ${avSignatures.length} signature AV${sigName ? `: ${sigName}` : ''}` : '',
  ]
    .filter(Boolean)
    .join(' ');
}

const HASH_CLEAN_DETAIL = 'Tidak ada signature antivirus yang cocok';

// ip-feed row: { ipaddr, name, status, release, geo, asn }
// `name` = nama IP feed yang memuat IP ini, null kalau tidak terdaftar.
function verdictFromIpFeed(feed: string): Verdict {
  // "Known malicious" = sudah terbukti jahat. "High risk" / "Bulletproof hosting"
  // menggambarkan lingkungan IP-nya, belum tentu IP itu sendiri sedang menyerang,
  // jadi ditandai suspicious supaya analyst tetap memeriksa -- bukan langsung blokir.
  return feed.toLowerCase().includes('malicious') ? 'malicious' : 'suspicious';
}

function ipContext(row: any): string {
  return [row?.geo, row?.asn].filter((x) => typeof x === 'string' && x.trim()).join(' -- ');
}

function readIpRow(row: any): { verdict: Verdict; detail: string } {
  const feed = typeof row?.name === 'string' && row.name.trim() ? row.name.trim() : '';
  const context = ipContext(row);

  if (!feed) {
    return {
      verdict: 'clean',
      detail: ['Tidak terdaftar di IP feed Threat Prevention', context].filter(Boolean).join(' -- '),
    };
  }
  return {
    verdict: verdictFromIpFeed(feed),
    detail: [`Terdaftar di "${feed}"`, context].filter(Boolean).join(' -- '),
  };
}

// --- Jalur tunggal: dipakai IOC Checker, Bulk Checker, dan kartu Vendor Lookup ---

export async function checkThreatVault(
  value: string,
  type: IocType,
  apiKey: string | undefined,
): Promise<ProviderResult | null> {
  if (type !== 'hash' && type !== 'ip') return null;

  // 32 hex = MD5, 64 hex = SHA-256. SHA-1 (40) tidak didukung endpoint /threats.
  const hashParam = value.length === 32 ? 'md5' : value.length === 64 ? 'sha256' : null;
  if (type === 'hash' && !hashParam) return null;

  if (!apiKey) return { name: TV_NAME, verdict: 'unknown', detail: NO_KEY_DETAIL };

  const url =
    type === 'hash'
      ? `${BASE}/threats?${hashParam}=${encodeURIComponent(value)}`
      : `${BASE}/ip-feed?ipaddr=${encodeURIComponent(value)}`;

  try {
    const res = await fetch(url, { headers: authHeaders(apiKey) });

    // Hash tanpa signature dijawab 404 -- wajar, bukan kegagalan. /ip-feed tidak
    // pernah 404: IP bersih tetap 200 dengan name: null.
    if (res.status === 404 && type === 'hash') {
      return { name: TV_NAME, verdict: 'clean', detail: HASH_CLEAN_DETAIL };
    }
    if (res.status === 401 || res.status === 403) {
      return {
        name: TV_NAME,
        verdict: 'unknown',
        detail: `API key ditolak (${res.status}) -- cek key dan status langganan`,
        error: true,
      };
    }
    if (!res.ok) {
      return { name: TV_NAME, verdict: 'unknown', detail: `API error (${res.status})`, error: true };
    }

    const data = await res.json<any>();

    // FAIL-SAFE: hanya simpulkan sesuatu kalau responsnya memang BERBENTUK hasil
    // yang kita kenali. Struktur tak dikenali -> unknown, jangan tebak clean.
    if (!data || typeof data !== 'object' || data.success !== true) {
      return {
        name: TV_NAME,
        verdict: 'unknown',
        detail: 'Format respons Threat Vault tidak dikenali -- cek manual di portal',
        error: true,
      };
    }

    if (type === 'hash') {
      const files: any[] = Array.isArray(data?.data?.fileinfo) ? data.data.fileinfo : [];
      if (files.length === 0) return { name: TV_NAME, verdict: 'clean', detail: HASH_CLEAN_DETAIL };
      return { name: TV_NAME, verdict: verdictFromFileInfo(files[0]), detail: detailFromFileInfo(files[0]) };
    }

    const rows: any[] = Array.isArray(data?.data) ? data.data : [];
    if (rows.length === 0) {
      return { name: TV_NAME, verdict: 'unknown', detail: 'Tidak ada data IP feed untuk alamat ini' };
    }
    const { verdict, detail } = readIpRow(rows[0]);
    return { name: TV_NAME, verdict, detail };
  } catch {
    return { name: TV_NAME, verdict: 'unknown', detail: 'Gagal menghubungi Threat Vault', error: true };
  }
}

// --- Jalur batch: mode "banyak IOC" di Vendor Lookup ---

export interface BulkInput {
  value: string;
  type: IocType;
}

export interface BulkRow {
  value: string;
  type: IocType;
  /** false = Threat Vault memang tidak mencakup tipe ini (domain/URL/email/SHA-1) */
  supported: boolean;
  verdict: Verdict;
  detail: string;
  error?: boolean;
}

type Group = 'ip' | 'md5' | 'sha256';

function groupOf(item: BulkInput): Group | null {
  if (item.type === 'ip') return 'ip';
  if (item.type !== 'hash') return null;
  if (item.value.length === 32) return 'md5';
  if (item.value.length === 64) return 'sha256';
  return null; // SHA-1 tidak didukung
}

// IP dicocokkan apa adanya, hash dicocokkan lowercase (md5 bisa balik huruf besar).
function keyOf(group: Group, value: string): string {
  return group === 'ip' ? value : value.toLowerCase();
}

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

// Mengembalikan null kalau API menjawab 404. Itu BUKAN kegagalan: endpoint batch
// hash menjawab 404 ketika tidak ada SATU PUN hash di potongan itu yang punya
// signature -- artinya semuanya bersih. Kalau sebagian cocok, jawabannya 200
// berisi hanya yang cocok. Sempat salah ditangani sebagai error, yang membuat
// 80 hash bersih tampil "tidak diketahui".
async function postJson(path: string, body: unknown, apiKey: string): Promise<any | null> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { ...authHeaders(apiKey), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (res.status === 404) return null;
  if (res.status === 401 || res.status === 403) {
    throw new Error(`API key ditolak (${res.status}) -- cek key dan status langganan`);
  }
  if (res.status === 429) {
    throw new Error('Kuota Threat Vault habis (batas 200/menit, 2000/hari) -- coba lagi sebentar lagi');
  }
  if (!res.ok) throw new Error(`API error (${res.status})`);

  const data = await res.json<any>();
  if (!data || typeof data !== 'object' || data.success !== true) {
    throw new Error('Format respons Threat Vault tidak dikenali -- cek manual di portal');
  }
  return data;
}

interface GroupOutcome {
  /** hasil yang ketemu, kunci sudah dinormalkan lewat keyOf() */
  found: Map<string, any>;
  /** terisi kalau panggilan gagal -- semua anggota grup jadi unknown, JANGAN clean */
  failure?: string;
}

async function fetchGroup(group: Group, values: string[], apiKey: string): Promise<GroupOutcome> {
  const found = new Map<string, any>();
  if (values.length === 0) return { found };

  try {
    // Potongan dikirim berurutan supaya tidak menabrak batas 200 panggilan/menit;
    // ketiga grup sendiri berjalan paralel di checkThreatVaultBulk().
    for (const part of chunk(values, BATCH_LIMIT)) {
      if (group === 'ip') {
        const data = await postJson('/ip-feed', { ipaddr: part }, apiKey);
        const rows: any[] = Array.isArray(data?.data) ? data.data : [];
        for (const row of rows) {
          if (typeof row?.ipaddr === 'string') found.set(row.ipaddr, row);
        }
      } else {
        // md5 dan sha256 TIDAK boleh dikirim dalam satu panggilan -- API menolaknya.
        // data === null berarti 404: tidak ada yang cocok di potongan ini, jadi
        // tidak ada yang dimasukkan ke `found` dan semuanya nanti dibaca bersih.
        const data = await postJson('/threats', { [group]: part }, apiKey);
        const files: any[] = Array.isArray(data?.data?.fileinfo) ? data.data.fileinfo : [];
        for (const file of files) {
          const raw = file?.[group];
          if (typeof raw === 'string' && raw) found.set(raw.toLowerCase(), file);
        }
      }
    }
    return { found };
  } catch (err) {
    return { found, failure: err instanceof Error ? err.message : 'Gagal menghubungi Threat Vault' };
  }
}

export async function checkThreatVaultBulk(items: BulkInput[], apiKey: string | undefined): Promise<BulkRow[]> {
  const base = items.map((item) => ({ value: item.value, type: item.type, supported: groupOf(item) !== null }));

  if (!apiKey) {
    return base.map((b) => ({ ...b, verdict: 'unknown' as Verdict, detail: NO_KEY_DETAIL }));
  }

  // Nilai unik per grup. Dedup di sini menghemat kuota harian tanpa mengubah
  // keluaran -- setiap item input tetap mendapat barisnya sendiri di bawah.
  const unique: Record<Group, Set<string>> = { ip: new Set(), md5: new Set(), sha256: new Set() };
  for (const item of items) {
    const group = groupOf(item);
    if (group) unique[group].add(keyOf(group, item.value));
  }

  const [ip, md5, sha256] = await Promise.all([
    fetchGroup('ip', [...unique.ip], apiKey),
    fetchGroup('md5', [...unique.md5], apiKey),
    fetchGroup('sha256', [...unique.sha256], apiKey),
  ]);
  const outcomes: Record<Group, GroupOutcome> = { ip, md5, sha256 };

  return items.map((item, i) => {
    const row = base[i];
    const group = groupOf(item);

    if (!group) {
      return {
        ...row,
        verdict: 'unknown' as Verdict,
        detail: 'Threat Vault tidak mencakup tipe ini -- pakai portal vendor di bawah',
      };
    }

    const outcome = outcomes[group];
    if (outcome.failure) {
      return { ...row, verdict: 'unknown' as Verdict, detail: outcome.failure, error: true };
    }

    const hit = outcome.found.get(keyOf(group, item.value));

    if (group === 'ip') {
      // Batch IP mengembalikan semua alamat; tidak ketemu = di luar dugaan,
      // jadi unknown (bukan clean) supaya tidak ada IP yang lolos dianggap aman.
      if (!hit) return { ...row, verdict: 'unknown' as Verdict, detail: 'Tidak ada data IP feed untuk alamat ini' };
      return { ...row, ...readIpRow(hit) };
    }

    // Batch hash HANYA mengembalikan hash yang punya data -- yang tidak ikut
    // kembali memang tidak punya signature yang cocok.
    if (!hit) return { ...row, verdict: 'clean' as Verdict, detail: HASH_CLEAN_DETAIL };
    return { ...row, verdict: verdictFromFileInfo(hit), detail: detailFromFileInfo(hit) };
  });
}

// --- Cakupan CVE: apakah Palo Alto punya signature untuk CVE tertentu ---

export interface CveSignature {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  defaultAction: string;
  status: string;
  references: string[];
  latestRelease: string;
}

export interface CveResult {
  covered: boolean;
  signatures: CveSignature[];
  message?: string;
  error?: boolean;
}

export const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

function str(v: unknown): string {
  return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
}

export async function checkThreatVaultCve(cve: string, apiKey: string | undefined): Promise<CveResult> {
  if (!apiKey) return { covered: false, signatures: [], message: NO_KEY_DETAIL, error: true };

  try {
    const res = await fetch(`${BASE}/threats?cve=${encodeURIComponent(cve.toUpperCase())}`, {
      headers: authHeaders(apiKey),
    });

    // 404 = tidak ada signature untuk CVE ini. Itu jawaban yang sah, bukan error.
    if (res.status === 404) {
      return { covered: false, signatures: [], message: 'Belum ada signature Palo Alto untuk CVE ini' };
    }
    if (res.status === 401 || res.status === 403) {
      return {
        covered: false,
        signatures: [],
        message: `API key ditolak (${res.status}) -- cek key dan status langganan`,
        error: true,
      };
    }
    if (!res.ok) {
      return { covered: false, signatures: [], message: `API error (${res.status})`, error: true };
    }

    const data = await res.json<any>();
    if (!data || typeof data !== 'object' || data.success !== true) {
      return {
        covered: false,
        signatures: [],
        message: 'Format respons Threat Vault tidak dikenali -- cek manual di portal',
        error: true,
      };
    }

    const rows: any[] = Array.isArray(data?.data?.vulnerability) ? data.data.vulnerability : [];
    if (rows.length === 0) {
      return { covered: false, signatures: [], message: 'Belum ada signature Palo Alto untuk CVE ini' };
    }

    const signatures: CveSignature[] = rows.map((r) => ({
      id: str(r?.id),
      name: str(r?.name),
      description: str(r?.description),
      category: str(r?.category),
      severity: str(r?.severity),
      defaultAction: str(r?.default_action),
      status: str(r?.status),
      references: Array.isArray(r?.reference) ? r.reference.filter((x: unknown) => typeof x === 'string') : [],
      latestRelease: str(r?.latest_release_version),
    }));

    return { covered: true, signatures };
  } catch {
    return { covered: false, signatures: [], message: 'Gagal menghubungi Threat Vault', error: true };
  }
}
