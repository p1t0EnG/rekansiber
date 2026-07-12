# Rekan Siber — Panduan Setup dari Nol

Stack: **Astro (frontend + API routes) + Hono (routing backend) + Cloudflare D1
(database) + Cloudflare KV (cache berita) + TypeScript**, semua jalan di
**Cloudflare Workers/Pages** (free tier).

---

## 0. Prasyarat

Install dulu di komputer kamu:

1. **Node.js** versi 20 ke atas → cek dengan `node -v`
   Download: https://nodejs.org
2. **Git** → cek dengan `git -v`
3. Akun **Cloudflare** (yang sudah kamu pakai)
4. Akun **GitHub** (repo `rekansiber` yang sudah di-rename)
5. Text editor, misalnya VS Code

---

## 1. Login ke Cloudflare lewat terminal

```bash
npm install -g wrangler
wrangler login
```

Ini akan membuka browser untuk otorisasi. Setelah berhasil, terminal akan
menunjukkan akun Cloudflare kamu sudah terhubung.

---

## 2. Clone starter kit ini ke komputer kamu

Kalau kamu dapat file ini sebagai zip dari Claude, extract dulu, lalu:

```bash
cd rekansiber
npm install
```

Tunggu sampai semua dependency (Astro, Hono, Wrangler, dll) selesai
terinstall.

---

## 3. Buat database D1

```bash
wrangler d1 create rekansiber-db
```

Perintah ini akan menampilkan output seperti ini:

```
[[d1_databases]]
binding = "DB"
database_name = "rekansiber-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Copy `database_id` itu**, lalu buka `wrangler.toml` di project ini dan
ganti `GANTI_DENGAN_ID_DARI_WRANGLER_D1_CREATE` dengan nilai tersebut.

Setelah itu, jalankan migrasi skema (bikin tabel users, ioc_checks, dll):

```bash
npm run db:migrate:local    # untuk development di komputer kamu
npm run db:migrate:remote   # untuk database production di Cloudflare
```

---

## 4. Buat KV namespace (cache berita)

```bash
wrangler kv namespace create NEWS_CACHE
```

Sama seperti D1, copy `id` yang muncul, lalu tempel ke `wrangler.toml` di
bagian `[[kv_namespaces]]`.

---

## 5. Isi environment variables (API key)

```bash
cp .dev.vars.example .dev.vars
```

Buka file `.dev.vars` yang baru dibuat, isi dengan API key asli:
- `VT_API_KEY` — dari virustotal.com (buat akun gratis dulu kalau belum)
- `ABUSEIPDB_API_KEY` — dari abuseipdb.com
- `OTX_API_KEY` — dari otx.alienvault.com
- `SESSION_SECRET` — generate string acak: `openssl rand -base64 48`

File `.dev.vars` **tidak akan ter-commit ke git** (sudah ada di
`.gitignore`), jadi aman.

---

## 6. Jalankan di komputer kamu (local development)

```bash
npm run dev
```

Buka `http://localhost:4321` di browser. Kamu akan lihat homepage, halaman
IOC checker, berita, dan login (masih kerangka, belum full functional —
itu tahap coding berikutnya).

Untuk test endpoint API secara langsung:
```bash
curl http://localhost:4321/api/health
```

---

## 7. Push ke GitHub

```bash
git init
git add .
git commit -m "Initial scaffold: Astro + Hono + D1 + KV"
git branch -M main
git remote add origin https://github.com/p1t0EnG/rekansiber.git
git push -u origin main
```

(Ganti URL kalau nama repo kamu berbeda)

---

## 8. Deploy ke Cloudflare Pages

Ikuti langkah "buat Pages project baru" yang sudah kita bahas sebelumnya:
Workers & Pages → Create application → Pages → Connect to Git → pilih repo
`rekansiber`.

**Perbedaan penting dari sebelumnya** karena sekarang pakai Astro:
- **Framework preset**: pilih **Astro** (Cloudflare akan otomatis isi build
  command & output directory yang benar)
- **Build command**: `npm run build`
- **Build output directory**: `dist`

Setelah project dibuat, **sebelum deploy pertama jalan dengan benar**, kamu
perlu hubungkan D1 & KV binding ke Pages project juga (bukan cuma di
`wrangler.toml` lokal):
1. Buka project Pages kamu → **Settings → Functions**
2. Di bagian **D1 database bindings**, tambahkan binding `DB` → pilih
   database `rekansiber-db`
3. Di bagian **KV namespace bindings**, tambahkan binding `NEWS_CACHE` →
   pilih namespace yang tadi dibuat
4. Di **Settings → Environment variables**, tambahkan `VT_API_KEY`,
   `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `SESSION_SECRET` (centang **Encrypt**)

---

## 9. Struktur project ini

```
rekansiber/
├── db/schema.sql              # skema database (users, ioc_checks, sessions, reports)
├── src/
│   ├── env.d.ts                # tipe TypeScript untuk Cloudflare bindings
│   ├── server/hono-app.ts      # SEMUA routing API ada di sini (Hono)
│   ├── pages/
│   │   ├── index.astro         # homepage publik
│   │   ├── ioc-checker.astro   # IOC checker publik
│   │   ├── news.astro          # berita CVE & ransomware
│   │   ├── login.astro         # login tim SOC
│   │   └── api/[...path].ts    # jembatan Astro → Hono (jangan diedit, cukup edit hono-app.ts)
│   └── components/Navbar.astro
└── wrangler.toml               # binding D1, KV, config Cloudflare
```

**Prinsip penting**: kalau mau nambah endpoint API baru (misal
`/api/reports/monthly`), cukup edit `src/server/hono-app.ts`. Kalau mau
nambah halaman baru, buat file baru di `src/pages/`.

---

## 10. Roadmap fitur (urutan yang aku sarankan untuk sesi coding berikutnya)

1. **IOC Checker publik** — implementasi pemanggilan VirusTotal/AbuseIPDB/OTX
   yang sesungguhnya + rate limiting sederhana
2. **Auth tim SOC** — hashing password, session cookie, middleware proteksi
   halaman `/dashboard`
3. **Bulk checking + export CSV/Excel** — upload banyak IOC sekaligus
4. **Dashboard usage per anggota** — query agregasi dari `ioc_checks`
5. **Cron job berita** — Worker terpisah dengan `scheduled()` yang fetch RSS
   TheHackerNews/RansomHub tiap beberapa jam, simpan ke KV
6. **Report bulanan** — generate PDF/Excel rekap per anggota tim
7. **Template report phishing ke hosting provider**

---

Kalau ada langkah di atas yang error atau membingungkan, kirim pesan error-nya
ke Claude, sertakan konteks kamu ada di step berapa.
