#!/usr/bin/env node
// Generate perintah `wrangler d1 execute` untuk membuat akun tim SOC baru.
// Pakai script terpisah (bukan endpoint publik) karena akun tim tidak boleh
// bisa didaftarkan sendiri oleh siapapun dari internet.
//
// Usage: node scripts/create-user.mjs <email> <password> "<nama lengkap>" [role=admin|member]

import { webcrypto } from 'node:crypto';

const [, , email, password, fullName, role = 'member'] = process.argv;

if (!email || !password || !fullName) {
  console.error('Usage: node scripts/create-user.mjs <email> <password> "<nama lengkap>" [role=admin|member]');
  process.exit(1);
}
if (role !== 'admin' && role !== 'member') {
  console.error('role harus "admin" atau "member"');
  process.exit(1);
}

const PBKDF2_ITERATIONS = 100_000;

function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hashPassword(pw) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await webcrypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256,
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toHex(salt)}$${toHex(bits)}`;
}

const hash = await hashPassword(password);
const sql = `INSERT INTO users (email, password_hash, full_name, role) VALUES ('${email.replace(/'/g, "''")}', '${hash}', '${fullName.replace(/'/g, "''")}', '${role}');`;

// PENTING: hash-nya mengandung tanda "$" (format pbkdf2$iterasi$salt$hash).
// Kalau command di bawah dibungkus tanda kutip GANDA di shell (bash/zsh), setiap
// "$..." dianggap variabel shell dan otomatis jadi string kosong -- hash rusak
// tanpa pesan error. Makanya di sini setiap "$" di-escape jadi "\$" biar aman
// dipakai persis apa adanya (jangan diubah manual jadi kutip tunggal atau dihapus \-nya).
const shellSafeSql = sql.replace(/\$/g, '\\$');

console.log('\nJalankan salah satu perintah berikut untuk menyimpan user ini:\n');
console.log(`  wrangler d1 execute rekansiber-db --local --command "${shellSafeSql}"`);
console.log(`  wrangler d1 execute rekansiber-db --remote --command "${shellSafeSql}"`);
console.log();
