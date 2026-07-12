import type { IocType } from './types';

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
// md5 (32), sha1 (40), sha256 (64) hex
const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

export function isValidIoc(value: string, type: IocType): boolean {
  const v = value.trim();
  switch (type) {
    case 'ip':
      return IPV4_RE.test(v) || IPV6_RE.test(v);
    case 'domain':
      return DOMAIN_RE.test(v);
    case 'hash':
      return HASH_RE.test(v);
    case 'url':
      try {
        const u = new URL(v);
        return u.protocol === 'http:' || u.protocol === 'https:';
      } catch {
        return false;
      }
  }
}

// Dipakai bulk checker: user cuma tempel daftar value tanpa milih type satu-satu.
// Urutan cek penting -- hash & url tidak ambigu, dicek duluan sebelum ip/domain.
export function detectIocType(rawValue: string): IocType | null {
  const value = rawValue.trim();
  if (!value) return null;
  if (isValidIoc(value, 'hash')) return 'hash';
  if (isValidIoc(value, 'url')) return 'url';
  if (isValidIoc(value, 'ip')) return 'ip';
  if (isValidIoc(value, 'domain')) return 'domain';
  return null;
}
