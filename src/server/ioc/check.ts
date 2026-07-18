import type { IocType, ProviderResult } from './types';
import { checkVirusTotal, checkAbuseIPDB, checkOTX, checkMxToolbox } from './providers';
import { aggregateVerdict } from './aggregate';

export interface IocProviderEnv {
  VT_API_KEY: string;
  ABUSEIPDB_API_KEY: string;
  OTX_API_KEY: string;
  MXTOOLBOX_API_KEY?: string;
}

// Dipakai bareng oleh /ioc/check (publik) dan /ioc/bulk-check (tim SOC) --
// keduanya butuh logika pemanggilan provider + agregasi verdict yang sama persis.
export async function checkIoc(env: IocProviderEnv, value: string, type: IocType) {
  const [vt, abuseIpdb, otx, mxtoolbox] = await Promise.all([
    checkVirusTotal(value, type, env.VT_API_KEY),
    checkAbuseIPDB(value, type, env.ABUSEIPDB_API_KEY),
    checkOTX(value, type, env.OTX_API_KEY),
    checkMxToolbox(value, type, env.MXTOOLBOX_API_KEY),
  ]);

  const providers = [vt, abuseIpdb, otx, mxtoolbox].filter((r): r is ProviderResult => r !== null);
  const verdict = aggregateVerdict(providers);
  return { verdict, providers };
}
