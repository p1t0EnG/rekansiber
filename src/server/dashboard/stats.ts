export interface UserStatsSummary {
  user_id: number;
  full_name: string;
  email: string;
  total_checks: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
}

export interface DailyStat {
  day: string;
  user_id: number;
  full_name: string;
  count: number;
}

export interface DashboardStats {
  summary: UserStatsSummary[];
  daily: DailyStat[];
}

// Dipakai bareng oleh GET /api/dashboard/stats dan halaman dashboard.astro,
// biar query agregasinya tidak dobel. userId diisi untuk role 'member' supaya
// mereka cuma lihat aktivitas sendiri, dikosongkan (undefined) untuk admin
// supaya lihat seluruh tim.
export async function getDashboardStats(db: D1Database, userId?: number): Promise<DashboardStats> {
  const summaryResult = await db
    .prepare(
      `SELECT
         u.id AS user_id,
         u.full_name,
         u.email,
         COUNT(*) AS total_checks,
         SUM(CASE WHEN ic.verdict = 'malicious' THEN 1 ELSE 0 END) AS malicious_count,
         SUM(CASE WHEN ic.verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
         SUM(CASE WHEN ic.verdict = 'clean' THEN 1 ELSE 0 END) AS clean_count
       FROM ioc_checks ic
       JOIN users u ON u.id = ic.user_id
       WHERE (?1 IS NULL OR u.id = ?1)
       GROUP BY u.id
       ORDER BY total_checks DESC`,
    )
    .bind(userId ?? null)
    .all<UserStatsSummary>();

  const dailyResult = await db
    .prepare(
      `SELECT
         DATE(ic.checked_at) AS day,
         u.id AS user_id,
         u.full_name,
         COUNT(*) AS count
       FROM ioc_checks ic
       JOIN users u ON u.id = ic.user_id
       WHERE ic.checked_at >= datetime('now', '-30 days')
         AND (?1 IS NULL OR u.id = ?1)
       GROUP BY u.id, DATE(ic.checked_at)
       ORDER BY day DESC`,
    )
    .bind(userId ?? null)
    .all<DailyStat>();

  return { summary: summaryResult.results, daily: dailyResult.results };
}
