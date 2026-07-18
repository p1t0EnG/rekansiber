export type PhishingReportStatus = 'draft' | 'sent' | 'resolved';

export interface PhishingReport {
  id: number;
  user_id: number;
  target_domain: string;
  hosting_email: string | null;
  status: PhishingReportStatus;
  notes: string | null;
  created_at: string;
  reporter_name: string;
}

const SELECT_BASE = `
  SELECT pr.id, pr.user_id, pr.target_domain, pr.hosting_email, pr.status, pr.notes, pr.created_at,
         u.full_name AS reporter_name
  FROM phishing_reports pr
  JOIN users u ON u.id = pr.user_id
`;

export async function listPhishingReports(db: D1Database): Promise<PhishingReport[]> {
  const result = await db.prepare(`${SELECT_BASE} ORDER BY pr.created_at DESC`).all<PhishingReport>();
  return result.results;
}

export async function getPhishingReport(db: D1Database, id: number): Promise<PhishingReport | null> {
  const row = await db.prepare(`${SELECT_BASE} WHERE pr.id = ?`).bind(id).first<PhishingReport>();
  return row ?? null;
}

export async function createPhishingReport(
  db: D1Database,
  userId: number,
  targetDomain: string,
  hostingEmail: string | null,
  notes: string | null,
): Promise<number> {
  const result = await db
    .prepare(`INSERT INTO phishing_reports (user_id, target_domain, hosting_email, notes) VALUES (?, ?, ?, ?)`)
    .bind(userId, targetDomain, hostingEmail, notes)
    .run();
  return result.meta.last_row_id as number;
}

export async function updatePhishingReportStatus(
  db: D1Database,
  id: number,
  status: PhishingReportStatus,
): Promise<void> {
  await db.prepare(`UPDATE phishing_reports SET status = ? WHERE id = ?`).bind(status, id).run();
}

export async function deletePhishingReport(db: D1Database, id: number): Promise<void> {
  await db.prepare(`DELETE FROM phishing_reports WHERE id = ?`).bind(id).run();
}
