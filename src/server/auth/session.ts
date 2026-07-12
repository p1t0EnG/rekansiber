const SESSION_TTL_DAYS = 7;

export interface SessionUser {
  id: number;
  email: string;
  full_name: string;
  role: 'admin' | 'member';
}

function generateToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function createSession(db: D1Database, userId: number): Promise<{ token: string; expiresAt: Date }> {
  const token = generateToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);

  await db
    .prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, expiresAt.toISOString())
    .run();

  return { token, expiresAt };
}

export async function getSessionUser(db: D1Database, token: string): Promise<SessionUser | null> {
  if (!token) return null;

  const row = await db
    .prepare(
      `SELECT users.id, users.email, users.full_name, users.role
       FROM sessions
       JOIN users ON users.id = sessions.user_id
       WHERE sessions.id = ? AND sessions.expires_at > datetime('now')`,
    )
    .bind(token)
    .first<SessionUser>();

  return row ?? null;
}

export async function deleteSession(db: D1Database, token: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
}
