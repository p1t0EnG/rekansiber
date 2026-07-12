export async function getUserPasswordHash(db: D1Database, userId: number): Promise<string | null> {
  const row = await db
    .prepare('SELECT password_hash FROM users WHERE id = ?')
    .bind(userId)
    .first<{ password_hash: string }>();

  return row?.password_hash ?? null;
}

export async function updateUserPassword(db: D1Database, userId: number, passwordHash: string): Promise<void> {
  await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(passwordHash, userId).run();
}
