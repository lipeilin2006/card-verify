import type { CardRow, D1Like, SessionRow } from "./types.ts";
import {
  ApiError,
  asInteger,
  asObject,
  formatCode,
  normalizeCode,
  randomCode,
  randomHex,
  sha256Hex,
  validateHwid,
} from "./util.ts";

export interface ServiceOptions {
  now: number;
}

interface SessionWithCard extends SessionRow {
  card_status: CardRow["status"];
  card_code: string;
  card_expires_at: number | null;
}

function cardView(card: CardRow) {
  return {
    code: formatCode(card.code),
    status: card.status,
    bound_hwid: card.bound_hwid,
    hwid_changed_at: card.hwid_changed_at,
    duration_seconds: card.duration_seconds,
    expires_at: card.expires_at,
    activated_at: card.activated_at,
    created_at: card.created_at,
    note: card.note,
  };
}

async function getCard(db: D1Like, code: string): Promise<CardRow | null> {
  return db.prepare("SELECT * FROM cards WHERE code = ?1").bind(code).first<CardRow>();
}

async function countOnline(db: D1Like, cardId: string): Promise<number> {
  const row = await db.prepare("SELECT COUNT(*) AS count FROM sessions WHERE card_id = ?1")
    .bind(cardId)
    .first<{ count: number }>();
  return Number(row?.count ?? 0);
}

function validateCard(card: CardRow | null, now: number): asserts card is CardRow {
  if (!card) throw new ApiError(404, "card_not_found", "卡密不存在");
  if (card.status === "disabled") throw new ApiError(403, "card_disabled", "卡密已被禁用");
  if (card.expires_at !== null && card.expires_at <= now) throw new ApiError(410, "card_expired", "卡密已过期");
}

export async function verifyRequestHwid(
  db: D1Like,
  method: string,
  path: string,
  input: unknown,
  _now: number,
): Promise<{ hwid: string }> {
  const object = asObject(input);
  const hwid = validateHwid(object.hwid);
  return { hwid };
}

export async function redeem(db: D1Like, input: unknown, options: ServiceOptions): Promise<Record<string, unknown>> {
  const object = asObject(input);
  const data = asObject(object.data ?? object);
  const code = normalizeCode(data.code);
  const hwid = validateHwid(object.hwid);
  let card = await getCard(db, code);
  validateCard(card, options.now);

  if (card.status === "unused") {
    await db.prepare(`UPDATE cards
      SET status = 'active', activated_at = ?1,
          expires_at = CASE
            WHEN expires_at IS NOT NULL AND duration_seconds IS NOT NULL THEN MIN(expires_at, ?1 + duration_seconds)
            WHEN expires_at IS NOT NULL THEN expires_at
            WHEN duration_seconds IS NOT NULL THEN ?1 + duration_seconds
            ELSE NULL
          END
      WHERE code = ?2 AND status = 'unused'`).bind(options.now, code).run();
    card = await getCard(db, code);
    validateCard(card, options.now);
  }

  if (card.bound_hwid === null) {
    await db.prepare("UPDATE cards SET bound_hwid = ?1, hwid_changed_at = ?2 WHERE id = ?3 AND bound_hwid IS NULL")
      .bind(hwid, options.now, card.id).run();
    card = await getCard(db, code);
    validateCard(card, options.now);
  } else if (card.bound_hwid !== hwid) {
    const changedAt = card.hwid_changed_at ?? 0;
    if (options.now - changedAt < 86400) {
      throw new ApiError(409, "hwid_change_limited", "该卡密每天只允许更换一次设备");
    }
    await db.prepare("UPDATE cards SET bound_hwid = ?1, hwid_changed_at = ?2 WHERE id = ?3 AND bound_hwid = ?4 AND (hwid_changed_at IS NULL OR hwid_changed_at <= ?5)")
      .bind(hwid, options.now, card.id, card.bound_hwid, options.now - 86400).run();
    card = await getCard(db, code);
    validateCard(card, options.now);
    if (card.bound_hwid !== hwid) throw new ApiError(409, "hwid_change_limited", "该卡密每天只允许更换一次设备");
  }

  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const insert = db.prepare(`INSERT INTO sessions
      (token_hash, card_id, hwid, created_at)
    SELECT ?1, ?2, ?3, ?4
    FROM cards c
    WHERE c.id = ?2
      AND c.status = 'active'
      AND (c.expires_at IS NULL OR c.expires_at > ?4)
    ON CONFLICT(card_id) DO UPDATE SET
      token_hash = excluded.token_hash`)
    .bind(tokenHash, card.id, hwid, options.now);
  await insert.run();

  const session = await db.prepare("SELECT token_hash FROM sessions WHERE token_hash = ?1").bind(tokenHash).first<{ token_hash: string }>();
  if (!session) throw new ApiError(500, "session_create_failed", "无法创建认证会话");
  const online = await countOnline(db, card.id);
  return {
    token,
    hwid,
    card: cardView(card),
    expires_at: card.expires_at,
    online_devices: online,
    server_time: options.now,
  };
}

export async function release(db: D1Like, input: unknown, now: number): Promise<Record<string, unknown>> {
  const object = asObject(input);
  const data = asObject(object.data ?? object);
  const token = typeof data.token === "string" ? data.token.trim().toLowerCase() : "";
  const hash = await sha256Hex(token);
  const session = await db.prepare("SELECT hwid FROM sessions WHERE token_hash = ?1").bind(hash).first<{ hwid: string }>();
  if (session && validateHwid(object.hwid) !== session.hwid) throw new ApiError(401, "invalid_hwid", "设备身份不匹配");
  await db.prepare("DELETE FROM sessions WHERE token_hash = ?1").bind(hash).run();
  return { released: Boolean(session), hwid: session?.hwid ?? null, server_time: now };
}

export async function status(db: D1Like, token: string, now: number): Promise<Record<string, unknown>> {
  const hash = await sha256Hex(token);
  const row = await db.prepare(`SELECT s.*, c.code AS card_code, c.status AS card_status,
      c.expires_at AS card_expires_at
    FROM sessions s JOIN cards c ON c.id = s.card_id WHERE s.token_hash = ?1`).bind(hash).first<SessionWithCard>();
  if (!row) throw new ApiError(401, "session_expired", "会话不存在或已失效");
  return {
    hwid: row.hwid,
    card: { code: formatCode(row.card_code), status: row.card_status, expires_at: row.card_expires_at },
    session: { created_at: row.created_at, valid: row.card_status === "active" && (row.card_expires_at === null || row.card_expires_at > now) },
    online_devices: await countOnline(db, row.card_id),
    server_time: now,
  };
}

export async function createCards(db: D1Like, input: unknown, now: number): Promise<Record<string, unknown>> {
  const object = asObject(input);
  const count = asInteger(object.count, "count", 1, 500, 1);
  const codeLength = asInteger(object.code_length, "code_length", 6, 64, 20);
  const prefix = typeof object.prefix === "string" ? object.prefix.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8) : "CV";
  if (!prefix || prefix.length > 8 || prefix.length >= codeLength) throw new ApiError(400, "bad_request", "prefix 长度必须小于卡密长度");
  const durationSeconds = object.duration_seconds === undefined ? null : asInteger(object.duration_seconds, "duration_seconds", 60, 315360000);
  const expiresAt = object.expires_at === undefined || object.expires_at === null ? null : asInteger(object.expires_at, "expires_at", now + 1, 4102444800);
  const note = object.note === undefined || object.note === null ? null : String(object.note).slice(0, 200);
  const cards: string[] = [];
  for (let index = 0; index < count; index += 1) cards.push(randomCode(prefix, codeLength));
  const statements = cards.map((code) => db.prepare(`INSERT INTO cards
    (id, code, status, duration_seconds, expires_at, created_at, note)
    VALUES (?1, ?2, 'unused', ?3, ?4, ?5, ?6)`)
    .bind(randomHex(16), code, durationSeconds, expiresAt, now, note));
  await db.batch(statements);
  return { cards: cards.map(formatCode), count: cards.length, code_length: codeLength, duration_seconds: durationSeconds, expires_at: expiresAt };
}

export async function listCards(db: D1Like, input: URLSearchParams, now: number): Promise<Record<string, unknown>> {
  const limit = Math.min(200, Math.max(1, Number(input.get("limit") ?? 50) || 50));
  const offset = Math.max(0, Number(input.get("offset") ?? 0) || 0);
  const status = input.get("status");
  const code = input.get("code");
  const conditions: string[] = [];
  const params: unknown[] = [];
  if (status) { params.push(status); conditions.push(`c.status = ?${params.length}`); }
  if (code) { params.push(normalizeCode(code)); conditions.push(`c.code = ?${params.length}`); }
  const filter = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const rows = await db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM sessions s WHERE s.card_id = c.id) AS online_devices FROM cards c ${filter} ORDER BY c.created_at DESC LIMIT ${Math.floor(limit)} OFFSET ${Math.floor(offset)}`).bind(...params).all<CardRow & { online_devices: number }>();
  const totalFilter = filter.replaceAll("c.", "");
  const total = await db.prepare(`SELECT COUNT(*) AS count FROM cards ${totalFilter}`).bind(...params).first<{ count: number }>();
  return { total: Number(total?.count ?? 0), limit, offset, items: rows.results.map((row) => ({ ...cardView(row), online_devices: Number(row.online_devices) })) };
}

export async function updateCard(db: D1Like, input: unknown, now: number): Promise<Record<string, unknown>> {
  const object = asObject(input);
  const code = normalizeCode(object.code);
  const current = await getCard(db, code);
  validateCard(current, now);
  const sets: string[] = [];
  const values: unknown[] = [];
  if (object.expires_at !== undefined) {
    if (object.expires_at !== null) values.push(asInteger(object.expires_at, "expires_at", 1, 4102444800));
    else values.push(null);
    sets.push(`expires_at = ?${values.length}`);
  }
  if (object.status !== undefined) {
    if (object.status !== "active" && object.status !== "disabled") throw new ApiError(400, "bad_request", "status 只能是 active 或 disabled");
    values.push(object.status);
    sets.push(`status = ?${values.length}`);
  }
  if (object.note !== undefined) {
    values.push(object.note === null ? null : String(object.note).slice(0, 200));
    sets.push(`note = ?${values.length}`);
  }
  if (sets.length === 0) throw new ApiError(400, "bad_request", "没有可更新字段");
  values.push(code);
  await db.prepare(`UPDATE cards SET ${sets.join(", ")} WHERE code = ?${values.length}`).bind(...values).run();
  const updated = await getCard(db, code);
  if (updated?.status === "disabled" || (updated?.expires_at !== null && updated?.expires_at !== undefined && updated.expires_at <= now)) {
    await db.prepare("DELETE FROM sessions WHERE card_id = ?1").bind(updated.id).run();
  }
  return { card: updated ? cardView(updated) : null };
}

export async function deleteCard(db: D1Like, input: unknown): Promise<Record<string, unknown>> {
  const object = asObject(input);
  const code = normalizeCode(object.code);
  const card = await getCard(db, code);
  if (!card) throw new ApiError(404, "card_not_found", "卡密不存在");
  await db.prepare("DELETE FROM sessions WHERE card_id = ?1").bind(card.id).run();
  await db.prepare("DELETE FROM cards WHERE id = ?1").bind(card.id).run();
  return { deleted: true, code: formatCode(code) };
}

export async function kickDevice(db: D1Like, input: unknown): Promise<Record<string, unknown>> {
  const object = asObject(input);
  const code = normalizeCode(object.code);
  const card = await getCard(db, code);
  if (!card) throw new ApiError(404, "card_not_found", "卡密不存在");
  if (object.hwid === undefined) {
    await db.prepare("DELETE FROM sessions WHERE card_id = ?1").bind(card.id).run();
    return { kicked: "all", code: formatCode(code) };
  }
  const hwid = validateHwid(object.hwid);
  await db.prepare("DELETE FROM sessions WHERE card_id = ?1 AND hwid = ?2").bind(card.id, hwid).run();
  return { kicked: hwid, code: formatCode(code) };
}
