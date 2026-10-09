import type { Env } from "./types.ts";
import { createCards, deleteCard, kickDevice, listCards, redeem, release, status, updateCard, verifyRequestHwid } from "./service.ts";
import { ApiError, asObject, decryptProtocol, encryptProtocol, json, nowSeconds, signResponse, stableJson, verifyPow } from "./util.ts";

async function readJson(request: Request, env: Env): Promise<{ value: Record<string, unknown> }> {
  const raw = await request.text();
  try {
    const outer = asObject(raw ? JSON.parse(raw) : {});
  const plaintext = await decryptProtocol(env.aes_key, String(outer.payload ?? ""));
    return { value: asObject(JSON.parse(plaintext)) };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(400, "bad_request", "JSON 格式不正确");
  }
}

function requireAdmin(request: Request, env: Env): void {
  if (!env.manager_apikey) throw new ApiError(404, "not_found", "管理接口未启用");
  if (request.headers.get("x-api-key") !== env.manager_apikey) {
    throw new ApiError(401, "unauthorized", "管理令牌无效");
  }
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const now = nowSeconds();
  if (request.method === "OPTIONS") return json(null, 204);
  const powBody = request.method === "GET" ? "" : await request.clone().text();
  await verifyPow(request, env, powBody, now);
  if (request.method === "GET" && path === "/health") return json({ ok: true, server_time: now });
  if (request.method === "GET" && path === "/api/version") {
    const record = await env.cache.get<Record<string, unknown> | null>("app_version", "json");
    return json({
      ok: true,
      version: record?.version ?? null,
      url: record?.url ?? null,
      notes: record?.notes ?? null,
      published_at: record?.published_at ?? null,
    });
  }

  if (path === "/api/redeem" && request.method === "POST") {
    const { value } = await readJson(request, env);
    await verifyRequestHwid(env.card_infos, request.method, path, value, now);
    return signedJson(env, { ok: true, ...(await redeem(env.card_infos, value, { now })) });
  }
  if (path === "/api/release" && request.method === "POST") {
    const { value } = await readJson(request, env);
    return signedJson(env, { ok: true, ...(await release(env.card_infos, value, now)) });
  }
  if (path === "/api/status" && request.method === "GET") {
    const token = url.searchParams.get("token") ?? "";
    return signedJson(env, { ok: true, ...(await status(env.card_infos, token, now)) });
  }
  if (path === "/api/admin/cards" && request.method === "GET") {
    requireAdmin(request, env);
    return signedJson(env, { ok: true, ...(await listCards(env.card_infos, url.searchParams, now)) });
  }
  if (path === "/api/admin/cards/update" && request.method === "POST") {
    requireAdmin(request, env);
    return signedJson(env, { ok: true, ...(await updateCard(env.card_infos, (await readJson(request, env)).value, now)) });
  }
  if (path === "/api/admin/cards/delete" && request.method === "POST") {
    requireAdmin(request, env);
    return signedJson(env, { ok: true, ...(await deleteCard(env.card_infos, (await readJson(request, env)).value)) });
  }
  if (path === "/api/admin/kick" && request.method === "POST") {
    requireAdmin(request, env);
    return signedJson(env, { ok: true, ...(await kickDevice(env.card_infos, (await readJson(request, env)).value)) });
  }
  if (path === "/api/admin/version" && request.method === "POST") {
    requireAdmin(request, env);
    const { value } = await readJson(request, env);
    const version = String(value.version ?? "").trim();
    const downloadUrl = String(value.url ?? "").trim();
    const notes = String(value.notes ?? "").trim();
    if (downloadUrl && !/^https:\/\//.test(downloadUrl)) throw new ApiError(400, "bad_request", "url 必须是 https 地址");
    const publishedAt = Number(value.published_at);
    if (Number.isFinite(publishedAt) && publishedAt > 0) {
      if (publishedAt > now + 86400) throw new ApiError(400, "bad_request", "发布时间不能超过当前时间 1 天");
    }
    const record = { version, url: downloadUrl, notes, published_at: Number.isFinite(publishedAt) && publishedAt > 0 ? Math.floor(publishedAt) : now };
    await env.cache.put("app_version", JSON.stringify(record));
    return signedJson(env, { ok: true, ...record });
  }
  if (path === "/api/admin/cards" && request.method === "POST") {
    requireAdmin(request, env);
    return signedJson(env, { ok: true, ...(await createCards(env.card_infos, (await readJson(request, env)).value, now)) });
  }
  throw new ApiError(404, "not_found", "接口不存在");
}

async function signedJson(env: Env, body: Record<string, unknown>, status = 200): Promise<Response> {
  const signature = await signResponse(env.ed_priv, stableJson(body));
  if (!signature) return json({ ok: false, error: { code: "server_not_configured", message: "服务端签名密钥未配置" } }, 500);
  return json({ payload: await encryptProtocol(env.aes_key, JSON.stringify({ ...body, response_signature: signature })) }, status);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (error) {
      if (error instanceof ApiError) return signedJson(env, { ok: false, error: { code: error.code, message: error.message } }, error.status);
      console.error("request_failed", error instanceof Error ? error.stack ?? error.message : error);
      return signedJson(env, { ok: false, error: { code: "internal", message: error instanceof Error ? error.message : "服务器内部错误" } }, 500);
    }
  },
};
