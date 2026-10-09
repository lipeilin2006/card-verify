const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function json(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type, authorization, x-api-key, x-pow-timestamp, x-pow-nonce, x-pow-proof",
      "access-control-allow-methods": "GET, POST, PATCH, OPTIONS",
    },
  });
}

export function normalizeCode(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApiError(400, "bad_request", "code 必须是字符串");
  }
  const code = value.trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (code.length < 6 || code.length > 64) {
    throw new ApiError(400, "invalid_code", "卡密长度必须在 6 到 64 位之间");
  }
  return code;
}

export function formatCode(code: string): string {
  return code.match(/.{1,4}/g)?.join("-") ?? code;
}

export function validateDeviceId(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApiError(400, "invalid_device_id", "device_id 必须是字符串");
  }
  const deviceId = value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/.test(deviceId)) {
    throw new ApiError(400, "invalid_device_id", "device_id 格式不正确");
  }
  return deviceId;
}

export function validateHwid(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value.trim())) {
    throw new ApiError(400, "invalid_hwid", "hwid 格式不正确");
  }
  return value.trim().toLowerCase();
}

export function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(",")}}`;
}

function hexToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function asBufferSource(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

export async function signResponse(keyText: string | undefined, message: string): Promise<string | null> {
  if (!keyText) return null;
  try {
    let keyBytes = base64Bytes(keyText);
    if (keyBytes.length === 32) {
      const prefix = hexBytes("302e020100300506032b657004220420");
      const wrapped = new Uint8Array(prefix.length + keyBytes.length);
      wrapped.set(prefix, 0);
      wrapped.set(keyBytes, prefix.length);
      keyBytes = wrapped;
    }
    const key = await crypto.subtle.importKey(
      "pkcs8",
      asBufferSource(keyBytes),
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign({ name: "Ed25519" }, key, asBufferSource(new TextEncoder().encode(message)));
    return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}

function base64Bytes(value: string): Uint8Array {
  const normalized = value.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(normalized), (char) => char.charCodeAt(0));
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function hexBytes(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return result;
}

function protocolKey(key: string | undefined): ArrayBuffer {
  if (!key) throw new Error("PROTOCOL_AES_KEY is not configured");
  const bytes = base64Bytes(key);
  if (bytes.length !== 32) throw new Error("PROTOCOL_AES_KEY must be 32 bytes");
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export async function encryptProtocol(key: string | undefined, plaintext: string): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", protocolKey(key), "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, cryptoKey, new TextEncoder().encode(plaintext));
  const output = new Uint8Array(nonce.byteLength + ciphertext.byteLength);
  output.set(nonce, 0);
  output.set(new Uint8Array(ciphertext), nonce.byteLength);
  return bytesToBase64(output);
}

export async function decryptProtocol(key: string | undefined, payload: string): Promise<string> {
  const bytes = base64Bytes(payload);
  if (bytes.length <= 12 + 16) throw new ApiError(400, "invalid_encrypted_body", "加密消息格式不正确");
  const cryptoKey = await crypto.subtle.importKey("raw", protocolKey(key), "AES-GCM", false, ["decrypt"]);
  try {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, cryptoKey, bytes.slice(12));
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new ApiError(400, "invalid_encrypted_body", "加密消息校验失败");
  }
}

export function randomHex(bytes: number): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function randomCode(prefix: string, length = 20): string {
  const data = new Uint8Array(Math.max(1, length - prefix.length));
  crypto.getRandomValues(data);
  let body = "";
  for (const byte of data) body += CODE_ALPHABET[byte & 31];
  return prefix + body;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ApiError(400, "bad_request", "请求体必须是 JSON 对象");
  }
  return value as Record<string, unknown>;
}

export function asInteger(value: unknown, name: string, min: number, max: number, fallback?: number): number {
  if (value === undefined || value === null) {
    if (fallback !== undefined) return fallback;
    throw new ApiError(400, "bad_request", `${name} 必须是整数`);
  }
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(number) || number < min || number > max) {
    throw new ApiError(400, "bad_request", `${name} 必须在 ${min} 到 ${max} 之间`);
  }
  return number;
}

export function powDifficulty(env: { POW_DIFFICULTY?: string }): number {
  const value = Number(env.POW_DIFFICULTY ?? 4);
  return Number.isInteger(value) && value >= 0 && value <= 8 ? value : 4;
}

export async function verifyPow(request: Request, env: { POW_DIFFICULTY?: string; cache: { get(key: string): Promise<string | null>; put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> } }, body: string, now: number): Promise<void> {
  const url = new URL(request.url);
  let bodyObject: Record<string, unknown> | null = null;
  try { bodyObject = body ? JSON.parse(body) : null; } catch { bodyObject = null; }
  const timestamp = request.headers.get("x-pow-timestamp") ?? url.searchParams.get("pow_timestamp") ?? (typeof bodyObject?.pow_timestamp === "string" ? bodyObject.pow_timestamp : null);
  const nonce = request.headers.get("x-pow-nonce") ?? url.searchParams.get("pow_nonce") ?? (typeof bodyObject?.pow_nonce === "string" ? bodyObject.pow_nonce : null);
  const proof = request.headers.get("x-pow-proof") ?? url.searchParams.get("pow_proof") ?? (typeof bodyObject?.pow_proof === "string" ? bodyObject.pow_proof : null);
  if (!timestamp || !nonce || !proof || !/^\d+$/.test(timestamp) || !/^[0-9a-z_-]{8,128}$/i.test(nonce) || !/^[0-9a-f]{64}$/i.test(proof)) {
    throw new ApiError(400, "pow_required", "缺少有效的 PoW 参数");
  }
  const time = Number(timestamp);
  if (!Number.isSafeInteger(time) || Math.abs(now - time) > 300) throw new ApiError(408, "pow_expired", "PoW 已过期");
  const cleanParams = new URLSearchParams(url.searchParams);
  cleanParams.delete("pow_timestamp");
  cleanParams.delete("pow_nonce");
  cleanParams.delete("pow_proof");
  const cleanQuery = cleanParams.toString();
  const requestPath = `${url.pathname}${cleanQuery ? `?${cleanQuery}` : ""}`;
  let signedBody = body;
  if (bodyObject && (bodyObject.pow_timestamp || bodyObject.pow_nonce || bodyObject.pow_proof)) {
    delete bodyObject.pow_timestamp;
    delete bodyObject.pow_nonce;
    delete bodyObject.pow_proof;
    signedBody = JSON.stringify(bodyObject);
  }
  const source = [request.method.toUpperCase(), requestPath, timestamp, nonce.toLowerCase(), signedBody].join("\n");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(source));
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (hex !== proof.toLowerCase() || !hex.startsWith("0".repeat(powDifficulty(env)))) throw new ApiError(403, "pow_invalid", "PoW 校验失败");
  const replayKey = `pow:${request.method}:${new URL(request.url).pathname}:${nonce.toLowerCase()}`;
  if (await env.cache.get(replayKey)) throw new ApiError(409, "pow_replay", "PoW 请求已使用");
  await env.cache.put(replayKey, "1", { expirationTtl: 600 });
}
