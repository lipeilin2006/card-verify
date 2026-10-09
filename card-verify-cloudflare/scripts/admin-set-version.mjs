import crypto from "node:crypto";

const [baseUrl, adminToken, aesKeyBase64, version, downloadUrl, notes = "", publishedAt] = process.argv.slice(2);

if (!baseUrl || !adminToken || !aesKeyBase64 || !version) {
  console.error("usage: node scripts/admin-set-version.mjs <base-url> <manager-apikey> <aes-key-base64> <version> [download-url] [notes] [published-at]");
  console.error("  published-at: Unix 秒或 ISO 时间（如 2026-10-05T18:00:00+08:00），留空用当前时间");
  process.exit(2);
}

const workerUrl = normalizeBaseUrl(baseUrl);
const key = Buffer.from(aesKeyBase64, "base64");
if (key.length !== 32) throw new Error("AES key must be 32 bytes base64");

const path = "/api/admin/version";
const data = { version, url: downloadUrl ?? "", notes };
if (publishedAt) {
  const timestamp = /^\d+$/.test(publishedAt) ? Number(publishedAt) : Math.floor(Date.parse(publishedAt) / 1000);
  if (!Number.isFinite(timestamp) || timestamp <= 0) throw new Error("published-at 无效：填写 Unix 秒或 ISO 时间");
  data.published_at = timestamp;
}
const body = JSON.stringify({ payload: encrypt(key, JSON.stringify(data)) });
const headers = {
  "x-api-key": adminToken,
  "content-type": "application/json",
  ...(await solvePow("POST", path, body)),
};

const response = await fetch(`${workerUrl}${path}`, { method: "POST", headers, body });
const envelope = await response.json();
if (!envelope.payload) throw new Error(`HTTP ${response.status}: ${JSON.stringify(envelope)}`);

console.log(decrypt(key, envelope.payload));
if (!response.ok) process.exit(1);

function encrypt(keyBuffer, plaintext) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBuffer, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([nonce, encrypted]).toString("base64");
}

function decrypt(keyBuffer, payload) {
  const buffer = Buffer.from(payload, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuffer, buffer.subarray(0, 12));
  decipher.setAuthTag(buffer.subarray(buffer.length - 16));
  return Buffer.concat([decipher.update(buffer.subarray(12, buffer.length - 16)), decipher.final()]).toString("utf8");
}

async function solvePow(method, requestPath, body) {
  const base = crypto.randomBytes(12).toString("base64").replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  const timestamp = Math.floor(Date.now() / 1000);
  for (let counter = 0; ; counter += 1) {
    const nonce = `${base}${counter.toString(16)}`;
    const proof = crypto.createHash("sha256").update(`${method}\n${requestPath}\n${timestamp}\n${nonce}\n${body}`).digest("hex");
    if (proof.startsWith("0000")) {
      return { "x-pow-timestamp": String(timestamp), "x-pow-nonce": nonce, "x-pow-proof": proof };
    }
  }
}

function normalizeBaseUrl(value) {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) throw new Error("Worker URL 不能为空，例如 https://cardverify.654645.xyz");
  if (trimmed.startsWith("https://") || trimmed.startsWith("http://")) return trimmed;
  return `https://${trimmed}`;
}
