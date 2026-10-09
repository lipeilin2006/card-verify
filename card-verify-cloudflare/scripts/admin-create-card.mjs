import crypto from "node:crypto";

const [baseUrl, adminToken, aesKeyHex, count = "1", durationDays] = process.argv.slice(2);

if (!baseUrl || !adminToken || !aesKeyHex) {
  console.error("usage: node scripts/admin-create-card.mjs <base-url> <manager-apikey> <aes-key-base64> [count] [duration-hours]");
  process.exit(2);
}

const workerUrl = normalizeBaseUrl(baseUrl);
const key = Buffer.from(aesKeyHex, "base64");
if (key.length !== 32) throw new Error("AES key must be 32 bytes base64");

const data = {
  count: Number(count),
  ...(durationDays ? { duration_seconds: Number(durationDays) * 3600 } : {}),
};

const nonce = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
const encrypted = Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final(), cipher.getAuthTag()]);
const payload = Buffer.concat([nonce, encrypted]).toString("base64");

const response = await fetch(`${workerUrl}/api/admin/cards`, {
  method: "POST",
  headers: {
    "x-api-key": adminToken,
    "content-type": "application/json",
  },
  body: JSON.stringify({ payload }),
});

const envelope = await response.json();
if (!envelope.payload) throw new Error(JSON.stringify(envelope));

const encryptedResponse = Buffer.from(envelope.payload, "base64");
const responseNonce = encryptedResponse.subarray(0, 12);
const responseCiphertext = encryptedResponse.subarray(12, -16);
const responseTag = encryptedResponse.subarray(-16);
const decipher = crypto.createDecipheriv("aes-256-gcm", key, responseNonce);
decipher.setAuthTag(responseTag);
const plaintext = Buffer.concat([decipher.update(responseCiphertext), decipher.final()]).toString("utf8");

console.log(JSON.stringify(JSON.parse(plaintext), null, 2));
if (!response.ok) process.exit(1);

function normalizeBaseUrl(value) {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) throw new Error("Worker URL 不能为空，例如 https://example.workers.dev");
  if (trimmed.startsWith("https://") || trimmed.startsWith("http://")) return trimmed;
  return `https://${trimmed}`;
}
