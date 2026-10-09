import { computed, reactive } from "vue";
import { fetch as tauriFetch } from "@tauri-apps/plugin-http";

export const config = reactive({ workerUrl: "", apiKey: "", aesKey: "", publicKey: "" });
export const configReady = computed(() => config.workerUrl && config.apiKey && config.aesKey && config.publicKey);

export function loadConfig() {
  try {
    Object.assign(config, JSON.parse(localStorage.getItem("card-manage-config") || "{}"));
    return true;
  } catch {
    return false;
  }
}

export function saveConfig() {
  localStorage.setItem("card-manage-config", JSON.stringify(config));
}

export function errorMessage(error) {
  if (typeof error === "string") return error;
  if (error?.message) return error.message;
  try { return JSON.stringify(error); } catch { return "请求失败，请检查配置和网络"; }
}

export async function runRequest(path, method, data = null) {
  if (!configReady.value) throw new Error("请先完成连接配置");
  const url = new URL(path, config.workerUrl.replace(/\/$/, "/"));
  const body = data === null ? "" : JSON.stringify({ payload: await encrypt(config.aesKey, JSON.stringify(data)) });
  const timestamp = Math.floor(Date.now() / 1000);
  const [nonce, proof] = await solvePow(method, `${url.pathname}${url.search}`, timestamp, body, 4);
  const headers = new Headers();
  headers.set("content-type", "application/json");
  headers.set("x-api-key", config.apiKey);
  headers.set("x-pow-timestamp", String(timestamp));
  headers.set("x-pow-nonce", nonce);
  headers.set("x-pow-proof", proof);
  const response = await tauriFetch(url.toString(), { method, headers, body: method === "GET" ? undefined : body });
  const text = await response.text();
  let envelope = null;
  try { envelope = JSON.parse(text); } catch { envelope = null; }
  if (!envelope) throw new Error(describeBadBody(response.status, text));
  if (!envelope.payload) throw new Error(`HTTP ${response.status}: ${JSON.stringify(envelope)}`);
  const result = JSON.parse(await decrypt(config.aesKey, envelope.payload));
  if (!response.ok || result.ok === false) throw new Error(result.error?.message || `HTTP ${response.status}`);
  return result;
}

function describeBadBody(status, text) {
  const raw = (text || "").trim().replace(/\s+/g, " ").slice(0, 200);
  const cfCode = raw.match(/error code:?\s*(\d+)/i);
  if (cfCode) {
    const code = cfCode[1];
    const hints = {
      "1034": "Cloudflare 1034 Edge IP Restricted：该边缘 IP 不接受此域名，请更换其他优选 IP",
      "1000": "Cloudflare 1000：Host 头不匹配，请检查 Worker URL 域名",
      "1016": "Cloudflare 1016：源站 DNS 解析失败",
      "502": "Cloudflare 502：Worker 异常或超时",
    };
    return `HTTP ${status}: ${raw}${hints[code] ? `；${hints[code]}` : ""}`;
  }
  return `HTTP ${status}: ${raw || "非 JSON 响应"}`;
}

export async function fetchVersion() {
  if (!configReady.value) throw new Error("请先完成连接配置");
  const path = "/api/version";
  const timestamp = Math.floor(Date.now() / 1000);
  const [nonce, proof] = await solvePow("GET", path, timestamp, "", 4);
  const response = await tauriFetch(`${config.workerUrl.replace(/\/+$/, "")}${path}`, {
    method: "GET",
    headers: {
      "x-pow-timestamp": String(timestamp),
      "x-pow-nonce": nonce,
      "x-pow-proof": proof,
    },
  });
  const text = await response.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = null; }
  if (!data) throw new Error(describeBadBody(response.status, text));
  if (!data.ok) throw new Error(data.error?.message || `HTTP ${response.status}`);
  return data;
}

export async function setVersion(input) {
  return runRequest("/api/admin/version", "POST", input);
}

export function formatTime(value) {
  if (!value) return "未设置";
  const date = new Date(Number(value) * 1000);
  const pad = (part) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function displayStatus(item) {
  if (item.status === "active" && item.expires_at && item.expires_at * 1000 <= Date.now()) return "expired";
  return item.status || "-";
}

export function formatDuration(seconds) {
  if (seconds === undefined || seconds === null) return "永久";
  return seconds % 3600 === 0 ? `${seconds / 3600} 小时` : `${seconds} 秒`;
}

async function encrypt(keyText, plaintext) {
  const key = await crypto.subtle.importKey("raw", base64ToBytes(keyText), "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(plaintext));
  return bytesToBase64(concat(nonce, new Uint8Array(ciphertext)));
}

async function decrypt(keyText, payload) {
  const bytes = base64ToBytes(payload);
  const key = await crypto.subtle.importKey("raw", base64ToBytes(keyText), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));
  return new TextDecoder().decode(plaintext);
}

async function solvePow(method, path, timestamp, body, difficulty) {
  const base = bytesToBase64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  const prefix = "0".repeat(difficulty);
  for (let counter = 0; ; counter += 1) {
    const nonce = `${base}${counter.toString(16)}`;
    const source = `${method}\n${path}\n${timestamp}\n${nonce}\n${body}`;
    const hash = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(source))));
    if (hash.startsWith(prefix)) return [nonce, hash];
  }
}

function base64ToBytes(value) { return Uint8Array.from(atob(value.replace(/-----[^-]+-----/g, "").replace(/\s/g, "")), (char) => char.charCodeAt(0)); }
function bytesToBase64(value) { let binary = ""; value.forEach((byte) => { binary += String.fromCharCode(byte); }); return btoa(binary); }
function bytesToHex(value) { return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function concat(a, b) { const output = new Uint8Array(a.length + b.length); output.set(a, 0); output.set(b, a.length); return output; }
