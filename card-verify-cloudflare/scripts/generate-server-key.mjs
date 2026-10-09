import { generateKeyPairSync } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "der", type: "pkcs8" },
  publicKeyEncoding: { format: "der", type: "spki" },
});

console.log(`SERVER_SIGNING_KEY=${privateKey.toString("base64")}`);
console.log(`SERVER_PUBLIC_KEY=${publicKey.subarray(-32).toString("base64")}`);
