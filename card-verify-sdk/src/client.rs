use crate::error::{AuthError, Error};
use crate::identity::DeviceIdentity;
use crate::protocol::{ErrorResponse, RedeemResponse, RequestEnvelope, VersionResponse};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub struct CardClientBuilder {
    base_url: String,
    aes_key_hex: String,
    server_public_key_hex: String,
    request_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct AuthenticationInfo {
    pub hwid: String,
    pub expires_at: Option<i64>,
}

/// 服务端发布的产品版本信息（`GET /api/version`）。
#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version: String,
    pub url: String,
    pub notes: String,
    pub published_at: Option<i64>,
}

impl CardClientBuilder {
    pub fn new(
        base_url: impl Into<String>,
        aes_key_hex: impl Into<String>,
        server_public_key_hex: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            aes_key_hex: aes_key_hex.into(),
            server_public_key_hex: server_public_key_hex.into(),
            request_timeout: Duration::from_secs(10),
        }
    }
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
    #[cfg_attr(feature = "vmp", inline(never))]
    pub fn build(self) -> Result<CardClient, Error> {
        crate::vmp::begin_virtualization(b"k9\0");
        if self.base_url.trim().is_empty() {
            return Err(Error::Config("base_url 不能为空".into()));
        }
        let out = Ok(CardClient {
            base_url: self.base_url.trim_end_matches('/').to_string(),
            identity: DeviceIdentity::current()?,
            agent: ureq::AgentBuilder::new()
                .timeout(self.request_timeout)
                .build(),
            aes_key: parse_aes_key(&self.aes_key_hex)?,
            server_key: parse_server_key(&self.server_public_key_hex)?,
        });
        crate::vmp::end();
        out
    }
}

pub struct CardClient {
    base_url: String,
    identity: DeviceIdentity,
    agent: ureq::Agent,
    aes_key: [u8; 32],
    server_key: VerifyingKey,
}

impl CardClient {
    pub fn builder(
        base_url: impl Into<String>,
        aes_key_hex: impl Into<String>,
        server_public_key_hex: impl Into<String>,
    ) -> CardClientBuilder {
        CardClientBuilder::new(base_url, aes_key_hex, server_public_key_hex)
    }
    pub fn hwid(&self) -> &str {
        &self.identity.hwid
    }
    pub fn authenticate(&self, card_code: &str) -> Result<AuthenticationInfo, AuthError> {
        self.authenticate_result(card_code).map_err(AuthError::from)
    }

    pub fn authenticate_detailed(&self, card_code: &str) -> Result<AuthenticationInfo, AuthError> {
        self.authenticate_result(card_code).map_err(AuthError::from)
    }

    /// 查询服务端发布的产品版本（`GET /api/version`，明文 JSON + PoW 头）。
    /// 返回 `Ok(None)` = 服务端尚未发布信息（`published_at` 无效且 version 为空）。
    /// 发布与否以 `published_at` 时间戳为准，version 允许为空字符串。
    pub fn latest_version(&self) -> Result<Option<VersionInfo>, Error> {
        let timestamp = unix_seconds();
        let nonce = random_nonce()?;
        let (pow_nonce, proof) = solve_pow("GET", "/api/version", timestamp, &nonce, "", 4);
        let response = self
            .agent
            .get(&format!("{}/api/version", self.base_url))
            .set("x-pow-timestamp", &timestamp.to_string())
            .set("x-pow-nonce", &pow_nonce)
            .set("x-pow-proof", &proof)
            .call();
        let value = match response {
            Ok(response) => response
                .into_json::<Value>()
                .map_err(|e| Error::InvalidResponse(e.to_string()))?,
            Err(ureq::Error::Status(status, response)) => {
                // 错误响应走 signedJson（加密 + 签名信封），与 redeem 一致。
                let outer = response
                    .into_json::<Value>()
                    .map_err(|e| Error::InvalidResponse(e.to_string()))?;
                let value = decrypt_response(&self.aes_key, &outer)?;
                self.verify_response(&value)?;
                let error: ErrorResponse = serde_json::from_value(value)
                    .map_err(|e| Error::InvalidResponse(e.to_string()))?;
                return Err(Error::Api {
                    status,
                    code: error.error.code,
                    message: error.error.message,
                });
            }
            Err(ureq::Error::Transport(error)) => return Err(Error::Transport(error.to_string())),
        };
        let info: VersionResponse =
            serde_json::from_value(value).map_err(|e| Error::InvalidResponse(e.to_string()))?;
        let version = info.version.unwrap_or_default();
        let published_at = info.published_at.filter(|value| *value > 0);
        if published_at.is_none() && version.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(VersionInfo {
            version,
            url: info.url.unwrap_or_default(),
            notes: info.notes.unwrap_or_default(),
            published_at,
        }))
    }

    #[cfg_attr(feature = "vmp", inline(never))]
    fn authenticate_result(&self, card_code: &str) -> Result<AuthenticationInfo, Error> {
        crate::vmp::begin_virtualization(b"k4\0");
        if card_code.trim().is_empty() {
            return Err(Error::Config("card_code 不能为空".into()));
        }
        let envelope = RequestEnvelope {
            payload: encrypt(
                &self.aes_key,
                &serde_json::json!({ "code": card_code, "hwid": self.identity.hwid }),
            )?,
        };
        let body = serde_json::to_string(&envelope)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        let timestamp = unix_seconds();
        let nonce = random_nonce()?;
        let (pow_nonce, proof) = solve_pow("POST", "/api/redeem", timestamp, &nonce, &body, 4);
        let response = self
            .agent
            .post(&format!("{}/api/redeem", self.base_url))
            .set("content-type", "application/json")
            .set("x-pow-timestamp", &timestamp.to_string())
            .set("x-pow-nonce", &pow_nonce)
            .set("x-pow-proof", &proof)
            .send_string(&body);
        let value = match response {
            Ok(response) => decrypt_response(
                &self.aes_key,
                &response
                    .into_json::<Value>()
                    .map_err(|e| Error::InvalidResponse(e.to_string()))?,
            )?,
            Err(ureq::Error::Status(status, response)) => {
                let value = decrypt_response(
                    &self.aes_key,
                    &response
                        .into_json::<Value>()
                        .map_err(|e| Error::InvalidResponse(e.to_string()))?,
                )?;
                self.verify_response(&value)?;
                let error: ErrorResponse = serde_json::from_value(value)
                    .map_err(|e| Error::InvalidResponse(e.to_string()))?;
                return Err(Error::Api {
                    status,
                    code: error.error.code,
                    message: error.error.message,
                });
            }
            Err(ureq::Error::Transport(error)) => return Err(Error::Transport(error.to_string())),
        };
        self.verify_response(&value)?;
        let response: RedeemResponse =
            serde_json::from_value(value).map_err(|e| Error::InvalidResponse(e.to_string()))?;
        let returned_hwid = response.hwid.trim().to_ascii_lowercase();
        if returned_hwid != self.identity.hwid || response.token.is_empty() {
            return Err(Error::InvalidResponse("response validation failed".into()));
        }
        let out = Ok(AuthenticationInfo {
            hwid: returned_hwid,
            expires_at: response.expires_at,
        });
        crate::vmp::end();
        out
    }

    #[cfg_attr(feature = "vmp", inline(never))]
    fn verify_response(&self, value: &Value) -> Result<(), Error> {
        crate::vmp::begin_virtualization(b"k1\0");
        let signature = value
            .get("response_signature")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidResponse("缺少 response_signature".into()))?;
        let signature = Signature::from_slice(
            &hex::decode(signature).map_err(|e| Error::InvalidResponse(e.to_string()))?,
        )
        .map_err(|e| Error::InvalidResponse(e.to_string()))?;
        let mut signed = value.clone();
        signed
            .as_object_mut()
            .ok_or_else(|| Error::InvalidResponse("响应不是对象".into()))?
            .remove("response_signature");
        let out = self
            .server_key
            .verify(canonical_value(&signed).as_bytes(), &signature)
            .map_err(|_| Error::InvalidResponse("响应签名无效".into()));
        crate::vmp::end();
        out
    }
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_nonce() -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| Error::Transport(error.to_string()))?;
    Ok(hex::encode(bytes))
}

#[cfg_attr(feature = "vmp", inline(never))]
fn solve_pow(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &str,
    difficulty: usize,
) -> (String, String) {
    // PoW hot loop (~65k iterations): Mutation, not Virtualization — VM
    // execution made every login take seconds. PoW is not the secret; the
    // AES keys / signature live in k5/k7/k8/k1 which stay virtualized.
    crate::vmp::begin_mutation(b"k3\0");
    let prefix = "0".repeat(difficulty);
    let mut counter = 0u64;
    let out = loop {
        let candidate = format!("{nonce}{counter:x}");
        let source = format!("{method}\n{path}\n{timestamp}\n{candidate}\n{body}");
        let digest = Sha256::digest(source.as_bytes());
        let proof = hex::encode(digest);
        if proof.starts_with(&prefix) {
            break (candidate, proof);
        }
        counter += 1;
    };
    crate::vmp::end();
    out
}

#[cfg_attr(feature = "vmp", inline(never))]
fn cipher(key: &[u8; 32]) -> Result<Aes256Gcm, Error> {
    crate::vmp::begin_virtualization(b"k6\0");
    let out = Aes256Gcm::new_from_slice(key).map_err(|error| Error::Config(error.to_string()));
    crate::vmp::end();
    out
}

#[cfg_attr(feature = "vmp", inline(never))]
fn encrypt(key: &[u8; 32], value: &Value) -> Result<String, Error> {
    crate::vmp::begin_virtualization(b"k5\0");
    let cipher = cipher(key)?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|error| Error::Transport(error.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            serde_json::to_vec(value).unwrap().as_ref(),
        )
        .map_err(|error| Error::InvalidResponse(error.to_string()))?;
    let mut output = nonce.to_vec();
    output.extend(ciphertext);
    let out = Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        output,
    ));
    crate::vmp::end();
    out
}

#[cfg_attr(feature = "vmp", inline(never))]
fn decrypt_response(key: &[u8; 32], value: &Value) -> Result<Value, Error> {
    crate::vmp::begin_virtualization(b"k2\0");
    let Some(payload) = value.get("payload").and_then(Value::as_str) else {
        return Err(Error::InvalidResponse(format!(
            "缺少加密响应，服务端返回: {value}"
        )));
    };
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload)
        .map_err(|error| Error::InvalidResponse(error.to_string()))?;
    if bytes.len() <= 28 {
        return Err(Error::InvalidResponse("加密响应格式错误".into()));
    }
    let plaintext = cipher(key)?
        .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
        .map_err(|error| Error::InvalidResponse(error.to_string()))?;
    let out = serde_json::from_slice(&plaintext).map_err(|error| Error::InvalidResponse(error.to_string()));
    crate::vmp::end();
    out
}

#[cfg_attr(feature = "vmp", inline(never))]
fn parse_aes_key(value: &str) -> Result<[u8; 32], Error> {
    crate::vmp::begin_virtualization(b"k7\0");
    let out = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|e| Error::Config(format!("AES 密钥无效: {e}")))?
        .try_into()
        .map_err(|_| Error::Config("AES 密钥必须是 32 字节 Base64".into()));
    crate::vmp::end();
    out
}

#[cfg_attr(feature = "vmp", inline(never))]
fn parse_server_key(value: &str) -> Result<VerifyingKey, Error> {
    crate::vmp::begin_virtualization(b"k8\0");
    if !value.contains("-----BEGIN PUBLIC KEY-----") || !value.contains("-----END PUBLIC KEY-----")
    {
        return Err(Error::Config("服务端公钥必须是完整 PEM 格式".into()));
    }
    let normalized = value
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(char::is_whitespace, "");
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, normalized)
        .map_err(|e| Error::Config(e.to_string()))?;
    if decoded.len() < 32 {
        return Err(Error::Config("服务端公钥 PEM 内容无效".into()));
    }
    let bytes: [u8; 32] = decoded[decoded.len() - 32..]
        .try_into()
        .map_err(|_| Error::Config("服务端公钥长度无效".into()))?;
    let out = VerifyingKey::from_bytes(&bytes)
        .map_err(|e| Error::Config(format!("服务端公钥无效，请确认它与 ed_priv 对应: {e}")));
    crate::vmp::end();
    out
}

#[cfg_attr(feature = "vmp", inline(never))]
fn canonical_value(value: &Value) -> String {
    crate::vmp::begin_virtualization(b"k10\0");
    let out = match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_value)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical_value(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    };
    crate::vmp::end();
    out
}

