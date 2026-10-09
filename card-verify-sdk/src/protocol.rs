use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(crate) struct RequestEnvelope {
    pub payload: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorDetail {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RedeemResponse {
    pub token: String,
    pub hwid: String,
    pub expires_at: Option<i64>,
}

/// GET /api/version 明文响应（非信封）：字段可为 null。
#[derive(Debug, Deserialize)]
pub(crate) struct VersionResponse {
    pub version: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub published_at: Option<i64>,
}
