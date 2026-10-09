use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("配置错误: {0}")]
    Config(String),
    #[error("文件错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("网络错误: {0}")]
    Transport(String),
    #[error("服务端错误 {status} {code}: {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("响应格式错误: {0}")]
    InvalidResponse(String),
    #[error("尚未兑换卡密")]
    NotRedeemed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("卡密格式无效")]
    InvalidCode,
    #[error("卡密不存在")]
    CardNotFound,
    #[error("卡密已过期")]
    CardExpired,
    #[error("卡密已禁用")]
    CardDisabled,
    #[error("HWID 每天只能更换一次")]
    HwidChangeLimited,
    #[error("HWID 与服务端绑定身份不匹配")]
    HwidMismatch,
    #[error("卡密 IP 状态异常")]
    DeviceIpBanned,
    #[error("缺少 PoW 参数")]
    PowRequired,
    #[error("PoW 校验失败")]
    PowInvalid,
    #[error("加密消息处理失败")]
    EncryptionFailed,
    #[error("服务端响应签名无效")]
    ResponseSignatureInvalid,
    #[error("网络错误")]
    Network,
    #[error("服务端错误")]
    Server,
    #[error("响应格式错误")]
    InvalidResponse,
    #[error("未知认证错误")]
    Unknown,
}

impl From<Error> for AuthError {
    fn from(error: Error) -> Self {
        match error {
            Error::Transport(_) => Self::Network,
            Error::InvalidResponse(message) if message.contains("签名") => {
                Self::ResponseSignatureInvalid
            }
            Error::InvalidResponse(message) if message.contains("加密") => Self::EncryptionFailed,
            Error::InvalidResponse(_) => Self::InvalidResponse,
            Error::Api { code, .. } => match code.as_str() {
                "invalid_code" | "bad_request" => Self::InvalidCode,
                "card_not_found" => Self::CardNotFound,
                "card_expired" => Self::CardExpired,
                "card_disabled" => Self::CardDisabled,
                "hwid_change_limited" => Self::HwidChangeLimited,
                "invalid_hwid" => Self::HwidMismatch,
                "card_ip_banned" => Self::DeviceIpBanned,
                "pow_required" => Self::PowRequired,
                "pow_invalid" | "pow_expired" | "pow_replay" => Self::PowInvalid,
                _ => Self::Server,
            },
            _ => Self::Unknown,
        }
    }
}

impl Error {
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn is_session_lost(&self) -> bool {
        matches!(self.code(), Some("session_expired" | "session_lost"))
    }

    pub fn is_expired(&self) -> bool {
        matches!(self.code(), Some("card_expired"))
    }

    pub fn is_disabled(&self) -> bool {
        matches!(self.code(), Some("card_disabled"))
    }

    pub fn is_device_limit(&self) -> bool {
        matches!(self.code(), Some("device_limit"))
    }
}
