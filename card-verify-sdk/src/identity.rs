use crate::error::Error;
use machine_uid::get as machine_uid;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub hwid: String,
}

impl DeviceIdentity {
    #[cfg_attr(feature = "vmp", inline(never))]
    pub fn current() -> Result<Self, Error> {
        crate::vmp::begin_virtualization(b"k11\0");
        let machine = machine_uid().unwrap_or_else(|_| "unknown-machine".to_string());
        let host = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown-host".to_string());
        let user = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "unknown-user".to_string());
        let mut hasher = Sha256::new();
        hasher.update(machine.as_bytes());
        hasher.update(b"\n");
        hasher.update(host.as_bytes());
        hasher.update(b"\n");
        hasher.update(user.as_bytes());
        let out = Ok(Self {
            hwid: hex::encode(hasher.finalize()),
        });
        crate::vmp::end();
        out
    }
}
