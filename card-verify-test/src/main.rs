use card_verify_sdk::CardClient;
use serde::Deserialize;
use std::io::{self, Write};

#[derive(Debug, Deserialize)]
struct Config {
    worker_url: String,
    aes_key: String,
    server_public_key: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("测试失败: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let card_code = std::env::args().nth(1).unwrap_or_else(|| {
        print!("请输入卡密: ");
        let _ = io::stdout().flush();
        let mut value = String::new();
        io::stdin().read_line(&mut value).expect("读取卡密失败");
        value.trim().to_string()
    });

    if card_code.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "卡密不能为空").into());
    }

    println!("正在认证卡密...");
    let client = CardClient::builder(
        &config.worker_url,
        &config.aes_key,
        &config.server_public_key,
    )
    .build()?;

    match client.authenticate_detailed(&card_code) {
        Ok(info) => {
            println!("认证成功");
            println!("HWID: {}", info.hwid);
            match info.expires_at {
                Some(value) => println!("失效时间（Unix 秒）: {value}"),
                None => println!("失效时间: 永久"),
            }
            Ok(())
        }
        Err(error) => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()).into())
        }
    }
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string("config.json").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "无法读取 config.json，请根据 config.json.example 创建配置文件",
        )
    })?;
    let config: Config = serde_json::from_str(&text)?;
    if config.worker_url.trim().is_empty()
        || config.aes_key.trim().is_empty()
        || config.server_public_key.trim().is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config.json 缺少 worker_url、aes_key 或 server_public_key",
        )
        .into());
    }
    Ok(config)
}
