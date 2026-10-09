#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use chrono::{Local, TimeZone};
use eframe::egui;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::mpsc::{self, Receiver};

#[derive(serde::Deserialize)]
struct Config {
    worker_url: String,
    manager_apikey: String,
    aes_key: String,
}

fn load_config() -> Result<Config, String> {
    let text =
        std::fs::read_to_string("config.json").map_err(|_| "无法读取 config.json".to_string())?;
    let config: Config =
        serde_json::from_str(&text).map_err(|error| format!("config.json 格式错误: {error}"))?;
    if config.worker_url.trim().is_empty()
        || config.manager_apikey.trim().is_empty()
        || config.aes_key.trim().is_empty()
    {
        return Err("config.json 缺少 worker_url、manager_apikey 或 aes_key".into());
    }
    Ok(config)
}

struct ManagerApp {
    base_url: String,
    api_key: String,
    aes_key: String,
    count: String,
    code_length: String,
    duration_hours: String,
    query_code: String,
    output: String,
    busy: bool,
    result: Option<Receiver<Result<String, String>>>,
}

impl Default for ManagerApp {
    fn default() -> Self {
        match load_config() {
            Ok(config) => Self {
                base_url: config.worker_url,
                api_key: config.manager_apikey,
                aes_key: config.aes_key,
                count: "1".into(),
                code_length: "20".into(),
                duration_hours: "720".into(),
                query_code: String::new(),
                output: String::new(),
                busy: false,
                result: None,
            },
            Err(error) => Self {
                base_url: String::new(),
                api_key: String::new(),
                aes_key: String::new(),
                count: "1".into(),
                code_length: "20".into(),
                duration_hours: "720".into(),
                query_code: String::new(),
                output: error,
                busy: false,
                result: None,
            },
        }
    }
}

impl eframe::App for ManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(receiver) = &self.result
            && let Ok(result) = receiver.try_recv()
        {
            self.busy = false;
            self.output = result.unwrap_or_else(|error| error);
            self.result = None;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Card Manage");
            ui.separator();
            ui.label("配置文件: config.json");
            ui.horizontal(|ui| {
                ui.label("生成数量");
                ui.add(egui::TextEdit::singleline(&mut self.count).desired_width(160.0));
            });
            ui.horizontal(|ui| {
                ui.label("卡密长度");
                ui.add(egui::TextEdit::singleline(&mut self.code_length).desired_width(160.0));
            });
            ui.horizontal(|ui| {
                ui.label("生效时长（小时）");
                ui.add(egui::TextEdit::singleline(&mut self.duration_hours).desired_width(160.0));
            });
            if ui
                .add_enabled(!self.busy, egui::Button::new("Generate Cards"))
                .clicked()
            {
                self.start_create();
            }
            ui.horizontal(|ui| {
                ui.label("查询卡密");
                ui.add(egui::TextEdit::singleline(&mut self.query_code).desired_width(240.0));
                if ui
                    .add_enabled(!self.busy, egui::Button::new("查询"))
                    .clicked()
                {
                    self.start_query();
                }
            });
            ui.separator();
            ui.label("Response");
            ui.add(
                egui::TextEdit::multiline(&mut self.output)
                    .desired_rows(16)
                    .desired_width(f32::INFINITY),
            );
        });
        if self.busy {
            ctx.request_repaint();
        }
    }
}

impl ManagerApp {
    fn start_create(&mut self) {
        let base_url = self.base_url.trim_end_matches('/').to_string();
        let api_key = self.api_key.clone();
        let aes_key = self.aes_key.clone();
        let count = self.count.parse::<u32>().unwrap_or(0);
        let code_length = self.code_length.parse::<u32>().unwrap_or(20);
        let duration_hours = self.duration_hours.parse::<u64>().unwrap_or(0);
        let (sender, receiver) = mpsc::channel();
        self.busy = true;
        self.result = Some(receiver);
        std::thread::spawn(move || {
            let result = create_cards(
                &base_url,
                &api_key,
                &aes_key,
                count,
                code_length,
                duration_hours,
            );
            let _ = sender.send(result);
        });
    }

    fn start_query(&mut self) {
        let base_url = self.base_url.trim_end_matches('/').to_string();
        let api_key = self.api_key.clone();
        let aes_key = self.aes_key.clone();
        let code = self.query_code.clone();
        let (sender, receiver) = mpsc::channel();
        self.busy = true;
        self.result = Some(receiver);
        std::thread::spawn(move || {
            let _ = sender.send(query_card(&base_url, &api_key, &aes_key, &code));
        });
    }
}

fn create_cards(
    base_url: &str,
    api_key: &str,
    aes_key: &str,
    count: u32,
    code_length: u32,
    duration_hours: u64,
) -> Result<String, String> {
    let base_url = normalize_base_url(base_url)?;
    let key = decode_key(aes_key)?;
    let payload = serde_json::json!({ "count": count, "code_length": code_length, "duration_seconds": duration_hours.saturating_mul(3600) });
    let encrypted = encrypt(
        &key,
        &serde_json::to_string(&payload).map_err(|error| error.to_string())?,
    )?;
    let body = serde_json::json!({ "payload": encrypted }).to_string();
    let timestamp = unix_seconds();
    let base_nonce = hex::encode(rand_nonce());
    let (pow_nonce, proof) =
        solve_pow("POST", "/api/admin/cards", timestamp, &base_nonce, &body, 4);
    let response = ureq::post(&format!("{}/api/admin/cards", base_url))
        .set("x-api-key", api_key)
        .set("content-type", "application/json")
        .set("x-pow-timestamp", &timestamp.to_string())
        .set("x-pow-nonce", &pow_nonce)
        .set("x-pow-proof", &proof)
        .send_string(&body);
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            let envelope: Value = response.into_json().map_err(|error| error.to_string())?;
            let message = decrypt(
                &key,
                envelope
                    .get("payload")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("HTTP {status}: missing encrypted error"))?,
            )?;
            return Err(format!("HTTP {status}: {message}"));
        }
        Err(error) => return Err(error.to_string()),
    };
    let envelope: Value = response.into_json().map_err(|error| error.to_string())?;
    let plaintext = decrypt(
        &key,
        envelope
            .get("payload")
            .and_then(Value::as_str)
            .ok_or("missing payload")?,
    )?;
    let response: Value = serde_json::from_str(&plaintext).map_err(|error| error.to_string())?;
    let cards = response
        .get("cards")
        .and_then(Value::as_array)
        .ok_or_else(|| response.to_string())?;
    Ok(cards
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n"))
}

fn query_card(base_url: &str, api_key: &str, aes_key: &str, code: &str) -> Result<String, String> {
    let key = decode_key(aes_key)?;
    let path = format!("/api/admin/cards?code={}", code.trim());
    let timestamp = unix_seconds();
    let (nonce, proof) = solve_pow("GET", &path, timestamp, &hex::encode(rand_nonce()), "", 4);
    let response = ureq::get(&format!("{}{}", normalize_base_url(base_url)?, path))
        .set("x-api-key", api_key)
        .set("x-pow-timestamp", &timestamp.to_string())
        .set("x-pow-nonce", &nonce)
        .set("x-pow-proof", &proof)
        .call()
        .map_err(|error| error.to_string())?;
    let envelope: Value = response.into_json().map_err(|error| error.to_string())?;
    let plaintext = decrypt(
        &key,
        envelope
            .get("payload")
            .and_then(Value::as_str)
            .ok_or("missing payload")?,
    )?;
    let value: Value = serde_json::from_str(&plaintext).map_err(|error| error.to_string())?;
    let item = value
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or("卡密不存在")?;
    format_card_info(item)
}

fn format_card_info(item: &Value) -> Result<String, String> {
    let text = |name: &str| item.get(name).and_then(Value::as_str).unwrap_or("-");
    let status = display_status(item);
    let timestamp = |name: &str| {
        item.get(name)
            .and_then(Value::as_i64)
            .map(format_timestamp)
            .unwrap_or_else(|| "未设置".into())
    };
    let duration = item
        .get("duration_seconds")
        .and_then(Value::as_i64)
        .map(|seconds| format_duration(seconds))
        .unwrap_or_else(|| "永久".into());
    let bound_hwid = text("bound_hwid");
    let binding = if bound_hwid == "-" || bound_hwid.is_empty() {
        "未绑定"
    } else {
        bound_hwid
    };
    Ok(format!(
        "卡密: {}\n状态: {}\n绑定 HWID: {}\n创建时间: {}\n激活时间: {}\n失效时间: {}\n生效时长: {}\nHWID 最近变更: {}\n备注: {}",
        text("code"),
        status,
        binding,
        timestamp("created_at"),
        timestamp("activated_at"),
        timestamp("expires_at"),
        duration,
        timestamp("hwid_changed_at"),
        item.get("note").and_then(Value::as_str).unwrap_or("无"),
    ))
}

fn display_status(item: &Value) -> String {
    let status = text_value(item, "status");
    if status == "active" {
        if let Some(expires_at) = item.get("expires_at").and_then(Value::as_i64) {
            let now = chrono::Utc::now().timestamp();
            if expires_at <= now {
                return "expired".into();
            }
        }
    }
    status.to_string()
}

fn text_value<'a>(item: &'a Value, name: &str) -> &'a str {
    item.get(name).and_then(Value::as_str).unwrap_or("-")
}

fn format_timestamp(seconds: i64) -> String {
    Local
        .timestamp_opt(seconds, 0)
        .single()
        .map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| seconds.to_string())
}

fn format_duration(seconds: i64) -> String {
    if seconds % 3600 == 0 {
        format!("{} 小时", seconds / 3600)
    } else {
        format!("{} 秒", seconds)
    }
}

fn normalize_base_url(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() {
        return Err("Worker URL 不能为空，例如 https://example.workers.dev".into());
    }
    let url = if value.starts_with("https://") || value.starts_with("http://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    if !url.contains("://") || url.ends_with("://") {
        return Err("Worker URL 格式不正确，例如 https://example.workers.dev".into());
    }
    Ok(url)
}

fn decode_key(value: &str) -> Result<[u8; 32], String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "AES key must decode to 32 bytes".into())
}

fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
    let nonce = rand_nonce();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut data = nonce.to_vec();
    data.extend(ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(data))
}

fn decrypt(key: &[u8; 32], payload: &str) -> Result<String, String> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|error| error.to_string())?;
    if data.len() <= 28 {
        return Err("invalid encrypted response".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&data[..12]), &data[12..])
        .map_err(|error| error.to_string())?;
    String::from_utf8(plaintext).map_err(|error| error.to_string())
}

fn rand_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("system random unavailable");
    nonce
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn solve_pow(
    method: &str,
    path: &str,
    timestamp: i64,
    base_nonce: &str,
    body: &str,
    difficulty: usize,
) -> (String, String) {
    let prefix = "0".repeat(difficulty);
    let mut counter = 0u64;
    loop {
        let nonce = format!("{base_nonce}{counter:x}");
        let source = format!("{method}\n{path}\n{timestamp}\n{nonce}\n{body}");
        let proof = hex::encode(Sha256::digest(source.as_bytes()));
        if proof.starts_with(&prefix) {
            return (nonce, proof);
        }
        counter += 1;
    }
}

fn main() -> eframe::Result {
    eframe::run_native(
        "Card Manage",
        eframe::NativeOptions::default(),
        Box::new(|cc| {
            configure_chinese_font(&cc.egui_ctx);
            Ok(Box::new(ManagerApp::default()))
        }),
    )
}

fn configure_chinese_font(ctx: &egui::Context) {
    let candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
    ];
    let Some(path) = candidates
        .iter()
        .find(|path| std::path::Path::new(path).exists())
    else {
        return;
    };
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "card_manage_chinese".to_string(),
        egui::FontData::from_owned(bytes).into(),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "card_manage_chinese".to_string());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "card_manage_chinese".to_string());
    ctx.set_fonts(fonts);
}
