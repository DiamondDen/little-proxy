//! Настройки в little-proxy.ini рядом с exe: `ключ=значение`, правило `match=` может повторяться.

use std::{fs, io, path::PathBuf};

pub struct Config {
    /// Прокси одной строкой: `socks5://логин:пароль@хост:порт` (разбирает `Upstream::parse`).
    pub proxy: String,
    pub rules: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config { proxy: "socks5://127.0.0.1:1080".into(), rules: vec![r"\\claude[^\\]*\.exe$".into()] }
    }
}

fn path() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe.with_file_name("little-proxy.ini"))
}

impl Config {
    /// `Ok(None)` — файла ещё нет (первый запуск).
    pub fn load() -> io::Result<Option<Config>> {
        let text = match fs::read_to_string(path()?) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut cfg = Config::default();
        cfg.rules.clear();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else { continue };
            let value = value.trim().to_string();
            match key.trim() {
                "proxy" => cfg.proxy = value,
                "match" if !value.is_empty() => cfg.rules.push(value),
                _ => {}
            }
        }
        Ok(Some(cfg))
    }

    pub fn save(&self) -> io::Result<()> {
        let mut text = format!("proxy={}\r\n", self.proxy);
        for rule in &self.rules {
            text.push_str(&format!("match={rule}\r\n"));
        }
        fs::write(path()?, text)
    }
}
