//! Журнал для окна: потоки движка кладут строки, GUI забирает их по таймеру.

use std::sync::{Arc, Mutex};

use windows_sys::Win32::System::SystemInformation::GetLocalTime;

#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    pub fn push(&self, line: impl AsRef<str>) {
        // SAFETY: GetLocalTime только заполняет структуру.
        let t = unsafe {
            let mut t = std::mem::zeroed();
            GetLocalTime(&mut t);
            t
        };
        let line = format!("{:02}:{:02}:{:02}  {}", t.wHour, t.wMinute, t.wSecond, line.as_ref());
        self.0.lock().unwrap().push(line);
    }

    pub fn drain(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}
