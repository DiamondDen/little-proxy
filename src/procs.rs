//! Кому принадлежат сокеты и подходит ли процесс под правила.

use std::{io, mem, path::Path, ptr, sync::Arc};

use regex_lite::{Regex, RegexBuilder};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR, UNICODE_STRING},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, SetTcpEntry, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_LH,
        MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_LISTEN,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    System::ProcessStatus::EnumProcesses,
    System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION},
};

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// Процессы, которые никогда не заворачиваем: Idle и System.
const SYSTEM_PIDS: u32 = 4;

pub struct Matcher {
    rules: Vec<Regex>,
    own_pid: u32,
}

impl Matcher {
    /// Компилирует правила (без учёта регистра); ошибка называет строку с плохим выражением.
    pub fn new(rules: &[String]) -> Result<Matcher, String> {
        let rules = rules
            .iter()
            .map(|r| {
                RegexBuilder::new(r).case_insensitive(true).build().map_err(|e| format!("правило «{r}»: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if rules.is_empty() {
            return Err("не задано ни одного правила для процессов".into());
        }
        Ok(Matcher { rules, own_pid: std::process::id() })
    }

    /// Имя exe, если процесс подходит под правила. Сами себя не заворачиваем никогда — иначе петля.
    pub fn check(&self, pid: u32) -> Option<Arc<str>> {
        let path = self.matched_path(pid).ok()??;
        let name = Path::new(&path).file_name().map_or(path.as_str(), |n| n.to_str().unwrap_or(&path));
        Some(name.into())
    }

    /// `Ok(Some(путь))` — подходит, `Ok(None)` — не подходит или исключён, `Err` — путь не прочитан.
    fn matched_path(&self, pid: u32) -> Result<Option<String>, ()> {
        if pid <= SYSTEM_PIDS || pid == self.own_pid {
            return Ok(None);
        }
        let path = image_path(pid).ok_or(())?;
        Ok(self.rules.iter().any(|r| r.is_match(&path)).then_some(path))
    }

    /// Запущенные сейчас процессы, подходящие под правила, по пути и PID. Второе значение —
    /// сколько процессов не удалось прочитать (успели завершиться или защищены системой).
    pub fn running(&self) -> io::Result<(Vec<Process>, usize)> {
        let mut found = Vec::new();
        let mut unreadable = 0;
        for pid in all_pids()? {
            match self.matched_path(pid) {
                Ok(Some(path)) => found.push(Process { pid, command_line: command_line(pid), path }),
                Ok(None) => {}
                Err(()) => unreadable += 1,
            }
        }
        found.sort_by(|a, b| (&a.path, a.pid).cmp(&(&b.path, b.pid)));
        Ok((found, unreadable))
    }
}

pub struct Process {
    pub pid: u32,
    pub path: String,
    /// `None`, если командную строку прочитать не удалось.
    pub command_line: Option<String>,
}

impl Process {
    pub fn name(&self) -> &str {
        Path::new(&self.path).file_name().and_then(|n| n.to_str()).unwrap_or(&self.path)
    }
}

/// Командная строка процесса (Windows 8.1+). `None`, если процесс завершился или недоступен.
fn command_line(pid: u32) -> Option<String> {
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    // SAFETY: хэндл закрывается ниже; буфер выровнен под UNICODE_STRING, а её Buffer указывает
    // внутрь этого же буфера на Length байт.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut len = 0u32;
        let mut buf: Vec<u64> = Vec::new();
        let mut status = NtQueryInformationProcess(h, ProcessCommandLineInformation, ptr::null_mut(), 0, &mut len);
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf.resize((len as usize).div_ceil(8), 0);
            status = NtQueryInformationProcess(h, ProcessCommandLineInformation, buf.as_mut_ptr().cast(), len, &mut len);
        }
        CloseHandle(h);
        if status < 0 || buf.is_empty() {
            return None;
        }
        let s = &*(buf.as_ptr() as *const UNICODE_STRING);
        if s.Buffer.is_null() {
            return None;
        }
        let chars = std::slice::from_raw_parts(s.Buffer, s.Length as usize / 2);
        Some(String::from_utf16_lossy(chars))
    }
}

fn all_pids() -> io::Result<Vec<u32>> {
    let mut pids = vec![0u32; 1024];
    loop {
        let size = (pids.len() * 4) as u32;
        let mut used = 0u32;
        // SAFETY: буфер размером size байт.
        if unsafe { EnumProcesses(pids.as_mut_ptr(), size, &mut used) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Заполненный до конца буфер означает, что процессов могло быть больше.
        if used < size {
            pids.truncate(used as usize / 4);
            return Ok(pids);
        }
        pids.resize(pids.len() * 2, 0);
    }
}

/// Полный путь exe; `None`, если процесс уже завершился или недоступен.
fn image_path(pid: u32) -> Option<String> {
    // SAFETY: хэндл закрывается ниже, буфер и длина согласованы.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

pub struct Sock {
    pub proto: u8,
    pub port: u16,
    pub pid: u32,
    pub listening: bool,
}

/// Все TCP/UDP-сокеты системы (IPv4 и IPv6) с владельцами.
pub fn sockets() -> io::Result<Vec<Sock>> {
    let mut out = Vec::new();
    for af in [AF_INET, AF_INET6] {
        for proto in [TCP, UDP] {
            collect(proto, af, &mut out)?;
        }
    }
    Ok(out)
}

/// Владелец локального порта и слушает ли кто-то на нём. Вызывается из горячего пути пакетов,
/// поэтому сбой чтения таблиц не логируется, а означает «владелец неизвестен».
pub fn owner_of(proto: u8, port: u16) -> Option<(u32, bool)> {
    let mut socks = Vec::new();
    collect(proto, AF_INET, &mut socks).ok()?;
    collect(proto, AF_INET6, &mut socks).ok()?;
    let mut found = socks.iter().filter(|s| s.port == port).peekable();
    let pid = found.peek()?.pid;
    Some((pid, found.any(|s| s.listening)))
}

fn collect(proto: u8, af: u32, out: &mut Vec<Sock>) -> io::Result<()> {
    let table = table(proto, af)?;
    let (tcp, v6) = (proto == TCP, af == AF_INET6);
    let row_size = match (tcp, v6) {
        (true, false) => mem::size_of::<MIB_TCPROW_OWNER_PID>(),
        (true, true) => mem::size_of::<MIB_TCP6ROW_OWNER_PID>(),
        (false, false) => mem::size_of::<MIB_UDPROW_OWNER_PID>(),
        (false, true) => mem::size_of::<MIB_UDP6ROW_OWNER_PID>(),
    };
    for row in rows(&table, row_size) {
        // SAFETY: строка ровно row_size байт нужного типа; читаем без требований к выравниванию.
        let (port, pid, state) = unsafe {
            match (tcp, v6) {
                (true, false) => {
                    let r = ptr::read_unaligned(row.as_ptr() as *const MIB_TCPROW_OWNER_PID);
                    (r.dwLocalPort, r.dwOwningPid, r.dwState)
                }
                (true, true) => {
                    let r = ptr::read_unaligned(row.as_ptr() as *const MIB_TCP6ROW_OWNER_PID);
                    (r.dwLocalPort, r.dwOwningPid, r.dwState)
                }
                (false, false) => {
                    let r = ptr::read_unaligned(row.as_ptr() as *const MIB_UDPROW_OWNER_PID);
                    (r.dwLocalPort, r.dwOwningPid, 0)
                }
                (false, true) => {
                    let r = ptr::read_unaligned(row.as_ptr() as *const MIB_UDP6ROW_OWNER_PID);
                    (r.dwLocalPort, r.dwOwningPid, 0)
                }
            }
        };
        out.push(Sock { proto, port: net_port(port), pid, listening: tcp && state == MIB_TCP_STATE_LISTEN as u32 });
    }
    Ok(())
}

/// Рвёт уже установленные IPv4-соединения процессов, для которых `is_target` истинно, чтобы они
/// переподключились через прокси. Для IPv6 такого API нет — их пакеты просто отбрасываются.
pub fn reset_tcp(is_target: impl Fn(u32) -> bool) -> io::Result<usize> {
    let table = table(TCP, AF_INET)?;
    let mut reset = 0;
    for row in rows(&table, mem::size_of::<MIB_TCPROW_OWNER_PID>()) {
        // SAFETY: строка ровно одного MIB_TCPROW_OWNER_PID.
        let r = unsafe { ptr::read_unaligned(row.as_ptr() as *const MIB_TCPROW_OWNER_PID) };
        let loopback = r.dwRemoteAddr.to_ne_bytes()[0] == 127;
        if r.dwState != MIB_TCP_STATE_ESTAB as u32 || loopback || !is_target(r.dwOwningPid) {
            continue;
        }
        let entry = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_DELETE_TCB },
            dwLocalAddr: r.dwLocalAddr,
            dwLocalPort: r.dwLocalPort,
            dwRemoteAddr: r.dwRemoteAddr,
            dwRemotePort: r.dwRemotePort,
        };
        // SAFETY: entry — корректно заполненная строка таблицы.
        if unsafe { SetTcpEntry(&entry) } == NO_ERROR {
            reset += 1;
        }
    }
    Ok(reset)
}

/// Порт в строках таблиц IP Helper хранится в сетевом порядке в младших 16 битах.
fn net_port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

/// Сырой буфер таблицы: `u32` с числом строк, затем строки (выравнивание 4).
fn table(proto: u8, af: u32) -> io::Result<Vec<u32>> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut buf = vec![0u32; (size as usize).div_ceil(4).max(1)];
        let mut len = (buf.len() * 4) as u32;
        // SAFETY: буфер размером len байт.
        let rc = unsafe {
            if proto == TCP {
                GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut len, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
            } else {
                GetExtendedUdpTable(buf.as_mut_ptr().cast(), &mut len, 0, af, UDP_TABLE_OWNER_PID, 0)
            }
        };
        match rc {
            NO_ERROR => return Ok(buf),
            // Таблица могла вырасти между вызовами — берём с запасом и повторяем.
            ERROR_INSUFFICIENT_BUFFER => size = len + len / 4,
            rc => return Err(io::Error::from_raw_os_error(rc as i32)),
        }
    }
    Err(io::Error::other("таблица сокетов меняется слишком быстро"))
}

fn rows(table: &[u32], row_size: usize) -> impl Iterator<Item = &[u8]> {
    // SAFETY: Vec<u32> можно читать как байты той же длины.
    let bytes = unsafe { std::slice::from_raw_parts(table.as_ptr() as *const u8, table.len() * 4) };
    let count = table[0] as usize;
    bytes[4..].chunks_exact(row_size).take(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_finds_process_by_path_regex() {
        let mut child = std::process::Command::new("ping").args(["-n", "5", "127.0.0.1"]).spawn().unwrap();
        let matcher = Matcher::new(&[r"\\PING\.exe$".to_string()]).unwrap();
        let (found, _) = matcher.running().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        let ping = found.iter().find(|p| p.pid == child.id()).expect("ping.exe не найден");
        assert_eq!(ping.name().to_lowercase(), "ping.exe");
        let cmd = ping.command_line.as_deref().unwrap_or_default();
        assert!(cmd.contains("-n 5 127.0.0.1"), "{cmd}");
        assert!(found.iter().all(|p| p.path.to_lowercase().ends_with("\\ping.exe")));
    }

    #[test]
    fn own_process_is_never_matched() {
        let matcher = Matcher::new(&[".*".to_string()]).unwrap();
        let (found, _) = matcher.running().unwrap();
        assert!(!found.iter().any(|p| p.pid == std::process::id()));
    }
}
