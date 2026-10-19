//! Локальный приёмник перенаправленных соединений и подключение к вышестоящему прокси.

use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use crate::engine::Shared;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Socks5,
    Http,
}

/// Без `Debug`: в структуре пароль.
#[derive(Clone)]
pub struct Upstream {
    kind: Kind,
    /// `хост:порт`, IPv6 — в квадратных скобках.
    addr: String,
    user: String,
    pass: String,
}

impl Upstream {
    /// Разбирает `socks5://логин:пароль@хост:порт` или `http://…`; без схемы — SOCKS5,
    /// логин и пароль необязательны и могут быть %-закодированы. Текст ошибки не содержит
    /// логина и пароля.
    pub fn parse(url: &str) -> Result<Upstream, String> {
        let url = url.trim();
        let (kind, rest) = match url.split_once("://") {
            Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
                "socks5" | "socks5h" | "socks" => (Kind::Socks5, rest),
                "http" => (Kind::Http, rest),
                other => return Err(format!("схема «{other}://» не поддерживается, нужна socks5:// или http://")),
            },
            None => (Kind::Socks5, url),
        };
        let rest = rest.trim_end_matches('/');
        // Пароль может содержать «@» без кодирования — адрес отделяем по последнему.
        let (creds, addr) = match rest.rsplit_once('@') {
            Some((creds, addr)) => (Some(creds), addr),
            None => (None, rest),
        };
        let port = addr.rsplit_once(':').filter(|(host, _)| !host.is_empty()).map(|(_, port)| port.parse::<u16>());
        if !matches!(port, Some(Ok(p)) if p != 0) {
            return Err(format!("адрес прокси «{addr}» должен быть вида хост:порт"));
        }
        let (user, pass) = match creds {
            Some(creds) => {
                let (user, pass) = creds.split_once(':').unwrap_or((creds, ""));
                (percent_decode(user)?, percent_decode(pass)?)
            }
            None => (String::new(), String::new()),
        };
        Ok(Upstream { kind, addr: addr.into(), user, pass })
    }
}

fn percent_decode(s: &str) -> Result<String, String> {
    const BAD: &str = "в логине или пароле неверная %-последовательность";
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = [bytes.next(), bytes.next()];
            let [Some(h), Some(l)] = hex else { return Err(BAD.into()) };
            let hex = std::str::from_utf8(&[h, l]).map_err(|_| BAD)?.to_owned();
            out.push(u8::from_str_radix(&hex, 16).map_err(|_| BAD)?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).map_err(|_| "логин или пароль — не UTF-8".into())
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Сколько ждём ClientHello, чтобы достать имя хоста из SNI.
const SNI_WAIT: Duration = Duration::from_millis(800);
const TLS_PORT: u16 = 443;
const THREAD_STACK: usize = 128 * 1024;
/// Страница Cloudflare со строками `ключ=значение`, среди них `ip=` — адрес, с которого пришли.
const TRACE_HOST: &str = "1.1.1.1";
const TRACE_PATH: &str = "/cdn-cgi/trace";
const TRACE_MAX: u64 = 16 * 1024;

/// Слушатели на одном порту для IPv4 и IPv6 (порт выбирает система).
pub fn listen() -> io::Result<(TcpListener, TcpListener)> {
    let mut last = None;
    for _ in 0..16 {
        let v4 = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let port = v4.local_addr()?.port();
        match TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)) {
            Ok(v6) => return Ok((v4, v6)),
            Err(e) => last = Some(e), // порт занят в IPv6 — пробуем другой
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("не удалось занять порт")))
}

pub fn accept_loop(sh: Arc<Shared>, listener: TcpListener) {
    for conn in listener.incoming() {
        if !sh.is_running() {
            break;
        }
        match conn {
            Ok(client) => {
                let worker = sh.clone();
                // Если поток не создался, клиентский сокет закроется вместе с замыканием.
                if let Err(e) = thread::Builder::new().stack_size(THREAD_STACK).spawn(move || session(worker, client)) {
                    sh.log.push(format!("Не удалось создать поток сессии: {e}"));
                }
            }
            Err(e) => {
                sh.log.push(format!("Ошибка приёма соединения: {e}"));
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Будит заблокированный `accept`, чтобы цикл увидел остановку.
pub fn wake(port: u16) {
    for ip in [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)] {
        // Отказ тут не важен: если подключиться не вышло, слушатель уже закрыт.
        let _ = TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(1));
    }
}

fn session(sh: Arc<Shared>, client: TcpStream) {
    let Ok(peer) = client.peer_addr() else { return };
    // Отражённый пакет приходит «от» исходного адресата: его IP и есть адрес назначения.
    let Some(flow) = sh.claim(peer.ip(), peer.port()) else { return };
    let registered = client.try_clone().map(|c| sh.register(flow.id, c));
    let first = if flow.port == TLS_PORT { first_bytes(&client) } else { Ok(Vec::new()) };
    let host = first.as_deref().ok().and_then(sni).unwrap_or_else(|| peer.ip().to_string());
    let target = format!("{} → {host}:{}", flow.name, flow.port);
    let result = registered.and(first).and_then(|first| {
        let mut up = connect(&sh.upstream, &host, flow.port)?;
        up.write_all(&first)?;
        sh.log.push(&target);
        relay(client, up)
    });
    if let Err(e) = result {
        sh.log.push(format!("{target}: {e}"));
    }
    sh.release(peer.ip(), peer.port(), flow.id);
}

/// Первые байты клиента (ClientHello) без блокирующего таймаута: таймаут чтения на Windows
/// оставляет сокет в неопределённом состоянии, поэтому опрашиваем в неблокирующем режиме.
fn first_bytes(client: &TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut len = 0;
    let start = Instant::now();
    client.set_nonblocking(true)?;
    while start.elapsed() < SNI_WAIT && len < buf.len() {
        match (&*client).read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if sni(&buf[..len]).is_some() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e),
        }
    }
    client.set_nonblocking(false)?;
    buf.truncate(len);
    Ok(buf)
}

/// Имя хоста из расширения server_name в TLS ClientHello.
fn sni(data: &[u8]) -> Option<String> {
    let mut r = Reader(data);
    if r.u8()? != 0x16 {
        return None; // не TLS handshake
    }
    r.skip(4)?; // версия записи и длина
    if r.u8()? != 0x01 {
        return None; // не ClientHello
    }
    r.skip(3 + 2 + 32)?; // длина, версия, random
    let sid = r.u8()? as usize;
    r.skip(sid)?;
    let suites = r.u16()? as usize;
    r.skip(suites)?;
    let comp = r.u8()? as usize;
    r.skip(comp)?;
    let exts_len = r.u16()? as usize;
    let mut exts = Reader(r.take(exts_len)?);
    while let (Some(kind), Some(len)) = (exts.u16(), exts.u16()) {
        let body = exts.take(len as usize)?;
        if kind != 0 {
            continue;
        }
        let mut names = Reader(body);
        names.skip(2)?; // длина списка
        if names.u8()? != 0 {
            return None; // не host_name
        }
        let name_len = names.u16()? as usize;
        let name = names.take(name_len)?;
        return std::str::from_utf8(name).ok().map(str::to_owned);
    }
    None
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = tail;
        Some(head)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
}

fn connect(up: &Upstream, host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs = up.addr.to_socket_addrs().map_err(|e| io::Error::new(e.kind(), format!("прокси {}: {e}", up.addr)))?;
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(mut s) => {
                s.set_nodelay(true)?;
                s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
                s.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
                match up.kind {
                    Kind::Socks5 => socks5(&mut s, up, host, port)?,
                    Kind::Http => http_connect(&mut s, up, host, port)?,
                }
                s.set_read_timeout(None)?;
                s.set_write_timeout(None)?;
                return Ok(s);
            }
            Err(e) => last = Some(e),
        }
    }
    let e = last.unwrap_or_else(|| io::Error::other("адрес не разрешился"));
    let kind = if e.kind() == io::ErrorKind::TimedOut { "таймаут подключения" } else { "недоступен" };
    Err(io::Error::new(e.kind(), format!("прокси {} {kind}: {e}", up.addr)))
}

fn socks5(s: &mut TcpStream, up: &Upstream, host: &str, port: u16) -> io::Result<()> {
    let auth = !up.user.is_empty();
    s.write_all(if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] })?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    match reply {
        [5, 0] => {}
        [5, 2] if auth => {
            let (user, pass) = (up.user.as_bytes(), up.pass.as_bytes());
            if user.len() > 255 || pass.len() > 255 {
                return Err(io::Error::other("SOCKS5: логин и пароль не длиннее 255 байт"));
            }
            let mut req = vec![1, user.len() as u8];
            req.extend_from_slice(user);
            req.push(pass.len() as u8);
            req.extend_from_slice(pass);
            s.write_all(&req)?;
            s.read_exact(&mut reply)?;
            if reply[1] != 0 {
                return Err(io::Error::other("SOCKS5: неверный логин или пароль"));
            }
        }
        [5, 0xFF] => return Err(io::Error::other("SOCKS5: прокси не принял способ аутентификации")),
        _ => return Err(io::Error::other("SOCKS5: неожиданный ответ прокси")),
    }

    let mut req = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) if host.len() <= 255 => {
            req.extend_from_slice(&[3, host.len() as u8]);
            req.extend_from_slice(host.as_bytes());
        }
        Err(_) => return Err(io::Error::other("SOCKS5: слишком длинное имя хоста")),
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0 {
        return Err(io::Error::other(format!("SOCKS5: отказ прокси, код {}", head[1])));
    }
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n)?;
            n[0] as usize
        }
        t => return Err(io::Error::other(format!("SOCKS5: неизвестный тип адреса {t}"))),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest)
}

fn http_connect(s: &mut TcpStream, up: &Upstream, host: &str, port: u16) -> io::Result<()> {
    let authority = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
        _ => format!("{host}:{port}"),
    };
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !up.user.is_empty() {
        let token = base64(format!("{}:{}", up.user, up.pass).as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;

    // Читаем по байту до конца заголовков, чтобы не съесть данные туннеля.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("HTTP: слишком длинный ответ прокси"));
        }
        s.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head);
    let status = status.lines().next().unwrap_or_default();
    match status.split_whitespace().nth(1) {
        Some(code) if code.starts_with('2') => Ok(()),
        _ => Err(io::Error::other(format!("HTTP: прокси ответил «{status}»"))),
    }
}

fn base64(data: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `ip (страна)` из https://1.1.1.1/cdn-cgi/trace, запрошенной через прокси: внешний адрес
/// трафика и заодно проверка, что прокси живой.
pub fn external_ip(up: &Upstream) -> io::Result<String> {
    let s = connect(up, TRACE_HOST, TLS_PORT)?;
    s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    s.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let tls = native_tls::TlsConnector::new().map_err(|e| io::Error::other(format!("TLS: {e}")))?;
    let mut tls = tls.connect(TRACE_HOST, s).map_err(|e| io::Error::other(format!("TLS с {TRACE_HOST}: {e}")))?;
    // HTTP/1.0: ответ без chunked, конец тела — закрытие соединения.
    tls.write_all(format!("GET {TRACE_PATH} HTTP/1.0\r\nHost: {TRACE_HOST}\r\n\r\n").as_bytes())?;
    let mut response = Vec::new();
    tls.take(TRACE_MAX).read_to_end(&mut response)?;
    parse_trace(&String::from_utf8_lossy(&response))
}

fn parse_trace(response: &str) -> io::Result<String> {
    let bad = |what: &str| io::Error::other(format!("{what} в ответе {TRACE_HOST}: «{}»", response.trim()));
    let (head, body) = response.split_once("\r\n\r\n").ok_or_else(|| bad("нет заголовков"))?;
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(bad("не 200"));
    }
    let field = |key: &str| body.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix('='));
    let ip = field("ip").ok_or_else(|| bad("нет ip="))?;
    Ok(match field("loc") {
        Some(loc) => format!("{ip} ({loc})"),
        None => ip.into(),
    })
}

/// Гоняет байты в обе стороны до закрытия. Обрыв соединения (reset) — обычный конец сессии.
fn relay(client: TcpStream, up: TcpStream) -> io::Result<()> {
    let (mut client_rx, mut up_tx) = (client.try_clone()?, up.try_clone()?);
    let upload = thread::Builder::new().stack_size(THREAD_STACK).spawn(move || {
        let r = io::copy(&mut client_rx, &mut up_tx);
        let _ = up_tx.shutdown(Shutdown::Write); // сокет мог быть уже закрыт другой стороной
        r
    })?;
    let (mut up_rx, mut client_tx) = (up, client);
    let down = io::copy(&mut up_rx, &mut client_tx);
    let _ = client_tx.shutdown(Shutdown::Write); // сокет мог быть уже закрыт другой стороной
    let up_result = upload.join().unwrap_or_else(|_| Err(io::Error::other("поток передачи упал")));
    [down, up_result].into_iter().try_for_each(|r| match r {
        Err(e) if !is_disconnect(&e) => Err(e),
        _ => Ok(()),
    })
}

fn is_disconnect(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(e.kind(), ConnectionReset | ConnectionAborted | BrokenPipe | NotConnected | UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_from_url() {
        let u = Upstream::parse(" socks5://8pEbLb:rLAAUn@103.229.30.184:8000 ").unwrap();
        assert_eq!((u.kind, u.addr.as_str(), u.user.as_str(), u.pass.as_str()), (Kind::Socks5, "103.229.30.184:8000", "8pEbLb", "rLAAUn"));

        let u = Upstream::parse("HTTP://user:p%40ss@w@[::1]:3128/").unwrap();
        assert_eq!((u.kind, u.addr.as_str(), u.user.as_str(), u.pass.as_str()), (Kind::Http, "[::1]:3128", "user", "p@ss@w"));

        let u = Upstream::parse("127.0.0.1:1080").unwrap();
        assert_eq!((u.kind, u.addr.as_str(), u.user.as_str()), (Kind::Socks5, "127.0.0.1:1080", ""));
    }

    #[test]
    fn upstream_errors_hide_credentials() {
        for bad in ["socks4://u:secret@h:1", "socks5://u:secret@h", "socks5://u:secret@h:0", "socks5://u:secret@:80"] {
            let e = Upstream::parse(bad).err().unwrap();
            assert!(!e.contains("secret"), "{e}");
        }
        assert!(Upstream::parse("socks5://u:%zz@h:1").is_err());
    }

    #[test]
    fn trace_gives_ip_and_country() {
        let ok = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfl=1\nh=1.1.1.1\nip=203.0.113.7\nts=1\nloc=NL\n";
        assert_eq!(parse_trace(ok).unwrap(), "203.0.113.7 (NL)");
        let no_loc = "HTTP/1.1 200 OK\r\n\r\nip=2001:db8::1\n";
        assert_eq!(parse_trace(no_loc).unwrap(), "2001:db8::1");
        let e = parse_trace("HTTP/1.1 403 Forbidden\r\n\r\nблок").unwrap_err().to_string();
        assert!(e.contains("403") && e.contains("блок"), "{e}");
        assert!(parse_trace("HTTP/1.1 200 OK\r\n\r\nvisit_scheme=https\n").is_err());
    }

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn sni_from_client_hello() {
        let name = b"api.anthropic.com";
        let mut sni_ext = vec![0, 0]; // type server_name
        let list_len = 3 + name.len();
        sni_ext.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let other_ext = [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]; // ec_point_formats

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[7; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        let exts_len = other_ext.len() + sni_ext.len();
        hello.extend_from_slice(&(exts_len as u16).to_be_bytes());
        hello.extend_from_slice(&other_ext);
        hello.extend_from_slice(&sni_ext);

        let mut hs = vec![1];
        hs.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&hello);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(sni(&rec).as_deref(), Some("api.anthropic.com"));
        assert_eq!(sni(&rec[..rec.len() - 3]), None);
        assert_eq!(sni(b"GET / HTTP/1.1\r\n"), None);
    }
}
