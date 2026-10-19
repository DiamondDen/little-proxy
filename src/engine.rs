//! Перехват трафика. Исходящие TCP/UDP-пакеты проходят через WinDivert; владельца локального
//! порта узнаём по событиям сокетного слоя WinDivert (с запасным чтением таблиц IP Helper).
//!
//! TCP целевого процесса A:a → B:b отражается локальному приёмнику: пакет становится B:a → A:P
//! и вбрасывается как входящий. Ответ приёмника A:P → B:a превращается обратно в B:b → A:a.
//! Так приёмник видит адресата B в адресе пира, а исходный порт b хранится в таблице NAT.
//! UDP целевых процессов и их соединения, открытые до запуска, отбрасываются — мимо прокси
//! не уходит ничего.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpStream},
    os::windows::process::CommandExt,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    config::Config,
    divert::{self, Address, Handle},
    log::Log,
    procs::{self, Matcher, TCP, UDP},
    proxy::{self, Upstream},
};

/// Сколько держим запись NAT после конца сессии: хвостовые FIN/ACK ещё нужно перевести.
const NAT_LINGER: Duration = Duration::from_secs(30);
const SWEEP_EVERY: Duration = Duration::from_secs(5);
const SEND_ERROR_LOG_EVERY: Duration = Duration::from_secs(10);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FIREWALL_RULE: &str = "little-proxy";
const ERROR_NO_DATA: i32 = 232;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

#[derive(Clone)]
struct Owner {
    pid: u32,
    /// Имя exe, если процесс подходит под правила.
    target: Option<Arc<str>>,
    /// На порту кто-то слушает: это ответы сервера, а не исходящие соединения.
    listening: bool,
}

impl Owner {
    /// Имя exe, если трафик с этого порта нужно завернуть.
    fn client_target(&self) -> Option<Arc<str>> {
        self.target.clone().filter(|_| !self.listening)
    }
}

struct Nat {
    id: u64,
    orig_port: u16,
    name: Arc<str>,
    created: Instant,
    accepted: bool,
    closed: Option<Instant>,
}

/// Перенаправленное соединение, принятое приёмником.
pub struct Flow {
    pub id: u64,
    pub port: u16,
    pub name: Arc<str>,
}

pub struct Shared {
    pub log: Log,
    pub upstream: Upstream,
    proxy_port: u16,
    running: AtomicBool,
    matcher: Matcher,
    owners: RwLock<HashMap<(u8, u16), Owner>>,
    /// Ключ — (IP адресата, локальный порт клиента).
    nat: Mutex<HashMap<(IpAddr, u16), Nat>>,
    next_id: AtomicU64,
    sessions: Mutex<HashMap<u64, TcpStream>>,
}

enum Verdict {
    Pass,
    Drop,
    Reflect,
}

impl Shared {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn claim(&self, ip: IpAddr, port: u16) -> Option<Flow> {
        let mut nat = self.nat.lock().unwrap();
        let n = nat.get_mut(&(ip, port)).filter(|n| n.closed.is_none())?;
        n.accepted = true;
        Some(Flow { id: n.id, port: n.orig_port, name: n.name.clone() })
    }

    pub fn register(&self, id: u64, client: TcpStream) {
        self.sessions.lock().unwrap().insert(id, client);
    }

    pub fn release(&self, ip: IpAddr, port: u16, id: u64) {
        self.sessions.lock().unwrap().remove(&id);
        // Порт мог уже уйти новому соединению с новой записью — её не трогаем.
        if let Some(n) = self.nat.lock().unwrap().get_mut(&(ip, port)).filter(|n| n.id == id) {
            n.closed = Some(Instant::now());
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    fn on_socket_event(&self, event: u8, s: &divert::SocketData) {
        let key = (s.protocol, s.local_port);
        match event {
            divert::EVENT_BIND | divert::EVENT_CONNECT | divert::EVENT_LISTEN | divert::EVENT_ACCEPT => {
                let listening = matches!(event, divert::EVENT_LISTEN | divert::EVENT_ACCEPT);
                let known = self.owners.read().unwrap().get(&key).map(|o| (o.pid, o.listening));
                let listening = match known {
                    Some((pid, was)) if pid == s.process_id => {
                        if was || !listening {
                            return;
                        }
                        true
                    }
                    _ => listening,
                };
                let owner = Owner { pid: s.process_id, target: self.matcher.check(s.process_id), listening };
                self.owners.write().unwrap().insert(key, owner);
            }
            divert::EVENT_CLOSE => {
                let mut owners = self.owners.write().unwrap();
                if owners.get(&key).is_some_and(|o| o.pid == s.process_id) {
                    owners.remove(&key);
                }
            }
            _ => {}
        }
    }

    /// Имя exe, если трафик с локального порта нужно завернуть. Событие сокета может прийти
    /// позже первого пакета, а порт — достаться новому владельцу раньше, чем придёт закрытие
    /// старого. Поэтому новое соединение (`fresh`) и промах кеша сверяем с таблицами IP Helper.
    fn target(&self, proto: u8, port: u16, fresh: bool) -> Option<Arc<str>> {
        if !fresh {
            if let Some(o) = self.owners.read().unwrap().get(&(proto, port)) {
                return o.client_target();
            }
        }
        // Владелец не найден (сокет уже закрыт) — не кешируем, чтобы не заслонить нового,
        // но и запись от событий сокета не теряем.
        let Some((pid, listening)) = procs::owner_of(proto, port) else {
            return self.owners.read().unwrap().get(&(proto, port)).and_then(Owner::client_target);
        };
        let cached = self.owners.read().unwrap().get(&(proto, port)).filter(|o| o.pid == pid).cloned();
        let owner = cached.unwrap_or_else(|| Owner { pid, target: self.matcher.check(pid), listening });
        let target = owner.client_target();
        self.owners.write().unwrap().insert((proto, port), owner);
        target
    }

    fn route(&self, p: &mut [u8], udp_noted: &mut HashSet<Arc<str>>) -> Verdict {
        let Some(ip) = Ip::parse(p) else { return Verdict::Pass };
        match ip.proto {
            TCP => self.route_tcp(p, &ip),
            UDP => match self.target(UDP, ip.port(p, 0), false) {
                Some(name) => {
                    if udp_noted.insert(name.clone()) {
                        self.log.push(format!("{name}: UDP заблокирован (прокси передаёт только TCP)"));
                    }
                    Verdict::Drop
                }
                None => Verdict::Pass,
            },
            _ => Verdict::Pass,
        }
    }

    fn route_tcp(&self, p: &mut [u8], ip: &Ip) -> Verdict {
        let (src_port, dst_port, dst) = (ip.port(p, 0), ip.port(p, 2), ip.dst(p));
        if src_port == self.proxy_port {
            // Ответ приёмника клиенту: возвращаем исходный порт адресата.
            let orig = self.nat.lock().unwrap().get(&(dst, dst_port)).map(|n| n.orig_port);
            let Some(orig) = orig else { return Verdict::Drop };
            ip.set_port(p, 0, orig);
            ip.swap_addrs(p);
            return Verdict::Reflect;
        }
        let key = (dst, src_port);
        let syn = p[ip.l4 + 13] & (TCP_SYN | TCP_ACK) == TCP_SYN;
        if !syn && self.nat.lock().unwrap().contains_key(&key) {
            return self.to_proxy(p, ip);
        }
        let Some(name) = self.target(TCP, src_port, syn) else {
            if syn {
                self.nat.lock().unwrap().remove(&key);
            }
            return Verdict::Pass;
        };
        if !syn {
            return Verdict::Drop; // соединение открыто до запуска: напрямую не пускаем
        }
        let mut nat = self.nat.lock().unwrap();
        let reuse = nat.get(&key).is_some_and(|n| n.orig_port == dst_port && n.closed.is_none());
        if !reuse {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let entry = Nat { id, orig_port: dst_port, name, created: Instant::now(), accepted: false, closed: None };
            nat.insert(key, entry);
        }
        drop(nat);
        self.to_proxy(p, ip)
    }

    fn to_proxy(&self, p: &mut [u8], ip: &Ip) -> Verdict {
        ip.set_port(p, 2, self.proxy_port);
        ip.swap_addrs(p);
        Verdict::Reflect
    }

    fn sweep(&self) {
        self.nat.lock().unwrap().retain(|_, n| match n.closed {
            Some(at) => at.elapsed() < NAT_LINGER,
            None => n.accepted || n.created.elapsed() < NAT_LINGER,
        });
    }
}

/// Разобранные смещения IP-пакета.
struct Ip {
    v6: bool,
    l4: usize,
    proto: u8,
}

impl Ip {
    fn parse(p: &[u8]) -> Option<Ip> {
        let ip = match p.first()? >> 4 {
            4 => {
                let ihl = (p[0] & 0x0F) as usize * 4;
                let frag_offset = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]) & 0x1FFF;
                if ihl < 20 || frag_offset != 0 {
                    return None; // во фрагментах без смещения 0 нет заголовка TCP/UDP
                }
                Ip { v6: false, l4: ihl, proto: p[9] }
            }
            6 => Ip { v6: true, l4: 40, proto: *p.get(6)? },
            _ => return None,
        };
        let min = if ip.proto == TCP { 20 } else { 8 };
        (p.len() >= ip.l4 + min).then_some(ip)
    }

    fn port(&self, p: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([p[self.l4 + at], p[self.l4 + at + 1]])
    }

    fn set_port(&self, p: &mut [u8], at: usize, port: u16) {
        p[self.l4 + at..self.l4 + at + 2].copy_from_slice(&port.to_be_bytes());
    }

    fn addr_range(&self) -> (usize, usize) {
        if self.v6 { (8, 16) } else { (12, 4) }
    }

    fn dst(&self, p: &[u8]) -> IpAddr {
        let (at, len) = self.addr_range();
        let b = &p[at + len..at + 2 * len];
        if self.v6 {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()))
        } else {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b).unwrap()))
        }
    }

    fn swap_addrs(&self, p: &mut [u8]) {
        let (at, len) = self.addr_range();
        let (src, dst) = p[at..at + 2 * len].split_at_mut(len);
        src.swap_with_slice(dst);
    }
}

pub struct Engine {
    shared: Arc<Shared>,
    handles: Vec<Arc<Handle>>,
    threads: Vec<JoinHandle<()>>,
}

impl Engine {
    pub fn start(cfg: &Config, log: Log) -> Result<Engine, String> {
        let upstream = Upstream::parse(&cfg.proxy)?;
        let matcher = Matcher::new(&cfg.rules)?;
        divert::load().map_err(|e| format!("WinDivert: {e}"))?;
        // Правило — до открытия порта: иначе Windows успевает показать окно «Разрешить доступ»,
        // а отмена в нём создаёт блокирующие правила, которые сильнее нашего разрешающего.
        allow_in_firewall(&log);
        let (v4, v6) = proxy::listen().map_err(|e| format!("локальный приёмник: {e}"))?;
        let proxy_port = v4.local_addr().map_err(|e| format!("локальный приёмник: {e}"))?.port();

        let shared = Arc::new(Shared {
            log,
            upstream,
            proxy_port,
            running: AtomicBool::new(true),
            matcher,
            owners: RwLock::default(),
            nat: Mutex::default(),
            next_id: AtomicU64::new(1),
            sessions: Mutex::default(),
        });
        let mut engine = Engine { shared: shared.clone(), handles: Vec::new(), threads: Vec::new() };
        match engine.spawn_all(v4, v6) {
            Ok(()) => Ok(engine),
            Err(e) => {
                engine.stop();
                Err(e)
            }
        }
    }

    fn spawn_all(&mut self, v4: std::net::TcpListener, v6: std::net::TcpListener) -> Result<(), String> {
        let sh = self.shared.clone();
        // Сокетный слой открываем первым: всё, что откроется после, придёт событием.
        let sock = Arc::new(
            Handle::open("tcp or udp", divert::LAYER_SOCKET, divert::FLAG_SNIFF | divert::FLAG_RECV_ONLY)
                .map_err(open_error)?,
        );
        self.handles.push(sock.clone());
        self.spawn("socket-events", {
            let sh = sh.clone();
            move || socket_events(sh, sock)
        })?;

        let socks = procs::sockets().map_err(|e| format!("таблица сокетов: {e}"))?;
        let mut checked: HashMap<u32, Option<Arc<str>>> = HashMap::new();
        {
            let mut owners = sh.owners.write().unwrap();
            for s in socks {
                let target = checked.entry(s.pid).or_insert_with(|| sh.matcher.check(s.pid)).clone();
                let entry = owners.entry((s.proto, s.port)).or_insert(Owner { pid: s.pid, target, listening: false });
                entry.listening |= s.listening;
            }
        }
        let targets: Vec<&str> = {
            let mut names: Vec<&str> = checked.values().flatten().map(|n| &**n).collect();
            names.sort_unstable();
            names.dedup();
            names
        };
        if !targets.is_empty() {
            sh.log.push(format!("Уже запущены: {}", targets.join(", ")));
        }
        match procs::reset_tcp(|pid| checked.get(&pid).is_some_and(Option::is_some)) {
            Ok(0) => {}
            Ok(n) => sh.log.push(format!("Сброшено старых соединений: {n} — они переподключатся через прокси")),
            Err(e) => sh.log.push(format!("Не удалось сбросить старые соединения: {e}")),
        }

        let net = Arc::new(Handle::open("outbound and !loopback and (tcp or udp)", divert::LAYER_NETWORK, 0).map_err(open_error)?);
        self.handles.push(net.clone());
        self.spawn("packets", {
            let sh = sh.clone();
            move || packets(sh, net)
        })?;
        for listener in [v4, v6] {
            let sh = sh.clone();
            self.spawn("accept", move || proxy::accept_loop(sh, listener))?;
        }
        sh.log.push(format!("Запущено, локальный приёмник на порту {}", sh.proxy_port));
        Ok(())
    }

    fn spawn(&mut self, name: &str, f: impl FnOnce() + Send + 'static) -> Result<(), String> {
        let t = thread::Builder::new().name(name.into()).spawn(f).map_err(|e| format!("поток {name}: {e}"))?;
        self.threads.push(t);
        Ok(())
    }

    pub fn shared(&self) -> &Shared {
        &self.shared
    }

    pub fn stop(self) {
        let sh = &self.shared;
        sh.running.store(false, Ordering::Release);
        for h in &self.handles {
            h.shutdown();
        }
        proxy::wake(sh.proxy_port);
        for (_, s) in sh.sessions.lock().unwrap().drain() {
            let _ = s.shutdown(Shutdown::Both); // сессия могла уже закрыться сама
        }
        for t in self.threads {
            if t.join().is_err() {
                sh.log.push("Поток движка завершился аварийно");
            }
        }
        sh.log.push("Остановлено");
    }
}

fn open_error(e: std::io::Error) -> String {
    let hint = match e.raw_os_error() {
        Some(5) => " — нужны права администратора",
        Some(577) | Some(1275) => " — система не загрузила драйвер WinDivert (подпись/блокировка антивирусом)",
        Some(2) => " — не найден WinDivert64.sys рядом с программой",
        _ => "",
    };
    format!("WinDivert: {e}{hint}")
}

fn socket_events(sh: Arc<Shared>, h: Arc<Handle>) {
    let mut addr = Address::default();
    let mut none = [0u8; 64]; // у событий сокетного слоя нет данных пакета
    loop {
        match h.recv(&mut none, &mut addr) {
            Ok(_) => sh.on_socket_event(addr.event(), &addr.socket()),
            Err(e) => {
                if sh.is_running() && e.raw_os_error() != Some(ERROR_NO_DATA) {
                    sh.log.push(format!("Слежение за сокетами остановлено: {e}"));
                }
                return;
            }
        }
    }
}

fn packets(sh: Arc<Shared>, h: Arc<Handle>) {
    let mut buf = vec![0u8; divert::MTU_MAX];
    let mut addr = Address::default();
    let mut udp_noted = HashSet::new();
    let mut last_sweep = Instant::now();
    let mut last_send_error: Option<Instant> = None;
    loop {
        let len = match h.recv(&mut buf, &mut addr) {
            Ok(len) => len,
            Err(e) => {
                if sh.is_running() && e.raw_os_error() != Some(ERROR_NO_DATA) {
                    sh.log.push(format!("Перехват остановлен: {e}"));
                }
                break;
            }
        };
        let p = &mut buf[..len];
        let sent = match sh.route(p, &mut udp_noted) {
            Verdict::Pass => h.send(p, &addr),
            Verdict::Drop => Ok(()),
            Verdict::Reflect => {
                addr.set_inbound();
                divert::checksums(p, &mut addr);
                h.send(p, &addr)
            }
        };
        if let Err(e) = sent {
            if last_send_error.is_none_or(|t| t.elapsed() > SEND_ERROR_LOG_EVERY) {
                sh.log.push(format!("Не удалось отправить пакет: {e}"));
                last_send_error = Some(Instant::now());
            }
        }
        if last_sweep.elapsed() > SWEEP_EVERY {
            sh.sweep();
            last_sweep = Instant::now();
        }
    }
    // Без этого необработанные пакеты копились бы в очереди и сеть системы встала бы.
    h.shutdown();
}

/// Отражённые пакеты для системы — входящие подключения к приёмнику; без разрешающего правила
/// брандмауэр Windows их режет. Правило пересоздаём, чтобы путь к exe был актуальным.
fn allow_in_firewall(log: &Log) {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return log.push(format!("Брандмауэр: не найден путь программы: {e}")),
    };
    let netsh = |args: &[&str], raw: Option<String>| {
        let mut cmd = Command::new("netsh");
        cmd.args(["advfirewall", "firewall"]).args(args).creation_flags(CREATE_NO_WINDOW);
        if let Some(raw) = raw {
            cmd.raw_arg(raw);
        }
        cmd.output()
    };
    let name = format!("name={FIREWALL_RULE}");
    // При первом запуске правила ещё нет — тогда удаление просто ничего не делает.
    let _ = netsh(&["delete", "rule", &name], None);
    let program = format!("program=\"{}\"", exe.display());
    match netsh(&["add", "rule", &name, "dir=in", "action=allow", "enable=yes", "profile=any"], Some(program)) {
        Ok(out) if out.status.success() => {}
        Ok(out) => log.push(format!(
            "Брандмауэр: правило не добавлено ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stdout).trim()
        )),
        Err(e) => log.push(format!("Брандмауэр: netsh не запустился: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[9] = TCP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[33] = flags;
        p
    }

    #[test]
    fn reflect_rewrites_ports_and_swaps_addresses() {
        let mut p = tcp_v4([10, 0, 0, 2], [1, 2, 3, 4], 50000, 443, TCP_SYN);
        let ip = Ip::parse(&p).unwrap();
        assert_eq!(ip.dst(&p), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        ip.set_port(&mut p, 2, 7777);
        ip.swap_addrs(&mut p);
        assert_eq!(&p[12..16], &[1, 2, 3, 4]);
        assert_eq!(&p[16..20], &[10, 0, 0, 2]);
        assert_eq!(ip.port(&p, 0), 50000);
        assert_eq!(ip.port(&p, 2), 7777);
    }

    #[test]
    fn non_first_fragments_are_not_parsed() {
        let mut p = tcp_v4([10, 0, 0, 2], [1, 2, 3, 4], 1, 2, 0);
        p[7] = 1; // смещение фрагмента
        assert!(Ip::parse(&p).is_none());
        assert!(Ip::parse(&p[..30]).is_none());
    }
}
