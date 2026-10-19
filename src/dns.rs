//! Разбор ответов DNS и сопоставление имён с доменами из правил.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// Предел переходов по указателям сжатия имени: защита от зацикленных пакетов.
const NAME_JUMPS_MAX: usize = 64;

/// Публичные серверы DoH, к которым браузеры и Windows подключаются по IP без запроса DNS.
pub const DOH_IPS: [IpAddr; 18] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9)),
    IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
    IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
    IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)),
    IpAddr::V4(Ipv4Addr::new(94, 140, 15, 15)),
    IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(77, 88, 8, 1)),
];

/// Имена серверов DoH из настроек браузеров: их адреса узнаём из ответов DNS.
pub const DOH_HOSTS: &[&str] = &[
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "doh.xfinity.com",
    "doh.dns.sb",
    "dns.yandex.net",
    "dns.controld.com",
];

/// Список доменов; каждый совпадает и с собой, и со своими поддоменами.
pub struct Domains(Vec<String>);

impl Domains {
    /// Без учёта регистра; `*.` в начале и точки по краям отбрасываются. Ошибка называет строку.
    pub fn new<S: AsRef<str>>(list: &[S]) -> Result<Domains, String> {
        list.iter()
            .map(|raw| {
                let raw = raw.as_ref();
                let d = raw.trim().trim_start_matches("*.").trim_matches('.').to_ascii_lowercase();
                let label_ok = |l: &str| {
                    !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                };
                if d.split('.').all(label_ok) {
                    Ok(d)
                } else {
                    Err(format!("домен «{raw}»: нужно имя вида example.com (национальные — в виде xn--…)"))
                }
            })
            .collect::<Result<_, _>>()
            .map(Domains)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn matches(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').as_bytes();
        self.0.iter().any(|d| {
            let d = d.as_bytes();
            match name.len().checked_sub(d.len()) {
                Some(0) => name.eq_ignore_ascii_case(d),
                Some(at) => name[at - 1] == b'.' && name[at..].eq_ignore_ascii_case(d),
                None => false,
            }
        })
    }
}

/// Успешный ответ DNS: имя из вопроса и адреса из записей A/AAAA (вместе с концом цепочки CNAME)
/// с их TTL в секундах.
pub struct Answer {
    pub name: String,
    pub addrs: Vec<(IpAddr, u32)>,
}

/// `None` — не ответ, ответ с ошибкой, не один вопрос или пакет повреждён.
pub fn parse_response(msg: &[u8]) -> Option<Answer> {
    let mut r = Cursor { msg, at: 0 };
    r.skip(2)?; // ID
    let flags = r.u16()?;
    if flags & 0x8000 == 0 || flags & 0x000F != 0 {
        return None; // запрос, а не ответ, или RCODE ошибки
    }
    let (questions, answers) = (r.u16()?, r.u16()?);
    r.skip(4)?; // NSCOUNT, ARCOUNT
    if questions != 1 {
        return None;
    }
    let name = r.name()?;
    r.skip(4)?; // QTYPE, QCLASS
    let mut addrs = Vec::new();
    for _ in 0..answers {
        r.skip_name()?;
        let (kind, class, ttl) = (r.u16()?, r.u16()?, r.u32()?);
        let len = r.u16()? as usize;
        let data = r.take(len)?;
        let addr = match (kind, class) {
            (TYPE_A, CLASS_IN) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?)),
            (TYPE_AAAA, CLASS_IN) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)),
            _ => continue,
        };
        addrs.push((addr, ttl));
    }
    Some(Answer { name, addrs })
}

/// Чтение с абсолютной позицией: указатели сжатия имён ссылаются на начало сообщения.
struct Cursor<'a> {
    msg: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.msg.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
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
    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn skip_name(&mut self) -> Option<()> {
        loop {
            let len = self.u8()?;
            match len & 0xC0 {
                0 if len == 0 => return Some(()),
                0 => self.skip(len as usize)?,
                0xC0 => return self.skip(1), // указатель завершает имя
                _ => return None,
            }
        }
    }

    /// Имя в нижнем регистре, без завершающей точки; указатели сжатия разворачиваются.
    fn name(&mut self) -> Option<String> {
        let mut out = String::new();
        let mut at = self.at;
        // Где продолжить чтение после имени: сразу за первым указателем, если он был.
        let mut resume = None;
        for _ in 0..NAME_JUMPS_MAX {
            loop {
                let len = *self.msg.get(at)? as usize;
                match len & 0xC0 {
                    0 if len == 0 => {
                        self.at = resume.unwrap_or(at + 1);
                        return Some(out);
                    }
                    0 => {
                        let label = std::str::from_utf8(self.msg.get(at + 1..at + 1 + len)?).ok()?;
                        if !out.is_empty() {
                            out.push('.');
                        }
                        out.push_str(&label.to_ascii_lowercase());
                        at += 1 + len;
                    }
                    0xC0 => {
                        resume.get_or_insert(at + 2);
                        at = (len & 0x3F) << 8 | *self.msg.get(at + 1)? as usize;
                        break;
                    }
                    _ => return None,
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    fn record(owner: &[u8], kind: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut r = owner.to_vec();
        r.extend_from_slice(&kind.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
        r
    }

    /// Ответ на `WWW.Example.com A`: CNAME на cdn.example.net и его адрес, имена сжаты.
    fn response(flags: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34];
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 3, 0, 0, 0, 0]);
        m.extend_from_slice(&name(&["WWW", "Example", "com"])); // с 12-го байта
        m.extend_from_slice(&[0, 1, 0, 1]);
        let cname_at = m.len();
        let mut target = name(&["cdn", "example", "net"]);
        m.extend_from_slice(&record(&[0xC0, 12], 5, 300, &target));
        let target_at = (cname_at + 12) as u8;
        target = vec![0xC0, target_at];
        m.extend_from_slice(&record(&target, TYPE_A, 60, &[93, 184, 216, 34]));
        m.extend_from_slice(&record(&target, TYPE_AAAA, 7200, &[0x26, 0x06, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        m
    }

    #[test]
    fn response_yields_question_and_addresses() {
        let a = parse_response(&response(0x8180)).unwrap();
        assert_eq!(a.name, "www.example.com");
        assert_eq!(a.addrs.len(), 2);
        assert_eq!(a.addrs[0], (IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 60));
        assert_eq!(a.addrs[1].0, "2606:2800::1".parse::<IpAddr>().unwrap());
        assert_eq!(a.addrs[1].1, 7200);
    }

    #[test]
    fn queries_errors_and_truncated_packets_are_ignored() {
        assert!(parse_response(&response(0x0100)).is_none()); // запрос
        assert!(parse_response(&response(0x8183)).is_none()); // NXDOMAIN
        let full = response(0x8180);
        assert!(parse_response(&full[..full.len() - 3]).is_none());
        let mut looped = full.clone();
        looped[12..14].copy_from_slice(&[0xC0, 12]); // имя вопроса указывает само на себя
        assert!(parse_response(&looped).is_none());
    }

    #[test]
    fn domains_match_themselves_and_subdomains() {
        let d = Domains::new(&["Example.com", "*.youtube.com.", "x.io"]).unwrap();
        assert!(d.matches("example.com"));
        assert!(d.matches("WWW.EXAMPLE.COM."));
        assert!(d.matches("youtube.com"));
        assert!(d.matches("rr1.googlevideo.youtube.com"));
        assert!(!d.matches("notexample.com"));
        assert!(!d.matches("example.com.evil"));
        assert!(!d.matches("io"));
        assert!(!d.matches("ьx.io"));
    }

    #[test]
    fn bad_domains_are_rejected_with_their_text() {
        for bad in ["", "exa mple.com", "пример.рф", "a..b", "https://example.com"] {
            let e = Domains::new(&[bad]).err().unwrap();
            assert!(e.contains(bad), "{e}");
        }
        assert!(DOH_HOSTS.iter().all(|h| Domains::new(&[h]).is_ok()));
    }
}
