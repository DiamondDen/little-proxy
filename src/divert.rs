//! Минимальная обёртка над WinDivert 2.2. Библиотека и драйвер вшиты в exe и при первом запуске
//! распаковываются рядом с ним: DLL грузится динамически, поэтому exe стартует и без неё.

use std::{ffi::c_void, fs, io, mem, path::Path, sync::OnceLock};

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    System::LibraryLoader::{GetProcAddress, LoadLibraryW},
};

static DLL: &[u8] = include_bytes!("../vendor/windivert/WinDivert.dll");
static SYS: &[u8] = include_bytes!("../vendor/windivert/WinDivert64.sys");

/// Имя службы, под которой WinDivert 2.x регистрирует свой драйвер.
pub const SERVICE: &str = "WinDivert";
/// Приоритет наших хэндлов. Другие программы на WinDivert (zapret, GoodbyeDPI) обычно открывают
/// свои с приоритетом 0; при равных приоритетах порядок не определён, и пакеты, которые мы
/// возвращаем в сеть, могут не дойти до их хэндлов (или наоборот). С более высоким приоритетом
/// пакет сначала проходит через нас, а пропущенный без изменений — дальше к ним.
const PRIORITY: i16 = 1000;
pub const LAYER_NETWORK: u32 = 0;
pub const LAYER_SOCKET: u32 = 3;
pub const FLAG_SNIFF: u64 = 0x1;
pub const FLAG_RECV_ONLY: u64 = 0x4;
pub const EVENT_BIND: u8 = 3;
pub const EVENT_CONNECT: u8 = 4;
pub const EVENT_LISTEN: u8 = 5;
pub const EVENT_ACCEPT: u8 = 6;
pub const EVENT_CLOSE: u8 = 7;
/// Максимальный размер пакета, который может отдать WinDivert.
pub const MTU_MAX: usize = 40 + 0xFFFF;
const SHUTDOWN_BOTH: u32 = 3;
const OUTBOUND_BIT: u32 = 1 << 17;

/// `WINDIVERT_ADDRESS`: битовые поля Layer/Event/флаги упакованы в `flags`, данные слоя — в `data`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    _timestamp: i64,
    flags: u32,
    _reserved: u32,
    data: [u64; 8],
}

/// `WINDIVERT_DATA_SOCKET`: порты в порядке байт хоста, протокол — номер IP-протокола.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketData {
    _endpoint_id: u64,
    _parent_endpoint_id: u64,
    pub process_id: u32,
    _local_addr: [u32; 4],
    _remote_addr: [u32; 4],
    pub local_port: u16,
    _remote_port: u16,
    pub protocol: u8,
}

const _: () = assert!(mem::size_of::<Address>() == 80);
const _: () = assert!(mem::size_of::<SocketData>() <= 64);

impl Default for Address {
    fn default() -> Self {
        // SAFETY: структура из целых чисел, нули — допустимое значение.
        unsafe { mem::zeroed() }
    }
}

impl Address {
    pub fn event(&self) -> u8 {
        (self.flags >> 8) as u8
    }

    pub fn set_inbound(&mut self) {
        self.flags &= !OUTBOUND_BIT;
    }

    pub fn socket(&self) -> SocketData {
        // SAFETY: данные слоя занимают 64 байта, SocketData помещается в них (проверено выше).
        unsafe { (self.data.as_ptr() as *const SocketData).read() }
    }
}

type Proc = unsafe extern "system" fn() -> isize;
type OpenFn = unsafe extern "C" fn(*const u8, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "C" fn(HANDLE, u32) -> i32;
type CloseFn = unsafe extern "C" fn(HANDLE) -> i32;
type ChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

struct Api {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    checksums: ChecksumsFn,
}

static API: OnceLock<Api> = OnceLock::new();

fn api() -> &'static Api {
    API.get().expect("WinDivert не загружен: сначала вызовите divert::load()")
}

/// Распаковывает WinDivert рядом с exe (если файлов нет или они другие) и загружает DLL.
pub fn load() -> io::Result<()> {
    if API.get().is_some() {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| io::Error::other("не найден каталог программы"))?;
    extract(dir, "WinDivert64.sys", SYS)?;
    let dll = extract(dir, "WinDivert.dll", DLL)?;
    let wide: Vec<u16> = dll.as_os_str().encode_wide_z();
    // SAFETY: путь — корректная строка с завершающим нулём.
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    let sym = |name: &[u8]| {
        // SAFETY: имя с завершающим нулём, модуль загружен.
        unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or_else(|| {
            io::Error::other(format!("в WinDivert.dll нет {}", String::from_utf8_lossy(&name[..name.len() - 1])))
        })
    };
    // SAFETY: сигнатуры соответствуют windivert.h версии 2.2.
    let api = unsafe {
        Api {
            open: mem::transmute::<Proc, OpenFn>(sym(b"WinDivertOpen\0")?),
            recv: mem::transmute::<Proc, RecvFn>(sym(b"WinDivertRecv\0")?),
            send: mem::transmute::<Proc, SendFn>(sym(b"WinDivertSend\0")?),
            shutdown: mem::transmute::<Proc, ShutdownFn>(sym(b"WinDivertShutdown\0")?),
            close: mem::transmute::<Proc, CloseFn>(sym(b"WinDivertClose\0")?),
            checksums: mem::transmute::<Proc, ChecksumsFn>(sym(b"WinDivertHelperCalcChecksums\0")?),
        }
    };
    let _ = API.set(api); // гонки нет: загрузка идёт только из потока GUI
    Ok(())
}

fn extract(dir: &Path, name: &str, data: &[u8]) -> io::Result<std::path::PathBuf> {
    let path = dir.join(name);
    let same = fs::read(&path).is_ok_and(|current| current == data);
    if !same {
        fs::write(&path, data).map_err(|e| io::Error::new(e.kind(), format!("запись {}: {e}", path.display())))?;
    }
    Ok(path)
}

trait EncodeWideZ {
    fn encode_wide_z(&self) -> Vec<u16>;
}

impl EncodeWideZ for std::ffi::OsStr {
    fn encode_wide_z(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain([0]).collect()
    }
}

/// Пересчитывает контрольные суммы IP/TCP/UDP изменённого пакета.
pub fn checksums(packet: &mut [u8], addr: &mut Address) {
    // SAFETY: буфер и адрес валидны на время вызова.
    unsafe { (api().checksums)(packet.as_mut_ptr().cast(), packet.len() as u32, addr, 0) };
}

pub struct Handle(HANDLE);

// SAFETY: хэндл WinDivert допускает Recv/Send/Shutdown из разных потоков.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn open(filter: &str, layer: u32, flags: u64) -> io::Result<Handle> {
        let filter = format!("{filter}\0");
        // SAFETY: фильтр — строка с завершающим нулём.
        let h = unsafe { (api().open)(filter.as_ptr(), layer, PRIORITY, flags) };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Handle(h))
    }

    pub fn recv(&self, buf: &mut [u8], addr: &mut Address) -> io::Result<usize> {
        let mut len = 0u32;
        // SAFETY: буфер и адрес валидны на время вызова.
        let ok = unsafe { (api().recv)(self.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut len, addr) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(len as usize)
    }

    pub fn send(&self, packet: &[u8], addr: &Address) -> io::Result<()> {
        // SAFETY: буфер и адрес валидны на время вызова.
        let ok = unsafe { (api().send)(self.0, packet.as_ptr().cast(), packet.len() as u32, std::ptr::null_mut(), addr) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Прерывает ожидающий `recv` и прекращает перехват — пакеты снова идут мимо нас.
    pub fn shutdown(&self) {
        // SAFETY: хэндл жив, пока жив self.
        unsafe { (api().shutdown)(self.0, SHUTDOWN_BOTH) };
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: хэндл открыт в open() и закрывается ровно один раз.
        unsafe { (api().close)(self.0) };
    }
}
