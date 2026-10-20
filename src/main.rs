#![windows_subsystem = "windows"]

use std::{
    cell::{Cell, RefCell},
    io,
    ptr::null,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
};

use windows_sys::Win32::{
    Foundation::{GlobalFree, HANDLE, HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::Gdi::{
        CreateFontIndirectW, DrawFocusRect, DrawTextW, FillRect, GetDC, GetSysColor, GetSysColorBrush, ReleaseDC,
        SelectObject, SetBkMode, SetTextColor, COLOR_BTNFACE, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT, COLOR_WINDOW,
        COLOR_WINDOWTEXT, DRAW_TEXT_FORMAT, DT_CALCRECT, DT_EDITCONTROL, DT_NOPREFIX, DT_WORDBREAK, HFONT, HGDIOBJ,
        TRANSPARENT,
    },
    System::{
        DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData},
        LibraryLoader::GetModuleHandleW,
        Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE},
        Ole::CF_UNICODETEXT,
    },
    UI::{
        Controls::{
            InitCommonControlsEx, DRAWITEMSTRUCT, ICC_LINK_CLASS, INITCOMMONCONTROLSEX, MEASUREITEMSTRUCT, NMHDR, NM_CLICK,
            NM_RETURN, ODS_FOCUS, ODS_SELECTED,
        },
        HiDpi::*,
        Input::KeyboardAndMouse::{EnableWindow, GetKeyState, VK_CONTROL},
        Shell::{
            ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
            NOTIFYICONDATAW,
        },
        WindowsAndMessaging::*,
    },
};

use little_proxy::{
    config::Config,
    engine::{Engine, Setup},
    log::Log,
    procs::Matcher,
    proxy,
};

const ID_START: i32 = 100;
const ID_CHECK: i32 = 101;
const ID_GITHUB: i32 = 102;
const ID_LOG: i32 = 103;
/// Отступ текста строки журнала от краёв, пикселей при 96 dpi.
const LOG_PAD: i32 = 2;
/// Больше строка списка с переменной высотой быть не может.
const LOG_ITEM_MAX: u32 = 255;
const GITHUB_URL: &str = "https://github.com/DiamondDen/little-proxy";
const TIMER_ID: usize = 1;
const TIMER_MS: u32 = 300;
const LOG_LINES: usize = 500;
/// Сколько символов командной строки показывать в журнале.
const CMDLINE_MAX: usize = 400;
const WM_TRAY: u32 = WM_APP + 1;
/// Повторный запуск просит уже работающую копию показать окно.
const WM_SHOW_EXISTING: u32 = WM_APP + 2;
const MENU_SHOW: usize = 1;
const MENU_TOGGLE: usize = 2;
const MENU_EXIT: usize = 3;
const MENU_COPY: usize = 4;
const MENU_COPY_ALL: usize = 5;
const MENU_SELECT_ALL: usize = 6;
/// Ответ на WM_VKEYTOITEM: клавиша обработана, список её не получит.
const VKEY_HANDLED: LRESULT = -2;
/// Ответ на WM_VKEYTOITEM: пусть список обработает клавишу сам.
const VKEY_DEFAULT: LRESULT = -1;

struct App {
    hwnd: HWND,
    icon: HICON,
    /// Значок в трее есть: только тогда окно можно прятать.
    tray_ok: bool,
    /// Подсказка «программа в трее» уже показана.
    tray_hinted: bool,
    proxy: HWND,
    rules: HWND,
    domains: HWND,
    start: HWND,
    status: HWND,
    log_box: HWND,
    log: Log,
    engine: Option<Engine>,
    /// Идёт проверка прокси; по её успеху перехват запустится с этими настройками.
    pending: Option<Pending>,
}

struct Pending {
    cfg: Config,
    setup: Setup,
    /// Внешний IP через прокси или причина, по которой прокси не ответил.
    result: Receiver<io::Result<String>>,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    /// Сообщение, которое Проводник рассылает после перезапуска: значок трея нужно вернуть.
    static TASKBAR_CREATED: Cell<u32> = const { Cell::new(0) };
    /// Текст строки, которую сейчас добавляют в журнал (для WM_MEASUREITEM).
    static LOG_ADDING: RefCell<Vec<u16>> = const { RefCell::new(Vec::new()) };
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn get_text(h: HWND) -> String {
    // SAFETY: буфер на длину текста плюс завершающий ноль.
    unsafe {
        let len = GetWindowTextLengthW(h);
        let mut buf = vec![0u16; len as usize + 1];
        let n = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32);
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

fn set_text(h: HWND, s: &str) {
    // SAFETY: строка с завершающим нулём живёт до конца вызова.
    unsafe { SetWindowTextW(h, wide(s).as_ptr()) };
}

/// Непустые строки многострочного поля без пробелов по краям.
fn lines(h: HWND) -> Vec<String> {
    get_text(h).lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect()
}

fn send(h: HWND, msg: u32, w: usize, l: isize) -> isize {
    // SAFETY: сообщения стандартных контролов с корректными аргументами.
    unsafe { SendMessageW(h, msg, w, l) }
}

/// Кладёт текст в буфер обмена.
fn set_clipboard(hwnd: HWND, text: &str) -> io::Result<()> {
    let text = wide(text);
    // SAFETY: память выделена на всю строку с нулём; после успешного SetClipboardData она
    // принадлежит системе, иначе освобождаем сами. Буфер закрывается на всех путях.
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return Err(io::Error::last_os_error());
        }
        let put = || {
            if EmptyClipboard() == 0 {
                return Err(io::Error::last_os_error());
            }
            let mem = GlobalAlloc(GMEM_MOVEABLE, text.len() * 2);
            if mem.is_null() {
                return Err(io::Error::last_os_error());
            }
            let dst = GlobalLock(mem) as *mut u16;
            if dst.is_null() {
                let e = io::Error::last_os_error();
                GlobalFree(mem);
                return Err(e);
            }
            std::ptr::copy_nonoverlapping(text.as_ptr(), dst, text.len());
            GlobalUnlock(mem);
            if SetClipboardData(CF_UNICODETEXT as u32, mem as HANDLE).is_null() {
                let e = io::Error::last_os_error();
                GlobalFree(mem);
                return Err(e);
            }
            Ok(())
        };
        let result = put();
        CloseClipboard();
        result
    }
}

const LOG_TEXT_FLAGS: DRAW_TEXT_FORMAT = DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX;

/// Прямоугольник текста строки журнала шириной `width`; отступы масштабируются с dpi.
fn log_text_rect(left: i32, top: i32, width: i32) -> RECT {
    // SAFETY: без аргументов.
    let pad = LOG_PAD * unsafe { GetDpiForSystem() } as i32 / 96;
    RECT { left: left + pad, top: top + pad / 2, right: left + width - pad, bottom: top + pad / 2 }
}

/// Добавляет строку в журнал. Высоту строки список спрашивает (WM_MEASUREITEM) посреди
/// LB_ADDSTRING, а надёжно передать туда текст можно только так — через `LOG_ADDING`.
fn add_log_line(list: HWND, line: &str) {
    LOG_ADDING.with(|t| *t.borrow_mut() = line.encode_utf16().collect());
    send(list, LB_ADDSTRING, 0, wide(line).as_ptr() as isize);
}

/// Высота добавляемой строки журнала с переносом по ширине списка.
unsafe fn measure_log_item(hwnd: HWND, mi: &mut MEASUREITEMSTRUCT) {
    let list = GetDlgItem(hwnd, ID_LOG);
    let mut client = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    GetClientRect(list, &mut client);
    let text = LOG_ADDING.with(|t| t.borrow().clone());
    let dc = GetDC(list);
    let old = SelectObject(dc, SendMessageW(list, WM_GETFONT, 0, 0) as HGDIOBJ);
    let mut rect = log_text_rect(0, 0, client.right);
    let line = DrawTextW(dc, text.as_ptr(), text.len() as i32, &mut rect, LOG_TEXT_FLAGS | DT_CALCRECT);
    SelectObject(dc, old);
    ReleaseDC(list, dc);
    let pad = rect.top * 2;
    mi.itemHeight = ((line.max(1) + pad) as u32).min(LOG_ITEM_MAX);
}

/// Рисует строку журнала с переносом; выделенные — системными цветами выделения.
unsafe fn draw_log_item(di: &DRAWITEMSTRUCT) {
    if di.itemID == u32::MAX {
        return; // пустой список: рисовать нечего
    }
    let list = di.hwndItem;
    let len = SendMessageW(list, LB_GETTEXTLEN, di.itemID as usize, 0).max(0) as usize;
    let mut buf = vec![0u16; len + 1];
    let n = SendMessageW(list, LB_GETTEXT, di.itemID as usize, buf.as_mut_ptr() as isize).max(0) as usize;
    let selected = di.itemState & ODS_SELECTED != 0;
    let (bg, fg) = if selected { (COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT) } else { (COLOR_WINDOW, COLOR_WINDOWTEXT) };
    FillRect(di.hDC, &di.rcItem, GetSysColorBrush(bg));
    SetTextColor(di.hDC, GetSysColor(fg));
    SetBkMode(di.hDC, TRANSPARENT as i32);
    let r = &di.rcItem;
    let mut rect = log_text_rect(r.left, r.top, r.right - r.left);
    rect.bottom = r.bottom;
    DrawTextW(di.hDC, buf.as_ptr(), n.min(len) as i32, &mut rect, LOG_TEXT_FLAGS);
    if di.itemState & ODS_FOCUS != 0 {
        DrawFocusRect(di.hDC, &di.rcItem);
    }
}

/// Значок в трее: добавить, обновить подсказку или убрать. `false` — оболочка отказала.
fn tray(hwnd: HWND, icon: HICON, op: u32, tip: &str) -> bool {
    // SAFETY: структура заполнена целиком, строка подсказки обрезана по размеру поля.
    unsafe {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY;
        nid.hIcon = icon;
        // szTip — 128 символов, последний оставляем под завершающий ноль.
        for (dst, src) in nid.szTip.iter_mut().zip(tip.encode_utf16().take(127)) {
            *dst = src;
        }
        Shell_NotifyIconW(op, &nid) != 0
    }
}

/// Всплывающее уведомление у значка в трее.
fn tray_balloon(hwnd: HWND, text: &str) {
    // SAFETY: структура заполнена целиком, строки обрезаны по размеру полей.
    unsafe {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO;
        for (dst, src) in nid.szInfoTitle.iter_mut().zip("little-proxy".encode_utf16().take(63)) {
            *dst = src;
        }
        for (dst, src) in nid.szInfo.iter_mut().zip(text.encode_utf16().take(255)) {
            *dst = src;
        }
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

impl App {
    /// Прячет окно в трей; при первом разе подсказывает, где программа и как её закрыть.
    fn hide_to_tray(&mut self) {
        // SAFETY: окно живо, пока жив App.
        unsafe { ShowWindow(self.hwnd, SW_HIDE) };
        if !self.tray_hinted {
            self.tray_hinted = true;
            tray_balloon(self.hwnd, "Программа работает в трее. Закрыть — правый клик по значку → «Выход».");
        }
    }

    fn restore(&self) {
        // SAFETY: окно живо, пока жив App.
        unsafe {
            ShowWindow(self.hwnd, SW_RESTORE);
            SetForegroundWindow(self.hwnd);
        }
    }

    fn tray_menu(&mut self) {
        // SAFETY: меню создаётся и уничтожается здесь же; SetForegroundWindow нужен, чтобы меню
        // закрывалось по клику мимо него.
        let cmd = unsafe {
            let menu = CreatePopupMenu();
            let toggle = if self.engine.is_some() { "Остановить" } else { "Запустить" };
            AppendMenuW(menu, MF_STRING, MENU_SHOW, wide("Открыть").as_ptr());
            AppendMenuW(menu, MF_STRING, MENU_TOGGLE, wide(toggle).as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING, MENU_EXIT, wide("Выход").as_ptr());
            let mut pt = std::mem::zeroed();
            GetCursorPos(&mut pt);
            SetForegroundWindow(self.hwnd);
            let cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, self.hwnd, null());
            DestroyMenu(menu);
            cmd as usize
        };
        match cmd {
            MENU_SHOW => self.restore(),
            MENU_TOGGLE => self.toggle(),
            // SAFETY: окно живо; WM_DESTROY остановит движок и уберёт значок.
            MENU_EXIT => unsafe {
                DestroyWindow(self.hwnd);
            },
            _ => {}
        }
    }

    fn open_github(&self) {
        // SAFETY: строки с завершающим нулём живут до конца вызова.
        let rc = unsafe {
            ShellExecuteW(self.hwnd, wide("open").as_ptr(), wide(GITHUB_URL).as_ptr(), null(), null(), SW_SHOWNORMAL)
        };
        // Значение не больше 32 — код ошибки ShellExecute.
        if rc as usize <= 32 {
            self.log.push(format!("Не удалось открыть {GITHUB_URL}: код {}", rc as usize));
        }
    }

    fn read_config(&self) -> Config {
        Config { proxy: get_text(self.proxy).trim().into(), rules: lines(self.rules), domains: lines(self.domains) }
    }

    fn show_config(&self, cfg: &Config) {
        set_text(self.proxy, &cfg.proxy);
        set_text(self.rules, &cfg.rules.join("\r\n"));
        set_text(self.domains, &cfg.domains.join("\r\n"));
    }

    /// Сверяет запущенные процессы с правилами из поля и выводит совпадения в журнал.
    fn check(&mut self) {
        let rules = self.read_config().rules;
        let found = Matcher::new(&rules).and_then(|m| m.running().map_err(|e| format!("список процессов: {e}")));
        match found {
            Err(e) => self.log.push(format!("Проверка: {e}")),
            Ok((found, unreadable)) => {
                if found.is_empty() {
                    self.log.push("Проверка: под правила не подходит ни один запущенный процесс");
                } else {
                    self.log.push(format!("Проверка: подходят {} процесс(ов):", found.len()));
                    for p in &found {
                        // Командная строка различает процессы с одним exe (например, вкладки
                        // Electron); если её не прочитать — хотя бы путь.
                        let detail = p.command_line.as_deref().unwrap_or(&p.path);
                        let detail: String = detail.chars().take(CMDLINE_MAX).collect();
                        self.log.push(format!("    {}  ·  PID {}  ·  {detail}", p.name(), p.pid));
                    }
                }
                if unreadable > 0 {
                    self.log.push(format!("Проверка: путь не прочитан у {unreadable} процесс(ов) — они не проверены"));
                }
            }
        }
        self.tick();
    }

    fn toggle(&mut self) {
        if let Some(engine) = self.engine.take() {
            engine.stop();
        } else if self.pending.is_none() {
            self.check_proxy();
        }
        self.update_controls();
        self.tick();
    }

    /// Запуск начинается с проверки прокси в фоне: трафик заворачиваем, только если прокси
    /// отвечает. Результат забирает `tick`.
    fn check_proxy(&mut self) {
        let cfg = self.read_config();
        let setup = match Setup::new(&cfg) {
            Ok(setup) => setup,
            Err(e) => return self.log.push(format!("Не запущено: {e}")),
        };
        let (tx, rx) = mpsc::channel();
        let up = setup.upstream().clone();
        // Окно могли закрыть до конца проверки — тогда результат никому не нужен.
        let spawned = thread::Builder::new().name("proxy-check".into()).spawn(move || drop(tx.send(proxy::external_ip(&up))));
        match spawned {
            Ok(_) => {
                self.log.push("Проверка прокси…");
                self.pending = Some(Pending { cfg, setup, result: rx });
            }
            Err(e) => self.log.push(format!("Не запущено: поток проверки прокси: {e}")),
        }
    }

    /// Результат проверки прокси, если он уже готов.
    fn poll_proxy_check(&mut self) {
        let Some(p) = &self.pending else { return };
        let result = match p.result.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(io::Error::other("поток проверки завершился без ответа")),
        };
        let Some(Pending { cfg, setup, .. }) = self.pending.take() else { return };
        match result {
            Err(e) => self.log.push(format!("Прокси не отвечает, перехват не запущен: {e}")),
            Ok(ip) => {
                self.log.push(format!("Прокси работает, внешний IP: {ip}"));
                match Engine::start(setup, self.log.clone()) {
                    Ok(engine) => {
                        if let Err(e) = cfg.save() {
                            self.log.push(format!("Настройки не сохранены: {e}"));
                        }
                        self.engine = Some(engine);
                    }
                    Err(e) => self.log.push(format!("Не запущено: {e}")),
                }
            }
        }
        self.update_controls();
    }

    fn update_controls(&self) {
        let (running, checking) = (self.engine.is_some(), self.pending.is_some());
        // SAFETY: хэндлы контролов живут вместе с окном.
        unsafe {
            for h in [self.proxy, self.rules, self.domains] {
                EnableWindow(h, (!running && !checking) as i32);
            }
            EnableWindow(self.start, (!checking) as i32);
        }
        set_text(self.start, if running { "Остановить" } else { "Запустить" });
    }

    /// Номера выделенных строк журнала.
    fn log_selection(&self) -> Vec<usize> {
        let count = send(self.log_box, LB_GETSELCOUNT, 0, 0).max(0) as usize;
        let mut items = vec![0i32; count];
        let got = send(self.log_box, LB_GETSELITEMS, count, items.as_mut_ptr() as isize).max(0) as usize;
        items.truncate(got);
        items.into_iter().map(|i| i as usize).collect()
    }

    fn log_line(&self, i: usize) -> String {
        let len = send(self.log_box, LB_GETTEXTLEN, i, 0).max(0) as usize;
        let mut buf = vec![0u16; len + 1];
        let n = send(self.log_box, LB_GETTEXT, i, buf.as_mut_ptr() as isize).max(0) as usize;
        String::from_utf16_lossy(&buf[..n.min(len)])
    }

    /// Копирует выделенные строки журнала (`all` — весь журнал) в буфер обмена.
    fn copy_log(&self, all: bool) {
        let items = if all {
            (0..send(self.log_box, LB_GETCOUNT, 0, 0).max(0) as usize).collect()
        } else {
            self.log_selection()
        };
        if items.is_empty() {
            return;
        }
        let text: Vec<String> = items.into_iter().map(|i| self.log_line(i)).collect();
        if let Err(e) = set_clipboard(self.hwnd, &text.join("\r\n")) {
            self.log.push(format!("Не удалось скопировать журнал: {e}"));
        }
    }

    fn select_all_log(&self) {
        let count = send(self.log_box, LB_GETCOUNT, 0, 0);
        if count > 0 {
            send(self.log_box, LB_SELITEMRANGEEX, 0, count - 1);
        }
    }

    /// Ctrl+C и Ctrl+A в журнале; остальные клавиши — списку.
    fn log_key(&self, vkey: u32) -> LRESULT {
        // SAFETY: читаем состояние клавиатуры текущего потока.
        let ctrl = unsafe { GetKeyState(VK_CONTROL as i32) } < 0;
        match (ctrl, char::from_u32(vkey)) {
            (true, Some('C')) => self.copy_log(false),
            (true, Some('A')) => self.select_all_log(),
            _ => return VKEY_DEFAULT,
        }
        VKEY_HANDLED
    }

    /// Меню журнала по правому клику или клавише меню (`l == -1`).
    fn log_menu(&self, l: LPARAM) {
        // SAFETY: меню создаётся и уничтожается здесь же.
        let cmd = unsafe {
            let menu = CreatePopupMenu();
            let copy_flags = if self.log_selection().is_empty() { MF_STRING | MF_GRAYED } else { MF_STRING };
            AppendMenuW(menu, copy_flags, MENU_COPY, wide("Копировать\tCtrl+C").as_ptr());
            AppendMenuW(menu, MF_STRING, MENU_COPY_ALL, wide("Копировать всё").as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING, MENU_SELECT_ALL, wide("Выделить всё\tCtrl+A").as_ptr());
            let (mut x, mut y) = ((l & 0xFFFF) as i16 as i32, ((l >> 16) & 0xFFFF) as i16 as i32);
            if l == -1 {
                let mut pt = std::mem::zeroed();
                GetCursorPos(&mut pt);
                (x, y) = (pt.x, pt.y);
            }
            let cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, x, y, 0, self.hwnd, null());
            DestroyMenu(menu);
            cmd as usize
        };
        match cmd {
            MENU_COPY => self.copy_log(false),
            MENU_COPY_ALL => self.copy_log(true),
            MENU_SELECT_ALL => self.select_all_log(),
            _ => {}
        }
    }

    fn log_height(&self) -> i32 {
        let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        // SAFETY: хэндл журнала жив вместе с окном.
        unsafe { GetClientRect(self.log_box, &mut rect) };
        rect.bottom - rect.top
    }

    /// Видна ли последняя строка журнала целиком (строки разной высоты — из-за переноса).
    fn log_at_bottom(&self) -> bool {
        let count = send(self.log_box, LB_GETCOUNT, 0, 0);
        if count <= 0 {
            return true;
        }
        let mut item = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        send(self.log_box, LB_GETITEMRECT, (count - 1) as usize, &mut item as *mut RECT as isize);
        item.bottom <= self.log_height()
    }

    /// Прокручивает так, чтобы последние строки заполнили журнал до низа.
    fn scroll_log_to_end(&self) {
        let count = send(self.log_box, LB_GETCOUNT, 0, 0).max(0) as usize;
        let height = self.log_height() as isize;
        let (mut top, mut used) = (count, 0);
        while top > 0 {
            let h = send(self.log_box, LB_GETITEMHEIGHT, top - 1, 0);
            if used + h > height {
                break;
            }
            used += h;
            top -= 1;
        }
        // Последняя строка выше окна журнала — показываем хотя бы её начало.
        send(self.log_box, LB_SETTOPINDEX, top.min(count.saturating_sub(1)), 0);
    }

    fn tick(&mut self) {
        self.poll_proxy_check();
        let lines = self.log.drain();
        if !lines.is_empty() {
            // Докручиваем вниз, только если пользователь и так внизу — иначе не мешаем читать.
            let follow = self.log_at_bottom();
            for line in lines {
                add_log_line(self.log_box, &line);
            }
            let count = send(self.log_box, LB_GETCOUNT, 0, 0).max(0) as usize;
            for _ in LOG_LINES..count {
                send(self.log_box, LB_DELETESTRING, 0, 0);
            }
            if follow {
                self.scroll_log_to_end();
            }
        }
        let status = match &self.engine {
            Some(e) => format!("Работает · сессий: {}", e.shared().session_count()),
            None if self.pending.is_some() => "Проверка прокси…".into(),
            None => "Остановлено".into(),
        };
        if get_text(self.status) != status {
            set_text(self.status, &status);
            tray(self.hwnd, self.icon, NIM_MODIFY, &format!("little-proxy — {status}"));
        }
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    // Контролы шлют родителю уведомления посреди наших же SendMessage — тогда состояние уже
    // занято, и сообщение уходит в обработку по умолчанию.
    // Журнал рисуем сами (перенос строк). Эти сообщения приходят посреди LB_ADDSTRING, когда
    // состояние окна занято, — поэтому обходимся без него.
    match msg {
        WM_MEASUREITEM if (*(l as *const MEASUREITEMSTRUCT)).CtlID == ID_LOG as u32 => {
            measure_log_item(hwnd, &mut *(l as *mut MEASUREITEMSTRUCT));
            return 1;
        }
        WM_DRAWITEM if (*(l as *const DRAWITEMSTRUCT)).CtlID == ID_LOG as u32 => {
            draw_log_item(&*(l as *const DRAWITEMSTRUCT));
            return 1;
        }
        _ => {}
    }
    let handled = APP.with(|app| {
        let mut app = app.try_borrow_mut().ok()?;
        let app = app.as_mut()?;
        match msg {
            WM_COMMAND if (w >> 16) as u32 == BN_CLICKED => match (w & 0xFFFF) as i32 {
                ID_START => app.toggle(),
                ID_CHECK => app.check(),
                _ => return None,
            },
            WM_NOTIFY => {
                let hdr = &*(l as *const NMHDR);
                if hdr.idFrom != ID_GITHUB as usize || !matches!(hdr.code, NM_CLICK | NM_RETURN) {
                    return None;
                }
                app.open_github();
            }
            WM_VKEYTOITEM if l as HWND == app.log_box => return Some(app.log_key((w & 0xFFFF) as u32)),
            WM_CONTEXTMENU if w as HWND == app.log_box => app.log_menu(l),
            WM_TIMER => app.tick(),
            // Свёрнутое окно прячем в трей. Крестик при работающем перехвате тоже прячет (выход —
            // из меню значка), а при остановленном — закрывает программу.
            WM_SIZE if w as u32 == SIZE_MINIMIZED && app.tray_ok => app.hide_to_tray(),
            WM_CLOSE if app.tray_ok && app.engine.is_some() => app.hide_to_tray(),
            WM_TRAY => match l as u32 & 0xFFFF {
                WM_LBUTTONUP => app.restore(),
                WM_RBUTTONUP => app.tray_menu(),
                _ => {}
            },
            WM_SHOW_EXISTING => app.restore(),
            // Проводник перезапустился — значок нужно добавить заново.
            m if m != 0 && m == TASKBAR_CREATED.get() => {
                app.tray_ok = tray(hwnd, app.icon, NIM_ADD, &format!("little-proxy — {}", get_text(app.status)));
                if !app.tray_ok {
                    app.log.push("Не удалось вернуть значок в трей после перезапуска Проводника");
                }
            }
            WM_DESTROY => {
                if let Some(engine) = app.engine.take() {
                    engine.stop();
                }
                // Значка может уже не быть (Проводник упал) — удалять тогда нечего.
                tray(hwnd, app.icon, NIM_DELETE, "");
                PostQuitMessage(0);
            }
            _ => return None,
        }
        Some(0)
    });
    handled.unwrap_or_else(|| DefWindowProcW(hwnd, msg, w, l))
}

fn main() {
    // SAFETY: последовательность вызовов Win32 из единственного потока GUI.
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE);
        let dpi = GetDpiForSystem() as i32;
        let s = |v: i32| v * dpi / 96;
        let instance = GetModuleHandleW(null());
        let class = wide("LittleProxy");
        // Одна копия на пользователя: вторая только показывает окно первой (оно может быть в трее).
        let existing = FindWindowW(class.as_ptr(), null());
        if !existing.is_null() {
            AllowSetForegroundWindow(ASFW_ANY);
            PostMessageW(existing, WM_SHOW_EXISTING, 0, 0);
            return;
        }
        let icon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
        TASKBAR_CREATED.set(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()));
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: instance,
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hIcon: icon,
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassW(&wc);

        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        // Без этого SysLink (ссылка на GitHub) не создастся.
        let icc = INITCOMMONCONTROLSEX { dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32, dwICC: ICC_LINK_CLASS };
        InitCommonControlsEx(&icc);
        let mut rect = RECT { left: 0, top: 0, right: s(480), bottom: s(540) };
        AdjustWindowRectEx(&mut rect, style, 0, WS_EX_CONTROLPARENT);
        let hwnd = CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class.as_ptr(),
            wide("little-proxy").as_ptr(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rect.right - rect.left,
            rect.bottom - rect.top,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            null(),
        );

        let mut ncm: NONCLIENTMETRICSW = std::mem::zeroed();
        ncm.cbSize = std::mem::size_of::<NONCLIENTMETRICSW>() as u32;
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, ncm.cbSize, (&mut ncm as *mut NONCLIENTMETRICSW).cast(), 0);
        let font: HFONT = CreateFontIndirectW(&ncm.lfMessageFont);

        let ctl = |class: &str, text: &str, style: i32, ex: u32, x: i32, y: i32, w: i32, h: i32, id: i32| {
            let h = CreateWindowExW(
                ex,
                wide(class).as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE | style as u32,
                s(x),
                s(y),
                s(w),
                s(h),
                hwnd,
                id as usize as HMENU,
                instance,
                null(),
            );
            SendMessageW(h, WM_SETFONT, font as usize, 1);
            h
        };
        let label = |text: &str, x, y, w| ctl("STATIC", text, 0, 0, x, y + 3, w, 20, 0);
        let edit = |style: i32, x, y, w, h| {
            ctl("EDIT", "", ES_AUTOHSCROLL | WS_TABSTOP as i32 | style, WS_EX_CLIENTEDGE, x, y, w, h, 0)
        };

        label("Прокси", 12, 12, 60);
        let proxy = edit(0, 76, 12, 392, 23);
        label("socks5://логин:пароль@хост:порт или http://…; логин и пароль необязательны", 76, 38, 392);
        label("Процессы — регулярные выражения по полному пути exe, по одному в строке:", 12, 68, 456);
        let multiline = ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL as i32;
        let rules = edit(multiline, 12, 92, 456, 64);
        label("Список доменов, DoH/DoT - будет заблокирован", 12, 166, 456);
        let domains = edit(multiline, 12, 190, 456, 64);
        let start = ctl("BUTTON", "Запустить", BS_PUSHBUTTON | WS_TABSTOP as i32, 0, 12, 264, 120, 28, ID_START);
        ctl("BUTTON", "Проверить", BS_PUSHBUTTON | WS_TABSTOP as i32, 0, 140, 264, 110, 28, ID_CHECK);
        let status = label("", 260, 268, 208);
        // Своя отрисовка строк — ради переноса. Полоса прокрутки видна всегда: ширина текста,
        // по которой считается перенос, не должна меняться с её появлением.
        let log_style = LBS_NOINTEGRALHEIGHT | LBS_EXTENDEDSEL | LBS_WANTKEYBOARDINPUT | LBS_OWNERDRAWVARIABLE | LBS_HASSTRINGS | LBS_DISABLENOSCROLL;
        let log_box = ctl("LISTBOX", "", log_style | WS_TABSTOP as i32 | WS_VSCROLL as i32, WS_EX_CLIENTEDGE, 12, 302, 456, 204, ID_LOG);
        let link = format!("<a>{}</a>", GITHUB_URL.trim_start_matches("https://"));
        ctl("SysLink", &link, WS_TABSTOP as i32, 0, 12, 514, 456, 20, ID_GITHUB);

        let tray_ok = tray(hwnd, icon, NIM_ADD, "little-proxy — Остановлено");
        let app = App { hwnd, icon, tray_ok, tray_hinted: false, proxy, rules, domains, start, status, log_box, log: Log::default(), engine: None, pending: None };
        match Config::load() {
            Ok(cfg) => app.show_config(&cfg.unwrap_or_default()),
            Err(e) => {
                app.log.push(format!("Настройки не прочитаны: {e}"));
                app.show_config(&Config::default());
            }
        }
        app.log.push("Укажите прокси и правила, затем «Запустить». Нужны права администратора.");
        if !tray_ok {
            app.log.push("Не удалось добавить значок в трей — окно будет сворачиваться и закрываться как обычно");
        }
        APP.with(|a| *a.borrow_mut() = Some(app));
        APP.with(|a| a.borrow_mut().as_mut().map(App::tick));
        SetTimer(hwnd, TIMER_ID, TIMER_MS, None);
        ShowWindow(hwnd, SW_SHOW);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
