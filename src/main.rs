#![windows_subsystem = "windows"]

use std::{
    cell::{Cell, RefCell},
    io,
    ptr::null,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
};

use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::Gdi::{CreateFontIndirectW, GetSysColorBrush, COLOR_BTNFACE, HFONT},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Controls::{InitCommonControlsEx, ICC_LINK_CLASS, INITCOMMONCONTROLSEX, NMHDR, NM_CLICK, NM_RETURN},
        HiDpi::*,
        Input::KeyboardAndMouse::EnableWindow,
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

    /// Видна ли последняя строка журнала.
    fn log_at_bottom(&self) -> bool {
        let count = send(self.log_box, LB_GETCOUNT, 0, 0);
        let top = send(self.log_box, LB_GETTOPINDEX, 0, 0);
        let item = send(self.log_box, LB_GETITEMHEIGHT, 0, 0).max(1);
        let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        // SAFETY: хэндл журнала жив вместе с окном.
        unsafe { GetClientRect(self.log_box, &mut rect) };
        let visible = (rect.bottom - rect.top) as isize / item;
        top + visible >= count
    }

    fn tick(&mut self) {
        self.poll_proxy_check();
        let lines = self.log.drain();
        if !lines.is_empty() {
            // Докручиваем вниз, только если пользователь и так внизу — иначе не мешаем читать.
            let follow = self.log_at_bottom();
            for line in lines {
                send(self.log_box, LB_ADDSTRING, 0, wide(&line).as_ptr() as isize);
            }
            let count = send(self.log_box, LB_GETCOUNT, 0, 0).max(0) as usize;
            for _ in LOG_LINES..count {
                send(self.log_box, LB_DELETESTRING, 0, 0);
            }
            if follow {
                send(self.log_box, LB_SETTOPINDEX, count.min(LOG_LINES).saturating_sub(1), 0);
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
    let handled = APP.with(|app| {
        let Ok(mut app) = app.try_borrow_mut() else { return false };
        let Some(app) = app.as_mut() else { return false };
        match msg {
            WM_COMMAND if (w >> 16) as u32 == BN_CLICKED => match (w & 0xFFFF) as i32 {
                ID_START => app.toggle(),
                ID_CHECK => app.check(),
                _ => return false,
            },
            WM_NOTIFY => {
                let hdr = &*(l as *const NMHDR);
                if hdr.idFrom != ID_GITHUB as usize || !matches!(hdr.code, NM_CLICK | NM_RETURN) {
                    return false;
                }
                app.open_github();
            }
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
            _ => return false,
        }
        true
    });
    if handled { 0 } else { DefWindowProcW(hwnd, msg, w, l) }
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
        let log_box =
            ctl("LISTBOX", "", LBS_NOINTEGRALHEIGHT | LBS_NOSEL | WS_VSCROLL as i32 | WS_HSCROLL as i32, WS_EX_CLIENTEDGE, 12, 302, 456, 204, 0);
        SendMessageW(log_box, LB_SETHORIZONTALEXTENT, s(1200) as usize, 0);
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
