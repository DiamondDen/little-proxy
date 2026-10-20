//! Службы Windows: в каком процессе работает служба и включение отключённой.

use std::{io, mem, ptr};

use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx,
    QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CHANGE_CONFIG,
    SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_STATUS_PROCESS,
};

/// Службы с таким именем нет.
pub const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
/// Служба помечена на удаление, но её ещё держит открытой какой-то процесс.
pub const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;

struct Service {
    scm: SC_HANDLE,
    svc: SC_HANDLE,
}

impl Service {
    fn open(name: &str, access: u32) -> io::Result<Service> {
        let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        // SAFETY: имя — строка с нулём на конце; хэндл менеджера закрывается и при ошибке.
        unsafe {
            let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return Err(io::Error::last_os_error());
            }
            let svc = OpenServiceW(scm, name.as_ptr(), access);
            if svc.is_null() {
                let e = io::Error::last_os_error();
                CloseServiceHandle(scm);
                return Err(e);
            }
            Ok(Service { scm, svc })
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: оба хэндла открыты в `open` и закрываются только здесь.
        unsafe {
            CloseServiceHandle(self.svc);
            CloseServiceHandle(self.scm);
        }
    }
}

/// PID процесса, в котором работает служба (у служб внутри svchost он общий с соседями).
pub fn pid(name: &str) -> io::Result<u32> {
    let s = Service::open(name, SERVICE_QUERY_STATUS)?;
    // SAFETY: буфер — ровно одна SERVICE_STATUS_PROCESS.
    let status = unsafe {
        let mut status: SERVICE_STATUS_PROCESS = mem::zeroed();
        let mut needed = 0;
        let size = mem::size_of::<SERVICE_STATUS_PROCESS>() as u32;
        if QueryServiceStatusEx(s.svc, SC_STATUS_PROCESS_INFO, &mut status as *mut _ as *mut u8, size, &mut needed) == 0 {
            return Err(io::Error::last_os_error());
        }
        status
    };
    match status.dwProcessId {
        0 => Err(io::Error::other("служба не запущена")),
        pid => Ok(pid),
    }
}

/// Переводит отключённую службу в запуск вручную. `Ok(true)` — была отключена и включена.
pub fn enable(name: &str) -> io::Result<bool> {
    let s = Service::open(name, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG)?;
    // SAFETY: размер буфера узнаём первым вызовом; буфер из u64 выровнен для QUERY_SERVICE_CONFIGW.
    unsafe {
        let mut needed = 0;
        QueryServiceConfigW(s.svc, ptr::null_mut(), 0, &mut needed);
        let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(mem::size_of::<QUERY_SERVICE_CONFIGW>().div_ceil(8))];
        let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if QueryServiceConfigW(s.svc, cfg, (buf.len() * 8) as u32, &mut needed) == 0 {
            return Err(io::Error::last_os_error());
        }
        if (*cfg).dwStartType != SERVICE_DISABLED {
            return Ok(false);
        }
        let ok = ChangeServiceConfigW(
            s.svc,
            SERVICE_NO_CHANGE,
            SERVICE_DEMAND_START,
            SERVICE_NO_CHANGE,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_service_pid_is_found() {
        // Путь svchost без прав администратора не прочитать — проверяем только сам PID.
        assert!(pid("Dnscache").unwrap() > 4);
    }

    #[test]
    fn missing_service_is_reported_by_code() {
        let e = pid("little-proxy-no-such-service").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(ERROR_SERVICE_DOES_NOT_EXIST));
    }
}
