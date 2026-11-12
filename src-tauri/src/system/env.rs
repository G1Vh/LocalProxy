//! User-level `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` for console tools
//! (git, npm, curl, pip...). Only programs started afterwards see them.

use std::collections::BTreeMap;
use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};

use super::wininet::wide;

const KEY: &str = "Environment";
const NAMES: [&str; 3] = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"];
/// Loopback stays direct even for tools that would otherwise send it to us.
const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Previous values; `None` means the variable did not exist.
pub type EnvBackup = BTreeMap<String, Option<String>>;

/// Current values, with ones LocalProxy itself wrote treated as absent.
pub fn read() -> io::Result<EnvBackup> {
    NAMES
        .iter()
        .map(|&name| {
            let value = get(name)?.filter(|v| !is_ours(name, v));
            Ok((name.to_owned(), value))
        })
        .collect()
}

pub fn set(port: u16) -> io::Result<()> {
    let url = proxy_url(port);
    put("HTTP_PROXY", &url)?;
    put("HTTPS_PROXY", &url)?;
    put("NO_PROXY", NO_PROXY)?;
    broadcast();
    Ok(())
}

pub fn restore(backup: &EnvBackup) -> io::Result<()> {
    for (name, value) in backup {
        match value {
            Some(value) => put(name, value)?,
            None => delete(name)?,
        }
    }
    broadcast();
    Ok(())
}

fn proxy_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn is_ours(name: &str, value: &str) -> bool {
    if name == "NO_PROXY" {
        return value == NO_PROXY;
    }
    value
        .strip_prefix("http://127.0.0.1:")
        .is_some_and(|port| port.parse::<u16>().is_ok())
}

fn get(name: &str) -> io::Result<Option<String>> {
    let (key, value) = (wide(KEY), wide(name));
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    let mut size = 0u32;
    // SAFETY: size query with a null buffer.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2)];
    // SAFETY: `buf` holds `size` bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            flags,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(Some(String::from_utf16_lossy(&buf[..len])))
}

fn put(name: &str, data: &str) -> io::Result<()> {
    let (key, value, data) = (wide(KEY), wide(name), wide(data));
    // SAFETY: all buffers are NUL-terminated and alive for the call.
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn delete(name: &str) -> io::Result<()> {
    let (key, value) = (wide(KEY), wide(name));
    // SAFETY: both strings are NUL-terminated.
    let status = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) };
    if status != 0 && status != ERROR_FILE_NOT_FOUND {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Lets Explorer pick up the change so newly started programs get it.
fn broadcast() {
    let param = wide(KEY);
    // SAFETY: `param` outlives the call; hung windows are skipped.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            param.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            3000,
            ptr::null_mut(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_values_we_write() {
        assert!(is_ours("HTTP_PROXY", "http://127.0.0.1:3128"));
        assert!(is_ours("HTTPS_PROXY", "http://127.0.0.1:8080"));
        assert!(is_ours("NO_PROXY", NO_PROXY));
        assert!(!is_ours("HTTP_PROXY", "http://localhost:3128"));
        assert!(!is_ours("HTTP_PROXY", "http://proxy.corp:8080"));
        assert!(!is_ours("NO_PROXY", "localhost"));
    }
}
