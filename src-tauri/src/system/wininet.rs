//! Per-user Internet Settings (what Windows calls "Proxy setup") through the
//! WinINet per-connection API. Unlike poking the registry directly, this also
//! updates `DefaultConnectionSettings` and notifies running programs.

use std::ffi::c_void;
use std::io;
use std::ptr;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_PROXY_SETTINGS_CHANGED,
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN,
    INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTION_LISTW,
    INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_PROXY_BYPASS,
    INTERNET_PER_CONN_PROXY_SERVER, InternetQueryOptionW, InternetSetOptionW,
    PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT,
};
use windows_sys::core::PWSTR;

/// The parts of the system proxy configuration LocalProxy touches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySettings {
    /// `PROXY_TYPE_*` bits: direct, manual proxy, PAC URL, auto-detect.
    pub flags: u32,
    pub proxy_server: Option<String>,
    pub bypass: Option<String>,
    pub autoconfig_url: Option<String>,
}

impl ProxySettings {
    /// No proxy at all: what Windows has out of the box.
    pub fn direct() -> Self {
        Self {
            flags: PROXY_TYPE_DIRECT,
            proxy_server: None,
            bypass: None,
            autoconfig_url: None,
        }
    }

    /// True when this points at a LocalProxy PAC (ours, possibly a stale one).
    pub fn is_localproxy_pac(&self) -> bool {
        self.flags & PROXY_TYPE_AUTO_PROXY_URL != 0
            && self
                .autoconfig_url
                .as_deref()
                .is_some_and(|u| u.starts_with("http://127.0.0.1:") && u.contains("/proxy.pac"))
    }
}

pub fn query() -> io::Result<ProxySettings> {
    let mut options = [
        INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_PROXY_SERVER,
        INTERNET_PER_CONN_PROXY_BYPASS,
        INTERNET_PER_CONN_AUTOCONFIG_URL,
    ]
    .map(|option| option_dword(option, 0));
    let mut list = option_list(&mut options);
    let mut size = list.dwSize;
    // SAFETY: `list` points at `options`, both alive for the call; a null
    // handle with PER_CONNECTION_OPTION queries the default connection.
    let ok = unsafe {
        InternetQueryOptionW(
            ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&raw mut list).cast::<c_void>(),
            &mut size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success WinINet filled the union member that matches each
    // option; strings are GlobalAlloc'ed and ours to free.
    unsafe {
        Ok(ProxySettings {
            flags: options[0].Value.dwValue,
            proxy_server: take_string(options[1].Value.pszValue),
            bypass: take_string(options[2].Value.pszValue),
            autoconfig_url: take_string(options[3].Value.pszValue),
        })
    }
}

/// Switches the system to our PAC. Manual proxy and bypass list are left as
/// they are (just not used), so restoring them is exact.
pub fn use_pac(url: &str) -> io::Result<()> {
    let url = wide(url);
    let mut options = [
        option_dword(
            INTERNET_PER_CONN_FLAGS,
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL,
        ),
        option_string(INTERNET_PER_CONN_AUTOCONFIG_URL, &url),
    ];
    set(&mut options)
}

/// Puts back settings captured with [`query`].
pub fn restore(settings: &ProxySettings) -> io::Result<()> {
    let server = settings.proxy_server.as_deref().map(wide);
    let bypass = settings.bypass.as_deref().map(wide);
    // An empty URL clears ours when there was none before.
    let url = wide(settings.autoconfig_url.as_deref().unwrap_or(""));

    let mut options = vec![
        option_dword(INTERNET_PER_CONN_FLAGS, settings.flags),
        option_string(INTERNET_PER_CONN_AUTOCONFIG_URL, &url),
    ];
    if let Some(server) = &server {
        options.push(option_string(INTERNET_PER_CONN_PROXY_SERVER, server));
    }
    if let Some(bypass) = &bypass {
        options.push(option_string(INTERNET_PER_CONN_PROXY_BYPASS, bypass));
    }
    set(&mut options)
}

fn set(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> io::Result<()> {
    let list = option_list(options);
    // SAFETY: `list` and the strings `options` point to outlive the call.
    let ok = unsafe {
        InternetSetOptionW(
            ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&raw const list).cast::<c_void>(),
            list.dwSize,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    notify();
    Ok(())
}

/// Tells WinINet-based programs (Edge, Chrome, Office, .NET...) to reload.
fn notify() {
    for option in [
        INTERNET_OPTION_PROXY_SETTINGS_CHANGED,
        INTERNET_OPTION_SETTINGS_CHANGED,
        INTERNET_OPTION_REFRESH,
    ] {
        // SAFETY: these options take no buffer.
        unsafe { InternetSetOptionW(ptr::null(), option, ptr::null(), 0) };
    }
}

fn option_list(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> INTERNET_PER_CONN_OPTION_LISTW {
    INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    }
}

fn option_dword(option: INTERNET_PER_CONN, value: u32) -> INTERNET_PER_CONN_OPTIONW {
    INTERNET_PER_CONN_OPTIONW {
        dwOption: option,
        Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: value },
    }
}

/// `value` must be NUL-terminated and outlive the option.
fn option_string(option: INTERNET_PER_CONN, value: &[u16]) -> INTERNET_PER_CONN_OPTIONW {
    INTERNET_PER_CONN_OPTIONW {
        dwOption: option,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            pszValue: value.as_ptr().cast_mut(),
        },
    }
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copies a WinINet-allocated string and frees it.
///
/// # Safety
/// `p` is null or a NUL-terminated string allocated with `GlobalAlloc`.
unsafe fn take_string(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0;
    // SAFETY: guaranteed NUL-terminated by the caller.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        GlobalFree(p.cast());
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_our_pac() {
        let mut s = ProxySettings::direct();
        assert!(!s.is_localproxy_pac());
        s.flags |= PROXY_TYPE_AUTO_PROXY_URL;
        s.autoconfig_url = Some("http://127.0.0.1:3128/proxy.pac?v=1".into());
        assert!(s.is_localproxy_pac());
        s.autoconfig_url = Some("http://wpad.corp/proxy.pac".into());
        assert!(!s.is_localproxy_pac());
    }

    /// Reads the real settings; no changes are made.
    #[test]
    fn query_reads_current_settings() {
        let s = query().expect("query works for the current user");
        assert!(s.flags & PROXY_TYPE_DIRECT != 0 || s.flags != 0);
    }
}
