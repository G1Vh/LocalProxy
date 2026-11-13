//! TUN mode: the whole system's traffic through LocalProxy. A Wintun adapter
//! takes every packet; the tunnel program turns them back into connections
//! and hands them to our SOCKS5 port by name, so the usual rules apply to
//! every program, browser extensions and proxy-less programs too.
//!
//! The adapter needs administrator rights, so it runs in the "LocalProxyTun"
//! Windows service (see `tunnel/internal/service`), which runs our own
//! localproxy-tunnel.exe from the install folder. Installing it asks for the
//! rights once; after that we start it ourselves with the session's
//! arguments, updates included.
//! It talks to us over a loopback TCP connection (`tunnel/internal/tun/run.go`).
//! Our own sockets out are pinned to the physical interface before the
//! adapter takes the routes, and re-pinned whenever the network changes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::time::timeout;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SERVICE_DOES_NOT_EXIST, GetLastError};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfigW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS, SERVICE_STOP,
    SERVICE_STOPPED, StartServiceW,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};

use crate::state::AppState;

const SERVICE: &str = "LocalProxyTun";
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
const ERROR_CANCELLED: i32 = 1223;

#[derive(Debug, Deserialize)]
struct Event {
    event: String,
    token: Option<String>,
    message: Option<String>,
    v4: Option<u32>,
    v6: Option<u32>,
    tcp: Option<i64>,
    udp: Option<i64>,
    dns: Option<i64>,
    refused: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunStats {
    pub tcp: i64,
    pub udp: i64,
    pub dns: i64,
    pub refused: i64,
}

pub struct TunSession {
    /// Until the routes are taken we read replies here; then a task does.
    lines: Option<Lines<BufReader<OwnedReadHalf>>>,
    writer: OwnedWriteHalf,
    status: Option<mpsc::Receiver<TunStats>>,
    alive: Arc<AtomicBool>,
    /// Physical interface (IPv4, IPv6) at the start.
    pub physical: (u32, u32),
    /// Routes taken: the system's traffic goes through us.
    pub active: bool,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn tunnel_exe() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("LOCALPROXY_TUNNEL") {
        return Ok(PathBuf::from(path));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(exe.with_file_name("localproxy-tunnel.exe"))
}

/// The service runs this very exe (not one from another install or build).
fn service_runs(s: &Sc, ours: &Path) -> bool {
    // SAFETY: two-step QueryServiceConfigW with a buffer of the size it asks for.
    let path = unsafe {
        let mut needed = 0u32;
        QueryServiceConfigW(s.0, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return false;
        }
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        let cfg = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        if QueryServiceConfigW(s.0, cfg, needed, &mut needed) == 0 {
            return false;
        }
        let p = (*cfg).lpBinaryPathName;
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    };
    let ours = ours.to_string_lossy().to_lowercase();
    path.to_lowercase().contains(&ours)
}

struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: a handle we opened.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Opens the service with the rights its installer gave us; `None` if it
/// is not installed.
fn open_service() -> Result<Option<Sc>, String> {
    // SAFETY: plain Win32 calls with valid wide strings.
    unsafe {
        let m = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if m.is_null() {
            return Err(format!(
                "диспетчер служб: {}",
                std::io::Error::last_os_error()
            ));
        }
        let m = Sc(m);
        let name = wide(SERVICE);
        let s = OpenServiceW(
            m.0,
            name.as_ptr(),
            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        );
        if s.is_null() {
            return if GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST {
                Ok(None)
            } else {
                Err(format!("служба TUN: {}", std::io::Error::last_os_error()))
            };
        }
        Ok(Some(Sc(s)))
    }
}

fn service_state(s: &Sc) -> u32 {
    // SAFETY: a valid service handle and a status struct to fill.
    unsafe {
        let mut st: SERVICE_STATUS = std::mem::zeroed();
        if QueryServiceStatus(s.0, &mut st) == 0 {
            return SERVICE_STOPPED;
        }
        st.dwCurrentState
    }
}

fn stop_service(s: &Sc) {
    if service_state(s) == SERVICE_STOPPED {
        return;
    }
    // SAFETY: a valid service handle.
    unsafe {
        let mut st: SERVICE_STATUS = std::mem::zeroed();
        ControlService(s.0, SERVICE_CONTROL_STOP, &mut st);
    }
    for _ in 0..50 {
        if service_state(s) == SERVICE_STOPPED {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Runs "localproxy-tunnel service install" elevated: the one UAC prompt.
fn install_service(exe: &Path) -> Result<(), String> {
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide("service install");
    // SAFETY: zeroed is a valid SHELLEXECUTEINFOW; the strings outlive the call.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 0; // SW_HIDE
    // SAFETY: info is fully initialised.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let err = std::io::Error::last_os_error();
        return Err(if err.raw_os_error() == Some(ERROR_CANCELLED) {
            "TUN не включён: запрос прав администратора отклонён".into()
        } else {
            format!("TUN не включён: {err}")
        });
    }
    // SAFETY: the process handle ShellExecuteEx gave us.
    let code = unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        code
    };
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "TUN не включён: служба не установилась (код {code})"
        ))
    }
}

/// Installs the service if needed, then starts it for this session.
fn start_service(args: &[String]) -> Result<(), String> {
    let exe = tunnel_exe()?;
    let exe = std::fs::canonicalize(&exe)
        .map(|p| PathBuf::from(p.to_string_lossy().trim_start_matches(r"\\?\").to_owned()))
        .unwrap_or(exe);
    let mut service = open_service()?;
    if !service.as_ref().is_some_and(|s| service_runs(s, &exe)) {
        tracing::info!("installing the TUN service");
        install_service(&exe)?;
        service = open_service()?;
    }
    let service = service.ok_or("TUN не включён: служба не установилась")?;
    // A session left from a crash: end it first.
    stop_service(&service);
    let wide_args: Vec<Vec<u16>> = args.iter().map(|a| wide(a)).collect();
    let ptrs: Vec<*const u16> = wide_args.iter().map(|a| a.as_ptr()).collect();
    // SAFETY: argument strings outlive the call.
    if unsafe { StartServiceW(service.0, ptrs.len() as u32, ptrs.as_ptr()) } == 0 {
        return Err(format!(
            "TUN не включён: служба не запустилась: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

impl TunSession {
    /// Starts the service and waits until the adapter is up; the routes are
    /// not taken yet (see [`TunSession::take_traffic`]).
    pub async fn start(socks_port: u16) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let control = listener.local_addr().map_err(|e| e.to_string())?;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let args: Vec<String> = vec![
            "-control".into(),
            control.to_string(),
            "-token".into(),
            token.clone(),
            "-socks".into(),
            format!("127.0.0.1:{socks_port}"),
            "-parent".into(),
            std::process::id().to_string(),
        ];
        tokio::task::spawn_blocking(move || start_service(&args))
            .await
            .map_err(|e| e.to_string())??;

        let (stream, _) = timeout(STEP_TIMEOUT, listener.accept())
            .await
            .map_err(|_| "TUN: служба не ответила".to_owned())?
            .map_err(|e| e.to_string())?;
        let (read, writer) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let hello = next_event(&mut lines).await?;
        if hello.event != "hello" || hello.token.as_deref() != Some(token.as_str()) {
            return Err("TUN: чужое подключение к управлению".to_owned());
        }
        let iface = next_event(&mut lines).await?;
        if iface.event != "interface" {
            return Err(format!(
                "TUN: {}",
                iface
                    .message
                    .unwrap_or_else(|| "адаптер не поднялся".into())
            ));
        }
        Ok(Self {
            lines: Some(lines),
            writer,
            status: None,
            alive: Arc::new(AtomicBool::new(true)),
            physical: (iface.v4.unwrap_or(0), iface.v6.unwrap_or(0)),
            active: false,
        })
    }

    /// Our sockets are pinned now: let the adapter take the traffic. From
    /// here a task reads the service's messages, re-pinning our sockets
    /// (and restarting tunnels) when the network changes.
    pub async fn take_traffic(&mut self, app: &AppHandle) -> Result<(), String> {
        self.send("routes").await?;
        let mut lines = self.lines.take().ok_or("TUN: сеанс уже запущен")?;
        let e = next_event(&mut lines).await?;
        if e.event != "ready" {
            return Err(format!(
                "TUN: {}",
                e.message.unwrap_or_else(|| "маршруты не заданы".into())
            ));
        }
        self.active = true;
        let (tx, rx) = mpsc::channel(4);
        self.status = Some(rx);
        tokio::spawn(read_events(lines, tx, self.alive.clone(), app.clone()));
        Ok(())
    }

    async fn send(&mut self, line: &str) -> Result<(), String> {
        self.writer
            .write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(|e| format!("TUN: служба не отвечает: {e}"))
    }

    pub async fn stats(&mut self) -> Result<TunStats, String> {
        self.send("status").await?;
        let rx = self.status.as_mut().ok_or("TUN: не запущен")?;
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .ok()
            .flatten()
            .ok_or_else(|| "TUN: нет ответа".to_owned())
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Closing the control connection makes the service remove the adapter
    /// (and so its routes and DNS) and stop.
    pub async fn stop(mut self) {
        let _ = self.writer.shutdown().await;
    }
}

async fn read_events(
    mut lines: Lines<BufReader<OwnedReadHalf>>,
    status: mpsc::Sender<TunStats>,
    alive: Arc<AtomicBool>,
    app: AppHandle,
) {
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(e) = serde_json::from_str::<Event>(&line) else {
            continue;
        };
        match e.event.as_str() {
            "status" => {
                let _ = status.try_send(TunStats {
                    tcp: e.tcp.unwrap_or_default(),
                    udp: e.udp.unwrap_or_default(),
                    dns: e.dns.unwrap_or_default(),
                    refused: e.refused.unwrap_or_default(),
                });
            }
            "interface" => {
                // Another network: pin our sockets to the new interface and
                // bring tunnels back on it.
                let (v4, v6) = (e.v4.unwrap_or(0), e.v6.unwrap_or(0));
                tracing::info!(v4, v6, "network changed");
                proxy_core::bind::set_interface(v4, v6);
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<AppState>();
                    crate::runtime::revive_tunnels(&app, &state).await;
                });
            }
            "error" => tracing::error!("tun: {}", e.message.unwrap_or_default()),
            _ => {}
        }
    }
    alive.store(false, Ordering::Relaxed);
    tracing::warn!("tun: the service ended the session");
}

async fn next_event(lines: &mut Lines<BufReader<OwnedReadHalf>>) -> Result<Event, String> {
    let line = timeout(STEP_TIMEOUT, lines.next_line())
        .await
        .map_err(|_| "TUN: служба не ответила вовремя".to_owned())?
        .map_err(|e| e.to_string())?
        .ok_or("TUN: служба завершила сеанс")?;
    serde_json::from_str(&line).map_err(|_| format!("TUN: непонятный ответ: {line}"))
}
