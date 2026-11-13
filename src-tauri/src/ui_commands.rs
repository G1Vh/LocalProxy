//! Commands behind the rules, outbound and connections tabs.

use proxy_core::config::{Config, MatchType, Outbound, OutboundKind, RuleAction};
use proxy_core::matcher::{RuleSet, normalize_pattern};
use proxy_core::outbound::Upstream;
use proxy_core::probe::{Probe, probe};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;

use crate::awg::{AwgProcess, BridgeStatus};
use crate::commands::apply_config;
use crate::events::RuleStats;
use crate::presets::{self, Entry, Source};
use crate::rules::{self, MergeReport};
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesChange {
    config: Config,
    report: MergeReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCheck {
    host: String,
    /// What happens to this host: through the outbound, or direct.
    action: RuleAction,
    /// The deciding rule (a user rule or a preset entry); `None` if none matched.
    rule_id: Option<Uuid>,
}

/// Canonical form of a pattern, or why it is invalid. Used to validate edits.
#[tauri::command]
pub fn normalize_rule_pattern(pattern: String, match_type: MatchType) -> Result<String, String> {
    normalize_pattern(&pattern, match_type).map_err(|e| e.to_string())
}

/// Which rule a URL or host hits with the current rules and selected presets
/// (works while routing is off too).
#[tauri::command]
pub fn check_host(state: State<'_, AppState>, input: String) -> Result<HostCheck, String> {
    let host = normalize_pattern(&input, MatchType::Exact).map_err(|e| e.to_string())?;
    let config = state.config().clone();
    let effective = presets::effective(&config, &state.presets().file);
    let decision = RuleSet::new(&effective.rules).decide(&host);
    Ok(HostCheck {
        host,
        action: decision.action,
        rule_id: decision.rule_id,
    })
}

#[tauri::command]
pub async fn test_outbound(
    state: State<'_, AppState>,
    outbound: Outbound,
) -> Result<Probe, String> {
    if let OutboundKind::Awg { config: conf } = &outbound.kind {
        return test_awg(&state, outbound.id, conf).await;
    }
    let upstream = Upstream::from_kind(&outbound.kind);
    if upstream.points_to(state.config().port) {
        return Err(proxy_core::router::SELF_LOOP.into());
    }
    probe(&upstream).await.map_err(|e| e.to_string())
}

/// Probes through the running bridge if it serves this profile; otherwise
/// starts a temporary one (two tunnels with the same key would fight).
async fn test_awg(state: &AppState, id: Uuid, conf: &str) -> Result<Probe, String> {
    let running = {
        let mut slot = state.awg.lock().await;
        match slot.as_mut() {
            Some(b) if b.outbound_id == id && b.conf == conf => {
                b.is_alive().then(|| b.endpoint.clone())
            }
            _ => None,
        }
    };
    if let Some(endpoint) = running {
        return probe(&Upstream::Socks5(endpoint))
            .await
            .map_err(|e| e.to_string());
    }
    let bridge = AwgProcess::start(id, conf).await?;
    let result = probe(&Upstream::Socks5(bridge.endpoint.clone())).await;
    bridge.stop().await;
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwgStatus {
    outbound_id: Uuid,
    #[serde(flatten)]
    status: BridgeStatus,
}

/// State of the running tunnel, for the outbound tab; `None` when no bridge runs.
#[tauri::command]
pub async fn get_awg_status(state: State<'_, AppState>) -> Result<Option<AwgStatus>, String> {
    let mut slot = state.awg.lock().await;
    let Some(bridge) = slot.as_mut() else {
        return Ok(None);
    };
    let status = bridge.status().await?;
    Ok(Some(AwgStatus {
        outbound_id: bridge.outbound_id,
        status,
    }))
}

/// Event name; payload is [`PresetsInfo`].
pub const PRESETS_CHANGED: &str = "presets-changed";

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PresetView {
    id: String,
    name: String,
    note: Option<String>,
    entries: Vec<Entry>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PresetsInfo {
    revision: u32,
    source: Source,
    last_error: Option<String>,
    presets: Vec<PresetView>,
}

fn presets_info(state: &AppState) -> PresetsInfo {
    let p = state.presets();
    PresetsInfo {
        revision: p.file.revision,
        source: p.source,
        last_error: p.last_error.clone(),
        presets: p
            .file
            .presets
            .iter()
            .map(|preset| PresetView {
                id: preset.id.clone(),
                name: preset.name.clone(),
                note: preset.note.clone(),
                entries: preset.entries(),
            })
            .collect(),
    }
}

#[tauri::command]
pub fn get_presets(state: State<'_, AppState>) -> PresetsInfo {
    presets_info(&state)
}

#[tauri::command]
pub async fn refresh_presets(app: AppHandle) -> PresetsInfo {
    refresh_presets_inner(&app).await
}

/// Downloads the preset list; if it is newer, caches it and switches to it.
/// Selected presets then apply the new entries right away. Failures are kept
/// for the UI, never fatal.
pub async fn refresh_presets_inner(app: &AppHandle) -> PresetsInfo {
    let state = app.state::<AppState>();
    match presets::fetch().await {
        Ok(file) => {
            let newer = {
                let mut p = state.presets();
                let newer = file.revision > p.file.revision;
                if newer || file.revision == p.file.revision {
                    p.source = Source::Remote;
                }
                if newer {
                    if let Err(e) = presets::save_cache(&state.dir, &file) {
                        tracing::warn!("cannot cache presets: {e}");
                    }
                    tracing::info!(revision = file.revision, "presets updated from GitHub");
                    p.file = file;
                }
                p.last_error = None;
                newer
            };
            let config = state.config().clone();
            if newer
                && !config.presets.is_empty()
                && let Err(e) = apply_config(app, &state, config).await
            {
                tracing::warn!("applying updated presets: {e}");
            }
        }
        Err(e) => {
            tracing::warn!("presets download failed: {e}");
            state.presets().last_error = Some(e);
        }
    }
    let info = presets_info(&state);
    let _ = app.emit(PRESETS_CHANGED, &info);
    info
}

/// Subscribes to a preset or unsubscribes from it.
#[tauri::command]
pub async fn set_preset_selected(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    selected: bool,
) -> Result<Config, String> {
    if selected && !state.presets().file.presets.iter().any(|p| p.id == id) {
        return Err(format!("нет набора «{id}»"));
    }
    let mut config = state.config().clone();
    config.presets.retain(|p| p != &id);
    if selected {
        config.presets.push(id);
    }
    apply_config(&app, &state, config).await
}

#[tauri::command]
pub fn get_rule_stats(state: State<'_, AppState>) -> RuleStats {
    state.rule_stats().clone()
}

#[tauri::command]
pub async fn add_rule_lines(
    app: AppHandle,
    state: State<'_, AppState>,
    text: String,
) -> Result<RulesChange, String> {
    let mut config = state.config().clone();
    let report = rules::add_lines(&mut config, &text);
    finish(&app, &state, config, report).await
}

#[tauri::command]
pub fn export_rules(state: State<'_, AppState>, path: String) -> Result<usize, String> {
    let config = state.config().clone();
    std::fs::write(&path, rules::export(&config))
        .map_err(|e| format!("Не удалось записать {path}: {e}"))?;
    Ok(config.rules.len())
}

#[tauri::command]
pub async fn import_rules(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<RulesChange, String> {
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("Не удалось прочитать {path}: {e}"))?;
    let mut config = state.config().clone();
    let report = rules::import(&mut config, &text);
    finish(&app, &state, config, report).await
}

async fn finish(
    app: &AppHandle,
    state: &AppState,
    config: Config,
    report: MergeReport,
) -> Result<RulesChange, String> {
    let config = apply_config(app, state, config).await?;
    Ok(RulesChange { config, report })
}

/// Browser extensions that override the proxy, so the user knows why a
/// browser ignores the rules. Reads profile files only; cheap to call often.
#[tauri::command]
pub async fn get_browser_warnings() -> Vec<crate::browsers::ProxyExtension> {
    tauri::async_runtime::spawn_blocking(crate::browsers::scan)
        .await
        .unwrap_or_default()
}

/// Bytes per host since the app started, busiest first.
#[tauri::command]
pub fn get_traffic(state: State<'_, AppState>) -> Vec<proxy_core::traffic::HostTraffic> {
    state.traffic.snapshot()
}

#[tauri::command]
pub fn reset_traffic(state: State<'_, AppState>) {
    state.traffic.reset();
}
