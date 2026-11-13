import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppInfo,
  Config,
  ConnEvent,
  HealthState,
  HostCheck,
  HostTraffic,
  MatchType,
  Outbound,
  PresetsInfo,
  ProxyExtension,
  Probe,
  RuleStat,
  RulesChange,
  TunnelStatus,
  UpdateInfo,
  UpdateProgress,
} from "./types";

export const getAppInfo = () => invoke<AppInfo>("get_app_info");
export const getConfig = () => invoke<Config>("get_config");
export const saveConfig = (config: Config) => invoke<Config>("save_config", { config });
export const setEnabled = (enabled: boolean) => invoke<Config>("set_enabled", { enabled });
export const getAutostart = () => invoke<boolean>("get_autostart");
export const setAutostart = (enabled: boolean) => invoke<boolean>("set_autostart", { enabled });

export const normalizePattern = (pattern: string, matchType: MatchType) =>
  invoke<string>("normalize_rule_pattern", { pattern, matchType });
export const checkHost = (input: string) => invoke<HostCheck>("check_host", { input });
export const testOutbound = (outbound: Outbound) => invoke<Probe>("test_outbound", { outbound });
export const getPresets = () => invoke<PresetsInfo>("get_presets");
export const refreshPresets = () => invoke<PresetsInfo>("refresh_presets");
export const getRuleStats = () => invoke<Record<string, RuleStat>>("get_rule_stats");
export const addRuleLines = (text: string) => invoke<RulesChange>("add_rule_lines", { text });
export const setPresetSelected = (id: string, selected: boolean) =>
  invoke<Config>("set_preset_selected", { id, selected });
export const exportRules = (path: string) => invoke<number>("export_rules", { path });
export const getBrowserWarnings = () => invoke<ProxyExtension[]>("get_browser_warnings");
export const getTunnelStatus = () => invoke<TunnelStatus[]>("get_tunnel_status");
export const getHealth = () => invoke<HealthState>("get_health");
export const getTraffic = () => invoke<HostTraffic[]>("get_traffic");
export const resetTraffic = () => invoke<void>("reset_traffic");
export const checkUpdate = () => invoke<UpdateInfo | null>("check_update");
export const getPendingUpdate = () => invoke<UpdateInfo | null>("get_pending_update");
/** Resolves only on failure: on success the app exits and the installer restarts it. */
export const installUpdate = () => invoke<void>("install_update");
export const importRules = (path: string) => invoke<RulesChange>("import_rules", { path });

/** Fires on every config change, including ones made from the tray. */
export const onConfigChanged = (handler: (config: Config) => void): Promise<UnlistenFn> =>
  listen<Config>("config-changed", (event) => handler(event.payload));

/** Errors from actions started outside the window, e.g. the tray toggle. */
export const onAppError = (handler: (message: string) => void): Promise<UnlistenFn> =>
  listen<string>("app-error", (event) => handler(event.payload));

/** Batches of connection events while the proxy runs. */
export const onConnEvents = (handler: (events: ConnEvent[]) => void): Promise<UnlistenFn> =>
  listen<ConnEvent[]>("conn-events", (event) => handler(event.payload));

export const onPresetsChanged = (handler: (info: PresetsInfo) => void): Promise<UnlistenFn> =>
  listen<PresetsInfo>("presets-changed", (event) => handler(event.payload));

export const onHealth = (handler: (health: HealthState) => void): Promise<UnlistenFn> =>
  listen<HealthState>("outbound-health", (event) => handler(event.payload));

export const onUpdateAvailable = (handler: (info: UpdateInfo) => void): Promise<UnlistenFn> =>
  listen<UpdateInfo>("update-available", (event) => handler(event.payload));

export const onUpdateProgress = (handler: (p: UpdateProgress) => void): Promise<UnlistenFn> =>
  listen<UpdateProgress>("update-progress", (event) => handler(event.payload));
