import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AppInfo, Config } from "./types";

export const getAppInfo = () => invoke<AppInfo>("get_app_info");
export const getConfig = () => invoke<Config>("get_config");
export const saveConfig = (config: Config) => invoke<Config>("save_config", { config });
export const setEnabled = (enabled: boolean) => invoke<Config>("set_enabled", { enabled });
export const getAutostart = () => invoke<boolean>("get_autostart");
export const setAutostart = (enabled: boolean) => invoke<boolean>("set_autostart", { enabled });

/** Fires on every config change, including ones made from the tray. */
export const onConfigChanged = (handler: (config: Config) => void): Promise<UnlistenFn> =>
  listen<Config>("config-changed", (event) => handler(event.payload));

/** Errors from actions started outside the window, e.g. the tray toggle. */
export const onAppError = (handler: (message: string) => void): Promise<UnlistenFn> =>
  listen<string>("app-error", (event) => handler(event.payload));
