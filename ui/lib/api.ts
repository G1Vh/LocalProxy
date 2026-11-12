import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AppInfo, Config } from "./types";

export const getAppInfo = () => invoke<AppInfo>("get_app_info");
export const getConfig = () => invoke<Config>("get_config");
export const saveConfig = (config: Config) => invoke<Config>("save_config", { config });
export const setEnabled = (enabled: boolean) => invoke<Config>("set_enabled", { enabled });

/** Fires on every config change, including ones made from the tray. */
export const onConfigChanged = (handler: (config: Config) => void): Promise<UnlistenFn> =>
  listen<Config>("config-changed", (event) => handler(event.payload));
