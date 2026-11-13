// Shared app state for all tabs.

import * as api from "./api";
import type {
  AppInfo,
  Config,
  ConnEvent,
  Health,
  PresetsInfo,
  ProxyExtension,
  RuleStat,
} from "./types";

const MAX_EVENTS = 1000;
const BROWSER_CHECK_MS = 10_000;

class Store {
  config = $state<Config | null>(null);
  info = $state<AppInfo | null>(null);
  presets = $state<PresetsInfo | null>(null);
  /** Hits per rule id since the app started. */
  stats = $state<Record<string, RuleStat>>({});
  /** Newest first. */
  events = $state<ConnEvent[]>([]);
  error = $state<string | null>(null);
  /** Short-lived success message. */
  notice = $state<string | null>(null);
  busy = $state(false);
  /** Browser extensions that override the proxy (the browser then ignores our PAC). */
  browserWarnings = $state<ProxyExtension[]>([]);
  health = $state<Health>({ state: "off" });

  private noticeTimer: ReturnType<typeof setTimeout> | undefined;

  async init() {
    const unlisten = [
      api.onConfigChanged((c) => {
        this.config = c;
        if (c.enabled) this.error = null;
      }),
      api.onAppError((message) => (this.error = message)),
      api.onConnEvents((batch) => this.addEvents(batch)),
      api.onPresetsChanged((info) => (this.presets = info)),
      api.onHealth((h) => (this.health = h)),
    ];
    try {
      const [config, info, presets, stats, health] = await Promise.all([
        api.getConfig(),
        api.getAppInfo(),
        api.getPresets(),
        api.getRuleStats(),
        api.getHealth(),
      ]);
      this.health = health;
      this.config = config;
      this.info = info;
      this.presets = presets;
      this.stats = stats;
      if (!config.enabled && info.startError) this.error = info.startError;
    } catch (e) {
      this.error = String(e);
    }
    this.checkBrowsers();
    // Re-check when the user comes back, e.g. after switching an extension off,
    // and every few seconds while the window is shown: browsers write the
    // change to their profile files with a delay.
    const onFocus = () => this.checkBrowsers();
    window.addEventListener("focus", onFocus);
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") this.checkBrowsers();
    }, BROWSER_CHECK_MS);
    return () => {
      clearInterval(timer);
      window.removeEventListener("focus", onFocus);
      unlisten.forEach((u) => u.then((off) => off()));
    };
  }

  async checkBrowsers() {
    try {
      this.browserWarnings = await api.getBrowserWarnings();
    } catch {
      // Best effort: a broken profile file must not bother the user.
    }
  }

  private addEvents(batch: ConnEvent[]) {
    const stats = { ...this.stats };
    for (const e of batch) {
      if (!e.ruleId) continue;
      const s = stats[e.ruleId] ?? { hits: 0, lastMs: 0 };
      stats[e.ruleId] = { hits: s.hits + 1, lastMs: Math.max(s.lastMs, e.atMs) };
    }
    this.stats = stats;
    this.events = [...batch.reverse(), ...this.events].slice(0, MAX_EVENTS);
  }

  /** Runs an action that may fail, showing its error; returns its result or undefined. */
  async run<T>(action: () => Promise<T>): Promise<T | undefined> {
    this.busy = true;
    this.error = null;
    try {
      return await action();
    } catch (e) {
      this.error = String(e);
      return undefined;
    } finally {
      this.busy = false;
    }
  }

  /** Saves a changed copy of the config; the backend applies it right away. */
  async update(change: (c: Config) => void) {
    if (!this.config) return;
    const next: Config = structuredClone($state.snapshot(this.config));
    change(next);
    const saved = await this.run(() => api.saveConfig(next));
    if (saved) this.config = saved;
  }

  /** "openai.com" for a user rule, "YouTube: youtube.com" for a preset entry. */
  ruleLabel(id: string | null): string | null {
    if (!id) return null;
    const rule = this.config?.rules.find((r) => r.id === id);
    if (rule) return rule.pattern;
    for (const preset of this.presets?.presets ?? []) {
      const entry = preset.entries.find((e) => e.id === id);
      if (entry) return `${preset.name}: ${entry.pattern}`;
    }
    return null;
  }

  say(message: string) {
    this.notice = message;
    clearTimeout(this.noticeTimer);
    this.noticeTimer = setTimeout(() => (this.notice = null), 4000);
  }
}

export const store = new Store();

export function newId(): string {
  return crypto.randomUUID();
}

export function timeAgo(ms: number): string {
  if (!ms) return "";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 10) return "сейчас";
  if (s < 60) return `${s} с назад`;
  if (s < 3600) return `${Math.round(s / 60)} мин назад`;
  if (s < 86400) return `${Math.round(s / 3600)} ч назад`;
  return new Date(ms).toLocaleDateString();
}
