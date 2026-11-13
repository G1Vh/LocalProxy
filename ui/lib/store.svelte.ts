// Shared app state for all tabs.

import * as api from "./api";
import type {
  AppInfo,
  Config,
  ConnEvent,
  HealthState,
  HiddenEvent,
  PresetsInfo,
  ProxyExtension,
  RuleStat,
  UpdateInfo,
  UpdateProgress,
} from "./types";

const MAX_EVENTS = 1000;
const BROWSER_CHECK_MS = 10_000;

class Store {
  config = $state<Config | null>(null);
  info = $state<AppInfo | null>(null);
  presets = $state<PresetsInfo | null>(null);
  /** Hits per rule id since the app started. */
  stats = $state<Record<string, RuleStat>>({});
  /** Hits per hidden feed entry since the app started. */
  hiddenStats = $state<Record<string, RuleStat>>({});
  /** Newest first. */
  events = $state<ConnEvent[]>([]);
  error = $state<string | null>(null);
  /** Short-lived success message. */
  notice = $state<string | null>(null);
  busy = $state(false);
  /** Browser extensions that override the proxy (the browser then ignores our PAC). */
  browserWarnings = $state<ProxyExtension[]>([]);
  health = $state<HealthState>({ overall: { state: "off" }, outbounds: {} });
  /** A newer version on GitHub, once found. */
  newVersion = $state<UpdateInfo | null>(null);
  /** Set while the update downloads. */
  updateProgress = $state<UpdateProgress | null>(null);

  private noticeTimer: ReturnType<typeof setTimeout> | undefined;

  async init() {
    const unlisten = [
      api.onConfigChanged((c) => {
        this.config = c;
        // Switched on after a failed start: that start error is stale now.
        if (c.enabled && this.error && this.error === this.info?.startError) this.error = null;
      }),
      api.onAppError((message) => (this.error = message)),
      api.onConnEvents((batch) => this.addEvents(batch)),
      api.onHiddenStats((stats) => (this.hiddenStats = stats)),
      api.onPresetsChanged((info) => (this.presets = info)),
      api.onHealth((h) => (this.health = h)),
      api.onUpdateAvailable((u) => (this.newVersion = u)),
      api.onUpdateProgress((p) => (this.updateProgress = p)),
    ];
    try {
      const [config, info, presets, stats, health, update, hiddenStats] = await Promise.all([
        api.getConfig(),
        api.getAppInfo(),
        api.getPresets(),
        api.getRuleStats(),
        api.getHealth(),
        api.getPendingUpdate(),
        api.getHiddenStats(),
      ]);
      this.hiddenStats = hiddenStats;
      this.health = health;
      this.newVersion = update;
      this.config = config;
      this.info = info;
      this.presets = presets;
      this.stats = stats;
      if (info.startError) this.error = info.startError;
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
  outboundName(id: string | null | undefined): string | null {
    if (!id) return null;
    return this.config?.outbounds.find((o) => o.id === id)?.name ?? null;
  }

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

  async installUpdate() {
    this.error = null;
    this.updateProgress = { downloaded: 0, total: null };
    try {
      await api.installUpdate();
    } catch (e) {
      this.error = String(e);
    }
    this.updateProgress = null;
  }

  say(message: string) {
    this.notice = message;
    clearTimeout(this.noticeTimer);
    this.noticeTimer = setTimeout(() => (this.notice = null), 4000);
  }
}

export const store = new Store();

/** Whether a hidden-feed entry covers this connection (the app does the same). */
export function hides(h: HiddenEvent, e: ConnEvent): boolean {
  if (h.errorsOnly && !e.error) return false;
  const program = e.process?.slice(Math.max(e.process.lastIndexOf("\\"), e.process.lastIndexOf("/")) + 1);
  return (
    (h.process === undefined || program?.toLowerCase() === h.process) &&
    (h.host === undefined || e.host.toLowerCase() === h.host) &&
    (h.port === undefined || e.port === h.port)
  );
}

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
