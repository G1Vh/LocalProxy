<script lang="ts">
  import { onMount } from "svelte";
  import {
    getAppInfo,
    getAutostart,
    getConfig,
    onAppError,
    onConfigChanged,
    saveConfig,
    setAutostart,
    setEnabled,
  } from "./lib/api";
  import type { AppInfo, Config } from "./lib/types";

  let config = $state<Config | null>(null);
  let info = $state<AppInfo | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);
  let autostart = $state(false);
  let portInput = $state("");

  onMount(() => {
    const unlisteners = [
      onConfigChanged((c) => {
        config = c;
        portInput = String(c.port);
        // A start error is stale once routing is on (e.g. switched on from the tray).
        if (c.enabled) error = null;
      }),
      onAppError((message) => (error = message)),
    ];
    Promise.all([getConfig(), getAppInfo(), getAutostart()])
      .then(([c, i, a]) => {
        config = c;
        info = i;
        autostart = a;
        portInput = String(c.port);
        if (!c.enabled && i.startError) error = i.startError;
      })
      .catch((e) => (error = String(e)));
    return () => {
      for (const unlisten of unlisteners) unlisten.then((off) => off());
    };
  });

  async function toggle() {
    if (!config || busy) return;
    busy = true;
    error = null;
    try {
      config = await setEnabled(!config.enabled);
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  /** Saves a changed copy of the config; the backend applies it right away. */
  async function update(change: (c: Config) => void) {
    if (!config || busy) return;
    const next: Config = structuredClone($state.snapshot(config));
    change(next);
    busy = true;
    error = null;
    try {
      config = await saveConfig(next);
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function applyPort() {
    const port = Number(portInput);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      error = "Порт — число от 1 до 65535";
      portInput = String(config?.port ?? "");
      return;
    }
    if (port !== config?.port) update((c) => (c.port = port));
  }

  async function toggleAutostart() {
    error = null;
    try {
      autostart = await setAutostart(!autostart);
    } catch (e) {
      error = String(e);
    }
  }
</script>

<main>
  <header>
    <span class="title">LocalProxy</span>
    {#if config}
      <span class="pill" class:on={config.enabled}>
        {config.enabled ? `Включён · 127.0.0.1:${config.port}` : "Выключен"}
      </span>
    {/if}
    <span class="spacer"></span>
    {#if config}
      <span class="hint">{config.enabled ? "Вкл" : "Выкл"}</span>
      <button
        class="toggle"
        class:off={!config.enabled}
        onclick={toggle}
        disabled={busy}
        aria-label="Включить или выключить проксирование"
        aria-pressed={config.enabled}
      >
        <span></span>
      </button>
    {/if}
  </header>

  {#each info?.warnings ?? [] as warning}
    <div class="banner warning">{warning}</div>
  {/each}
  {#if error}
    <div class="banner error">{error}</div>
  {/if}

  <section class="content">
    {#if config}
      <div class="card">
        <h2>Настройки</h2>
        <label class="row">
          <span>Порт</span>
          <input
            class="port"
            type="text"
            inputmode="numeric"
            bind:value={portInput}
            onchange={applyPort}
            disabled={busy}
          />
        </label>
        <label class="row">
          <span>Если outbound недоступен</span>
          <select
            value={config.onOutboundDown}
            onchange={(e) =>
              update((c) => (c.onOutboundDown = e.currentTarget.value as Config["onOutboundDown"]))}
            disabled={busy}
          >
            <option value="block">блокировать эти домены</option>
            <option value="direct">пускать напрямую</option>
          </select>
        </label>
        <label class="check">
          <input
            type="checkbox"
            checked={config.socks5Enabled}
            onchange={() => update((c) => (c.socks5Enabled = !c.socks5Enabled))}
            disabled={busy}
          />
          <span>Принимать SOCKS5 на том же порту</span>
        </label>
        <label class="check">
          <input
            type="checkbox"
            checked={config.setEnvVars}
            onchange={() => update((c) => (c.setEnvVars = !c.setEnvVars))}
            disabled={busy}
          />
          <span>
            HTTP_PROXY / HTTPS_PROXY для консольных программ
            <span class="hint">— увидят только программы, запущенные после включения</span>
          </span>
        </label>
        <label class="check">
          <input type="checkbox" checked={autostart} onchange={toggleAutostart} />
          <span>Запускать при входе в Windows (свёрнутым в трей)</span>
        </label>
      </div>
      <p class="hint">
        Правил: {config.rules.length}, outbound-профилей: {config.outbounds.length}. Таблица правил и
        профили — на этапе 4.
      </p>
    {:else if !error}
      <p class="hint">Загрузка…</p>
    {/if}
  </section>

  <footer>
    {#if info}
      <span>v{info.version}</span>
      <span>Настройки: <code>{info.configPath}</code></span>
    {/if}
  </footer>
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .title {
    font-weight: 600;
    font-size: 16px;
  }
  .spacer {
    flex: 1;
  }
  .hint {
    color: var(--text-secondary);
    font-size: 13px;
  }
  .pill {
    font-size: 12px;
    padding: 2px 10px;
    border-radius: var(--radius);
    background: var(--surface-alt);
    color: var(--text-secondary);
  }
  .pill.on {
    background: var(--success-bg);
    color: var(--success-text);
  }
  .toggle {
    position: relative;
    width: 44px;
    height: 24px;
    padding: 0;
    border: none;
    border-radius: 12px;
    background: var(--success-text);
    transition: background 0.15s;
  }
  .toggle.off {
    background: var(--toggle-off);
  }
  .toggle span {
    position: absolute;
    top: 3px;
    left: 23px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--surface);
    transition: left 0.15s;
  }
  .toggle.off span {
    left: 3px;
  }
  .toggle:disabled {
    opacity: 0.6;
    cursor: progress;
  }
  .banner {
    margin: 12px 16px 0;
    padding: 8px 12px;
    border-radius: var(--radius);
    font-size: 13px;
  }
  .banner.warning {
    background: var(--warning-bg);
    color: var(--warning-text);
  }
  .banner.error {
    border: 1px solid var(--danger-text);
    color: var(--danger-text);
  }
  .content {
    flex: 1;
    padding: 16px;
    overflow: auto;
  }
  .card {
    max-width: 640px;
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  h2 {
    margin: 0 0 4px;
    font-size: 14px;
    font-weight: 600;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .check {
    display: flex;
    align-items: flex-start;
    gap: 8px;
  }
  .check input {
    margin-top: 3px;
  }
  input[type="text"],
  select {
    height: 30px;
    padding: 0 8px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--surface);
  }
  .port {
    width: 90px;
  }
  footer {
    display: flex;
    gap: 16px;
    padding: 8px 16px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-secondary);
  }
</style>
