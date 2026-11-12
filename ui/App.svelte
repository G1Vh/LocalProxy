<script lang="ts">
  import { onMount } from "svelte";
  import { getAppInfo, getConfig, onConfigChanged, setEnabled } from "./lib/api";
  import type { AppInfo, Config } from "./lib/types";

  let config = $state<Config | null>(null);
  let info = $state<AppInfo | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);

  onMount(() => {
    const unlisten = onConfigChanged((c) => (config = c));
    Promise.all([getConfig(), getAppInfo()])
      .then(([c, i]) => {
        config = c;
        info = i;
      })
      .catch((e) => (error = String(e)));
    return () => {
      unlisten.then((off) => off());
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

  {#if info?.loadWarning}
    <div class="banner warning">
      Файл настроек был повреждён, он переименован в <code>config.json.broken</code>, загружены
      настройки по умолчанию. {info.loadWarning}
    </div>
  {/if}
  {#if error}
    <div class="banner error">{error}</div>
  {/if}

  <section class="placeholder">
    {#if config}
      <p>Правил: {config.rules.length}. Outbound-профилей: {config.outbounds.length}.</p>
      <p class="hint">Таблица правил и профили появятся на этапе 4.</p>
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
  .placeholder {
    flex: 1;
    padding: 16px;
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
