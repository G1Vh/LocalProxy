<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "./lib/api";
  import { store } from "./lib/store.svelte";
  import RulesTab from "./components/RulesTab.svelte";
  import PresetsTab from "./components/PresetsTab.svelte";
  import ConnectionsTab from "./components/ConnectionsTab.svelte";
  import OutboundsTab from "./components/OutboundsTab.svelte";
  import SettingsTab from "./components/SettingsTab.svelte";
  import PortsTab from "./components/PortsTab.svelte";

  type Tab = "rules" | "presets" | "ports" | "connections" | "outbounds" | "settings";
  let tab = $state<Tab>("rules");

  onMount(() => {
    let cleanup: (() => void) | undefined;
    store.init().then((off) => (cleanup = off));
    return () => cleanup?.();
  });

  const config = $derived(store.config);
  const active = $derived(config?.outbounds.find((o) => o.id === config.activeOutboundId));
  const presetCount = $derived(config?.presets.length ?? 0);
  // The window frame follows from Rust; this covers the page right away.
  $effect(() => {
    const theme = config?.theme;
    if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  });
  // Port forwards are for proxy mode: in TUN every program reaches servers itself.
  $effect(() => {
    if (config?.tunEnabled && tab === "ports") tab = "rules";
  });
  const downCount = $derived(
    Object.values(store.health.outbounds).filter((h) => h.state === "down").length,
  );

  async function toggle() {
    if (!config) return;
    const saved = await store.run(() => api.setEnabled(!config.enabled));
    if (saved) store.config = saved;
  }

  const progress = $derived.by(() => {
    const p = store.updateProgress;
    if (!p) return "";
    const mb = (n: number) => (n / 1048576).toFixed(1);
    return p.total
      ? `Скачивается: ${Math.round((p.downloaded / p.total) * 100)}%`
      : `Скачивается: ${mb(p.downloaded)} МБ`;
  });

  function selectOutbound(id: string) {
    store.update((c) => (c.activeOutboundId = id || null));
  }
</script>

<main>
  <header>
    <span class="title">LocalProxy</span>
    {#if config}
      {@const h = store.health.overall}
      {@const mode = config.tunEnabled ? "TUN" : "Прокси"}
      <span
        class="pill status"
        class:ok={config.enabled && h.state === "up"}
        class:warn={config.enabled && h.state !== "up"}
        title={h.state === "down" ? h.reason : ""}
      >
        {#if !config.enabled}
          Выключен
        {:else if h.state === "up"}
          {mode} · {Object.keys(store.health.outbounds).length > 1 ? "каналы работают" : "канал работает"}
        {:else if h.state === "down"}
          {mode} · {downCount > 1 ? `недоступно каналов: ${downCount}` : "канал недоступен"}
        {:else if h.state === "noOutbound"}
          {mode} · канал не выбран
        {:else}
          {mode} · 127.0.0.1:{config.port}
        {/if}
      </span>
      <div class="controls">
      <label class="outbound-pick">
        <span class="hint" title="Для правил и наборов без своего канала">По умолчанию</span>
        <select
          value={config.activeOutboundId ?? ""}
          onchange={(e) => selectOutbound(e.currentTarget.value)}
          disabled={store.busy}
        >
          <option value="">— не выбран —</option>
          {#each config.outbounds as o (o.id)}
            <option value={o.id}>{o.name}</option>
          {/each}
        </select>
      </label>
      <span class="hint">{config.enabled ? "Вкл" : "Выкл"}</span>
      <button
        class="toggle"
        class:off={!config.enabled}
        onclick={toggle}
        disabled={store.busy}
        aria-label="Включить или выключить проксирование"
        aria-pressed={config.enabled}
      >
        <span></span>
      </button>
      </div>
    {/if}
  </header>

  {#each store.info?.warnings ?? [] as warning}
    <div class="banner warning">{warning}</div>
  {/each}
  {#if store.browserWarnings.length}
    {@const tun = config?.tunEnabled}
    <div class="banner {tun ? 'info' : 'warning'}">
      <span>
        {#each store.browserWarnings as w, i}
          {i ? "; " : ""}{w.browser} ({w.profile}): «{w.extension}»
        {/each}
        {#if tun}
          — ведёт часть сайтов через свой прокси, для этих сайтов правила LocalProxy не действуют.
        {:else}
          — расширение перехватывает прокси, правила LocalProxy в этом браузере не действуют.
        {/if}
      </span>
    </div>
  {/if}
  {#if config?.enabled && store.health.overall.state === "down"}
    <div class="banner warning">
      {downCount > 1 ? "Недоступны" : "Недоступен"}: {store.health.overall.reason}. Домены
      {config.onOutboundDown === "block" ? "блокируются" : "идут напрямую"}.
    </div>
  {/if}
  {#if config?.enabled && !active}
    <div class="banner warning">
      Канал по умолчанию не выбран — правила без своего канала {config.onOutboundDown === "block"
        ? "блокируются"
        : "идут напрямую"}.
    </div>
  {/if}
  {#if store.newVersion}
    <div class="banner notice">
      <span>
        Доступна версия {store.newVersion.version}.
        {#if progress}{progress}…{/if}
      </span>
      {#if !store.updateProgress}
        <button class="small" onclick={() => store.installUpdate()}>Обновить</button>
      {/if}
    </div>
  {/if}
  {#if store.error}
    <div class="banner error">
      <span>{store.error}</span>
      <button class="ghost small" onclick={() => (store.error = null)} aria-label="Скрыть">✕</button>
    </div>
  {/if}
  {#if store.notice}
    <div class="banner notice">{store.notice}</div>
  {/if}

  <nav>
    <button class:active={tab === "rules"} onclick={() => (tab = "rules")}>
      Правила <span class="count">{config?.rules.length ?? 0}</span>
    </button>
    <button class:active={tab === "presets"} onclick={() => (tab = "presets")}>
      Наборы {#if presetCount}<span class="count" title="выбрано">{presetCount}</span>{/if}
    </button>
    {#if !config?.tunEnabled}
      <button class:active={tab === "ports"} onclick={() => (tab = "ports")}>
        Порты {#if config?.forwards?.length}<span class="count">{config.forwards.length}</span>{/if}
      </button>
    {/if}
    <button class:active={tab === "connections"} onclick={() => (tab = "connections")}>
      Подключения
    </button>
    <button class:active={tab === "outbounds"} onclick={() => (tab = "outbounds")}>
      Каналы <span class="count">{config?.outbounds.length ?? 0}</span>
    </button>
    <button class:active={tab === "settings"} onclick={() => (tab = "settings")}>Настройки</button>
  </nav>

  <section class="content">
    {#if !config}
      {#if !store.error}<p class="hint">Загрузка…</p>{/if}
    {:else if tab === "rules"}
      <RulesTab />
    {:else if tab === "presets"}
      <PresetsTab />
    {:else if tab === "ports"}
      <PortsTab />
    {:else if tab === "connections"}
      <ConnectionsTab />
    {:else if tab === "outbounds"}
      <OutboundsTab />
    {:else}
      <SettingsTab />
    {/if}
  </section>

  <footer>
    {#if store.info}
      <span>v{store.info.version}</span>
      <span title={store.info.configPath}>Конфиг: <code>{store.info.configPath}</code></span>
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
    flex-wrap: wrap;
    gap: 8px 10px;
    padding: 10px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .title {
    font-weight: 600;
    font-size: 16px;
  }
  .status {
    min-width: 0;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .controls {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-left: auto;
  }
  .outbound-pick {
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }
  .outbound-pick select {
    width: 180px;
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
  .toggle:hover:not(:disabled) {
    background: var(--success-text);
  }
  .toggle.off,
  .toggle.off:hover:not(:disabled) {
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
  .banner {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 10px 16px 0;
    padding: 6px 12px;
    border-radius: var(--radius);
    font-size: 13px;
  }
  .banner span {
    flex: 1;
  }
  .banner.warning {
    background: var(--warning-bg);
    color: var(--warning-text);
  }
  .banner.error {
    border: 1px solid var(--danger-text);
    color: var(--danger-text);
  }
  .banner.info {
    background: var(--surface-alt);
    color: var(--text-secondary);
  }
  .banner.notice {
    background: var(--success-bg);
    color: var(--success-text);
  }
  nav {
    display: flex;
    gap: 2px;
    padding: 8px 16px 0;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    scrollbar-width: none;
  }
  nav button {
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    background: transparent;
    color: var(--text-secondary);
    height: 34px;
  }
  nav button.active {
    color: var(--text);
    border-bottom-color: var(--accent);
  }
  .count {
    font-size: 12px;
    color: var(--text-secondary);
    margin-left: 2px;
  }
  .content {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 14px 16px;
    /* Tabs adapt their tables to this width. */
    container-type: inline-size;
  }
  footer {
    display: flex;
    gap: 16px;
    padding: 6px 16px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-secondary);
    white-space: nowrap;
  }
  footer span {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
</style>
