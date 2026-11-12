<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "./lib/api";
  import { store } from "./lib/store.svelte";
  import RulesTab from "./components/RulesTab.svelte";
  import ConnectionsTab from "./components/ConnectionsTab.svelte";
  import OutboundsTab from "./components/OutboundsTab.svelte";
  import SettingsTab from "./components/SettingsTab.svelte";

  type Tab = "rules" | "connections" | "outbounds" | "settings";
  let tab = $state<Tab>("rules");

  onMount(() => {
    let cleanup: (() => void) | undefined;
    store.init().then((off) => (cleanup = off));
    return () => cleanup?.();
  });

  const config = $derived(store.config);
  const active = $derived(config?.outbounds.find((o) => o.id === config.activeOutboundId));
  const presetCount = $derived(config?.presets.length ?? 0);

  async function toggle() {
    if (!config) return;
    const saved = await store.run(() => api.setEnabled(!config.enabled));
    if (saved) store.config = saved;
  }

  function selectOutbound(id: string) {
    store.update((c) => (c.activeOutboundId = id || null));
  }
</script>

<main>
  <header>
    <span class="title">LocalProxy</span>
    {#if config}
      <span class="pill" class:ok={config.enabled}>
        {config.enabled ? `Включён · 127.0.0.1:${config.port}` : "Выключен"}
      </span>
      <span class="spacer"></span>
      <label class="outbound-pick">
        <span class="hint">Outbound</span>
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
    {/if}
  </header>

  {#each store.info?.warnings ?? [] as warning}
    <div class="banner warning">{warning}</div>
  {/each}
  {#if store.browserWarnings.length}
    <div class="banner warning">
      <span>
        {#each store.browserWarnings as w, i}
          {i ? "; " : ""}{w.browser} ({w.profile}): расширение «{w.extension}»
        {/each}
        — {store.browserWarnings.length > 1 ? "задают" : "задаёт"} свой прокси. Пока
        {store.browserWarnings.length > 1 ? "они включены" : "оно включено"}, браузер не применяет
        правила LocalProxy: расширения важнее настроек Windows. Отключите в списке расширений браузера,
        если хотите, чтобы работали правила LocalProxy.
      </span>
    </div>
  {/if}
  {#if config?.enabled && !active}
    <div class="banner warning">
      Outbound не выбран: домены из правил {config.onOutboundDown === "block"
        ? "блокируются"
        : "идут напрямую"}. Добавьте его на вкладке «Outbound».
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
      Правила <span class="count">{config?.rules.length ?? 0} + {presetCount} набор.</span>
    </button>
    <button class:active={tab === "connections"} onclick={() => (tab = "connections")}>
      Подключения
    </button>
    <button class:active={tab === "outbounds"} onclick={() => (tab = "outbounds")}>
      Outbound <span class="count">{config?.outbounds.length ?? 0}</span>
    </button>
    <button class:active={tab === "settings"} onclick={() => (tab = "settings")}>Настройки</button>
  </nav>

  <section class="content">
    {#if !config}
      {#if !store.error}<p class="hint">Загрузка…</p>{/if}
    {:else if tab === "rules"}
      <RulesTab />
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
      <span>Настройки: <code>{store.info.configPath}</code></span>
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
    padding: 10px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .title {
    font-weight: 600;
    font-size: 16px;
  }
  .outbound-pick {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .outbound-pick select {
    min-width: 160px;
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
  .banner.notice {
    background: var(--success-bg);
    color: var(--success-text);
  }
  nav {
    display: flex;
    gap: 2px;
    padding: 8px 16px 0;
    border-bottom: 1px solid var(--border);
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
    overflow: auto;
    padding: 14px 16px;
  }
  footer {
    display: flex;
    gap: 16px;
    padding: 6px 16px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-secondary);
  }
</style>
