<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { ON_DOWN, THEMES } from "../lib/labels";
  import { store } from "../lib/store.svelte";
  import type { McpStatus, OnOutboundDown, Theme, TunInfo } from "../lib/types";

  const config = $derived(store.config!);
  let portInput = $state(String(store.config?.port ?? ""));
  let autostart = $state(false);
  let checking = $state(false);
  let tun = $state<TunInfo | null>(null);
  let checkResult = $state("");
  let mcp = $state<McpStatus | null>(null);

  // The server follows the config; its state is read after every change.
  $effect(() => {
    void config.mcp?.enabled;
    void config.mcp?.port;
    api.getMcpStatus().then((s) => (mcp = s)).catch(() => (mcp = null));
  });

  async function copyMcpCommand() {
    if (!mcp?.command) return;
    try {
      await navigator.clipboard.writeText(mcp.command);
      store.say("Команда скопирована: выполните её в терминале");
    } catch (e) {
      store.error = `Не удалось скопировать: ${e}`;
    }
  }

  onMount(() => {
    api.getAutostart().then((a) => (autostart = a)).catch((e) => (store.error = String(e)));
    const poll = () => api.getTunStatus().then((t) => (tun = t)).catch(() => (tun = null));
    poll();
    const timer = setInterval(poll, 3000);
    return () => clearInterval(timer);
  });

  $effect(() => {
    portInput = String(config.port);
  });

  function applyPort() {
    const port = Number(portInput);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      store.error = "Порт — число от 1 до 65535";
      portInput = String(config.port);
      return;
    }
    if (port !== config.port) store.update((c) => (c.port = port));
  }

  async function toggleAutostart() {
    const value = await store.run(() => api.setAutostart(!autostart));
    if (value !== undefined) autostart = value;
  }

  async function checkNow() {
    checking = true;
    checkResult = "";
    try {
      const update = await api.checkUpdate();
      store.newVersion = update;
      checkResult = update ? `Есть версия ${update.version}` : "У вас последняя версия";
    } catch (e) {
      checkResult = String(e);
    } finally {
      checking = false;
    }
  }
</script>

<div class="card settings">
  <div class="mode">
    <span>Режим</span>
    <label class="check">
      <input
        type="radio"
        name="mode"
        checked={config.tunEnabled}
        onchange={() => store.update((c) => (c.tunEnabled = true))}
        disabled={store.busy}
      />
      <span>
        Весь трафик (TUN)
        <span class="hint">— все программы; права администратора один раз</span>
        {#if config.tunEnabled && config.enabled && tun}
          <span class="hint tun-state">
            {tun.active
              ? `работает · TCP ${tun.stats.tcp}, UDP ${tun.stats.udp}, DNS ${tun.stats.dns}`
              : "запускается…"}
          </span>
        {/if}
      </span>
    </label>
    <label class="check">
      <input
        type="radio"
        name="mode"
        checked={!config.tunEnabled}
        onchange={() => store.update((c) => (c.tunEnabled = false))}
        disabled={store.busy}
      />
      <span>
        Системный прокси
        <span class="hint">— без прав администратора; только программы, которые умеют прокси</span>
      </span>
    </label>
  </div>
  <label class="row">
    <span>Порт</span>
    <input
      class="port"
      type="text"
      inputmode="numeric"
      bind:value={portInput}
      onchange={applyPort}
      disabled={store.busy}
    />
  </label>
  <label class="row">
    <span>Если канал недоступен</span>
    <select
      value={config.onOutboundDown}
      onchange={(e) =>
        store.update((c) => (c.onOutboundDown = e.currentTarget.value as OnOutboundDown))}
      disabled={store.busy}
    >
      {#each ON_DOWN as o}<option value={o.value}>{o.label}</option>{/each}
    </select>
  </label>
  <label class="row">
    <span>Тема</span>
    <select
      value={config.theme}
      onchange={(e) => store.update((c) => (c.theme = e.currentTarget.value as Theme))}
      disabled={store.busy}
    >
      {#each THEMES as t}<option value={t.value}>{t.label}</option>{/each}
    </select>
  </label>
  <label class="check">
    <input
      type="checkbox"
      checked={config.socks5Enabled}
      onchange={() => store.update((c) => (c.socks5Enabled = !c.socks5Enabled))}
      disabled={store.busy}
    />
    <span>
      Принимать SOCKS5 на том же порту
      <span class="hint">— для ручной настройки (Telegram, SSH)</span>
    </span>
  </label>
  <label class="check">
    <input
      type="checkbox"
      checked={config.notifications}
      onchange={() => store.update((c) => (c.notifications = !c.notifications))}
      disabled={store.busy}
    />
    <span>
      Уведомлять о падении и восстановлении каналов
    </span>
  </label>
  <label class="check">
    <input
      type="checkbox"
      checked={config.setEnvVars}
      onchange={() => store.update((c) => (c.setEnvVars = !c.setEnvVars))}
      disabled={store.busy}
    />
    <span>
      HTTP_PROXY / HTTPS_PROXY для консольных программ
      <span class="hint">— для запущенных после включения</span>
    </span>
  </label>
  <label class="check">
    <input type="checkbox" checked={autostart} onchange={toggleAutostart} />
    <span>Запускать с Windows (в трее)</span>
  </label>
  <div class="mcp">
    <label class="check">
      <input
        type="checkbox"
        checked={config.mcp?.enabled ?? false}
        onchange={() => store.update((c) => (c.mcp = { ...c.mcp, enabled: !c.mcp?.enabled }))}
        disabled={store.busy}
      />
      <span>
        Управление через MCP
        <span class="hint">— для ИИ-агентов вроде Claude Code: правила, наборы, каналы, лента подключений</span>
      </span>
    </label>
    {#if config.mcp?.enabled && mcp}
      <div class="row mcp-state">
        {#if mcp.error}
          <span class="row-error">{mcp.error}</span>
        {:else}
          <span class="hint mono ellipsis" title={mcp.url}>{mcp.running ? mcp.url : "запускается…"}</span>
        {/if}
        <button class="small" onclick={copyMcpCommand} disabled={!mcp.command}>Скопировать команду для Claude Code</button>
      </div>
    {/if}
  </div>
  <label class="check">
    <input
      type="checkbox"
      checked={config.checkUpdates}
      onchange={() => store.update((c) => (c.checkUpdates = !c.checkUpdates))}
      disabled={store.busy}
    />
    <span>
      Проверять обновления
      <span class="hint">— раз в 6 часов, установка по кнопке</span>
    </span>
  </label>
  <div class="row updates">
    <span class="hint">{checkResult}</span>
    <button onclick={checkNow} disabled={checking}>{checking ? "Проверка…" : "Проверить сейчас"}</button>
  </div>
</div>

<style>
  .settings {
    display: flex;
    flex-direction: column;
    gap: 10px;
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
    margin-top: 4px;
  }
  .port {
    width: 90px;
  }
  .tun-state {
    display: block;
  }
  .mcp {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .mcp-state {
    padding-left: 24px;
    min-width: 0;
  }
  .mode {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
</style>
