<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { ON_DOWN } from "../lib/labels";
  import { store } from "../lib/store.svelte";
  import type { OnOutboundDown } from "../lib/types";

  const config = $derived(store.config!);
  let portInput = $state(String(store.config?.port ?? ""));
  let autostart = $state(false);
  let checking = $state(false);
  let checkResult = $state("");

  onMount(() => {
    api.getAutostart().then((a) => (autostart = a)).catch((e) => (store.error = String(e)));
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
    <span>Если outbound недоступен</span>
    <select
      value={config.onOutboundDown}
      onchange={(e) =>
        store.update((c) => (c.onOutboundDown = e.currentTarget.value as OnOutboundDown))}
      disabled={store.busy}
    >
      {#each ON_DOWN as o}<option value={o.value}>{o.label}</option>{/each}
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
      <span class="hint">— для программ, которые настраиваются вручную (Telegram, SSH)</span>
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
      Уведомлять, когда outbound падает и восстанавливается
      <span class="hint">— иконка в трее меняет цвет в любом случае</span>
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
      <span class="hint">— увидят только программы, запущенные после включения</span>
    </span>
  </label>
  <label class="check">
    <input type="checkbox" checked={autostart} onchange={toggleAutostart} />
    <span>Запускать при входе в Windows (свёрнутым в трей)</span>
  </label>
  <label class="check">
    <input
      type="checkbox"
      checked={config.checkUpdates}
      onchange={() => store.update((c) => (c.checkUpdates = !c.checkUpdates))}
      disabled={store.busy}
    />
    <span>
      Проверять обновления
      <span class="hint">— при запуске и раз в 6 часов; устанавливаются только по кнопке</span>
    </span>
  </label>
  <div class="row updates">
    <span class="hint">Версия {store.info?.version}{checkResult ? ` · ${checkResult}` : ""}</span>
    <button onclick={checkNow} disabled={checking}>{checking ? "Проверка…" : "Проверить сейчас"}</button>
  </div>
</div>

<style>
  .settings {
    max-width: 640px;
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
</style>
