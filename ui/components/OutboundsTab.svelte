<script lang="ts">
  import * as api from "../lib/api";
  import { newId, store } from "../lib/store.svelte";
  import type { Outbound, Probe } from "../lib/types";

  type Draft = {
    id: string;
    name: string;
    type: Outbound["type"];
    host: string;
    port: string;
    username: string;
    password: string;
    config: string;
  };

  let draft = $state<Draft | null>(null);
  let draftError = $state<string | null>(null);
  let showPassword = $state(false);
  let probes = $state<Record<string, { busy: boolean; result?: Probe; error?: string }>>({});

  const config = $derived(store.config!);

  const typeLabel = { http: "HTTP-прокси", socks5: "SOCKS5", awg: "WireGuard / AmneziaWG" } as const;

  function address(o: Outbound) {
    return o.type === "awg" ? "конфиг .conf" : `${o.host}:${o.port}${o.username ? " · с логином" : ""}`;
  }

  function startNew() {
    draftError = null;
    draft = {
      id: newId(),
      name: "",
      type: "http",
      host: "",
      port: "",
      username: "",
      password: "",
      config: "",
    };
  }

  function edit(o: Outbound) {
    draftError = null;
    draft = {
      id: o.id,
      name: o.name,
      type: o.type,
      host: o.type === "awg" ? "" : o.host,
      port: o.type === "awg" ? "" : String(o.port),
      username: o.type === "awg" ? "" : o.username,
      password: o.type === "awg" ? "" : o.password,
      config: o.type === "awg" ? o.config : "",
    };
  }

  function fromDraft(d: Draft): Outbound | string {
    const name = d.name.trim() || (d.type === "awg" ? "VPN" : d.host.trim());
    if (d.type === "awg") {
      if (!d.config.includes("[Interface]")) return "Вставьте содержимое .conf-файла WireGuard / AmneziaWG";
      return { id: d.id, name, type: "awg", config: d.config };
    }
    const host = d.host.trim();
    const port = Number(d.port);
    if (!host) return "Укажите адрес сервера";
    if (!Number.isInteger(port) || port < 1 || port > 65535) return "Порт — число от 1 до 65535";
    return {
      id: d.id,
      name: name || host,
      type: d.type,
      host,
      port,
      username: d.username,
      password: d.password,
    };
  }

  async function saveDraft() {
    if (!draft) return;
    const outbound = fromDraft(draft);
    if (typeof outbound === "string") {
      draftError = outbound;
      return;
    }
    await store.update((c) => {
      const i = c.outbounds.findIndex((o) => o.id === outbound.id);
      if (i >= 0) c.outbounds[i] = outbound;
      else c.outbounds.push(outbound);
      // The first profile becomes active right away.
      if (!c.activeOutboundId) c.activeOutboundId = outbound.id;
    });
    if (!store.error) draft = null;
  }

  function remove(o: Outbound) {
    store.update((c) => {
      c.outbounds = c.outbounds.filter((x) => x.id !== o.id);
      if (c.activeOutboundId === o.id) c.activeOutboundId = c.outbounds[0]?.id ?? null;
    });
  }

  async function test(o: Outbound) {
    probes[o.id] = { busy: true };
    try {
      probes[o.id] = { busy: false, result: await api.testOutbound(o) };
    } catch (e) {
      probes[o.id] = { busy: false, error: String(e) };
    }
  }

  async function testDraft() {
    if (!draft) return;
    const outbound = fromDraft(draft);
    if (typeof outbound === "string") {
      draftError = outbound;
      return;
    }
    draftError = null;
    await test(outbound);
  }

  async function loadConf(e: Event) {
    const file = (e.currentTarget as HTMLInputElement).files?.[0];
    if (file && draft) {
      draft.config = await file.text();
      if (!draft.name) draft.name = file.name.replace(/\.conf$/i, "");
    }
  }
</script>

{#snippet probeLine(id: string)}
  {@const p = probes[id]}
  {#if p?.busy}
    <span class="hint">проверяю…</span>
  {:else if p?.result}
    <span class="pill ok">
      работает · {p.result.latencyMs} мс{p.result.externalIp ? ` · внешний IP ${p.result.externalIp}` : ""}
    </span>
  {:else if p?.error}
    <span class="pill bad">{p.error}</span>
  {/if}
{/snippet}

<div class="stack">
  <div class="toolbar">
    <span class="hint">
      Через активный outbound идут все домены из правил и наборов. Активный выбирается вверху окна или
      здесь.
    </span>
    <span class="spacer"></span>
    <button class="primary" onclick={startNew} disabled={!!draft}>Добавить outbound</button>
  </div>

  {#if draft}
    <div class="card form">
      <h3>{config.outbounds.some((o) => o.id === draft!.id) ? "Изменить outbound" : "Новый outbound"}</h3>
      <div class="grid">
        <label>Название <input type="text" bind:value={draft.name} placeholder="Офис" /></label>
        <label>
          Тип
          <select bind:value={draft.type}>
            <option value="http">HTTP-прокси</option>
            <option value="socks5">SOCKS5</option>
            <option value="awg">WireGuard / AmneziaWG</option>
          </select>
        </label>
        {#if draft.type !== "awg"}
          <label>Адрес <input type="text" bind:value={draft.host} placeholder="proxy.example.com" /></label>
          <label>Порт <input type="text" inputmode="numeric" bind:value={draft.port} placeholder="8080" /></label>
          <label>Логин <input type="text" bind:value={draft.username} placeholder="необязательно" /></label>
          <label>
            Пароль
            <span class="pw">
              <input
                type={showPassword ? "text" : "password"}
                bind:value={draft.password}
                placeholder="необязательно"
              />
              <button class="small" onclick={() => (showPassword = !showPassword)}>
                {showPassword ? "Скрыть" : "Показать"}
              </button>
            </span>
          </label>
        {/if}
      </div>
      {#if draft.type === "awg"}
        <label class="conf">
          Конфигурация (.conf)
          <textarea rows="10" class="mono" bind:value={draft.config} placeholder={"[Interface]\nPrivateKey = …\n\n[Peer]\n…"}></textarea>
        </label>
        <div class="toolbar">
          <input type="file" accept=".conf,.txt" onchange={loadConf} />
          <span class="hint pill warn">Подключение через WireGuard / AmneziaWG появится на этапе 5 — пока профиль только сохраняется.</span>
        </div>
      {/if}
      {#if draftError}<div class="err">{draftError}</div>{/if}
      <div class="toolbar">
        {@render probeLine(draft.id)}
        <span class="spacer"></span>
        <button onclick={testDraft} disabled={draft.type === "awg" || probes[draft.id]?.busy}>Проверить</button>
        <button onclick={() => (draft = null)}>Отмена</button>
        <button class="primary" onclick={saveDraft} disabled={store.busy}>Сохранить</button>
      </div>
    </div>
  {/if}

  {#each config.outbounds as o (o.id)}
    {@const active = config.activeOutboundId === o.id}
    <div class="card item" class:active>
      <label class="radio">
        <input
          type="radio"
          name="active-outbound"
          checked={active}
          onchange={() => store.update((c) => (c.activeOutboundId = o.id))}
        />
        <span class="name">{o.name}</span>
      </label>
      <span class="pill">{typeLabel[o.type]}</span>
      <span class="hint mono">{address(o)}</span>
      <span class="spacer"></span>
      {@render probeLine(o.id)}
      <button class="small" onclick={() => test(o)} disabled={o.type === "awg" || probes[o.id]?.busy}>
        Проверить
      </button>
      <button class="small" onclick={() => edit(o)}>Изменить</button>
      <button class="small danger" onclick={() => remove(o)}>Удалить</button>
    </div>
  {:else}
    {#if !draft}
      <p class="hint">
        Outbound — это сервер, через который пойдут домены из правил: HTTP- или SOCKS5-прокси (позже —
        WireGuard / AmneziaWG). Добавьте хотя бы один.
      </p>
    {/if}
  {/each}
</div>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  h3 {
    margin: 0 0 8px;
    font-size: 14px;
    font-weight: 600;
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: 10px;
    max-width: 760px;
  }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px 16px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 13px;
    color: var(--text-secondary);
  }
  label input,
  label select,
  label textarea {
    color: var(--text);
  }
  .pw {
    display: flex;
    gap: 6px;
  }
  .pw input {
    flex: 1;
  }
  .conf textarea {
    font-size: 12.5px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .item.active {
    border-color: var(--accent);
  }
  .radio {
    flex-direction: row;
    align-items: center;
    gap: 8px;
    color: var(--text);
    font-size: 14px;
  }
  .name {
    font-weight: 600;
  }
  .err {
    color: var(--danger-text);
    font-size: 13px;
  }
</style>
