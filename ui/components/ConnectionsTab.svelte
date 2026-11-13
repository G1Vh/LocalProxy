<script lang="ts">
  import * as api from "../lib/api";
  import { ROUTES } from "../lib/labels";
  import { store } from "../lib/store.svelte";
  import type { ConnEvent } from "../lib/types";
  import TrafficView from "./TrafficView.svelte";

  let view = $state<"feed" | "stats">("feed");

  let filter = $state("");
  let onlyNotable = $state(false);
  const SHOWN = 400;

  const events = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    return store.events
      .filter((e) => !onlyNotable || e.route !== "direct")
      .filter((e) => !q || e.host.includes(q))
      .slice(0, SHOWN);
  });

  const time = (ms: number) =>
    new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  const inbound = { http: "HTTP", connect: "HTTPS", socks5: "SOCKS5" } as const;

  async function addToRules(e: ConnEvent) {
    const change = await store.run(() => api.addRuleLines(e.host));
    if (!change) return;
    store.config = change.config;
    store.say(
      change.report.added
        ? `${e.host} добавлен в правила: пойдёт через outbound`
        : `${e.host} уже есть в правилах`,
    );
  }
</script>

<div class="switch">
  <button class:active={view === "feed"} onclick={() => (view = "feed")}>Лента</button>
  <button class:active={view === "stats"} onclick={() => (view = "stats")}>Статистика</button>
</div>

{#if view === "stats"}
  <TrafficView />
{:else}
<div class="stack">
  <div class="toolbar">
    <input type="search" placeholder="Фильтр по адресу" bind:value={filter} />
    <label class="check"
      ><input type="checkbox" bind:checked={onlyNotable} /> только outbound, блокировки и ошибки</label
    >
    <span class="spacer"></span>
    <span class="hint">{store.events.length} в ленте</span>
    <button onclick={() => (store.events = [])} disabled={!store.events.length}>Очистить</button>
  </div>

  {#if !store.config?.enabled}
    <p class="hint">Прокси выключен — подключений нет. Включите его переключателем вверху.</p>
  {:else if store.events.length === 0}
    <p class="hint">
      Пока пусто. Сюда попадают соединения, которые идут через LocalProxy: домены из правил (через
      PAC) и всё от программ, настроенных на него вручную или через HTTP_PROXY.
    </p>
  {/if}

  {#if events.length}
    <table>
      <tbody>
        {#each events as e, i (e.atMs + e.host + i)}
          {@const route = ROUTES[e.route]}
          <tr>
            <td class="c-time hint mono">{time(e.atMs)}</td>
            <td class="c-route"><span class="pill {route.css}">{route.label}</span></td>
            <td class="c-in hint">{inbound[e.inbound]}</td>
            <td class="c-host">
              <span class="mono">{e.host}:{e.port}</span>
              {#if store.ruleLabel(e.ruleId)}
                <span class="hint">· {store.ruleLabel(e.ruleId)}</span>
              {/if}
              {#if e.error}<div class="err">{e.error}</div>{/if}
            </td>
            <td class="c-act">
              {#if !e.ruleId}
                <button class="small" onclick={() => addToRules(e)} title="Отправлять этот адрес через outbound">
                  + в правила
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
{/if}

<style>
  .switch {
    display: inline-flex;
    margin-bottom: 12px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    overflow: hidden;
  }
  .switch button {
    border: none;
    border-radius: 0;
    height: 28px;
  }
  .switch button.active {
    background: var(--accent-bg);
    color: var(--accent);
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  td {
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  tr:last-child td {
    border-bottom: none;
  }
  .c-host {
    overflow: hidden;
    text-overflow: ellipsis;
    -webkit-user-select: text;
    user-select: text;
  }
  .err {
    color: var(--danger-text);
    font-size: 12px;
  }
  .c-time {
    width: 80px;
  }
  .c-route {
    width: 190px;
  }
  .c-in {
    width: 70px;
  }
  .c-act {
    width: 110px;
    text-align: right;
  }
</style>
