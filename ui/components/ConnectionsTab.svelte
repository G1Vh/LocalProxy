<script lang="ts">
  import * as api from "../lib/api";
  import { programName, ROUTES } from "../lib/labels";
  import { hides, newId, store } from "../lib/store.svelte";
  import type { ConnEvent, HiddenEvent } from "../lib/types";
  import TrafficView from "./TrafficView.svelte";

  let view = $state<"feed" | "stats">("feed");

  let filter = $state("");
  let onlyNotable = $state(false);
  const SHOWN = 400;

  const events = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    return store.events
      .filter((e) => !onlyNotable || e.route !== "direct")
      .filter((e) => !q || e.host.includes(q) || !!e.process?.toLowerCase().includes(q))
      .slice(0, SHOWN);
  });

  const time = (ms: number) =>
    new Date(ms).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  const inbound = { http: "HTTP", connect: "HTTPS", socks5: "SOCKS5", udp: "UDP", forward: "порт" } as const;

  const hidden = $derived(store.config?.hiddenEvents ?? []);

  // The "Hide" dialog: which parts of the connection to match.
  let hideFor = $state<ConnEvent | null>(null);
  let hideProcess = $state(true);
  let hideHost = $state(true);
  let hidePort = $state(true);
  let hideErrorsOnly = $state(true);
  let hiddenOpen = $state(false);

  function openHide(e: ConnEvent) {
    hideFor = e;
    hideProcess = !!e.process;
    hideHost = true;
    hidePort = true;
    hideErrorsOnly = !!e.error;
  }

  async function confirmHide() {
    const e = hideFor;
    if (!e) return;
    const entry: HiddenEvent = { id: newId(), errorsOnly: hideErrorsOnly };
    if (hideProcess && e.process) entry.process = programName(e.process).toLowerCase();
    if (hideHost) entry.host = e.host.toLowerCase();
    if (hidePort) entry.port = e.port;
    const same = (h: HiddenEvent) =>
      h.process === entry.process && h.host === entry.host && h.port === entry.port && h.errorsOnly === entry.errorsOnly;
    hideFor = null;
    if (!hidden.some(same)) {
      await store.update((c) => (c.hiddenEvents ??= []).push(entry));
    }
    store.events = store.events.filter((x) => !hides(entry, x));
  }

  function unhide(id: string) {
    return store.update((c) => {
      c.hiddenEvents = (c.hiddenEvents ?? []).filter((h) => h.id !== id);
    });
  }

  /** "RustDesk.exe → access.example.com:21114", parts absent read as "any". */
  function describe(h: HiddenEvent): string {
    const where = h.host ? (h.port ? `${h.host}:${h.port}` : h.host) : h.port ? `порт ${h.port}` : "любой адрес";
    return `${h.process ?? "любая программа"} → ${where}`;
  }

  /** Adds the host, or the program (by file name), as a proxy rule. */
  async function addToRules(entry: string) {
    const change = await store.run(() => api.addRuleLines(entry));
    if (!change) return;
    store.config = change.config;
    store.say(change.report.added ? `${entry} добавлен в правила` : `${entry} уже в правилах`);
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
    <input type="search" placeholder="Фильтр по адресу или программе" bind:value={filter} />
    <label class="check"
      ><input type="checkbox" bind:checked={onlyNotable} /> без «напрямую»</label
    >
    <span class="spacer"></span>
    {#if hidden.length}
      <button class="link" onclick={() => (hiddenOpen = true)} title="Записи, скрытые из ленты">
        Скрыто: {hidden.length}
      </button>
    {/if}
    <span class="hint">{store.events.length}</span>
    <button onclick={() => (store.events = [])} disabled={!store.events.length}>Очистить</button>
  </div>

  {#if !store.config?.enabled}
    <p class="hint">LocalProxy выключен.</p>
  {:else if store.events.length === 0}
    <p class="hint">Пока пусто.</p>
  {/if}

  {#if events.length}
    <div class="table-wrap">
    <table>
      <tbody>
        {#each events as e, i (e.atMs + e.host + i)}
          {@const route = ROUTES[e.route]}
          {@const via = store.outboundName(e.outboundId)}
          <tr>
            <td class="c-time hint mono">{time(e.atMs)}</td>
            <td class="c-route">
            <span class="pill route {route.css}" title={via ? `канал «${via}»` : ""}>
              {e.route === "proxy" && via ? via : route.label}
            </span>
          </td>
            <td class="c-in hint">{inbound[e.inbound]}</td>
            <td class="c-proc" title={e.process ?? ""}>
              {#if e.process}
                {@const name = programName(e.process)}
                <span class="proc">{name}</span>
                {#if name.toLowerCase().endsWith(".exe")}
                  <button
                    class="small add-proc"
                    onclick={() => addToRules(name)}
                    title="Добавить программу в правила: весь её трафик пойдёт через канал"
                  >+</button>
                {/if}
              {/if}
            </td>
            <td class="c-host">
              <span class="mono">{e.host}:{e.port}</span>
              {#if store.ruleLabel(e.ruleId)}
                <span class="hint">· {store.ruleLabel(e.ruleId)}</span>
              {/if}
              {#if e.error}<div class="err">{e.error}</div>{/if}
            </td>
            <td class="c-act">
              <button class="small hide-btn" onclick={() => openHide(e)} title="Скрыть такие записи из ленты">
                Скрыть
              </button>
              {#if !e.ruleId && e.inbound !== "forward"}
                <button class="small" onclick={() => addToRules(e.host)} title="Добавить в правила">
                  + в правила
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {/if}
</div>
{/if}

{#if hideFor}
  {@const e = hideFor}
  <div class="overlay" role="presentation" onclick={(ev) => ev.target === ev.currentTarget && (hideFor = null)}>
    <div class="card dialog">
      <h2>Скрыть из ленты</h2>
      <p class="hint">
        Такие записи перестанут появляться в ленте. На маршрут, каналы и статистику это не влияет.
      </p>
      {#if e.process}
        <label class="check"
          ><input type="checkbox" bind:checked={hideProcess} /> программа <b>{programName(e.process)}</b></label
        >
      {/if}
      <label class="check"><input type="checkbox" bind:checked={hideHost} /> адрес <b>{e.host}</b></label>
      <label class="check"><input type="checkbox" bind:checked={hidePort} /> порт <b>{e.port}</b></label>
      <label class="check"><input type="checkbox" bind:checked={hideErrorsOnly} /> только ошибки</label>
      <div class="toolbar">
        <span class="spacer"></span>
        <button onclick={() => (hideFor = null)}>Отмена</button>
        <button
          class="primary"
          onclick={confirmHide}
          disabled={store.busy || !((hideProcess && e.process) || hideHost || hidePort)}>Скрыть</button
        >
      </div>
    </div>
  </div>
{/if}

{#if hiddenOpen}
  <div class="overlay" role="presentation" onclick={(ev) => ev.target === ev.currentTarget && (hiddenOpen = false)}>
    <div class="card dialog">
      <h2>Скрыто из ленты</h2>
      {#if hidden.length === 0}
        <p class="hint">Ничего не скрыто.</p>
      {:else}
        <table>
          <tbody>
            {#each hidden as h (h.id)}
              {@const hits = store.hiddenStats[h.id]?.hits ?? 0}
              <tr>
                <td class="mono">{describe(h)}</td>
                <td class="hint nowrap">
                  {h.errorsOnly ? "ошибки" : "все"}{hits ? ` · скрыто ${hits}` : ""}
                </td>
                <td class="c-unhide"><button class="small" onclick={() => unhide(h.id)}>Вернуть</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
      <div class="toolbar">
        <span class="spacer"></span>
        <button onclick={() => (hiddenOpen = false)}>Закрыть</button>
      </div>
    </div>
  </div>
{/if}

<svelte:window
  onkeydown={(ev) => {
    if (ev.key !== "Escape") return;
    hideFor = null;
    hiddenOpen = false;
  }}
/>

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
  td {
    vertical-align: top;
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
    white-space: nowrap;
  }
  .route {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: middle;
  }
  .c-route {
    width: 190px;
  }
  .c-in {
    width: 70px;
  }
  .c-proc {
    width: 150px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .proc {
    font-size: 12px;
  }
  .add-proc {
    visibility: hidden;
    margin-left: 4px;
    padding: 0 6px;
  }
  tr:hover .add-proc {
    visibility: visible;
  }
  .c-act {
    width: 180px;
    text-align: right;
    white-space: nowrap;
  }
  .hide-btn {
    visibility: hidden;
    margin-right: 4px;
  }
  tr:hover .hide-btn {
    visibility: visible;
  }
  .link {
    border: none;
    background: none;
    color: var(--accent);
    padding: 0 4px;
    height: auto;
  }
  .nowrap {
    white-space: nowrap;
  }
  .c-unhide {
    width: 90px;
    text-align: right;
  }
  @container (max-width: 640px) {
    .c-in {
      display: none;
    }
    .c-proc {
      width: 110px;
    }
    .c-route {
      width: 150px;
    }
    .c-act {
      width: 160px;
    }
  }
  @container (max-width: 520px) {
    .c-proc {
      display: none;
    }
  }
</style>
