<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { bytes } from "../lib/labels";
  import { store, timeAgo } from "../lib/store.svelte";
  import type { HostTraffic } from "../lib/types";

  let rows = $state<HostTraffic[]>([]);
  let filter = $state("");
  let onlyOutbound = $state(false);

  onMount(() => {
    const load = () =>
      api.getTraffic().then((r) => (rows = r)).catch((e) => (store.error = String(e)));
    load();
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
  });

  const shown = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    return rows.filter((r) => (!onlyOutbound || r.viaOutbound) && (!q || r.host.includes(q)));
  });

  const sum = (list: HostTraffic[]) => list.reduce((s, r) => s + r.up + r.down, 0);
  /** Per outbound with traffic, then direct. */
  const totals = $derived.by(() => {
    const ids = [...new Set(rows.filter((r) => r.outboundId).map((r) => r.outboundId!))];
    return [
      ...ids.map((id) => ({
        label: `Через «${store.outboundName(id) ?? "удалённый канал"}»`,
        bytes: sum(rows.filter((r) => r.outboundId === id)),
      })),
      { label: "Напрямую", bytes: sum(rows.filter((r) => !r.viaOutbound)) },
    ];
  });

  async function reset() {
    await store.run(() => api.resetTraffic());
    rows = [];
  }
</script>

<div class="stack">
  <div class="totals">
    {#each totals as t (t.label)}
      <div class="tile">
        <span class="hint">{t.label}</span>
        <span class="num">{bytes(t.bytes)}</span>
      </div>
    {/each}
  </div>
  <div class="toolbar">
    <input type="search" placeholder="Фильтр по адресу" bind:value={filter} />
    <label class="check"><input type="checkbox" bind:checked={onlyOutbound} /> только через каналы</label>
    <span class="spacer"></span>
    <span class="hint">с запуска</span>
    <button onclick={reset} disabled={!rows.length}>Сбросить</button>
  </div>

  {#if shown.length}
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Адрес</th>
          <th class="c-via">Маршрут</th>
          <th class="c-num">Получено</th>
          <th class="c-num">Отправлено</th>
          <th class="c-num c-conn">Соединений</th>
          <th class="c-last">Последнее</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as r (r.host + r.outboundId + r.udp)}
          <tr>
            <td class="mono host" title={r.host}>{r.host}</td>
            <td>
              <span class="pill via" class:proxy={r.viaOutbound}>
                {r.viaOutbound ? (store.outboundName(r.outboundId) ?? "канал") : "напрямую"}
              </span>
              {#if r.udp}<span class="pill" title="UDP через SOCKS5">UDP</span>{/if}
            </td>
            <td class="c-num">{bytes(r.down)}</td>
            <td class="c-num">{bytes(r.up)}</td>
            <td class="c-num c-conn">{r.connections}</td>
            <td class="hint c-last ellipsis">{timeAgo(r.lastMs)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {:else}
    <p class="hint">
      {rows.length ? "Ничего не найдено." : "Пока пусто."}
    </p>
  {/if}
</div>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .totals {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 10px;
  }
  .tile {
    display: flex;
    flex-direction: column;
    padding: 10px 14px;
    border-radius: 8px;
    background: var(--surface-alt);
  }
  .num {
    font-size: 20px;
    font-weight: 600;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
  }
  .host {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    -webkit-user-select: text;
    user-select: text;
  }
  .c-via {
    width: 150px;
  }
  .c-num {
    width: 100px;
    text-align: right;
  }
  .c-last {
    width: 120px;
  }
  .c-via {
    overflow: hidden;
    white-space: nowrap;
  }
  .via {
    max-width: calc(100% - 40px);
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: middle;
  }
  @container (max-width: 720px) {
    .c-conn,
    .c-last {
      display: none;
    }
    .c-num {
      width: 84px;
    }
  }
</style>
