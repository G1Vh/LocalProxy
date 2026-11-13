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

  const total = (via: boolean) =>
    rows.filter((r) => r.viaOutbound === via).reduce((s, r) => s + r.up + r.down, 0);

  async function reset() {
    await store.run(() => api.resetTraffic());
    rows = [];
  }
</script>

<div class="stack">
  <div class="totals">
    <div class="tile">
      <span class="hint">Через outbound</span>
      <span class="num">{bytes(total(true))}</span>
    </div>
    <div class="tile">
      <span class="hint">Напрямую через LocalProxy</span>
      <span class="num">{bytes(total(false))}</span>
    </div>
  </div>
  <div class="toolbar">
    <input type="search" placeholder="Фильтр по адресу" bind:value={filter} />
    <label class="check"><input type="checkbox" bind:checked={onlyOutbound} /> только через outbound</label>
    <span class="spacer"></span>
    <span class="hint">с запуска программы</span>
    <button onclick={reset} disabled={!rows.length}>Сбросить</button>
  </div>

  {#if shown.length}
    <table>
      <thead>
        <tr>
          <th>Адрес</th>
          <th class="c-via">Маршрут</th>
          <th class="c-num">Получено</th>
          <th class="c-num">Отправлено</th>
          <th class="c-num">Соединений</th>
          <th class="c-last">Последнее</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as r (r.host + r.viaOutbound + r.udp)}
          <tr>
            <td class="mono host">{r.host}</td>
            <td>
              <span class="pill" class:proxy={r.viaOutbound}>{r.viaOutbound ? "outbound" : "напрямую"}</span>
              {#if r.udp}<span class="pill" title="UDP через SOCKS5">UDP</span>{/if}
            </td>
            <td class="c-num">{bytes(r.down)}</td>
            <td class="c-num">{bytes(r.up)}</td>
            <td class="c-num">{r.connections}</td>
            <td class="hint">{timeAgo(r.lastMs)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="hint">
      {rows.length ? "Ничего не найдено." : "Пока пусто: трафик появится, когда через LocalProxy пойдут соединения."}
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
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  th {
    text-align: left;
    font-weight: 500;
    font-size: 12.5px;
    color: var(--text-secondary);
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  .host {
    overflow: hidden;
    text-overflow: ellipsis;
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
</style>
