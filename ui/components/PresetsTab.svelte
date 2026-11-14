<script lang="ts">
  import * as api from "../lib/api";
  import { store, timeAgo } from "../lib/store.svelte";
  import type { Preset } from "../lib/types";

  const OTHER = "Другое";
  // A set this long gets a search box in its contents dialog.
  const SEARCH_FROM = 12;

  const config = $derived(store.config!);
  let filter = $state("");

  // Preset whose entries are shown in the dialog.
  let shownId = $state<string | null>(null);
  let entryFilter = $state("");
  const shown = $derived(store.presets?.presets.find((p) => p.id === shownId) ?? null);
  const shownEntries = $derived.by(() => {
    const q = entryFilter.trim().toLowerCase();
    const entries = shown?.entries ?? [];
    return q ? entries.filter((e) => e.pattern.includes(q)) : entries;
  });

  const all = $derived(store.presets?.presets ?? []);
  // Groups in the order the list first mentions them; a set matches the
  // filter by its name or any of its entries.
  const groups = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    const found = q
      ? all.filter((p) => p.name.toLowerCase().includes(q) || p.entries.some((e) => e.pattern.includes(q)))
      : all;
    const map = new Map<string, Preset[]>();
    for (const p of found) {
      const g = p.group || OTHER;
      map.set(g, [...(map.get(g) ?? []), p]);
    }
    return [...map];
  });

  const source = $derived(
    { remote: "с GitHub", cache: "сохранённый с GitHub", bundled: "встроенный" }[
      store.presets?.source ?? "bundled"
    ],
  );
  const defaultName = $derived(store.outboundName(config.activeOutboundId));

  function hits(p: Preset) {
    let total = 0;
    let last = 0;
    for (const e of p.entries) {
      const s = store.stats[e.id];
      if (!s) continue;
      total += s.hits;
      last = Math.max(last, s.lastMs);
    }
    return { total, last };
  }

  function entriesLabel(n: number) {
    const tens = n % 100;
    const ones = n % 10;
    if (tens >= 11 && tens <= 14) return `${n} записей`;
    if (ones === 1) return `${n} запись`;
    if (ones >= 2 && ones <= 4) return `${n} записи`;
    return `${n} записей`;
  }

  async function toggle(id: string, selected: boolean) {
    const saved = await store.run(() => api.setPresetSelected(id, selected));
    if (saved) store.config = saved;
  }

  function setOutbound(id: string, outbound: string) {
    store.update((c) => {
      const map = { ...(c.presetOutbounds ?? {}) };
      if (outbound) map[id] = outbound;
      else delete map[id];
      c.presetOutbounds = map;
    });
  }

  async function refresh() {
    const info = await store.run(() => api.refreshPresets());
    if (!info) return;
    store.presets = info;
    if (info.lastError) store.error = `Список наборов не обновлён: ${info.lastError}`;
    else store.say(`Список наборов актуален, ревизия ${info.revision}`);
  }

  function show(id: string) {
    entryFilter = "";
    shownId = id;
  }
</script>

<div class="stack">
  <div class="toolbar">
    <input type="search" placeholder="Поиск: название или домен" bind:value={filter} class="search" />
    <span class="hint">выбрано {config.presets.length} из {all.length}</span>
    <span class="spacer"></span>
    <span class="hint revision">ревизия {store.presets?.revision ?? "—"}, {source}</span>
    <button class="small" onclick={refresh} disabled={store.busy}>Проверить обновления</button>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th class="c-on"></th>
          <th>Набор</th>
          <th class="c-entries">Состав</th>
          <th class="c-outbound">Канал</th>
          <th class="c-hits">Срабатывания</th>
        </tr>
      </thead>
      <tbody>
        {#each groups as [group, presets] (group)}
          <tr class="group"><td colspan="5">{group}</td></tr>
          {#each presets as p (p.id)}
            {@const selected = config.presets.includes(p.id)}
            {@const h = hits(p)}
            <tr class:selected>
              <td>
                <input
                  type="checkbox"
                  checked={selected}
                  onchange={() => toggle(p.id, !selected)}
                  disabled={store.busy}
                  aria-label="Набор выбран"
                />
              </td>
              <td>
                <div class="name ellipsis" title={p.name}>{p.name}</div>
                {#if p.note}<div class="hint ellipsis note" title={p.note}>{p.note}</div>{/if}
              </td>
              <td class="c-entries">
                <button class="ghost small link" onclick={() => show(p.id)} title="Что входит в набор">
                  {entriesLabel(p.entries.length)}
                </button>
              </td>
              <td class="c-outbound">
                {#if selected && config.outbounds.length > 1}
                  <select
                    value={config.presetOutbounds?.[p.id] ?? ""}
                    onchange={(e) => setOutbound(p.id, e.currentTarget.value)}
                    disabled={store.busy}
                    title="Через какой канал идёт набор"
                  >
                    <option value="">по умолчанию{defaultName ? ` (${defaultName})` : ""}</option>
                    {#each config.outbounds as o (o.id)}<option value={o.id}>{o.name}</option>{/each}
                  </select>
                {:else if selected}
                  <span class="hint">{defaultName ?? "канал не выбран"}</span>
                {:else}
                  <span class="hint">—</span>
                {/if}
              </td>
              <td class="hint c-hits ellipsis">
                {#if h.total}{h.total} · {timeAgo(h.last)}{/if}
              </td>
            </tr>
          {/each}
        {/each}
      </tbody>
    </table>
  </div>
  {#if groups.length === 0}
    <p class="hint">Ничего не найдено.</p>
  {:else}
    <p class="hint">
      Отмеченные наборы обновляются сами: список доменов приходит с GitHub без обновления программы. Свои правила
      важнее наборов, так что исключение «напрямую» на вкладке «Правила» работает.
    </p>
  {/if}
</div>

<svelte:window onkeydown={(e) => e.key === "Escape" && (shownId = null)} />

{#if shown}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (shownId = null)}>
    <div class="card dialog preset-dialog">
      <div class="toolbar head">
        <h2 class="ellipsis" title={shown.name}>{shown.name}</h2>
        <span class="spacer"></span>
        <button class="ghost small" onclick={() => (shownId = null)} aria-label="Закрыть">✕</button>
      </div>
      {#if shown.note}<p class="hint note-full">{shown.note}</p>{/if}
      <div class="toolbar">
        <span class="hint">{entriesLabel(shown.entries.length)}</span>
        {#if shown.entries.length > SEARCH_FROM}
          <span class="spacer"></span>
          <input type="search" placeholder="Поиск в наборе" bind:value={entryFilter} class="entry-search" />
        {/if}
      </div>
      <ul class="entries">
        {#each shownEntries as e (e.id)}
          {@const n = store.stats[e.id]?.hits}
          <li>
            <span class="mono ellipsis" title={e.pattern}>{e.pattern}</span>
            {#if n}<span class="pill proxy">{n}</span>{/if}
          </li>
        {:else}
          <li class="hint">Ничего не найдено.</li>
        {/each}
      </ul>
    </div>
  </div>
{/if}

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .search {
    flex: 0 1 280px;
  }
  .table-wrap table {
    min-width: 0;
  }
  tr.group td {
    padding: 4px 10px;
    background: var(--surface-alt);
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  tr.selected td {
    background: color-mix(in srgb, var(--accent-bg) 60%, var(--surface));
  }
  .name {
    font-weight: 500;
  }
  .note {
    font-size: 12px;
    line-height: 1.3;
  }
  .link {
    color: var(--accent);
  }
  td select {
    width: 100%;
    height: 28px;
  }
  .c-on {
    width: 34px;
  }
  .c-entries {
    width: 120px;
  }
  .c-outbound {
    width: 200px;
  }
  .c-hits {
    width: 130px;
  }
  /* As small as its contents: a column of a few addresses. */
  .preset-dialog {
    width: min(400px, calc(100vw - 32px));
    gap: 8px;
  }
  .preset-dialog .head h2 {
    min-width: 0;
  }
  .entry-search {
    width: 160px;
  }
  .entries {
    max-height: min(420px, calc(100vh - 220px));
    overflow-y: auto;
    margin: 0;
    padding: 4px 0;
    list-style: none;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  .entries li {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    padding: 2px 2px;
    -webkit-user-select: text;
    user-select: text;
  }
  .entries li .mono {
    flex: 1;
  }
  .note-full {
    margin: 0;
    -webkit-user-select: text;
    user-select: text;
  }
  /* Narrow window: hit counts and the source give way first. */
  @container (max-width: 760px) {
    .c-hits,
    .revision {
      display: none;
    }
  }
  @container (max-width: 560px) {
    .c-entries {
      width: 96px;
    }
    .c-outbound {
      width: 140px;
    }
  }
</style>
