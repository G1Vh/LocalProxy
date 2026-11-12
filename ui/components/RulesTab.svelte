<script lang="ts">
  import { open, save } from "@tauri-apps/plugin-dialog";
  import * as api from "../lib/api";
  import { ACTIONS, MATCH_TYPES } from "../lib/labels";
  import { newId, store, timeAgo } from "../lib/store.svelte";
  import type { MatchType, MergeReport, Rule, RuleAction } from "../lib/types";

  let filter = $state("");
  let pasteOpen = $state(false);
  let pasteText = $state("");
  let checkInput = $state("");
  let checkResult = $state<{ text: string; proxy: boolean } | null>(null);
  let openNotes = $state<Record<string, boolean>>({});

  let newPattern = $state("");
  let newType = $state<MatchType>("domainAndSubdomains");
  let newAction = $state<RuleAction>("proxy");
  let newComment = $state("");
  let newError = $state<string | null>(null);

  let rowErrors = $state<Record<string, string>>({});

  const config = $derived(store.config!);
  const rules = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return config.rules;
    return config.rules.filter(
      (r) => r.pattern.includes(q) || r.comment.toLowerCase().includes(q),
    );
  });

  const presetSource = $derived(
    { remote: "с GitHub", cache: "сохранённый с GitHub", bundled: "встроенный" }[
      store.presets?.source ?? "bundled"
    ],
  );

  function presetHits(entries: { id: string }[]) {
    return entries.reduce((sum, e) => sum + (store.stats[e.id]?.hits ?? 0), 0);
  }

  function report(r: MergeReport) {
    const parts = [`добавлено ${r.added}`];
    if (r.skipped) parts.push(`уже были ${r.skipped}`);
    if (r.invalid.length) parts.push(`не распознано: ${r.invalid.join(", ")}`);
    store.say(parts.join(", "));
  }

  async function addRule() {
    newError = null;
    let pattern: string;
    try {
      pattern = await api.normalizePattern(newPattern, newType);
    } catch (e) {
      newError = String(e);
      return;
    }
    if (config.rules.some((r) => r.pattern === pattern && r.matchType === newType)) {
      newError = "Такое правило уже есть";
      return;
    }
    const rule: Rule = {
      id: newId(),
      enabled: true,
      pattern,
      matchType: newType,
      action: newAction,
      comment: newComment.trim(),
    };
    await store.update((c) => c.rules.unshift(rule));
    newPattern = "";
    newComment = "";
  }

  function patch(id: string, change: Partial<Rule>) {
    return store.update((c) => {
      const rule = c.rules.find((r) => r.id === id);
      if (rule) Object.assign(rule, change);
    });
  }

  async function commitPattern(rule: Rule, value: string, matchType = rule.matchType) {
    try {
      const pattern = await api.normalizePattern(value, matchType);
      delete rowErrors[rule.id];
      if (pattern !== rule.pattern || matchType !== rule.matchType) {
        await patch(rule.id, { pattern, matchType });
      }
    } catch (e) {
      rowErrors[rule.id] = String(e);
    }
  }

  function remove(id: string) {
    delete rowErrors[id];
    store.update((c) => (c.rules = c.rules.filter((r) => r.id !== id)));
  }

  async function togglePreset(id: string, selected: boolean) {
    const saved = await store.run(() => api.setPresetSelected(id, selected));
    if (saved) store.config = saved;
  }

  async function refreshPresets() {
    const info = await store.run(() => api.refreshPresets());
    if (!info) return;
    store.presets = info;
    if (info.lastError) store.error = `Список наборов не обновлён: ${info.lastError}`;
    else store.say(`Список наборов актуален, ревизия ${info.revision}`);
  }

  async function paste() {
    const change = await store.run(() => api.addRuleLines(pasteText));
    if (!change) return;
    store.config = change.config;
    report(change.report);
    pasteOpen = false;
    pasteText = "";
  }

  async function exportFile() {
    const path = await save({
      defaultPath: "localproxy-rules.json",
      filters: [{ name: "Правила LocalProxy", extensions: ["json"] }],
    });
    if (!path) return;
    const count = await store.run(() => api.exportRules(path));
    if (count !== undefined) store.say(`Сохранено правил: ${count}, наборов: ${config.presets.length}`);
  }

  async function importFile() {
    const path = await open({
      multiple: false,
      filters: [{ name: "Правила или список доменов", extensions: ["json", "txt", "lst"] }],
    });
    if (typeof path !== "string") return;
    const change = await store.run(() => api.importRules(path));
    if (!change) return;
    store.config = change.config;
    report(change.report);
  }

  async function check() {
    checkResult = null;
    if (!checkInput.trim()) return;
    const result = await store.run(() => api.checkHost(checkInput));
    if (!result) return;
    const rule = store.ruleLabel(result.ruleId);
    const proxy = result.action === "proxy";
    const how = proxy ? "через outbound" : "напрямую";
    checkResult = {
      proxy,
      text: rule ? `${result.host} → ${how} (правило ${rule})` : `${result.host} → напрямую (нет правила)`,
    };
  }
</script>

<div class="stack">
  <div class="card presets">
    <div class="toolbar">
      <h3>Наборы доменов</h3>
      <span class="hint">
        ревизия {store.presets?.revision ?? "—"}, {presetSource}. Отмеченные наборы обновляются сами.
      </span>
      <span class="spacer"></span>
      <button class="small" onclick={refreshPresets} disabled={store.busy}>Проверить обновления</button>
    </div>
    <div class="preset-list">
      {#each store.presets?.presets ?? [] as preset (preset.id)}
        {@const selected = config.presets.includes(preset.id)}
        <div class="preset" class:selected>
          <label>
            <input
              type="checkbox"
              checked={selected}
              onchange={() => togglePreset(preset.id, !selected)}
              disabled={store.busy}
            />
            <span class="name">{preset.name}</span>
          </label>
          <span class="hint">{preset.entries.length} зап.</span>
          {#if presetHits(preset.entries)}
            <span class="pill proxy">{presetHits(preset.entries)}</span>
          {/if}
          <button
            class="ghost small"
            onclick={() => (openNotes[preset.id] = !openNotes[preset.id])}
            aria-label="Подробнее">{openNotes[preset.id] ? "▴" : "▾"}</button
          >
          {#if openNotes[preset.id]}
            <div class="note">
              {#if preset.note}<p>{preset.note}</p>{/if}
              <p class="mono">{preset.entries.map((e) => e.pattern).join(", ")}</p>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  </div>

  <div class="toolbar">
    <input type="search" placeholder="Поиск по правилам" bind:value={filter} class="search" />
    <button onclick={() => (pasteOpen = true)}>Вставить списком</button>
    <button onclick={importFile} disabled={store.busy}>Импорт</button>
    <button onclick={exportFile} disabled={store.busy}>Экспорт</button>
    <span class="spacer"></span>
    <input
      type="search"
      placeholder="Проверить адрес: chatgpt.com"
      bind:value={checkInput}
      onkeydown={(e) => e.key === "Enter" && check()}
      class="check"
    />
    <button onclick={check}>Проверить</button>
  </div>
  {#if checkResult}
    <div class="check-result" class:proxy={checkResult.proxy}>{checkResult.text}</div>
  {/if}

  <table>
    <thead>
      <tr>
        <th class="c-on"></th>
        <th>Шаблон</th>
        <th class="c-type">Тип</th>
        <th class="c-action">Действие</th>
        <th class="c-comment">Комментарий</th>
        <th class="c-hits">Срабатывания</th>
        <th class="c-del"></th>
      </tr>
    </thead>
    <tbody>
      <tr class="new-row">
        <td></td>
        <td>
          <input
            type="text"
            placeholder="Новый домен, маска или подсеть"
            bind:value={newPattern}
            class:invalid={!!newError}
            title={newError ?? ""}
            onkeydown={(e) => e.key === "Enter" && addRule()}
          />
        </td>
        <td>
          <select bind:value={newType}>
            {#each MATCH_TYPES as t}<option value={t.value} title={t.hint}>{t.label}</option>{/each}
          </select>
        </td>
        <td>
          <select bind:value={newAction}>
            {#each ACTIONS as a}<option value={a.value}>{a.label}</option>{/each}
          </select>
        </td>
        <td><input type="text" placeholder="Комментарий" bind:value={newComment} /></td>
        <td colspan="2">
          <button class="primary small" onclick={addRule} disabled={!newPattern.trim() || store.busy}>
            Добавить
          </button>
        </td>
      </tr>
      {#if newError}
        <tr><td></td><td colspan="6" class="row-error">{newError}</td></tr>
      {/if}
      {#each rules as rule (rule.id)}
        {@const stat = store.stats[rule.id]}
        <tr class:disabled={!rule.enabled}>
          <td>
            <input
              type="checkbox"
              checked={rule.enabled}
              onchange={() => patch(rule.id, { enabled: !rule.enabled })}
              aria-label="Правило включено"
            />
          </td>
          <td>
            <input
              type="text"
              class="mono"
              value={rule.pattern}
              class:invalid={!!rowErrors[rule.id]}
              title={rowErrors[rule.id] ?? ""}
              onchange={(e) => commitPattern(rule, e.currentTarget.value)}
              onkeydown={(e) => e.key === "Enter" && e.currentTarget.blur()}
            />
          </td>
          <td>
            <select
              value={rule.matchType}
              onchange={(e) => commitPattern(rule, rule.pattern, e.currentTarget.value as MatchType)}
            >
              {#each MATCH_TYPES as t}<option value={t.value} title={t.hint}>{t.label}</option>{/each}
            </select>
          </td>
          <td>
            <select
              value={rule.action}
              class:direct={rule.action === "direct"}
              onchange={(e) => patch(rule.id, { action: e.currentTarget.value as RuleAction })}
            >
              {#each ACTIONS as a}<option value={a.value}>{a.label}</option>{/each}
            </select>
          </td>
          <td>
            <input
              type="text"
              value={rule.comment}
              onchange={(e) => patch(rule.id, { comment: e.currentTarget.value.trim() })}
            />
          </td>
          <td class="hint">
            {#if stat}{stat.hits} · {timeAgo(stat.lastMs)}{/if}
          </td>
          <td>
            <button class="ghost small danger" onclick={() => remove(rule.id)} aria-label="Удалить правило">
              ✕
            </button>
          </td>
        </tr>
        {#if rowErrors[rule.id]}
          <tr><td></td><td colspan="6" class="row-error">{rowErrors[rule.id]}</td></tr>
        {/if}
      {/each}
    </tbody>
  </table>
  {#if config.rules.length === 0}
    <p class="hint">
      Своих правил пока нет. Отметьте набор выше, добавьте домен в строке над таблицей или вставьте
      список.
    </p>
  {:else if rules.length === 0}
    <p class="hint">Ничего не найдено.</p>
  {/if}
</div>

{#if pasteOpen}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (pasteOpen = false)}>
    <div class="card dialog">
      <h2>Вставить списком</h2>
      <p class="hint">
        По одному на строку: домены, адреса из браузера, маски (cdn-*.example.net) или подсети
        (149.154.160.0/20). <code>*.example.com</code> означает домен вместе с поддоменами, после
        <code>#</code> — комментарий. Повторы пропускаются.
      </p>
      <textarea rows="12" bind:value={pasteText} placeholder={"chatgpt.com\nhttps://claude.ai/new\n*.githubcopilot.com"}></textarea>
      <div class="toolbar">
        <span class="spacer"></span>
        <button onclick={() => (pasteOpen = false)}>Отмена</button>
        <button class="primary" onclick={paste} disabled={!pasteText.trim() || store.busy}>Добавить</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  h3 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
  }
  .preset-list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    align-items: start;
    gap: 6px 12px;
    margin-top: 8px;
  }
  .preset {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    border-radius: 6px;
    border: 1px solid var(--border);
  }
  .preset.selected {
    border-color: var(--accent);
    background: var(--accent-bg);
  }
  .preset label {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1;
    min-width: 0;
  }
  .preset .name {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .note {
    flex-basis: 100%;
    font-size: 12.5px;
    color: var(--text-secondary);
  }
  .note p {
    margin: 4px 0;
    -webkit-user-select: text;
    user-select: text;
  }
  .search {
    width: 220px;
  }
  .check {
    width: 260px;
  }
  .check-result {
    padding: 6px 10px;
    border-radius: 6px;
    background: var(--surface-alt);
    font-size: 13px;
  }
  .check-result.proxy {
    background: var(--accent-bg);
    color: var(--accent);
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
    padding: 6px;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 3px 6px;
    border-bottom: 1px solid var(--border);
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  td input[type="text"],
  td select {
    width: 100%;
    height: 28px;
  }
  td input[type="text"]:not(:focus):not(.invalid),
  td select:not(:focus) {
    border-color: transparent;
    background: transparent;
  }
  tr:hover td input[type="text"]:not(:focus):not(.invalid),
  tr:hover td select:not(:focus) {
    border-color: var(--border);
  }
  .new-row td {
    background: var(--surface-alt);
  }
  .new-row input[type="text"],
  .new-row select {
    border-color: var(--border-strong) !important;
    background: var(--surface) !important;
  }
  tr.disabled td {
    opacity: 0.5;
  }
  select.direct {
    color: var(--warning-text);
  }
  .row-error {
    color: var(--danger-text);
    font-size: 12.5px;
  }
  .c-on {
    width: 34px;
  }
  .c-type {
    width: 185px;
  }
  .c-action {
    width: 160px;
  }
  .c-comment {
    width: 22%;
  }
  .c-hits {
    width: 130px;
  }
  .c-del {
    width: 40px;
  }
</style>
