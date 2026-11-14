<script lang="ts">
  import { open, save } from "@tauri-apps/plugin-dialog";
  import * as api from "../lib/api";
  import { MATCH_TYPES } from "../lib/labels";
  import { newId, store, timeAgo } from "../lib/store.svelte";
  import type { MatchType, MergeReport, Rule } from "../lib/types";

  let filter = $state("");
  let pasteOpen = $state(false);
  let pasteText = $state("");
  let checkInput = $state("");
  let checkResult = $state<{ text: string; proxy: boolean } | null>(null);
  let newPattern = $state("");
  let newType = $state<MatchType>("domainAndSubdomains");
  let newRoute = $state("proxy");
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

  // A rule's route as one select value: "direct", "proxy" (default outbound)
  // or "proxy:<outbound id>".
  const routeOf = (r: Pick<Rule, "action" | "outbound">) =>
    r.action === "direct" ? "direct" : r.outbound ? `proxy:${r.outbound}` : "proxy";
  const fromRoute = (v: string): Pick<Rule, "action" | "outbound"> =>
    v === "direct"
      ? { action: "direct", outbound: null }
      : { action: "proxy", outbound: v.startsWith("proxy:") ? v.slice(6) : null };
  const defaultName = $derived(store.outboundName(config.activeOutboundId));

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
      ...fromRoute(newRoute),
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
    const via = store.outboundName(result.outboundId);
    const how = proxy ? (via ? `через «${via}»` : "через канал (не выбран)") : "напрямую";
    checkResult = {
      proxy,
      text: rule ? `${result.host} → ${how} (${rule})` : `${result.host} → напрямую`,
    };
  }
</script>

{#snippet routeOptions()}
  <option value="proxy">через канал{defaultName ? ` (${defaultName})` : ""}</option>
  {#each config.outbounds.filter((o) => o.id !== config.activeOutboundId) as o (o.id)}
    <option value={"proxy:" + o.id}>через «{o.name}»</option>
  {/each}
  <option value="direct">напрямую</option>
{/snippet}

<div class="stack">
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

  <div class="table-wrap edit-table">
  <table>
    <thead>
      <tr>
        <th class="c-on"></th>
        <th>Шаблон</th>
        <th class="c-type">Тип</th>
        <th class="c-action">Куда</th>
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
            placeholder="Домен, маска, подсеть или программа"
            bind:value={newPattern}
            class:invalid={!!newError}
            title={newError ?? ""}
            onkeydown={(e) => e.key === "Enter" && addRule()}
          />
          {#if newError}<div class="row-error">{newError}</div>{/if}
        </td>
        <td>
          <select bind:value={newType}>
            {#each MATCH_TYPES as t}<option value={t.value} title={t.hint}>{t.label}</option>{/each}
          </select>
        </td>
        <td>
          <select bind:value={newRoute}>
            {@render routeOptions()}
          </select>
        </td>
        <td class="c-comment"><input type="text" placeholder="Комментарий" bind:value={newComment} /></td>
        <td class="c-hits"></td>
        <td>
          <button
            class="primary small add"
            onclick={addRule}
            disabled={!newPattern.trim() || store.busy}
            title="Добавить правило"
            aria-label="Добавить правило">+</button
          >
        </td>
      </tr>
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
            {#if rowErrors[rule.id]}<div class="row-error">{rowErrors[rule.id]}</div>{/if}
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
              value={routeOf(rule)}
              class:direct={rule.action === "direct"}
              onchange={(e) => patch(rule.id, fromRoute(e.currentTarget.value))}
            >
              {@render routeOptions()}
            </select>
          </td>
          <td class="c-comment">
            <input
              type="text"
              value={rule.comment}
              onchange={(e) => patch(rule.id, { comment: e.currentTarget.value.trim() })}
            />
          </td>
          <td class="hint c-hits ellipsis">
            {#if stat}{stat.hits} · {timeAgo(stat.lastMs)}{/if}
          </td>
          <td>
            <button class="ghost small danger" onclick={() => remove(rule.id)} aria-label="Удалить правило">
              ✕
            </button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  </div>
  {#if config.rules.length === 0}
    <p class="hint">
      Правил нет. Добавьте домен или выберите готовый набор на вкладке «Наборы».
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
        По одному на строку: домен, ссылка, маска или подсеть. <code>*.example.com</code> — с поддоменами,
        после <code>#</code> — комментарий.
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

<svelte:window
  onkeydown={(e) => {
    if (e.key !== "Escape") return;
    pasteOpen = false;
  }}
/>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
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
  select.direct {
    color: var(--warning-text);
  }
  .c-on {
    width: 34px;
  }
  .c-type {
    width: 200px;
  }
  .add {
    width: 28px;
    padding: 0;
    font-size: 16px;
  }
  .c-action {
    width: 190px;
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
  /* Narrow window: comment and hit counts give way to the pattern. */
  @container (max-width: 1080px) {
    .c-comment,
    .c-hits {
      display: none;
    }
  }
  @container (max-width: 620px) {
    .c-type {
      width: 120px;
    }
    .c-action {
      width: 130px;
    }
  }
</style>
