<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { newId, store } from "../lib/store.svelte";
  import type { ForwardStatus, PortForward } from "../lib/types";

  const config = $derived(store.config!);
  const defaultName = $derived(store.outboundName(config.activeOutboundId));

  let status = $state<Record<string, ForwardStatus>>({});
  onMount(() => {
    const poll = () =>
      api
        .getForwardStatus()
        .then((list) => (status = Object.fromEntries(list.map((s) => [s.id, s]))))
        .catch(() => (status = {}));
    poll();
    const timer = setInterval(poll, 2000);
    return () => clearInterval(timer);
  });

  let newTarget = $state("");
  let newLocal = $state("");
  // The local port follows the target until the user types one.
  let localEdited = $state(false);
  let newOutbound = $state("");
  let newComment = $state("");
  let newError = $state<string | null>(null);
  let rowErrors = $state<Record<string, string>>({});

  /** "host:port", "[v6]:port" or "v6" with a port after the last colon. */
  function parseTarget(text: string): { host: string; port: number } | string {
    const t = text.trim().replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "");
    const m = t.match(/^\[([^\]]+)\]:(\d+)$/) ?? t.match(/^([^:\s]+):(\d+)$/);
    if (!m) return "Формат: сервер:порт";
    const port = Number(m[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return "Порт — число от 1 до 65535";
    return { host: m[1].toLowerCase(), port };
  }

  function checkLocal(port: number, id: string): string | null {
    if (!Number.isInteger(port) || port < 1 || port > 65535) return "Локальный порт — число от 1 до 65535";
    if (port === config.port) return `Порт ${port} — это порт LocalProxy`;
    if (config.forwards?.some((f) => f.id !== id && f.localPort === port))
      return `Порт ${port} уже занят пробросом`;
    return null;
  }

  /** A free-looking local port for a target port: 3306 → 13306. */
  function suggest(port: number): number {
    const taken = new Set([config.port, ...(config.forwards ?? []).map((f) => f.localPort)]);
    let p = port < 55536 ? port + 10000 : port;
    while (taken.has(p) && p < 65535) p++;
    return p;
  }

  $effect(() => {
    if (localEdited) return;
    const t = parseTarget(newTarget);
    newLocal = typeof t === "string" ? "" : String(suggest(t.port));
  });

  async function add() {
    newError = null;
    const t = parseTarget(newTarget);
    if (typeof t === "string") return void (newError = t);
    const local = newLocal ? Number(newLocal) : suggest(t.port);
    const bad = checkLocal(local, "");
    if (bad) return void (newError = bad);
    const forward: PortForward = {
      id: newId(),
      enabled: true,
      localPort: local,
      targetHost: t.host,
      targetPort: t.port,
      outbound: newOutbound || null,
      comment: newComment.trim(),
    };
    await store.update((c) => (c.forwards = [...(c.forwards ?? []), forward]));
    if (!store.error) {
      newTarget = newLocal = newComment = "";
      localEdited = false;
    }
  }

  function patch(id: string, change: Partial<PortForward>) {
    return store.update((c) => {
      const f = c.forwards?.find((x) => x.id === id);
      if (f) Object.assign(f, change);
    });
  }

  function setTarget(f: PortForward, text: string) {
    const t = parseTarget(text);
    if (typeof t === "string") return void (rowErrors[f.id] = t);
    delete rowErrors[f.id];
    if (t.host !== f.targetHost || t.port !== f.targetPort) patch(f.id, { targetHost: t.host, targetPort: t.port });
  }

  function setLocal(f: PortForward, text: string) {
    const port = Number(text);
    const bad = checkLocal(port, f.id);
    if (bad) return void (rowErrors[f.id] = bad);
    delete rowErrors[f.id];
    if (port !== f.localPort) patch(f.id, { localPort: port });
  }

  function remove(id: string) {
    delete rowErrors[id];
    store.update((c) => (c.forwards = (c.forwards ?? []).filter((f) => f.id !== id)));
  }

  const target = (f: PortForward) =>
    `${f.targetHost.includes(":") ? `[${f.targetHost}]` : f.targetHost}:${f.targetPort}`;
</script>

{#snippet outboundOptions()}
  <option value="">по умолчанию{defaultName ? ` (${defaultName})` : ""}</option>
  {#each config.outbounds.filter((o) => o.id !== config.activeOutboundId) as o (o.id)}
    <option value={o.id}>{o.name}</option>
  {/each}
{/snippet}

{#snippet stateCell(f: PortForward)}
  {@const s = status[f.id]}
  {#if !f.enabled}
    <span class="hint">выключен</span>
  {:else if !config.enabled}
    <span class="hint">LocalProxy выкл.</span>
  {:else if s?.state === "listening"}
    <span class="pill ok" title="Подключений с запуска">слушает{s.connections ? ` · ${s.connections}` : ""}</span>
  {:else if s?.state === "failed"}
    <span class="pill bad" title={s.reason}>{s.reason}</span>
  {:else}
    <span class="hint">запускается…</span>
  {/if}
{/snippet}

<div class="stack">
  <p class="hint intro">
    Для программ без прокси (Navicat, HeidiSQL, RDP, SSH): в программе укажите сервер
    <span class="mono">127.0.0.1</span> и порт из первой колонки — соединение уйдёт к серверу через канал.
  </p>

  <div class="table-wrap edit-table">
    <table>
      <thead>
        <tr>
          <th class="c-on"></th>
          <th class="c-local" title="Порт на 127.0.0.1 для программы">Порт</th>
          <th>Сервер</th>
          <th class="c-via">Через</th>
          <th class="c-state">Состояние</th>
          <th class="c-comment">Комментарий</th>
          <th class="c-del"></th>
        </tr>
      </thead>
      <tbody>
        <tr class="new-row">
          <td></td>
          <td>
            <input
              type="text"
              inputmode="numeric"
              placeholder="авто"
              bind:value={newLocal}
              oninput={() => (localEdited = newLocal !== "")}
            />
          </td>
          <td>
            <input
              type="text"
              placeholder="mysql.office.lan:3306"
              bind:value={newTarget}
              class:invalid={!!newError}
              onkeydown={(e) => e.key === "Enter" && add()}
            />
            {#if newError}<div class="row-error">{newError}</div>{/if}
          </td>
          <td class="c-via">
            <select bind:value={newOutbound}>{@render outboundOptions()}</select>
          </td>
          <td class="c-state">
            <button class="primary small" onclick={add} disabled={!newTarget.trim() || store.busy}>Добавить</button>
          </td>
          <td class="c-comment"><input type="text" placeholder="Комментарий" bind:value={newComment} /></td>
          <td></td>
        </tr>
        {#each config.forwards ?? [] as f (f.id)}
          <tr class:disabled={!f.enabled}>
            <td>
              <input
                type="checkbox"
                checked={f.enabled}
                onchange={() => patch(f.id, { enabled: !f.enabled })}
                aria-label="Проброс включён"
              />
            </td>
            <td>
              <input
                type="text"
                class="mono"
                inputmode="numeric"
                value={f.localPort}
                onchange={(e) => setLocal(f, e.currentTarget.value)}
                onkeydown={(e) => e.key === "Enter" && e.currentTarget.blur()}
                title={`127.0.0.1:${f.localPort}`}
              />
            </td>
            <td>
              <input
                type="text"
                class="mono"
                value={target(f)}
                class:invalid={!!rowErrors[f.id]}
                onchange={(e) => setTarget(f, e.currentTarget.value)}
                onkeydown={(e) => e.key === "Enter" && e.currentTarget.blur()}
              />
              {#if rowErrors[f.id]}<div class="row-error">{rowErrors[f.id]}</div>{/if}
            </td>
            <td class="c-via">
              <select
                value={f.outbound ?? ""}
                onchange={(e) => patch(f.id, { outbound: e.currentTarget.value || null })}
              >
                {@render outboundOptions()}
              </select>
            </td>
            <td class="c-state ellipsis">{@render stateCell(f)}</td>
            <td class="c-comment">
              <input
                type="text"
                value={f.comment}
                onchange={(e) => patch(f.id, { comment: e.currentTarget.value.trim() })}
              />
            </td>
            <td>
              <button class="ghost small danger" onclick={() => remove(f.id)} aria-label="Удалить проброс">✕</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if !(config.forwards ?? []).length}
    <p class="hint">
      Пробросов нет. Впишите сервер:порт выше — локальный порт подставится сам.
    </p>
  {/if}
</div>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .intro {
    margin: 0;
    max-width: 900px;
  }
  .c-on {
    width: 34px;
  }
  .c-local {
    width: 120px;
  }
  .c-via {
    width: 170px;
  }
  .c-state {
    width: 170px;
  }
  .c-comment {
    width: 20%;
  }
  .c-del {
    width: 40px;
  }
  @container (max-width: 820px) {
    .c-comment {
      display: none;
    }
  }
  @container (max-width: 620px) {
    .c-local {
      width: 80px;
    }
    .c-via,
    .c-state {
      width: 118px;
    }
  }
</style>
