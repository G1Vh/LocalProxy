<script lang="ts">
  import * as api from "../lib/api";
  import { newId, store } from "../lib/store.svelte";
  import { onMount } from "svelte";
  import type { Outbound, Probe, TunnelStatus } from "../lib/types";

  type Draft = {
    id: string;
    name: string;
    type: Outbound["type"];
    host: string;
    port: string;
    username: string;
    password: string;
    config: string;
    server: string;
    cert: "system" | "pin" | "none";
    certSha256: string;
  };

  let draft = $state<Draft | null>(null);
  let draftError = $state<string | null>(null);
  let showPassword = $state(false);
  let probes = $state<Record<string, { busy: boolean; result?: Probe; error?: string }>>({});

  const config = $derived(store.config!);

  // State of the running tunnel (WireGuard, SSTP), refreshed while the tab is open.
  let tunnels = $state<TunnelStatus[]>([]);
  onMount(() => {
    const poll = () =>
      api.getTunnelStatus().then((s) => (tunnels = s)).catch(() => (tunnels = []));
    poll();
    const timer = setInterval(poll, 3000);
    return () => clearInterval(timer);
  });

  function bytes(n: number) {
    if (n < 1024) return `${n} Б`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} КБ`;
    return `${(n / 1024 / 1024).toFixed(1)} МБ`;
  }

  const typeLabel = {
    http: "HTTP-прокси",
    socks5: "SOCKS5",
    awg: "WireGuard / AmneziaWG",
    sstp: "SSTP",
  } as const;

  function address(o: Outbound) {
    switch (o.type) {
      case "awg":
        return "конфиг .conf";
      case "sstp":
        return `${o.server} · ${o.username}`;
      default:
        return `${o.host}:${o.port}${o.username ? " · с логином" : ""}`;
    }
  }

  const isProxy = (t: Outbound["type"]) => t === "http" || t === "socks5";
  const HEX64 = /^[0-9a-f]{64}$/;
  const normalizeFingerprint = (s: string) => s.replace(/[\s:-]/g, "").toLowerCase();

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
      server: "",
      cert: "system",
      certSha256: "",
    };
  }

  function edit(o: Outbound) {
    draftError = null;
    draft = {
      id: o.id,
      name: o.name,
      type: o.type,
      host: isProxy(o.type) && "host" in o ? o.host : "",
      port: isProxy(o.type) && "port" in o ? String(o.port) : "",
      username: o.type === "awg" ? "" : o.username,
      password: o.type === "awg" ? "" : o.password,
      config: o.type === "awg" ? o.config : "",
      server: o.type === "sstp" ? o.server : "",
      cert: o.type !== "sstp" ? "system" : o.certSha256 ? "pin" : o.insecure ? "none" : "system",
      certSha256: o.type === "sstp" ? o.certSha256 : "",
    };
  }

  function fromDraft(d: Draft): Outbound | string {
    const name = d.name.trim() || (d.type === "awg" ? "VPN" : d.host.trim());
    if (d.type === "awg") {
      if (!d.config.includes("[Interface]")) return "Вставьте содержимое .conf-файла WireGuard / AmneziaWG";
      return { id: d.id, name, type: "awg", config: d.config };
    }
    if (d.type === "sstp") {
      const server = d.server.trim();
      if (!server) return "Укажите адрес SSTP-сервера";
      if (!d.username.trim()) return "Укажите логин";
      const pin = normalizeFingerprint(d.certSha256);
      if (d.cert === "pin" && !HEX64.test(pin)) return "Отпечаток SHA-256 — 64 шестнадцатеричных символа";
      return {
        id: d.id,
        name: d.name.trim() || server,
        type: "sstp",
        server,
        username: d.username.trim(),
        password: d.password,
        certSha256: d.cert === "pin" ? pin : "",
        insecure: d.cert === "none",
      };
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

  /** Rules and presets that name this outbound. */
  function usage(o: Outbound) {
    const rules = config.rules.filter((r) => r.action === "proxy" && r.outbound === o.id).length;
    const presets = Object.entries(config.presetOutbounds ?? {}).filter(
      ([p, id]) => id === o.id && config.presets.includes(p),
    ).length;
    return { rules, presets };
  }

  function usageText(o: Outbound) {
    const { rules, presets } = usage(o);
    const parts = [];
    if (rules) parts.push(`правил: ${rules}`);
    if (presets) parts.push(`наборов: ${presets}`);
    return parts.join(", ");
  }

  async function remove(o: Outbound) {
    const moved = usageText(o);
    await store.update((c) => {
      c.outbounds = c.outbounds.filter((x) => x.id !== o.id);
      if (c.activeOutboundId === o.id) c.activeOutboundId = c.outbounds[0]?.id ?? null;
    });
    if (moved && !store.error) store.say(`«${o.name}» удалён; ${moved} теперь идут через outbound по умолчанию`);
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

  /** The fingerprint an SSTP check reported for an untrusted certificate. */
  function reportedFingerprint(id: string): string | null {
    return probes[id]?.error?.match(/SHA-256: ([0-9A-F]{2}(?::[0-9A-F]{2}){31})/)?.[1] ?? null;
  }

  function trustReported(fp: string) {
    if (!draft) return;
    draft.cert = "pin";
    draft.certSha256 = fp;
    testDraft();
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
      Правила и наборы идут через outbound по умолчанию (отмечен кружком, выбирается и вверху окна) или
      через свой, если он указан в правиле. Подключены одновременно все используемые.
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
            <option value="sstp">SSTP</option>
          </select>
        </label>
        {#if draft.type === "sstp"}
          <label>Сервер <input type="text" bind:value={draft.server} placeholder="vpn.example.com или vpn.example.com:4443" /></label>
          <label>
            Сертификат сервера
            <select bind:value={draft.cert}>
              <option value="system">проверять (доверенный в Windows)</option>
              <option value="pin">доверять по отпечатку</option>
              <option value="none">не проверять</option>
            </select>
          </label>
          <label>Логин <input type="text" bind:value={draft.username} placeholder="user или DOMAIN\user" /></label>
          <label>
            Пароль
            <span class="pw">
              <input type={showPassword ? "text" : "password"} bind:value={draft.password} />
              <button class="small" onclick={() => (showPassword = !showPassword)}>
                {showPassword ? "Скрыть" : "Показать"}
              </button>
            </span>
          </label>
        {:else if draft.type !== "awg"}
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
          <span class="hint">Подходит и обычный WireGuard, и AmneziaWG (все версии маскировки). Туннель поднимается внутри LocalProxy: без драйвера и прав администратора, через него идут только домены из правил.</span>
        </div>
      {/if}
      {#if draft.type === "sstp"}
        {#if draft.cert === "pin"}
          <label class="conf">
            Отпечаток SHA-256 сертификата
            <input type="text" class="mono" bind:value={draft.certSha256} placeholder="AB:CD:…" />
          </label>
        {:else if draft.cert === "none"}
          <div class="hint">
            Без проверки сертификата кто-то посередине может выдать себя за сервер и узнать хэш пароля.
            Лучше доверять по отпечатку.
          </div>
        {/if}
        <div class="hint">
          Вход по MS-CHAPv2 или PAP; подходят Windows RRAS, MikroTik, SoftEther. Туннель поднимается внутри
          LocalProxy, без драйвера и прав администратора. Для самоподписанного сертификата нажмите
          «Проверить»: программа покажет его отпечаток и предложит ему доверять.
        </div>
      {/if}
      {#if draftError}<div class="err">{draftError}</div>{/if}
      <div class="toolbar">
        {@render probeLine(draft.id)}
        {#if draft.type === "sstp" && reportedFingerprint(draft.id)}
          {@const fp = reportedFingerprint(draft.id)!}
          <button class="small" onclick={() => trustReported(fp)}>Доверять этому сертификату</button>
        {/if}
        <span class="spacer"></span>
        <button onclick={testDraft} disabled={probes[draft.id]?.busy}>Проверить</button>
        <button onclick={() => (draft = null)}>Отмена</button>
        <button class="primary" onclick={saveDraft} disabled={store.busy}>Сохранить</button>
      </div>
    </div>
  {/if}

  {#each config.outbounds as o (o.id)}
    {@const active = config.activeOutboundId === o.id}
    {@const health = config.enabled ? store.health.outbounds[o.id] : undefined}
    {@const tunnel = tunnels.find((t) => t.outboundId === o.id)}
    <div class="card item" class:active>
      <label class="radio">
        <input
          type="radio"
          name="active-outbound"
          title="Outbound по умолчанию: для правил и наборов без своего"
          checked={active}
          onchange={() => store.update((c) => (c.activeOutboundId = o.id))}
        />
        <span class="name">{o.name}</span>
        {#if active}<span class="hint">по умолчанию</span>{/if}
      </label>
      <span class="pill">{typeLabel[o.type]}</span>
      <span class="hint mono">{address(o)}</span>
      {#if usageText(o)}<span class="hint" title="Правила и наборы с этим outbound">{usageText(o)}</span>{/if}
      {#if health?.state === "up"}
        <span class="pill ok">работает</span>
      {:else if health?.state === "down"}
        <span class="pill bad" title={health.reason}>недоступен</span>
      {/if}
      {#if tunnel}
        {@const ago = tunnel.lastHandshake ? Math.round(Date.now() / 1000 - tunnel.lastHandshake) : null}
        {@const fresh = ago !== null && ago < (o.type === "awg" ? 180 : 60)}
        <span class="pill {fresh ? 'ok' : 'warn'}" title="Состояние туннеля">
          {#if o.type === "awg"}
            {ago === null ? "сервер пока не ответил" : `рукопожатие ${ago} с назад`}
          {:else}
            {fresh ? "подключено" : "нет связи с сервером, переподключение"}
          {/if}
          · ↓ {bytes(tunnel.rx)} ↑ {bytes(tunnel.tx)}
        </span>
      {/if}
      <span class="spacer"></span>
      {@render probeLine(o.id)}
      <button class="small" onclick={() => test(o)} disabled={probes[o.id]?.busy}>
        Проверить
      </button>
      <button class="small" onclick={() => edit(o)}>Изменить</button>
      <button class="small danger" onclick={() => remove(o)}>Удалить</button>
    </div>
  {:else}
    {#if !draft}
      <p class="hint">
        Outbound — это сервер, через который пойдут домены из правил: HTTP- или SOCKS5-прокси, VPN
        WireGuard / AmneziaWG или SSTP. Добавьте хотя бы один.
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
