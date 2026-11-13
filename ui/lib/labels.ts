import type { MatchType, OnOutboundDown, RouteKind } from "./types";

export const MATCH_TYPES: { value: MatchType; label: string; hint: string }[] = [
  { value: "domainAndSubdomains", label: "домен и поддомены", hint: "openai.com → и api.openai.com" },
  { value: "exact", label: "только точно", hint: "ровно этот адрес" },
  { value: "mask", label: "маска", hint: "* — любые символы, ? — один" },
  { value: "cidr", label: "подсеть", hint: "149.154.160.0/20 — для адресов по IP" },
  { value: "process", label: "программа", hint: "discord.exe — весь трафик программы, в режиме TUN" },
];

/** File name of an exe path: C:\…\Discord.exe → Discord.exe. */
export function programName(path: string): string {
  return path.slice(Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/")) + 1);
}

export const ROUTES: Record<RouteKind, { label: string; css: string }> = {
  proxy: { label: "канал", css: "proxy" },
  direct: { label: "напрямую", css: "" },
  fallback: { label: "напрямую (сбой)", css: "warn" },
  blocked: { label: "заблокировано", css: "bad" },
  failed: { label: "ошибка", css: "bad" },
};

export const ON_DOWN: { value: OnOutboundDown; label: string }[] = [
  { value: "block", label: "блокировать эти домены" },
  { value: "direct", label: "пускать напрямую" },
];

export function bytes(n: number): string {
  if (n < 1024) return `${n} Б`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} КБ`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} МБ`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} ГБ`;
}
