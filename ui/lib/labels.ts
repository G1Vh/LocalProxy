import type { MatchType, OnOutboundDown, RouteKind, RuleAction } from "./types";

export const MATCH_TYPES: { value: MatchType; label: string; hint: string }[] = [
  { value: "domainAndSubdomains", label: "домен и поддомены", hint: "openai.com → и api.openai.com" },
  { value: "exact", label: "только точно", hint: "ровно этот адрес" },
  { value: "mask", label: "маска", hint: "* — любые символы, ? — один" },
  { value: "cidr", label: "подсеть", hint: "149.154.160.0/20, для программ, идущих по IP" },
];

export const ACTIONS: { value: RuleAction; label: string }[] = [
  { value: "proxy", label: "через outbound" },
  { value: "direct", label: "напрямую" },
];

export const ROUTES: Record<RouteKind, { label: string; css: string }> = {
  proxy: { label: "outbound", css: "proxy" },
  direct: { label: "напрямую", css: "" },
  fallback: { label: "напрямую (outbound упал)", css: "warn" },
  blocked: { label: "заблокировано", css: "bad" },
  failed: { label: "ошибка", css: "bad" },
};

export const ON_DOWN: { value: OnOutboundDown; label: string }[] = [
  { value: "block", label: "блокировать эти домены" },
  { value: "direct", label: "пускать напрямую" },
];

export const matchTypeLabel = (t: MatchType) =>
  MATCH_TYPES.find((m) => m.value === t)?.label ?? t;
