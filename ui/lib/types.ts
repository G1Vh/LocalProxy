// Mirrors the Rust types (serde camelCase).

export type OnOutboundDown = "block" | "direct";
export type MatchType = "exact" | "domainAndSubdomains" | "mask" | "cidr";
export type RuleAction = "proxy" | "direct";

export interface ProxyEndpoint {
  host: string;
  port: number;
  username: string;
  password: string;
}

export type OutboundKind =
  | ({ type: "http" } & ProxyEndpoint)
  | ({ type: "socks5" } & ProxyEndpoint)
  | { type: "awg"; config: string };

export type Outbound = { id: string; name: string } & OutboundKind;

export interface Rule {
  id: string;
  enabled: boolean;
  pattern: string;
  matchType: MatchType;
  action: RuleAction;
  comment: string;
}

export interface Config {
  version: number;
  enabled: boolean;
  port: number;
  socks5Enabled: boolean;
  setEnvVars: boolean;
  onOutboundDown: OnOutboundDown;
  notifications: boolean;
  activeOutboundId: string | null;
  outbounds: Outbound[];
  rules: Rule[];
  /** Ids of selected presets; their entries apply from the current preset list. */
  presets: string[];
}

export interface AppInfo {
  version: string;
  configPath: string;
  warnings: string[];
  /** Why the proxy did not start at launch; null once it runs. */
  startError: string | null;
}

export type Inbound = "http" | "connect" | "socks5";
export type RouteKind = "direct" | "proxy" | "fallback" | "blocked" | "failed";

export interface ConnEvent {
  atMs: number;
  inbound: Inbound;
  host: string;
  port: number;
  route: RouteKind;
  ruleId: string | null;
  error: string | null;
}

export interface RuleStat {
  hits: number;
  lastMs: number;
}

export interface Probe {
  latencyMs: number;
  externalIp: string | null;
}

export interface HostCheck {
  host: string;
  action: RuleAction;
  ruleId: string | null;
}

export interface MergeReport {
  added: number;
  skipped: number;
  invalid: string[];
}

export interface RulesChange {
  config: Config;
  report: MergeReport;
}

export interface PresetEntry {
  /** Rule id used in connection events and hit counters. */
  id: string;
  pattern: string;
  matchType: MatchType;
}

export interface Preset {
  id: string;
  name: string;
  note: string | null;
  entries: PresetEntry[];
}

export interface PresetsInfo {
  revision: number;
  source: "bundled" | "cache" | "remote";
  lastError: string | null;
  presets: Preset[];
}

export interface ProxyExtension {
  browser: string;
  profile: string;
  extension: string;
  id: string;
}

export interface AwgStatus {
  outboundId: string;
  /** Unix seconds; 0 while the server has not answered. */
  lastHandshake: number;
  rx: number;
  tx: number;
}
