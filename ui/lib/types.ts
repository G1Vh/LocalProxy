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
  | { type: "awg"; config: string }
  | ({ type: "sstp" } & SstpEndpoint);

export interface SstpEndpoint {
  /** host or host:port, 443 by default */
  server: string;
  username: string;
  password: string;
  /** SHA-256 of a trusted (self-signed) server certificate; "" = Windows decides */
  certSha256: string;
  insecure: boolean;
}

export type Outbound = { id: string; name: string } & OutboundKind;

export interface Rule {
  id: string;
  enabled: boolean;
  pattern: string;
  matchType: MatchType;
  action: RuleAction;
  comment: string;
  /** For proxy rules: their own outbound; absent means the default one. */
  outbound?: string | null;
}

export interface Config {
  version: number;
  enabled: boolean;
  port: number;
  socks5Enabled: boolean;
  setEnvVars: boolean;
  onOutboundDown: OnOutboundDown;
  notifications: boolean;
  checkUpdates: boolean;
  /** The default outbound: for proxy rules without one of their own. */
  activeOutboundId: string | null;
  outbounds: Outbound[];
  rules: Rule[];
  /** Ids of selected presets; their entries apply from the current preset list. */
  presets: string[];
  /** Outbound per selected preset; a preset not listed uses the default. */
  presetOutbounds?: Record<string, string>;
  /** Local ports led to a fixed address through an outbound. */
  forwards?: PortForward[];
}

export interface AppInfo {
  version: string;
  configPath: string;
  warnings: string[];
  /** Why the proxy did not start at launch; null once it runs. */
  startError: string | null;
}

export type Inbound = "http" | "connect" | "socks5" | "udp" | "forward";
export type RouteKind = "direct" | "proxy" | "fallback" | "blocked" | "failed";

export interface ConnEvent {
  atMs: number;
  inbound: Inbound;
  host: string;
  port: number;
  route: RouteKind;
  ruleId: string | null;
  /** The outbound a proxy rule sent it to (or tried to). */
  outboundId: string | null;
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
  outboundId: string | null;
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

export interface TunnelStatus {
  outboundId: string;
  /** Unix seconds of the last sign of life from the server; 0 if none. */
  lastHandshake: number;
  rx: number;
  tx: number;
}

/** Overall verdict plus one per outbound in use (only "up" / "down" there). */
export interface PortForward {
  id: string;
  enabled: boolean;
  localPort: number;
  targetHost: string;
  targetPort: number;
  /** Absent or null: the default outbound. */
  outbound?: string | null;
  comment: string;
}

export type ForwardStatus = { id: string; connections: number } & (
  | { state: "starting" }
  | { state: "listening" }
  | { state: "failed"; reason: string }
);

export interface HealthState {
  overall: Health;
  outbounds: Record<string, Health>;
}

export type Health =
  | { state: "off" }
  | { state: "noOutbound" }
  | { state: "up" }
  | { state: "down"; reason: string };

export interface HostTraffic {
  host: string;
  viaOutbound: boolean;
  outboundId: string | null;
  udp: boolean;
  up: number;
  down: number;
  connections: number;
  lastMs: number;
}

export interface UpdateInfo {
  version: string;
  currentVersion: string;
  notes: string | null;
}

export interface UpdateProgress {
  downloaded: number;
  total: number | null;
}
