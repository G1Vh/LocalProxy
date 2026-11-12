// Mirrors crates/proxy-core/src/config.rs (serde camelCase).

export type OnOutboundDown = "block" | "direct";
export type MatchType = "exact" | "domainAndSubdomains" | "mask";
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
  preset?: string;
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
}

export interface AppInfo {
  version: string;
  configPath: string;
  warnings: string[];
  /** Why the proxy did not start at launch; null once it runs. */
  startError: string | null;
}
