export type SentinelMode = "audit" | "lockdown";

export interface DenyPolicy {
  media: boolean;
  webrtc: boolean;
  clipboardRead: boolean;
  filePickers: boolean;
  hardware: boolean;
  payments: boolean;
  webauthn: boolean;
  geolocation: boolean;
  notifications: boolean;
}

export interface PolicyConfig {
  mode: SentinelMode;
  stackSampleRate: number;
  deny: DenyPolicy;
}

export interface RunOptions {
  headless: boolean;
  waitTime: number;
  policy: PolicyConfig;
}

export type AvEvent = Record<string, any>;

export interface ContextNode {
  id: string;
  kind: "page" | "frame" | "popup" | "worker" | "shared_worker" | "service_worker";
  url: string;
  parentId?: string;
  depth: number;
  flags: Record<string, any>;
  createdAt: string;
}
