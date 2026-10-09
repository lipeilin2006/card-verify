export type CardStatus = "unused" | "active" | "disabled";

export interface D1Meta {
  changes?: number;
  rows_written?: number;
  last_row_id?: number;
  [key: string]: unknown;
}

export interface D1Result<T = unknown> {
  results: T[];
  success: boolean;
  meta: D1Meta;
}

export interface D1Statement {
  bind(...values: unknown[]): D1Statement;
  first<T>(): Promise<T | null>;
  all<T>(): Promise<D1Result<T>>;
  run(): Promise<D1Result>;
}

export interface D1Like {
  prepare(sql: string): D1Statement;
  batch(statements: D1Statement[]): Promise<D1Result[]>;
}

export interface KVLike {
  get<T = unknown>(key: string, type?: "json"): Promise<T | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface Env {
  card_infos: D1Like;
  cache: KVLike;
  manager_apikey?: string;
  aes_key?: string;
  ed_priv?: string;
  POW_DIFFICULTY?: string;
}

export interface CardRow {
  id: string;
  code: string;
  status: CardStatus;
  bound_hwid: string | null;
  hwid_changed_at: number | null;
  duration_seconds: number | null;
  expires_at: number | null;
  activated_at: number | null;
  created_at: number;
  note: string | null;
}

export interface SessionRow {
  token_hash: string;
  card_id: string;
  hwid: string;
  created_at: number;
}
