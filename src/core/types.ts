/** Mandate Protocol draft 0.1 types. */

export const PROTOCOL_VERSION = '0.1';
export const SIGNATURE_TAG = 'mandate/0.1';
export const SIGNATURE_LABEL = 'mandate';
export const MANDATE_TYP = 'mandate+jws';

export type Decision = 'allow' | 'deny' | 'hold';

export type KeyType = 'agent' | 'issuer' | 'verifier';
export type KeyStatus = 'active' | 'revoked';
export type Assurance = 'basic' | 'verified' | 'preflight';

export const ASSURANCE_RANK: Record<Assurance, number> = { basic: 0, verified: 1, preflight: 2 };

export interface PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

export interface PrivateJwk extends PublicJwk {
  d: string;
}

/** A key pair as stored on disk by `mandate keygen`. */
export interface KeyFile {
  kid: string;
  type: KeyType;
  jwk: PrivateJwk;
  created_at: number;
}

export interface Operator {
  name: string;
  url?: string;
}

export interface PreflightRecord {
  report_url: string;
  agent_version: string;
  expires_at: number;
}

export interface KeyRecord {
  kid: string;
  type: KeyType;
  jwk: PublicJwk;
  name?: string;
  operator?: Operator;
  status: KeyStatus;
  assurance: Assurance;
  created_at: number;
  revoked_at?: number;
  preflight?: PreflightRecord;
}

export type AssetClass = 'us_equity' | 'etf' | 'option' | 'crypto' | 'fx' | 'future' | 'bond' | 'fund';
export type Side = 'buy' | 'sell';
export type OrderType = 'market' | 'limit' | 'stop' | 'stop_limit' | 'trailing_stop';

export interface Policy {
  instruments?: AssetClass[];
  symbols?: { allow?: string[]; deny?: string[] };
  sides?: Side[];
  allow_short?: boolean;
  order_types?: OrderType[];
  max_order_notional?: number;
  max_daily_notional?: number;
  max_position_pct?: number;
  max_leverage?: number;
  max_orders_per_minute?: number;
  require_approval?: { above_notional?: number };
  exits?: 'always_allow' | 'evaluate';
  currency?: string;
  [extra: string]: unknown;
}

export interface MandatePayload {
  v: string;
  mid: string;
  iss: string;
  sub: string;
  agent: string;
  aud?: string[];
  iat: number;
  nbf?: number;
  exp: number;
  policy: Policy;
}

export interface Order {
  symbol: string;
  side: Side;
  qty?: number;
  notional?: number;
  type: OrderType;
  limit_price?: number;
  stop_price?: number;
  asset_class: AssetClass;
  time_in_force?: string;
  client_order_id?: string;
}

export interface Position {
  /** Signed quantity: positive long, negative short. */
  qty: number;
  /** Absolute market value in the policy currency. */
  market_value?: number;
  /** Latest price. */
  price?: number;
}

/** Account state supplied by the verifier's host (the broker). */
export interface AccountContext {
  equity?: number;
  positions?: Record<string, Position>;
  /** Reference prices by symbol, used when an order has no notional or limit price. */
  prices?: Record<string, number>;
}

export type ReasonCode =
  | 'unsigned' | 'unsupported_alg' | 'components_missing' | 'signature_not_yet_valid'
  | 'signature_expired' | 'replay' | 'digest_mismatch' | 'agent_unknown' | 'agent_revoked'
  | 'assurance_insufficient' | 'signature_invalid' | 'mandate_missing' | 'mandate_invalid'
  | 'issuer_unknown' | 'issuer_revoked' | 'issuer_untrusted' | 'mandate_agent_mismatch'
  | 'mandate_audience_mismatch' | 'mandate_revoked' | 'mandate_not_yet_valid' | 'mandate_expired'
  | 'instrument_not_allowed' | 'symbol_denied' | 'symbol_not_allowed' | 'side_not_allowed'
  | 'short_not_allowed' | 'order_type_not_allowed' | 'order_notional_exceeded'
  | 'daily_notional_exceeded' | 'position_limit_exceeded' | 'leverage_exceeded'
  | 'rate_limit_exceeded' | 'approval_required' | 'notional_unknown' | 'context_unavailable'
  | 'exit_always_allowed' | 'not_an_order' | 'order_unreadable';

export interface Reason {
  code: ReasonCode;
  message: string;
}

/** A request as seen by the verifier. Header names are case-insensitive. */
export interface HttpRequestLike {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined> | Headers;
  body?: Uint8Array | string | null;
}
