/** Agent SDK: sign every order with the agent's key and its mandate. */
import { signRequest, type SignedHeaders } from '../core/signature.js';
import { decodeMandate } from '../core/mandate.js';
import type { KeyFile, MandatePayload } from '../core/types.js';

export interface AgentOptions {
  key: KeyFile;
  mandate: string;
  /** Signature lifetime, seconds. Default 60. */
  ttl?: number;
  fetch?: typeof fetch;
}

export interface SignedFetchInit extends Omit<RequestInit, 'body'> {
  body?: string | Uint8Array | null;
  /** Convenience: JSON body. Sets content-type. */
  json?: unknown;
}

export class MandateAgent {
  readonly kid: string;
  readonly mandate: MandatePayload;
  private f: typeof fetch;

  constructor(private opts: AgentOptions) {
    if (opts.key.type !== 'agent') throw new Error('key is not an agent key');
    this.kid = opts.key.kid;
    this.mandate = decodeMandate(opts.mandate).payload;
    if (this.mandate.agent !== this.kid) throw new Error('mandate was issued to a different agent key');
    this.f = opts.fetch ?? fetch;
  }

  /** Headers to add to a request. The URL must be the exact URL you send to. */
  sign(req: { method: string; url: string; body?: string | Uint8Array | null }): SignedHeaders {
    return signRequest({ method: req.method, url: req.url, body: req.body, mandate: this.opts.mandate, key: this.opts.key, ttl: this.opts.ttl });
  }

  /** fetch() that signs the request first. */
  async fetch(url: string | URL, init: SignedFetchInit = {}): Promise<Response> {
    const u = new URL(String(url)).toString();
    const method = (init.method ?? (init.json !== undefined || init.body ? 'POST' : 'GET')).toUpperCase();
    const headers = new Headers(init.headers);
    let body: string | Uint8Array | null | undefined = init.body;
    if (init.json !== undefined) {
      body = JSON.stringify(init.json);
      if (!headers.has('content-type')) headers.set('content-type', 'application/json');
    }
    for (const [k, v] of Object.entries(this.sign({ method, url: u, body }))) if (v) headers.set(k, v);
    const { json: _json, ...rest } = init;
    return this.f(u, { ...rest, method, headers, body: body ?? undefined } as RequestInit);
  }

  /** Seconds until the mandate expires. */
  expiresIn(): number {
    return this.mandate.exp - Math.floor(Date.now() / 1000);
  }
}

export function createAgent(opts: AgentOptions): MandateAgent {
  return new MandateAgent(opts);
}
