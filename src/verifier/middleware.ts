/** Framework bindings: Node/Express/Connect middleware and WHATWG fetch Request. */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Verifier, VerifyResult } from './index.js';

export interface MiddlewareOptions {
  /**
   * Reconstruct the URL the agent signed. Default: `X-Forwarded-Proto`/`Host` if
   * `trustProxy` is set, otherwise http(s) from the socket plus the Host header.
   */
  targetUri?: (req: IncomingMessage) => string;
  trustProxy?: boolean;
  /** Called for held orders. Default responds 202 with the approval id. */
  onHold?: (result: VerifyResult, req: IncomingMessage, res: ServerResponse) => void;
  /** Maximum body size, bytes. Default 1 MB. */
  limit?: number;
}

export function targetUriOf(req: IncomingMessage, trustProxy = false): string {
  const fwdProto = trustProxy ? String(req.headers['x-forwarded-proto'] ?? '').split(',')[0]?.trim() : '';
  const fwdHost = trustProxy ? String(req.headers['x-forwarded-host'] ?? '').split(',')[0]?.trim() : '';
  const proto = fwdProto || ((req.socket as any).encrypted ? 'https' : 'http');
  const host = fwdHost || req.headers.host || 'localhost';
  return `${proto}://${host}${req.url ?? '/'}`;
}

export async function readBody(req: IncomingMessage, limit = 1_048_576): Promise<Buffer> {
  const existing = (req as any).rawBody ?? (Buffer.isBuffer((req as any).body) ? (req as any).body : undefined);
  if (existing) return existing;
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > limit) throw Object.assign(new Error('body too large'), { status: 413 });
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

export function denyBody(r: VerifyResult) {
  return { error: 'mandate_denied', reasons: r.reasons, evidence_id: r.evidence.hash };
}

export function holdBody(r: VerifyResult, approvalId = r.evidence.hash) {
  return { status: 'held', approval_id: approvalId, reasons: r.reasons, evidence_id: r.evidence.hash };
}

/**
 * Connect/Express middleware. Put it before body parsers on order routes, or use a
 * parser that keeps `req.rawBody`. On allow it sets `req.mandate` and the raw body
 * as `req.rawBody`, then calls next().
 */
export function mandateMiddleware(verifier: Verifier, opts: MiddlewareOptions = {}) {
  return async (req: IncomingMessage & { mandate?: VerifyResult; rawBody?: Buffer }, res: ServerResponse, next: (err?: unknown) => void) => {
    try {
      const body = await readBody(req, opts.limit);
      req.rawBody = body;
      const url = opts.targetUri ? opts.targetUri(req) : targetUriOf(req, opts.trustProxy);
      const r = await verifier.verify({ method: req.method ?? 'GET', url, headers: req.headers, body });
      req.mandate = r;
      if (r.decision === 'allow') {
        res.setHeader('Mandate-Decision', `allow; evidence="${r.evidence.hash}"`);
        return next();
      }
      if (r.decision === 'hold') {
        if (opts.onHold) return opts.onHold(r, req, res);
        res.writeHead(202, { 'content-type': 'application/json' });
        return res.end(JSON.stringify(holdBody(r)));
      }
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify(denyBody(r)));
    } catch (e) {
      next(e);
    }
  };
}

/** Verify a WHATWG Request (Hono, Next.js route handlers, Cloudflare Workers, Deno, Bun). */
export async function verifyFetchRequest(verifier: Verifier, request: Request, url = request.url): Promise<{ result: VerifyResult; response?: Response; body: Uint8Array }> {
  const body = new Uint8Array(await request.clone().arrayBuffer());
  const result = await verifier.verify({ method: request.method, url, headers: request.headers, body });
  if (result.decision === 'allow') return { result, body };
  const status = result.decision === 'hold' ? 202 : 403;
  const payload = result.decision === 'hold' ? holdBody(result) : denyBody(result);
  return { result, body, response: new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } }) };
}
