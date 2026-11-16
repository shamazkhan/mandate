/** Reference registry server (Mandate Protocol draft 0.1, section 8). */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import { canonicalJson, nowSeconds, b64u } from '../core/encoding.js';
import { isPublicJwk, publicOf, thumbprint, verifyBytes } from '../core/keys.js';
import { ASSURANCE_RANK, type Assurance, type KeyRecord, type KeyType } from '../core/types.js';

export interface RegistryData {
  keys: Record<string, KeyRecord>;
  mandates: Record<string, { mid: string; status: 'revoked'; revoked_at: number; by?: string }>;
}

export interface RegistryServerOptions {
  /** JSON file for persistence. Omit for in-memory. */
  dataFile?: string;
  /** Bearer token for operator actions. Without it, operator endpoints are disabled. */
  adminToken?: string;
  /** Allow anyone to register issuer keys (default false: operator only). */
  openIssuerRegistration?: boolean;
  /** Accepted clock difference for proofs, seconds. Default 300. */
  proofWindow?: number;
  log?: (msg: string) => void;
}

export class RegistryStore {
  data: RegistryData = { keys: {}, mandates: {} };
  constructor(private file?: string) {
    if (file && existsSync(file)) this.data = JSON.parse(readFileSync(file, 'utf8'));
  }
  save(): void {
    if (!this.file) return;
    const tmp = this.file + '.tmp';
    writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    renameSync(tmp, this.file);
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': status === 200 ? 'max-age=30' : 'no-store', 'access-control-allow-origin': '*' });
  res.end(s);
}

async function readJson(req: IncomingMessage, limit = 16_384): Promise<any> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > limit) throw Object.assign(new Error('body too large'), { status: 413 });
    chunks.push(c as Buffer);
  }
  if (!n) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('invalid JSON'), { status: 400 });
  }
}

export function createRegistryServer(opts: RegistryServerOptions = {}): { server: Server; store: RegistryStore } {
  const store = new RegistryStore(opts.dataFile);
  const window = opts.proofWindow ?? 300;
  const log = opts.log ?? (() => {});

  const isAdmin = (req: IncomingMessage) => {
    if (!opts.adminToken) return false;
    const h = req.headers.authorization ?? '';
    const want = Buffer.from(`Bearer ${opts.adminToken}`);
    const got = Buffer.from(h);
    return got.length === want.length && timingSafeEqual(got, want);
  };

  const checkProof = (jwk: KeyRecord['jwk'], msg: Record<string, unknown>, proof: any): string | null => {
    if (!proof || !Number.isInteger(proof.ts) || typeof proof.sig !== 'string') return 'proof required';
    if (Math.abs(nowSeconds() - proof.ts) > window) return 'proof timestamp outside window';
    let sig: Buffer;
    try { sig = b64u.decode(proof.sig); } catch { return 'bad proof encoding'; }
    return verifyBytes(jwk, canonicalJson({ ...msg, ts: proof.ts }), sig) ? null : 'bad proof signature';
  };

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://registry');
    const p = url.pathname.replace(/\/+$/, '') || '/';
    const m = req.method ?? 'GET';
    let match: RegExpExecArray | null;

    if (m === 'OPTIONS') {
      res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type, authorization' });
      return res.end();
    }
    if (m === 'GET' && p === '/.well-known/mandate-registry') return send(res, 200, { protocol: 'mandate/0.1', api: '/v0' });
    if (m === 'GET' && p === '/healthz') return send(res, 200, { ok: true, keys: Object.keys(store.data.keys).length });

    if (m === 'GET' && (match = /^\/v0\/keys\/([A-Za-z0-9_-]{43})$/.exec(p))) {
      const rec = store.data.keys[match[1]!];
      return rec ? send(res, 200, rec) : send(res, 404, { error: 'not_found' });
    }

    if (m === 'POST' && p === '/v0/keys') {
      const b = await readJson(req);
      const type = b.type as KeyType;
      if (!['agent', 'issuer', 'verifier'].includes(type)) return send(res, 400, { error: 'type must be agent, issuer or verifier' });
      if (!isPublicJwk(b.jwk)) return send(res, 400, { error: 'jwk must be an Ed25519 public key' });
      const jwk = publicOf(b.jwk);
      const kid = thumbprint(jwk);
      const admin = isAdmin(req);
      if (type !== 'agent' && !admin && !(type === 'issuer' && opts.openIssuerRegistration)) return send(res, 403, { error: `${type} keys are registered by the registry operator` });
      const err = checkProof(jwk, { op: 'register', kid }, b.proof);
      if (err) return send(res, 401, { error: err });
      if (store.data.keys[kid]) return send(res, 409, { error: 'already registered', kid });
      const name = typeof b.name === 'string' ? b.name.slice(0, 120) : undefined;
      const operator = b.operator && typeof b.operator.name === 'string'
        ? { name: String(b.operator.name).slice(0, 120), ...(typeof b.operator.url === 'string' ? { url: String(b.operator.url).slice(0, 300) } : {}) }
        : undefined;
      const rec: KeyRecord = { kid, type, jwk, status: 'active', assurance: 'basic', created_at: nowSeconds(), ...(name ? { name } : {}), ...(operator ? { operator } : {}) };
      store.data.keys[kid] = rec;
      store.save();
      log(`registered ${type} ${kid}`);
      return send(res, 201, rec);
    }

    if (m === 'POST' && (match = /^\/v0\/keys\/([A-Za-z0-9_-]{43})\/revoke$/.exec(p))) {
      const kid = match[1]!;
      const rec = store.data.keys[kid];
      if (!rec) return send(res, 404, { error: 'not_found' });
      const b = await readJson(req);
      if (!isAdmin(req)) {
        const err = checkProof(rec.jwk, { op: 'revoke', kid }, b.proof);
        if (err) return send(res, 401, { error: err });
      }
      if (rec.status !== 'revoked') {
        store.data.keys[kid] = { ...rec, status: 'revoked', revoked_at: nowSeconds() };
        store.save();
        log(`revoked key ${kid}`);
      }
      return send(res, 200, store.data.keys[kid]);
    }

    if (m === 'POST' && (match = /^\/v0\/keys\/([A-Za-z0-9_-]{43})\/assurance$/.exec(p))) {
      if (!isAdmin(req)) return send(res, 403, { error: 'operator only' });
      const kid = match[1]!;
      const rec = store.data.keys[kid];
      if (!rec) return send(res, 404, { error: 'not_found' });
      const b = await readJson(req);
      if (!(b.assurance in ASSURANCE_RANK)) return send(res, 400, { error: 'assurance must be basic, verified or preflight' });
      const next: KeyRecord = { ...rec, assurance: b.assurance as Assurance };
      if (b.assurance === 'preflight') {
        const pf = b.preflight;
        if (!pf || typeof pf.report_url !== 'string' || typeof pf.agent_version !== 'string' || !Number.isInteger(pf.expires_at))
          return send(res, 400, { error: 'preflight requires report_url, agent_version and expires_at' });
        next.preflight = { report_url: pf.report_url, agent_version: pf.agent_version, expires_at: pf.expires_at };
      } else delete next.preflight;
      store.data.keys[kid] = next;
      store.save();
      return send(res, 200, next);
    }

    if (m === 'GET' && (match = /^\/v0\/mandates\/([A-Za-z0-9_-]{16,128})$/.exec(p))) {
      const r = store.data.mandates[match[1]!];
      return send(res, 200, r ?? { mid: match[1], status: 'active' });
    }

    if (m === 'POST' && (match = /^\/v0\/mandates\/([A-Za-z0-9_-]{16,128})\/revoke$/.exec(p))) {
      const mid = match[1]!;
      const b = await readJson(req);
      let by: string | undefined;
      if (!isAdmin(req)) {
        const issuer = store.data.keys[b.kid];
        if (!issuer || issuer.type !== 'issuer') return send(res, 401, { error: 'issuer key required' });
        const err = checkProof(issuer.jwk, { op: 'revoke_mandate', mid, kid: issuer.kid }, b.proof);
        if (err) return send(res, 401, { error: err });
        by = issuer.kid;
      }
      store.data.mandates[mid] ??= { mid, status: 'revoked', revoked_at: nowSeconds(), ...(by ? { by } : {}) };
      store.save();
      log(`revoked mandate ${mid}`);
      return send(res, 200, store.data.mandates[mid]);
    }

    if (m === 'GET' && p === '/v0/revocations') {
      const since = Number(url.searchParams.get('since') ?? 0) || 0;
      const now = nowSeconds();
      const revocations = [
        ...Object.values(store.data.keys).filter((k) => k.status === 'revoked' && (k.revoked_at ?? 0) >= since).map((k) => ({ kind: 'key', id: k.kid, revoked_at: k.revoked_at })),
        ...Object.values(store.data.mandates).filter((x) => x.revoked_at >= since).map((x) => ({ kind: 'mandate', id: x.mid, revoked_at: x.revoked_at })),
      ];
      res.setHeader('cache-control', 'no-store');
      return send(res, 200, { revocations, now });
    }

    return send(res, 404, { error: 'not_found' });
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((e: any) => send(res, e?.status ?? 500, { error: e?.status ? e.message : 'internal error' }));
  });
  return { server, store };
}
