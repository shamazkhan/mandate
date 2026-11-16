/** The verifier: Mandate Protocol draft 0.1, section 7. */
import { decodeMandate, verifyMandateSignature, type DecodedMandate } from '../core/mandate.js';
import { parseSignature, verifySignature, requiredComponents, MAX_SIGNATURE_WINDOW } from '../core/signature.js';
import { checkContentDigest } from '../core/digest.js';
import { getHeader } from '../core/http.js';
import { toBytes } from '../core/encoding.js';
import { evaluatePolicy, combine, isExit } from '../core/policy.js';
import {
  ASSURANCE_RANK, SIGNATURE_TAG,
  type AccountContext, type Assurance, type Decision, type HttpRequestLike, type KeyRecord,
  type MandatePayload, type Order, type Reason, type ReasonCode,
} from '../core/types.js';
import type { Resolver } from '../registry/types.js';
import { genericAdapter, type OrderAdapter } from '../adapters/index.js';
import { EvidenceLog, type EvidenceEntry, type EvidenceSink } from '../evidence/index.js';
import { MemoryState, type StateStore } from './state.js';

export interface ContextArgs {
  order: Order;
  mandate: MandatePayload;
  agent: KeyRecord;
  request: HttpRequestLike;
}

export interface VerifierOptions {
  /** Where agent and issuer keys are looked up. */
  registry: Resolver;
  /** This verifier's identifier, matched against a mandate's `aud`. */
  id?: string;
  /** Maps requests to orders. Default: genericAdapter(). */
  adapter?: OrderAdapter;
  /** If set, only mandates from these issuer kids are accepted. */
  trustedIssuers?: string[];
  /** Minimum agent assurance level. Default "basic". */
  minAssurance?: Assurance;
  /** Supplies equity, positions and prices for the account in the mandate's `sub`. */
  context?: (args: ContextArgs) => Promise<AccountContext | undefined> | AccountContext | undefined;
  evidence?: EvidenceSink;
  state?: StateStore;
  /** Allowed clock skew, seconds. Default 60. */
  maxSkew?: number;
  /** Allow signed requests that are not orders (reads, cancels). Default true. */
  allowNonOrders?: boolean;
  /** Clock, Unix seconds. For tests. */
  now?: () => number;
}

export interface VerifyResult {
  decision: Decision;
  reasons: Reason[];
  agent?: KeyRecord;
  mandate?: MandatePayload;
  order?: Order | null;
  notional?: number;
  evidence: EvidenceEntry;
}

const MESSAGES: Partial<Record<ReasonCode, string>> = {
  unsigned: 'Request has no Mandate signature.',
  unsupported_alg: 'Signature must use alg="ed25519" and tag="mandate/0.1".',
  components_missing: 'Signature does not cover @method, @target-uri, content-digest and mandate.',
  signature_not_yet_valid: 'Signature created time is in the future.',
  signature_expired: 'Signature has expired.',
  replay: 'Nonce already used.',
  digest_mismatch: 'Content-Digest does not match the body.',
  agent_unknown: 'Agent key is not registered.',
  agent_revoked: 'Agent key has been revoked.',
  assurance_insufficient: 'Agent assurance level is below this verifier\'s minimum.',
  signature_invalid: 'Signature is not valid.',
  mandate_missing: 'Request has no Mandate header.',
  mandate_invalid: 'Mandate is malformed or its signature is not valid.',
  issuer_unknown: 'Mandate issuer is not registered.',
  issuer_revoked: 'Mandate issuer key has been revoked.',
  issuer_untrusted: 'Mandate issuer is not trusted by this verifier.',
  mandate_agent_mismatch: 'Mandate was issued to a different agent.',
  mandate_audience_mismatch: 'Mandate is not valid at this verifier.',
  mandate_revoked: 'Mandate has been revoked.',
  mandate_not_yet_valid: 'Mandate is not valid yet.',
  mandate_expired: 'Mandate has expired.',
  not_an_order: 'Signed request is not an order.',
};

function reason(code: ReasonCode, message?: string): Reason {
  return { code, message: message ?? MESSAGES[code] ?? code };
}

export class Verifier {
  readonly id: string;
  readonly evidence: EvidenceSink;
  readonly state: StateStore;
  private adapter: OrderAdapter;

  constructor(private opts: VerifierOptions) {
    this.id = opts.id ?? 'verifier';
    this.adapter = opts.adapter ?? genericAdapter();
    this.evidence = opts.evidence ?? new EvidenceLog();
    this.state = opts.state ?? new MemoryState();
  }

  private now(): number {
    return this.opts.now ? this.opts.now() : Math.floor(Date.now() / 1000);
  }

  async verify(req: HttpRequestLike): Promise<VerifyResult> {
    const ctx: { agent?: KeyRecord; mandate?: DecodedMandate; order?: Order | null } = {};
    const finish = (decision: Decision, reasons: Reason[], notional?: number): VerifyResult => {
      const m = ctx.mandate?.payload;
      const evidence = this.evidence.append({
        decision,
        reasons: reasons.map((r) => r.code),
        agent: ctx.agent?.kid,
        assurance: ctx.agent?.assurance,
        operator: ctx.agent?.operator?.name,
        mandate: m?.mid,
        sub: m?.sub,
        issuer: m?.iss,
        order: ctx.order ?? undefined,
        request: { method: req.method.toUpperCase(), target: req.url, content_digest: getHeader(req.headers, 'content-digest') },
        verifier: this.id,
      });
      return { decision, reasons, agent: ctx.agent, mandate: m, order: ctx.order, notional, evidence };
    };
    const deny = (code: ReasonCode, message?: string) => finish('deny', [reason(code, message)]);

    // 1-3: signature present, profile, components
    const sig = parseSignature(req);
    if (!sig) return deny('unsigned');
    if (sig.alg !== 'ed25519' || sig.tag !== SIGNATURE_TAG || !sig.keyid || !sig.nonce || sig.created === undefined || sig.expires === undefined)
      return deny('unsupported_alg');
    const body = toBytes(req.body);
    const hasBody = body.length > 0;
    const need = requiredComponents(hasBody);
    if (!need.every((c) => sig.components.includes(c))) return deny('components_missing');

    // 4-5: freshness and replay
    const now = this.now();
    const skew = this.opts.maxSkew ?? 60;
    if (sig.created > now + skew) return deny('signature_not_yet_valid');
    if (sig.expires < now - skew || sig.expires - sig.created > MAX_SIGNATURE_WINDOW || sig.expires < sig.created) return deny('signature_expired');

    // 6: digest
    if (hasBody && !checkContentDigest(getHeader(req.headers, 'content-digest'), body)) return deny('digest_mismatch');

    // 7-10: agent key
    const agent = await this.opts.registry.getKey(sig.keyid);
    if (!agent || agent.type !== 'agent') return deny('agent_unknown');
    ctx.agent = agent;
    if (agent.status !== 'active') return deny('agent_revoked');
    const min = this.opts.minAssurance ?? 'basic';
    const effective: Assurance = agent.assurance === 'preflight' && agent.preflight && agent.preflight.expires_at < now ? 'verified' : agent.assurance;
    if (ASSURANCE_RANK[effective] < ASSURANCE_RANK[min]) return deny('assurance_insufficient', `Agent assurance is ${effective}; this verifier requires ${min}.`);
    if (!verifySignature(req, sig, agent.jwk)) return deny('signature_invalid');
    // Only record the nonce once the signature is proven, so forged requests cannot burn nonces.
    if (!this.state.checkNonce(sig.keyid, sig.nonce, sig.expires)) return deny('replay');

    // 11-16: mandate
    const token = getHeader(req.headers, 'mandate');
    if (!token) return deny('mandate_missing');
    let md: DecodedMandate;
    try {
      md = decodeMandate(token.trim());
    } catch (e) {
      return deny('mandate_invalid', `Mandate is malformed: ${(e as Error).message}.`);
    }
    const issuer = await this.opts.registry.getKey(md.header.kid);
    if (!issuer || issuer.type !== 'issuer') return deny('issuer_unknown');
    if (issuer.status !== 'active') return deny('issuer_revoked');
    if (this.opts.trustedIssuers && !this.opts.trustedIssuers.includes(issuer.kid)) return deny('issuer_untrusted');
    if (!verifyMandateSignature(md, issuer.jwk)) return deny('mandate_invalid');
    ctx.mandate = md;
    const m = md.payload;
    if (m.agent !== agent.kid) return deny('mandate_agent_mismatch');
    if (m.aud && !m.aud.includes(this.id)) return deny('mandate_audience_mismatch');
    if (await this.opts.registry.isMandateRevoked(m.mid)) return deny('mandate_revoked');

    // 17: order
    let json: unknown = undefined;
    if (hasBody) {
      try { json = JSON.parse(body.toString('utf8')); } catch { json = undefined; }
    }
    let url: URL;
    try { url = new URL(req.url); } catch { return deny('order_unreadable', 'Request URL is not absolute.'); }
    const ex = this.adapter.extract({ method: req.method.toUpperCase(), url, json });
    if (ex.kind === 'unreadable') return deny('order_unreadable', ex.message);
    if (ex.kind === 'none') {
      ctx.order = null;
      if (m.nbf !== undefined && now < m.nbf) return deny('mandate_not_yet_valid');
      if (now >= m.exp) return deny('mandate_expired');
      return this.opts.allowNonOrders === false ? deny('not_an_order') : finish('allow', [reason('not_an_order')]);
    }
    const order = ex.order;
    ctx.order = order;

    // 18-19: validity window (exits exempt) and policy
    let account: AccountContext | undefined;
    try {
      account = this.opts.context ? await this.opts.context({ order, mandate: m, agent, request: req }) : undefined;
    } catch {
      account = undefined;
    }
    const exitsAllowed = (m.policy.exits ?? 'always_allow') === 'always_allow';
    const exit = exitsAllowed && isExit(order, account);
    if (!exit) {
      if (m.nbf !== undefined && now < m.nbf) return deny('mandate_not_yet_valid');
      if (now >= m.exp) return deny('mandate_expired');
    }
    const nowMs = now * 1000;
    const usage = this.state.usage(m.mid, nowMs);
    const r = evaluatePolicy(m.policy, order, account, usage);
    const decision = combine(r.reasons);
    if (decision === 'allow') this.state.record(m.mid, r.exit ? 0 : r.notional ?? 0, nowMs);
    return finish(decision, r.reasons, r.notional);
  }

  /** Count a held order once the account holder approves it. */
  recordApproved(result: VerifyResult): void {
    if (result.mandate) this.state.record(result.mandate.mid, result.notional ?? 0, this.now() * 1000);
  }
}

export function createVerifier(opts: VerifierOptions): Verifier {
  return new Verifier(opts);
}

export { MemoryState, type StateStore } from './state.js';
