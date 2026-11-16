#!/usr/bin/env node
/** mandate: command-line tool for Mandate Protocol. */
import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { generateKey, parseKeyFile, publicOf } from '../core/keys.js';
import { issueMandate, decodeMandate } from '../core/mandate.js';
import { signRequest } from '../core/signature.js';
import { createRegistryServer } from '../registry/server.js';
import { RegistryClient } from '../registry/client.js';
import { StaticRegistry, chainResolvers } from '../registry/static.js';
import { createVerifier } from '../verifier/index.js';
import { alpacaAdapter, genericAdapter, mcpAdapter } from '../adapters/index.js';
import { createProxy, alpacaContext } from '../proxy/index.js';
import { EvidenceLog, readLog, verifyChain } from '../evidence/index.js';
import { runDemo } from './demo.js';
import { VERSION } from '../version.js';
import type { Assurance, KeyType, Policy } from '../core/types.js';

const HELP = `mandate ${VERSION} — signed orders for AI trading agents (Mandate Protocol draft 0.1)

Usage: mandate <command> [options]

  demo                                   Run the whole protocol locally and show allow / hold / deny
  keygen   [--type agent|issuer|verifier] [--out FILE]
                                         Create an Ed25519 key (prints kid; writes the private key file)
  issue    --issuer FILE --agent KID --sub ACCOUNT --policy FILE|JSON [--ttl 30d] [--aud ID,...]
                                         Sign a mandate for an agent (issuers only)
  inspect  TOKEN|@FILE                   Decode a mandate
  sign     --key FILE --mandate TOKEN|@FILE --url URL [--method POST] [--data JSON|@FILE] [--curl]
                                         Print the headers for a signed request
  registry serve [--port 8787] [--data FILE] [--admin-token T]
  registry register --url URL --key FILE [--name NAME] [--operator NAME] [--admin-token T]
  registry revoke   --url URL (--key FILE | --kid KID --admin-token T)
  registry revoke-mandate --url URL --mid MID (--issuer FILE | --admin-token T)
  registry assurance --url URL --kid KID --level basic|verified|preflight --admin-token T
  proxy    --upstream URL (--registry URL | --trust FILE,...) [--port 8788] [--adapter alpaca|mcp|generic]
           [--id VERIFIER_ID] [--trusted-issuers KID,...] [--min-assurance LEVEL] [--evidence FILE]
           [--admin-token T] [--public-url URL] [--data-url URL] [--trust-proxy]
                                         Verifying reverse proxy in front of a broker API
  evidence verify FILE [--key VERIFIER_KEY_FILE]
                                         Check an evidence log's hash chain (and signatures)
  version

Environment: MANDATE_ADMIN_TOKEN is used when --admin-token is not given.
Docs: https://github.com/shamazkhan/mandate`;

function readArg(v: string): string {
  return v.startsWith('@') ? readFileSync(v.slice(1), 'utf8').trim() : v;
}

function duration(s: string): number {
  const m = /^(\d+)([smhd]?)$/.exec(s.trim());
  if (!m) throw new Error(`bad duration ${s} (use e.g. 3600, 12h, 30d)`);
  return Number(m[1]) * ({ '': 1, s: 1, m: 60, h: 3600, d: 86400 } as Record<string, number>)[m[2]!]!;
}

function die(msg: string): never {
  console.error(`mandate: ${msg}`);
  process.exit(1);
}

const loadKey = (f: string) => parseKeyFile(readFileSync(f, 'utf8'));

async function main(argv: string[]): Promise<void> {
  const [cmd, sub] = argv;
  const rest = argv.slice(cmd === 'registry' || cmd === 'evidence' ? 2 : 1);
  const { values: o, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    strict: false,
    options: {
      type: { type: 'string' }, out: { type: 'string' }, issuer: { type: 'string' }, agent: { type: 'string' },
      sub: { type: 'string' }, policy: { type: 'string' }, ttl: { type: 'string' }, aud: { type: 'string' },
      key: { type: 'string' }, mandate: { type: 'string' }, url: { type: 'string' }, method: { type: 'string' },
      data: { type: 'string' }, curl: { type: 'boolean' }, port: { type: 'string' }, 'admin-token': { type: 'string' },
      name: { type: 'string' }, operator: { type: 'string' }, kid: { type: 'string' }, mid: { type: 'string' },
      level: { type: 'string' }, upstream: { type: 'string' }, registry: { type: 'string' }, trust: { type: 'string' },
      adapter: { type: 'string' }, id: { type: 'string' }, 'trusted-issuers': { type: 'string' },
      'min-assurance': { type: 'string' }, evidence: { type: 'string' }, 'public-url': { type: 'string' },
      'data-url': { type: 'string' }, 'trust-proxy': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
    },
  });
  const s = (k: string) => (typeof o[k] === 'string' ? (o[k] as string) : undefined);
  const req = (k: string) => s(k) ?? die(`--${k} is required`);
  const admin = s('admin-token') ?? process.env.MANDATE_ADMIN_TOKEN;

  if (!cmd || cmd === 'help' || o.help) return console.log(HELP);
  if (cmd === 'version' || cmd === '--version' || cmd === '-v') return console.log(VERSION);

  if (cmd === 'demo') {
    const ok = await runDemo();
    process.exit(ok ? 0 : 1);
  }

  if (cmd === 'keygen') {
    const type = (s('type') ?? 'agent') as KeyType;
    if (!['agent', 'issuer', 'verifier'].includes(type)) die('--type must be agent, issuer or verifier');
    const k = generateKey(type);
    const out = s('out') ?? `${type}-${k.kid.slice(0, 8)}.key.json`;
    if (existsSync(out)) die(`${out} already exists`);
    writeFileSync(out, JSON.stringify(k, null, 2) + '\n', { mode: 0o600 });
    console.log(`kid:  ${k.kid}\ntype: ${type}\nkey:  ${out} (private: keep it secret)\njwk:  ${JSON.stringify(publicOf(k.jwk))}`);
    return;
  }

  if (cmd === 'issue') {
    const issuer = loadKey(req('issuer'));
    if (issuer.type !== 'issuer') die('--issuer must be an issuer key');
    const pol = readArg(req('policy'));
    const policy = JSON.parse(existsSync(pol) ? readFileSync(pol, 'utf8') : pol) as Policy;
    const token = issueMandate({ issuer, agent: req('agent'), sub: req('sub'), policy, ttl: s('ttl') ? duration(s('ttl')!) : undefined, aud: s('aud')?.split(',').map((x) => x.trim()).filter(Boolean) });
    return console.log(token);
  }

  if (cmd === 'inspect') {
    const t = positionals[0] ?? s('mandate') ?? die('give a mandate token or @file');
    const d = decodeMandate(readArg(t));
    const p = d.payload;
    console.log(JSON.stringify({ header: d.header, payload: p, expires: new Date(p.exp * 1000).toISOString(), expired: Date.now() / 1000 >= p.exp }, null, 2));
    console.error('(decoded only; signature not verified here, verifiers check it against the registry)');
    return;
  }

  if (cmd === 'sign') {
    const key = loadKey(req('key'));
    const url = req('url');
    const method = (s('method') ?? (s('data') ? 'POST' : 'GET')).toUpperCase();
    const body = s('data') ? readArg(s('data')!) : undefined;
    const h = signRequest({ method, url, body, mandate: readArg(req('mandate')), key });
    if (o.curl) {
      const q = (x: string) => `'${x.replace(/'/g, `'\\''`)}'`;
      const parts = [`curl -X ${method} ${q(url)}`, ...Object.entries(h).map(([k, v]) => `-H ${q(`${k}: ${v}`)}`)];
      if (body) parts.push(`-H 'content-type: application/json'`, `--data-raw ${q(body)}`);
      return console.log(parts.join(' \\\n  '));
    }
    for (const [k, v] of Object.entries(h)) console.log(`${k}: ${v}`);
    return;
  }

  if (cmd === 'registry') {
    if (sub === 'serve') {
      const port = Number(s('port') ?? process.env.PORT ?? 8787);
      const { server } = createRegistryServer({ dataFile: s('data') ?? 'registry.json', adminToken: admin, log: (m) => console.log(new Date().toISOString(), m) });
      server.on('error', (e: NodeJS.ErrnoException) => die(e.code === 'EADDRINUSE' ? `port ${port} is already in use (use --port)` : e.message));
      server.listen(port, () => console.log(`Mandate registry on http://localhost:${port} (data: ${s('data') ?? 'registry.json'}${admin ? ', operator endpoints enabled' : ''})`));
      return;
    }
    const client = new RegistryClient({ url: req('url'), adminToken: admin, pollInterval: 0 });
    if (sub === 'register') {
      const key = loadKey(req('key'));
      const rec = await client.register(key, { name: s('name'), operator: s('operator') ? { name: s('operator')! } : undefined });
      return console.log(JSON.stringify(rec, null, 2));
    }
    if (sub === 'revoke') {
      const rec = s('key') ? await client.revokeKey(loadKey(s('key')!)) : await client.revokeKey(req('kid'));
      return console.log(JSON.stringify(rec, null, 2));
    }
    if (sub === 'revoke-mandate') {
      const r = await client.revokeMandate(req('mid'), s('issuer') ? loadKey(s('issuer')!) : undefined);
      return console.log(JSON.stringify(r, null, 2));
    }
    if (sub === 'assurance') {
      const r = await client.setAssurance(req('kid'), req('level') as Assurance);
      return console.log(JSON.stringify(r, null, 2));
    }
    die(`unknown registry command ${sub ?? ''}`);
  }

  if (cmd === 'proxy') {
    const upstream = req('upstream');
    const trusted = new StaticRegistry();
    for (const f of (s('trust') ?? '').split(',').filter(Boolean)) {
      const j = JSON.parse(readFileSync(f, 'utf8'));
      trusted.add({ kid: j.kid, type: j.type, jwk: publicOf(j.jwk) });
    }
    const registry = s('registry') ? chainResolvers(trusted, new RegistryClient({ url: s('registry')! })) : trusted;
    if (!s('registry') && !s('trust')) die('give --registry URL or --trust key files');
    const kind = s('adapter') ?? (/alpaca/.test(upstream) ? 'alpaca' : 'generic');
    const adapter = kind === 'alpaca' ? alpacaAdapter() : kind === 'mcp' ? mcpAdapter() : genericAdapter();
    const verifier = createVerifier({
      registry,
      id: s('id') ?? new URL(upstream).host,
      adapter,
      trustedIssuers: s('trusted-issuers')?.split(',').map((x) => x.trim()).filter(Boolean),
      minAssurance: (s('min-assurance') as Assurance) ?? 'basic',
      evidence: new EvidenceLog({ file: s('evidence') ?? 'evidence.jsonl' }),
      context: kind === 'alpaca' ? alpacaContext({ tradingUrl: upstream, dataUrl: s('data-url') ?? 'https://data.alpaca.markets' }) : undefined,
    });
    const port = Number(s('port') ?? process.env.PORT ?? 8788);
    const { server } = createProxy({ verifier, upstream, publicUrl: s('public-url'), trustProxy: !!o['trust-proxy'], adminToken: admin, log: (l) => console.log(new Date().toISOString().slice(11, 19), l) });
    server.on('error', (e: NodeJS.ErrnoException) => die(e.code === 'EADDRINUSE' ? `port ${port} is already in use (use --port)` : e.message));
    server.listen(port, () => console.log(`Mandate verifying proxy on http://localhost:${port} → ${upstream} (adapter: ${kind}, verifier id: ${verifier.id}, evidence: ${s('evidence') ?? 'evidence.jsonl'})`));
    return;
  }

  if (cmd === 'evidence') {
    if (sub !== 'verify') die('usage: mandate evidence verify FILE');
    const file = positionals[0] ?? die('give an evidence file');
    const key = s('key') ? loadKey(s('key')!) : undefined;
    const r = verifyChain(readLog(file), key ? publicOf(key.jwk) : undefined);
    console.log(r.ok ? `ok: ${r.count} entries, chain intact${key ? ', all signatures valid' : ''}` : `FAILED: ${r.error}`);
    process.exit(r.ok ? 0 : 1);
  }

  die(`unknown command ${cmd}. Run: mandate help`);
}

main(process.argv.slice(2)).catch((e) => die((e as Error).message));
