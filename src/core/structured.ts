/**
 * Minimal RFC 8941 Structured Field parser and serialiser, covering the
 * subset used by RFC 9421 and RFC 9530: dictionaries whose members are
 * byte sequences or inner lists of strings, with parameters.
 */

export type BareItem = string | number | boolean | Uint8Array | { token: string };
export type Params = Map<string, BareItem>;

export interface Item {
  kind: 'item';
  value: BareItem;
  params: Params;
}
export interface InnerList {
  kind: 'inner';
  items: Item[];
  params: Params;
}
export type Member = (Item | InnerList) & { raw: string };

class Parser {
  i = 0;
  constructor(readonly s: string) {}
  peek() { return this.s[this.i]; }
  eof() { return this.i >= this.s.length; }
  ws() { while (!this.eof() && (this.peek() === ' ' || this.peek() === '\t')) this.i++; }
  sp() { while (!this.eof() && this.peek() === ' ') this.i++; }
  fail(msg: string): never { throw new Error(`structured field: ${msg} at ${this.i}`); }

  key(): string {
    const m = /^[a-z*][a-z0-9_\-.*]*/.exec(this.s.slice(this.i));
    if (!m) this.fail('expected key');
    this.i += m[0].length;
    return m[0];
  }

  bare(): BareItem {
    const c = this.peek();
    if (c === '"') {
      this.i++;
      let out = '';
      while (true) {
        if (this.eof()) this.fail('unterminated string');
        const ch = this.s[this.i++]!;
        if (ch === '\\') {
          const n = this.s[this.i++];
          if (n !== '"' && n !== '\\') this.fail('bad escape');
          out += n;
        } else if (ch === '"') return out;
        else {
          const code = ch.charCodeAt(0);
          if (code < 0x20 || code > 0x7e) this.fail('bad string char');
          out += ch;
        }
      }
    }
    if (c === ':') {
      this.i++;
      const end = this.s.indexOf(':', this.i);
      if (end < 0) this.fail('unterminated byte sequence');
      const b64 = this.s.slice(this.i, end);
      if (!/^[A-Za-z0-9+/=]*$/.test(b64)) this.fail('bad byte sequence');
      this.i = end + 1;
      return new Uint8Array(Buffer.from(b64, 'base64'));
    }
    if (c === '?') {
      this.i++;
      const v = this.s[this.i++];
      if (v === '1') return true;
      if (v === '0') return false;
      this.fail('bad boolean');
    }
    if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) {
      const m = /^-?\d{1,15}(\.\d{1,3})?/.exec(this.s.slice(this.i));
      if (!m) this.fail('bad number');
      this.i += m[0].length;
      return Number(m[0]);
    }
    const m = /^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*/.exec(this.s.slice(this.i));
    if (!m) this.fail('expected item');
    this.i += m[0].length;
    return { token: m[0] };
  }

  params(): Params {
    const p: Params = new Map();
    while (!this.eof() && this.peek() === ';') {
      this.i++;
      this.sp();
      const k = this.key();
      let v: BareItem = true;
      if (this.peek() === '=') {
        this.i++;
        v = this.bare();
      }
      p.set(k, v);
    }
    return p;
  }

  itemOrInner(): Item | InnerList {
    if (this.peek() === '(') {
      this.i++;
      const items: Item[] = [];
      while (true) {
        this.sp();
        if (this.peek() === ')') { this.i++; break; }
        const value = this.bare();
        items.push({ kind: 'item', value, params: this.params() });
        if (this.peek() !== ' ' && this.peek() !== ')') this.fail('expected space or )');
      }
      return { kind: 'inner', items, params: this.params() };
    }
    const value = this.bare();
    return { kind: 'item', value, params: this.params() };
  }
}

/** Parse a Dictionary. Each member keeps its raw serialised value text. */
export function parseDictionary(input: string): Map<string, Member> {
  const p = new Parser(input.trim());
  const out = new Map<string, Member>();
  if (p.eof()) return out;
  while (true) {
    p.sp();
    const k = p.key();
    let member: Member;
    if (p.peek() === '=') {
      p.i++;
      const start = p.i;
      const v = p.itemOrInner();
      member = Object.assign(v, { raw: p.s.slice(start, p.i) });
    } else {
      const start = p.i;
      const params = p.params();
      member = { kind: 'item', value: true, params, raw: '?1' + p.s.slice(start, p.i) };
    }
    out.set(k, member);
    p.ws();
    if (p.eof()) return out;
    if (p.peek() !== ',') p.fail('expected ,');
    p.i++;
    p.ws();
    if (p.eof()) p.fail('trailing comma');
  }
}

export function serializeBare(v: BareItem): string {
  if (typeof v === 'string') {
    if (!/^[\x20-\x7e]*$/.test(v)) throw new Error('string not serialisable');
    return '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('only integers supported');
    return String(v);
  }
  if (typeof v === 'boolean') return v ? '?1' : '?0';
  if (v instanceof Uint8Array) return ':' + Buffer.from(v).toString('base64') + ':';
  return v.token;
}

export function serializeParams(p: Params | [string, BareItem][]): string {
  const entries = p instanceof Map ? [...p.entries()] : p;
  return entries.map(([k, v]) => (v === true ? `;${k}` : `;${k}=${serializeBare(v)}`)).join('');
}

export function serializeInnerList(items: string[], params: [string, BareItem][]): string {
  return '(' + items.map((s) => serializeBare(s)).join(' ') + ')' + serializeParams(params);
}

export function byteSequenceMember(m: Member | undefined): Uint8Array | null {
  if (!m || m.kind !== 'item' || !(m.value instanceof Uint8Array)) return null;
  return m.value;
}
