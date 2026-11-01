/**
 * The state record: a signed snapshot of an identity's CURRENT state, short enough for one DNS TXT record
 * (state-record.md; python/src/nodetide/core/state.py is the reference and verifies what this produces).
 *
 * Pure functions; the caller supplies canonicalize / sha256 / sign so this file has no dependencies and the browser
 * test can check its output against Python.
 */
(function (root) {
  'use strict';

  const PREFIX = 'nt1;';
  const SIGN_DOMAIN = 'nodetide-state-v1\u0000';
  const MAX_TEXT = 3800;
  const MAX_DEVICES = 12;
  const MAX_LINEAGE = 8;
  const LABEL_PREFIX = 32;
  const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
  const BAD_SUFFIXES = ['.local', '.localhost', '.internal', '.lan', '.home.arpa', '.onion', '.invalid', '.test', '.example'];

  class StateError extends Error {}

  /** "dns:Example.org", "example.org" -> "example.org"; null for anything that is not a plain public name. */
  function normalizeDomain(input) {
    if (typeof input !== 'string') return null;
    let d = input.trim().toLowerCase();
    if (d.startsWith('dns:')) d = d.slice(4).trim();
    d = d.replace(/\.$/, '');
    const labels = d.split('.');
    if (d.length > 253 || labels.length < 2 || !labels.every(l => LABEL.test(l))) return null;
    if (/^[0-9]+$/.test(labels[labels.length - 1]) || BAD_SUFFIXES.some(s => d.endsWith(s)) || d === 'localhost') return null;
    return d;
  }

  function recordName(domain, identityHash) {
    return `${identityHash.slice(0, LABEL_PREFIX)}._nodetide.${domain}`;
  }

  /**
   * @param {object} a
   * @param {string} a.identityHash
   * @param {object[]} a.events        the control chain, in order, as the node serves it
   * @param {object|null} a.commitment {count, root} over all content events, or null
   * @param {object[]} a.devices       active devices as the node lists them ({pubkey, encryption_pubkey, capabilities, added_at, expires})
   * @param {object} a.master          {signing:{publicKey,secretKey}, encryption:{publicKey}}
   */
  async function build(a) {
    const { identityHash, events, commitment, devices, master, canonicalize, sha256, sign } = a;
    const now = a.now ?? Math.floor(Date.now() / 1000);
    const validity = a.validity ?? 7 * 86400;
    if (!events || !events.length || events[0].type !== 'genesis') throw new StateError('the control chain does not start with a genesis');
    const genesis = events[0];
    if (genesis.owners != null) throw new StateError('organizations cannot publish a state (their key is governed by their owners): use the sigchain');
    if (await sha256(canonicalize(genesis)) !== identityHash) throw new StateError('the chain is not this identity\'s');

    // the master key's lineage: genesis, then each rotation signed by the key before it
    const lineage = [genesis];
    let current = genesis.pubkey, currentEnc = genesis.encryption_pubkey;
    for (const e of events.slice(1)) {
      if (e.type === 'rotate_master') {
        if (e.signed_by !== current) throw new StateError('a master rotation was governed or not signed by the previous key: use the sigchain');
        lineage.push(e);
        current = e.new_pubkey;
        currentEnc = e.new_encryption_pubkey;
      } else if (['social_recovery', 'resolve_fork', 'set_owners'].includes(e.type)) {
        throw new StateError(`this identity used ${e.type}, which a state cannot prove: use the sigchain`);
      }
    }
    if (lineage.length > MAX_LINEAGE) throw new StateError('too many master rotations for a short record: use the sigchain');
    if (master.signing.publicKey !== current) throw new StateError('the unlocked key is not the identity\'s current master key');

    const listed = (devices || []).filter(d => d.pubkey !== current);
    if (listed.length > MAX_DEVICES) throw new StateError(`${listed.length} devices do not fit a short record (the limit is ${MAX_DEVICES}): revoke unused ones`);

    const body = {
      v: 1,
      id: identityHash,
      head: await sha256(canonicalize(events[events.length - 1])),
      n: events.length,
      master: { sign: current, enc: currentEnc },
      devices: listed.map(d => ({ k: d.pubkey, e: d.encryption_pubkey, c: [...d.capabilities].sort(), a: d.added_at, x: d.expires ?? null })),
      content: commitment || null,
      ts: now,
      exp: now + validity,
    };
    return { body, sig: sign(SIGN_DOMAIN + canonicalize(body), master.signing.secretKey), lineage };
  }

  function b64url(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /** `nt1;` + base64url(zlib-deflate(canonical JSON)). */
  async function encode(doc, canonicalize) {
    const raw = new TextEncoder().encode(canonicalize(doc));
    const stream = new Blob([raw]).stream().pipeThrough(new CompressionStream('deflate'));
    const packed = new Uint8Array(await new Response(stream).arrayBuffer());
    const text = PREFIX + b64url(packed);
    if (text.length > MAX_TEXT) throw new StateError(`the state is ${text.length} characters, more than a TXT record should carry (${MAX_TEXT}): use the sigchain`);
    return text;
  }

  function txtStrings(text) {
    const out = [];
    for (let i = 0; i < text.length; i += 255) out.push(text.slice(i, i + 255));
    return out;
  }

  /** The record as a line for a zone file. */
  function zoneLine(name, text, ttl = 300) {
    return `${name}. ${ttl} IN TXT ${txtStrings(text).map(s => `"${s}"`).join(' ')}`;
  }

  const api = { PREFIX, MAX_TEXT, MAX_DEVICES, StateError, normalizeDomain, recordName, build, encode, txtStrings, zoneLine };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.NodetideState = api;
})(typeof window !== 'undefined' ? window : globalThis);
