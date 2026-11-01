/**
 * Nodetide Web Client
 * Single-file version (no ES modules for browser compatibility)
 */

(function() {
  'use strict';

  // Version injected at build time (replaced by Dockerfile)
  const WEB_VERSION = '__GIT_COMMIT__';

  // Set version info immediately (independent of Alpine)
  window.NODETIDE_VERSION = {
    web: (typeof WEB_VERSION === 'string' && !WEB_VERSION.startsWith('__')) ? WEB_VERSION.slice(0, 7) : 'dev',
    api: null
  };

  // Fetch API version immediately
  fetch('/health')
    .then(r => r.json())
    .then(data => {
      window.NODETIDE_VERSION.api = data.commit?.slice(0, 7) || 'unknown';
      updateVersionDisplay();
    })
    .catch(() => {
      window.NODETIDE_VERSION.api = 'offline';
      updateVersionDisplay();
    });

  function updateVersionDisplay() {
    const el = document.getElementById('version-display');
    if (el) {
      el.textContent = `(web:${window.NODETIDE_VERSION.web} api:${window.NODETIDE_VERSION.api || '...'})`;
    }
  }

  // Update on page show (handles bfcache)
  window.addEventListener('pageshow', updateVersionDisplay);

  // ============================================
  // CRYPTO MODULE
  // ============================================

  function encodeHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function decodeHex(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  // What the web client's device key may do: sign sign-in assertions (authenticate) and keep the identity's claims
  const DEVICE_CAPABILITIES = ['sign_messages', 'encrypt', 'authenticate', 'manage_claims'];

  function canonicalize(obj) {
    // Recursively sort keys and create compact JSON (no whitespace in structure)
    function sortRecursive(val) {
      if (val === null || typeof val !== 'object') {
        return val;
      }
      if (Array.isArray(val)) {
        return val.map(sortRecursive);
      }
      const sortedKeys = Object.keys(val).sort();
      const sorted = {};
      for (const key of sortedKeys) {
        if (val[key] !== undefined) {
          sorted[key] = sortRecursive(val[key]);
        }
      }
      return sorted;
    }
    // Python signs json.dumps(..., ensure_ascii=True): every non-ASCII character is a \\uXXXX escape. Match it, or
    // a name or label with such a character gives a signature and a hash the node does not reproduce.
    return JSON.stringify(sortRecursive(obj)).replace(/[\u0080-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  }

  // Sigchain v2 (sigchain-v2.md): claims are CONTENT events; everything else is the control chain, whose events
  // commit to the content so far with {count, root} (a Merkle root over the content events' hashes).
  const CONTENT_TYPES = ['add_claim', 'set_claim_order'];

  async function sha256Bytes(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  }

  function concatBytes(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const p of parts) { out.set(p, offset); offset += p.length; }
    return out;
  }

  async function merkleRootHex(hexHashes) {
    /** Same tree as python/src/nodetide/core/merkle.py (RFC 6962 style). */
    if (!hexHashes.length) return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const leaves = [];
    for (const h of hexHashes) leaves.push(await sha256Bytes(concatBytes(new Uint8Array([0]), decodeHex(h))));
    async function root(nodes) {
      if (nodes.length === 1) return nodes[0];
      let k = 1;
      while (k * 2 < nodes.length) k *= 2;
      return sha256Bytes(concatBytes(new Uint8Array([1]), await root(nodes.slice(0, k)), await root(nodes.slice(k))));
    }
    return encodeHex(await root(leaves));
  }

  async function sha256(data) {
    console.log('[sha256] called with:', typeof data, data?.length || data);
    if (!crypto || !crypto.subtle) {
      console.error('[sha256] crypto.subtle not available. Secure context:', window.isSecureContext);
      throw new Error('Web Crypto API not available. HTTPS required.');
    }
    const encoder = new TextEncoder();
    const bytes = typeof data === 'string' ? encoder.encode(data) : data;
    console.log('[sha256] hashing bytes:', bytes.length);
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const result = encodeHex(new Uint8Array(hashBuffer));
    console.log('[sha256] result:', result.slice(0, 16) + '...');
    return result;
  }

  // Sigchain helpers (consumer-side interpretation)
  const SigchainUtils = {
    /**
     * Get the latest value of a field from sigchain events.
     * Iterates through all events and returns the last non-null value found.
     */
    getLatestField(events, fieldName, defaultValue = null) {
      let value = defaultValue;
      for (const event of events) {
        if (event[fieldName] !== undefined && event[fieldName] !== null) {
          value = event[fieldName];
        }
      }
      return value;
    },
  };

  const Crypto = {
    generateKeyPair() {
      const signKp = nacl.sign.keyPair();
      const encKp = nacl.box.keyPair();
      return {
        signing: {
          publicKey: encodeHex(signKp.publicKey),
          secretKey: encodeHex(signKp.secretKey),
        },
        encryption: {
          publicKey: encodeHex(encKp.publicKey),
          secretKey: encodeHex(encKp.secretKey),
        },
      };
    },

    sign(message, secretKeyHex) {
      const secretKey = decodeHex(secretKeyHex);
      const messageBytes = new TextEncoder().encode(message);
      const signature = nacl.sign.detached(messageBytes, secretKey);
      return encodeHex(signature);
    },

    verify(message, signatureHex, publicKeyHex) {
      const publicKey = decodeHex(publicKeyHex);
      const signature = decodeHex(signatureHex);
      const messageBytes = new TextEncoder().encode(message);
      return nacl.sign.detached.verify(messageBytes, signature, publicKey);
    },

    async sha256Hex(data) {
      return sha256(data);
    },

    // Encryption parameters (must match Python ENCRYPTION_V1)
    ENCRYPTION_V1: {
      version: 1,
      kdf: 'pbkdf2-sha256',
      kdf_iterations: 100000,
      cipher: 'aes-256-gcm',
    },

    async encryptWithPassword(data, password, iterations) {
      const encoder = new TextEncoder();
      iterations = iterations || this.ENCRYPTION_V1.kdf_iterations;
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
      );

      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );

      const dataBytes = encoder.encode(typeof data === 'string' ? data : JSON.stringify(data));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, dataBytes);

      // Return explicit format with all parameters
      return {
        v: this.ENCRYPTION_V1.version,
        kdf: this.ENCRYPTION_V1.kdf,
        kdf_iterations: iterations,
        cipher: this.ENCRYPTION_V1.cipher,
        salt: encodeHex(salt),
        iv: encodeHex(iv),
        ciphertext: encodeHex(new Uint8Array(ciphertext)),
      };
    },

    async decryptWithPassword(encrypted, password) {
      const encoder = new TextEncoder();

      if (encrypted.v !== 1) {
        throw new Error(`Unsupported encryption version: ${encrypted.v}`);
      }

      const salt = decodeHex(encrypted.salt);
      const iv = decodeHex(encrypted.iv);
      const ciphertext = decodeHex(encrypted.ciphertext);
      const iterations = encrypted.kdf_iterations;
      if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_KDF_ITERATIONS) {
        throw new Error('Unsupported key derivation cost');
      }

      const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
      );

      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
      const decoder = new TextDecoder();
      return JSON.parse(decoder.decode(decrypted));
    },
  };

  // ============================================
  // STORAGE MODULE
  // ============================================

  const STORAGE_KEYS = {
    IDENTITIES: 'nodetide_identities',
    ACTIVE_IDENTITY: 'nodetide_active_identity',
    SETTINGS: 'nodetide_settings',
    PENDING_RECOVERY: 'nodetide_pending_recovery',
  };

  const StorageMethod = { PASSWORD: 'password', WEBAUTHN: 'webauthn' };

  const KeyStore = {
    listIdentities() {
      const data = localStorage.getItem(STORAGE_KEYS.IDENTITIES);
      if (!data) return [];
      try { return JSON.parse(data); } catch { return []; }
    },

    getIdentity(identityHash) {
      return this.listIdentities().find(i => i.identityHash === identityHash) || null;
    },

    getActiveIdentity() {
      return localStorage.getItem(STORAGE_KEYS.ACTIVE_IDENTITY);
    },

    setActiveIdentity(identityHash) {
      if (identityHash) {
        localStorage.setItem(STORAGE_KEYS.ACTIVE_IDENTITY, identityHash);
      } else {
        localStorage.removeItem(STORAGE_KEYS.ACTIVE_IDENTITY);
      }
    },

    async createIdentityWithPassword(name, password, distributionPoints = null) {
      console.log('[createIdentityWithPassword] starting, name:', name);

      // Generate master key pair (used only for identity management)
      const masterKeyPair = Crypto.generateKeyPair();
      console.log('[createIdentityWithPassword] masterKeyPair generated');

      // Create genesis event with master key
      const timestamp = Math.floor(Date.now() / 1000);
      const genesisEvent = {
        version: 1,
        type: 'genesis',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp,
        prev: null,
        signed_by: masterKeyPair.signing.publicKey,
        pubkey: masterKeyPair.signing.publicKey,
        encryption_pubkey: masterKeyPair.encryption.publicKey,
        identity_type: 'personal',
        name: name || null,
        ephemeral: false,
        ownership_proof: null,
        distribution_points: distributionPoints,
      };
      const genesisSignable = canonicalize(genesisEvent);
      genesisEvent.signature = Crypto.sign(genesisSignable, masterKeyPair.signing.secretKey);

      // Identity hash = hash of the complete signed genesis event
      const identityHash = await sha256(canonicalize(genesisEvent));
      console.log('[createIdentityWithPassword] identityHash:', identityHash.slice(0, 16) + '...');

      // Generate device key pair (used for daily operations)
      const deviceKeyPair = Crypto.generateKeyPair();
      console.log('[createIdentityWithPassword] deviceKeyPair generated');

      // Create AddDevice event signed by master key
      const genesisHash = await sha256(canonicalize(genesisEvent));
      const addDeviceEvent = {
        version: 1,
        type: 'add_device',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp: timestamp + 1, // 1 second after genesis
        prev: genesisHash,
        signed_by: masterKeyPair.signing.publicKey,
        device_pubkey: deviceKeyPair.signing.publicKey,
        device_encryption_pubkey: deviceKeyPair.encryption.publicKey,
        label: 'Web Browser',
        capabilities: DEVICE_CAPABILITIES,
        expires: null,
      };
      const addDeviceSignable = canonicalize(addDeviceEvent);
      addDeviceEvent.signature = Crypto.sign(addDeviceSignable, masterKeyPair.signing.secretKey);
      console.log('[createIdentityWithPassword] addDeviceEvent created');

      // Store device keys (for daily operations) and master keys (for identity management)
      const encryptedDeviceKeys = await Crypto.encryptWithPassword(deviceKeyPair, password);
      const encryptedMasterKeys = await Crypto.encryptWithPassword(masterKeyPair, password);

      const identity = {
        identityHash,
        name: name || '',
        createdAt: Date.now(),
        storageMethod: StorageMethod.PASSWORD,
        encryptedKeys: encryptedDeviceKeys, // Device keys for daily use
        encryptedMasterKeys, // Master keys for identity management
        signingPubkey: deviceKeyPair.signing.publicKey, // Device pubkey
        encryptionPubkey: deviceKeyPair.encryption.publicKey,
        masterSigningPubkey: masterKeyPair.signing.publicKey, // Master pubkey
        distributionPoints: distributionPoints,
        genesisEvent,
        addDeviceEvent, // Store for later sync
      };

      this._saveIdentity(identity);
      // Return device key pair for operations (not master)
      return { identity, keyPair: deviceKeyPair, masterKeyPair };
    },

    async unlockIdentity(identityHash, password) {
      const identity = this.getIdentity(identityHash);
      if (!identity) throw new Error('Identity not found');

      if (identity.storageMethod === StorageMethod.PASSWORD || identity.storageMethod === StorageMethod.WEBAUTHN) {
        password = await this._pw(identity, password);
        try {
          return await Crypto.decryptWithPassword(identity.encryptedKeys, password);
        } catch {
          throw new Error('Invalid password');
        }
      }
      throw new Error('Unknown storage method');
    },

    deleteIdentity(identityHash) {
      const identities = this.listIdentities().filter(i => i.identityHash !== identityHash);
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify(identities));
      if (this.getActiveIdentity() === identityHash) {
        this.setActiveIdentity(null);
      }
    },

    updateIdentity(identityHash, patch) {
      const identities = this.listIdentities().map(i => (i.identityHash === identityHash ? { ...i, ...patch } : i));
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify(identities));
    },

    _saveIdentity(identity) {
      const identities = this.listIdentities();
      identities.push(identity);
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify(identities));
    },

    async _pw(identity, password) {
      /** The typed password, or (none typed, identity has a passkey) the one the authenticator unwraps. */
      if (password) return password;
      const open = identity && WalletSession.get(identity.identityHash); // an unlocked wallet already holds it in memory
      if (open) return open.password;
      if (identity && identity.passkey) return Passkey.password(identity.identityHash);
      return password;
    },

    async _unlockBoth(identity, password) {
      password = await this._pw(identity, password);
      try {
        return {
          master: await Crypto.decryptWithPassword(identity.encryptedMasterKeys, password),
          device: await Crypto.decryptWithPassword(identity.encryptedKeys, password),
        };
      } catch {
        throw new Error('Invalid identity password');
      }
    },

    async createBackup(identityHash, identityPassword, backupPassword, backupConfirm) {
      /**
       * The file to keep elsewhere: master and device keys plus what is needed to re-create the identity,
       * encrypted with PBKDF2-SHA256 (BACKUP_KDF_ITERATIONS) + AES-256-GCM. It is read back before it is counted.
       */
      const identity = this.getIdentity(identityHash);
      if (!identity) throw new Error('Identity not found');
      if (backupPassword !== backupConfirm) throw new Error('The two backup passwords differ');
      const weak = weakPasswordReason(backupPassword);
      if (weak) throw new Error(weak);
      if (!identity.encryptedMasterKeys) throw new Error('This identity has no master key stored here');

      identityPassword = await this._pw(identity, identityPassword); // empty + passkey: the authenticator supplies it
      const keys = await this._unlockBoth(identity, identityPassword);
      const payload = {
        name: identity.name, distribution_points: identity.distributionPoints || null, created_at: identity.createdAt,
        master_keys: keys.master, device_keys: keys.device,
        genesis_event: identity.genesisEvent, add_device_event: identity.addDeviceEvent,
        wallet: await Wallet.exportData(identityHash, identityPassword), // claim values, salts, attestations
      };
      const encrypted = await Crypto.encryptWithPassword(JSON.stringify(payload), backupPassword, BACKUP_KDF_ITERATIONS);
      const back = await Crypto.decryptWithPassword(encrypted, backupPassword);
      if (JSON.stringify(back) !== JSON.stringify(payload)) throw new Error('The backup did not verify and was not counted');

      const now = Date.now();
      ProtectionState.save(identityHash, { backupAt: now });
      return { version: 1, format: 'nodetide-identity-backup', identity_hash: identityHash, created_at: now,
               holds_master_key: true, encrypted };
    },

    async restoreFromBackup(file, backupPassword, localPassword) {
      if (!file || file.format !== 'nodetide-identity-backup') throw new Error('Not a Nodetide identity backup');
      let payload;
      try {
        payload = await Crypto.decryptWithPassword(file.encrypted, backupPassword);
      } catch {
        throw new Error('Invalid password');
      }
      // Trust nothing in the file until it matches itself: the identity hash is the hash of the signed genesis
      // event, the genesis is signed by the master key we were given, and the device key is the one it authorized.
      const genesis = payload.genesis_event;
      if (!genesis || await sha256(canonicalize(genesis)) !== file.identity_hash) {
        throw new Error('The backup does not match its identity');
      }
      const { signature, ...unsigned } = genesis;
      const master = payload.master_keys;
      if (genesis.pubkey !== master.signing.publicKey || !Crypto.verify(canonicalize(unsigned), signature, genesis.pubkey)) {
        throw new Error('The backup\'s master key does not match the identity');
      }
      if (payload.add_device_event.device_pubkey !== payload.device_keys.signing.publicKey) {
        throw new Error('The backup\'s device key does not match the identity');
      }

      const identity = {
        identityHash: file.identity_hash,
        name: payload.name || '',
        createdAt: payload.created_at || Date.now(),
        storageMethod: StorageMethod.PASSWORD,
        encryptedKeys: await Crypto.encryptWithPassword(payload.device_keys, localPassword),
        encryptedMasterKeys: await Crypto.encryptWithPassword(master, localPassword),
        signingPubkey: payload.device_keys.signing.publicKey,
        encryptionPubkey: payload.device_keys.encryption.publicKey,
        masterSigningPubkey: master.signing.publicKey,
        distributionPoints: payload.distribution_points,
        genesisEvent: genesis,
        addDeviceEvent: payload.add_device_event,
      };
      const others = this.listIdentities().filter(i => i.identityHash !== identity.identityHash);
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify([...others, identity]));
      ProtectionState.save(identity.identityHash, { backupAt: file.created_at || Date.now() });
      if (payload.wallet) await Wallet.importData(identity.identityHash, payload.wallet, localPassword);

      // Make sure the node knows the identity (it normally does already)
      try { await api.submitGenesisEvent(genesis); } catch { /* already there */ }
      try { await api.submitEvent(identity.identityHash, payload.add_device_event); } catch { /* already there */ }
      return identity;
    },

    async setRecovery(identityHash, identityPassword, trusteesText, thresholdText) {
      /** Name the identities that can restore control of this one if every key is lost (signed by the master key). */
      const identity = this.getIdentity(identityHash);
      if (!identity) throw new Error('Identity not found');
      const trustees = trusteesText.split(/[\s,;]+/).map(t => t.trim().toLowerCase()).filter(Boolean);
      if (trustees.some(t => !/^[0-9a-f]{64}$/.test(t))) {
        throw new Error('Trustees are identity hashes: 64 hex characters each, one per line');
      }
      if (new Set(trustees).size !== trustees.length || trustees.includes(identityHash)) {
        throw new Error('Name each trustee once, and not this identity itself');
      }
      if (trustees.length < MIN_TRUSTEES) {
        throw new Error(`Name at least ${MIN_TRUSTEES} trustees: with fewer, losing one of them would end recovery`);
      }
      const threshold = Number.parseInt(thresholdText, 10);
      if (!(threshold >= 2 && threshold <= trustees.length)) {
        throw new Error(`The threshold must be between 2 and ${trustees.length}: that many trustees must agree`);
      }
      for (const trustee of trustees) {
        try { await api.request('GET', `/identities/${trustee}`); } catch {
          throw new Error(`The node does not know the identity ${trustee.slice(0, 12)}...: ask the trustee to register first`);
        }
      }

      const { master } = await this._unlockBoth(identity, identityPassword);
      const { events, head: chainHead, commitment } = await Wallet.chain(identityHash);
      if (!events.length) throw new Error('Cannot determine the sigchain head');
      const event = {
        version: 1,
        type: 'set_recovery',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp: Math.floor(Date.now() / 1000),
        prev: chainHead,
        signed_by: master.signing.publicKey,
        ...(commitment ? { content: commitment } : {}),
        primary_trustees: trustees,
        primary_threshold: threshold,
        backup_trustees: null,
        backup_threshold: null,
        backup_activates_after: null,
      };
      event.signature = Crypto.sign(canonicalize(event), master.signing.secretKey);
      await api.submitEvent(identityHash, event);
      return event;
    },

    // --- Organizations owned by this identity ------------------------------------------------------------------
    // Messages and events match python/src/nodetide/core/identity.py ("Organization identities").

    async _ownerApproval(owner, master, event) {
      /** This identity's approval of a governed event: signs the event body, bound to the owner and its chain state. */
      const chain = await api.request('GET', `/identities/${owner.identityHash}/sigchain?light=1`);
      const events = chain.events || [];
      const state = await sha256(canonicalize(events[events.length - 1]));
      const { signature, approvals, ...signable } = event;
      const message = { purpose: 'nodetide-owner-approval-v1', owner: owner.identityHash, state, event: signable };
      return {
        identity: owner.identityHash, state, key: master.signing.publicKey,
        signature: Crypto.sign(canonicalize(message), master.signing.secretKey),
      };
    },

    async approveOrganization(ownerHash, ownerPassword, requestText) {
      /**
       * Approve the founding of an organization this identity owns. The request is the genesis the organization's own
       * key (held by the verifier) has already signed. Every owner must approve it; a partly approved genesis is
       * handed to the next owner, and the last one publishes it.
       */
      const owner = this.getIdentity(ownerHash);
      if (!owner || !owner.encryptedMasterKeys) throw new Error('This browser does not hold the owner identity\'s master key');
      let request;
      try { request = JSON.parse(requestText); } catch { throw new Error('Paste the JSON the verifier shows at /api/issuer/request'); }
      const genesis = request.genesis || request;
      if (genesis.type !== 'genesis' || genesis.identity_type !== 'organization' || !Array.isArray(genesis.owners)) {
        throw new Error('That is not the founding request of an organization');
      }
      const { signature, approvals, ...unsigned } = genesis;
      if (!Crypto.verify(canonicalize(unsigned), signature, genesis.pubkey)) throw new Error('The request\'s signature is invalid');
      const mine = genesis.owners.find(o => o.identity === ownerHash);
      if (!mine) throw new Error('The active identity is not one of this organization\'s owners');

      const { master } = await this._unlockBoth(owner, ownerPassword);
      const approval = await this._ownerApproval(owner, master, genesis);
      genesis.approvals = [...(approvals || []).filter(a => a.identity !== ownerHash), approval];
      const complete = genesis.owners.every(o => genesis.approvals.some(a => a.identity === o.identity));
      if (!complete) return { complete: false, genesis, name: genesis.name, owners: genesis.owners };
      const orgHash = await sha256(canonicalize(genesis));
      await api.submitGenesisEvent(genesis);
      return { complete: true, orgHash, genesis, name: genesis.name, owners: genesis.owners };
    },

    async ownedOrganizations(ownerHash) {
      /** Organizations on the node whose owners (as of now) include this identity. */
      const listing = (await api.request('GET', '/identities')).identities || [];
      const found = [];
      for (const item of listing.filter(i => i.type === 'organization').slice(0, 200)) {
        let info;
        try { info = await api.getIdentity(item.identity_hash); } catch { continue; }
        const events = info.sigchain || [];
        let owners = null;
        for (const e of events) if ((e.type === 'genesis' || e.type === 'set_owners') && e.owners) owners = e.owners;
        if (!owners || !owners.some(o => o.identity === ownerHash)) continue;
        const total = owners.reduce((n, o) => n + o.weight, 0);
        found.push({
          hash: item.identity_hash, name: info.name || '(unnamed)', governance: (events[0] && events[0].governance) || 'self',
          owners: owners.map(o => ({ ...o, share: Math.round(100 * o.weight / total), me: o.identity === ownerHash })),
          devices: (info.devices || []).map(d => ({ label: d.label, key: d.pubkey.slice(0, 12) })),
          verified: info.verified, created: events[0] ? events[0].timestamp : null,
        });
      }
      return found;
    },

    async authorizeDevice(ownerHash, ownerPassword, orgHash, requestText) {
      /** In a "managed" organization the owners authorize its devices: approve an add_device for the verifier's signing key. */
      const owner = this.getIdentity(ownerHash);
      if (!owner || !owner.encryptedMasterKeys) throw new Error('This browser does not hold the owner identity\'s master key');
      if (!/^[0-9a-f]{64}$/.test(orgHash || '')) throw new Error('An organization hash is 64 hex characters');
      let request;
      try { request = JSON.parse(requestText); } catch { throw new Error('Paste the JSON the verifier shows at /api/issuer/request'); }
      const device = request.device || request;
      for (const f of ['device_pubkey', 'device_encryption_pubkey']) {
        if (!/^[0-9a-f]{64}$/.test(device[f] || '')) throw new Error(`The request has no valid ${f}`);
      }
      const info = await api.getIdentity(orgHash);
      const genesis = (info.sigchain || [])[0];
      if (!genesis || !(genesis.owners || []).some(o => o.identity === ownerHash)) throw new Error('The active identity is not an owner of that organization');
      if (genesis.governance !== 'managed') throw new Error('That organization manages its own devices: its own key authorizes them');
      const { master } = await this._unlockBoth(owner, ownerPassword);
      const events = (info.sigchain || []).filter(e => !CONTENT_TYPES.includes(e.type)); // the control chain
      const event = {
        version: 1, type: 'add_device', alg: 'ed25519', hash_alg: 'sha256', timestamp: Math.floor(Date.now() / 1000),
        prev: await sha256(canonicalize(events[events.length - 1])), signed_by: 'owners', signature: '',
        device_pubkey: device.device_pubkey, device_encryption_pubkey: device.device_encryption_pubkey,
        label: device.label || 'attestation signer', capabilities: device.capabilities || ['sign_identity'], expires: null,
      };
      event.approvals = [await this._ownerApproval(owner, master, event)];
      await api.submitEvent(orgHash, event);
      return { authorized: true };
    },

    // --- Social recovery -------------------------------------------------------------------------------------
    // Messages and records match python/src/nodetide/core/identity.py (recovery_message / sign_recovery).

    _parseRecoveryCode(code) {
      const m = /^([0-9a-f]{64}):(rec_[A-Za-z0-9_-]+)$/.exec((code || '').trim());
      if (!m) throw new Error('A recovery code looks like <64 hex characters>:rec_...');
      return { identityHash: m[1], recoveryId: m[2] };
    },

    async lookupRecovery(code) {
      /** What a trustee needs to see before agreeing: whose identity, which new key, how far along. */
      const { identityHash, recoveryId } = this._parseRecoveryCode(code);
      const status = await api.request('GET', `/identities/${identityHash}/recovery/${recoveryId}`);
      const info = await api.getIdentity(identityHash);
      return { identityHash, recoveryId, name: info.name || '', status, trustees: (info.recovery && info.recovery.primary_trustees) || [] };
    },

    async trusteeSign(trusteeHash, password, code) {
      /** Vouch for a recovery: sign (identity, chain head, new keys) with this trustee's master key. */
      const seen = await this.lookupRecovery(code);
      if (!seen.trustees.includes(trusteeHash)) throw new Error('This identity is not a trustee of that identity');
      const trustee = this.getIdentity(trusteeHash);
      if (!trustee || !trustee.encryptedMasterKeys) throw new Error('This browser does not hold the trustee identity\'s master key');
      const { master } = await this._unlockBoth(trustee, password);
      const chain = await api.request('GET', `/identities/${trusteeHash}/sigchain?light=1`);
      const events = chain.events || [];
      const state = await sha256(canonicalize(events[events.length - 1]));
      const message = {
        purpose: 'nodetide-social-recovery-v1',
        identity: seen.identityHash,
        prev: seen.status.prev,
        new_pubkey: seen.status.new_master_pubkey,
        new_encryption_pubkey: seen.status.new_encryption_pubkey,
        trustee: trusteeHash,
        state,
      };
      const record = {
        trustee_identity: trusteeHash,
        state,
        key: master.signing.publicKey,
        signature: Crypto.sign(canonicalize(message), master.signing.secretKey),
      };
      return api.request('POST', `/identities/${seen.identityHash}/recovery/${seen.recoveryId}/sign`, { record });
    },

    async startRecovery(identityHash, localPassword) {
      /** Ask for a recovery with a brand-new master key; the code goes to the trustees. */
      identityHash = (identityHash || '').trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(identityHash)) throw new Error('An identity hash is 64 hex characters');
      if (!localPassword || localPassword.length < 8) throw new Error('Choose a password of at least 8 characters for this browser');
      const info = await api.getIdentity(identityHash);
      if (!info.recovery) throw new Error('That identity has no recovery set up');
      const master = Crypto.generateKeyPair();
      const started = await api.request('POST', `/identities/${identityHash}/recovery/initiate`, {
        new_pubkey: master.signing.publicKey, new_encryption_pubkey: master.encryption.publicKey,
      });
      const pending = {
        identityHash, recoveryId: started.recovery_id, newPubkey: master.signing.publicKey,
        threshold: started.threshold, encryptedMaster: await Crypto.encryptWithPassword(master, localPassword),
      };
      localStorage.setItem(STORAGE_KEYS.PENDING_RECOVERY, JSON.stringify(pending));
      return { code: `${identityHash}:${started.recovery_id}`, threshold: started.threshold };
    },

    pendingRecovery() {
      try { return JSON.parse(localStorage.getItem(STORAGE_KEYS.PENDING_RECOVERY)); } catch { return null; }
    },

    async finishRecovery(localPassword) {
      /** When enough trustees have signed: publish the recovery with the new key, add a device and keep the identity here. */
      const pending = this.pendingRecovery();
      if (!pending) throw new Error('No recovery is waiting in this browser');
      const status = await api.request('GET', `/identities/${pending.identityHash}/recovery/${pending.recoveryId}`);
      if (status.status !== 'complete') return { done: false, collected: status.collected, threshold: status.threshold };

      let master;
      try { master = await Crypto.decryptWithPassword(pending.encryptedMaster, localPassword); } catch { throw new Error('Invalid password'); }
      const timestamp = Math.floor(Date.now() / 1000);
      const { commitment } = await Wallet.chain(pending.identityHash);
      const withCommitment = commitment ? { content: commitment } : {};
      const recovery = {
        version: 1, type: 'social_recovery', alg: 'ed25519', hash_alg: 'sha256', timestamp,
        ...withCommitment,
        prev: status.prev, signed_by: master.signing.publicKey,
        new_pubkey: master.signing.publicKey, new_encryption_pubkey: master.encryption.publicKey,
        recovery_signatures: status.signatures.map(s => s.record),
      };
      recovery.signature = Crypto.sign(canonicalize(recovery), master.signing.secretKey);
      await api.submitEvent(pending.identityHash, recovery);

      const device = Crypto.generateKeyPair();
      const addDevice = {
        version: 1, type: 'add_device', alg: 'ed25519', hash_alg: 'sha256', timestamp: timestamp + 1,
        prev: await sha256(canonicalize(recovery)), signed_by: master.signing.publicKey,
        device_pubkey: device.signing.publicKey, device_encryption_pubkey: device.encryption.publicKey,
        label: 'Web Browser', capabilities: DEVICE_CAPABILITIES, expires: null, ...withCommitment,
      };
      addDevice.signature = Crypto.sign(canonicalize(addDevice), master.signing.secretKey);
      await api.submitEvent(pending.identityHash, addDevice);

      const chain = await api.request('GET', `/identities/${pending.identityHash}/sigchain`);
      const genesis = chain.events[0];
      const identity = {
        identityHash: pending.identityHash, name: genesis.name || '', createdAt: Date.now(),
        storageMethod: StorageMethod.PASSWORD,
        encryptedKeys: await Crypto.encryptWithPassword(device, localPassword),
        encryptedMasterKeys: await Crypto.encryptWithPassword(master, localPassword),
        signingPubkey: device.signing.publicKey, encryptionPubkey: device.encryption.publicKey,
        masterSigningPubkey: master.signing.publicKey, distributionPoints: genesis.distribution_points || null,
        genesisEvent: genesis, addDeviceEvent: addDevice,
      };
      const others = this.listIdentities().filter(i => i.identityHash !== identity.identityHash);
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify([...others, identity]));
      localStorage.removeItem(STORAGE_KEYS.PENDING_RECOVERY);
      // Recovery restores control, not the stored claim values: a fresh backup is needed again
      ProtectionState.save(identity.identityHash, { backupAt: null });
      return { done: true, identity };
    },

    async dumpIdentity(identityHash, password) {
      /**
       * Create a portable dump of an identity with encrypted private keys.
       * Format is compatible with CLI 'identity restore' command.
       */
      const identity = this.getIdentity(identityHash);
      if (!identity) throw new Error('Identity not found');

      // Get decrypted keys (need to unlock first)
      const keyPair = SessionKeys.get(identityHash);
      if (!keyPair) throw new Error('Identity must be unlocked to dump');

      // Fetch sigchain from API
      let sigchain = [];
      try {
        const response = await api.request('GET', `/identities/${identityHash}/sigchain`);
        sigchain = response.events || [];
      } catch (e) {
        console.warn('Could not fetch sigchain from API, using empty:', e);
      }

      // Encrypt keys for dump (format compatible with CLI)
      const keysJson = JSON.stringify({
        signing_key: keyPair.signing.secretKey,
        encryption_key: keyPair.encryption.secretKey,
      });
      const encryptedKeys = await Crypto.encryptWithPassword(keysJson, password);

      // Create dump
      return {
        version: 1,
        format: 'nodetide-identity-dump',
        identity_hash: identityHash,
        sigchain: sigchain,
        encrypted_keys: encryptedKeys,
      };
    },

    async restoreIdentity(dump, password, localPassword) {
      /**
       * Restore an identity from a dump file.
       * @param dump - The dump object
       * @param password - Password used to encrypt the dump
       * @param localPassword - Password to use for local storage
       */
      if (dump.format !== 'nodetide-identity-dump') {
        throw new Error('Invalid dump format');
      }

      // Decrypt keys from dump
      let keysData;
      try {
        keysData = await Crypto.decryptWithPassword(dump.encrypted_keys, password);
      } catch (e) {
        throw new Error('Invalid password');
      }

      // Re-encrypt for local storage
      const encryptedKeys = await Crypto.encryptWithPassword(keysData, localPassword);

      // Parse keys to get public keys
      const keys = typeof keysData === 'string' ? JSON.parse(keysData) : keysData;

      // Derive public keys from secret keys using nacl
      const signingSecretKey = decodeHex(keys.signing_key);
      const signingKeyPair = nacl.sign.keyPair.fromSecretKey(signingSecretKey);
      const signingPubkey = encodeHex(signingKeyPair.publicKey);

      const encryptionSecretKey = decodeHex(keys.encryption_key);
      const encryptionKeyPair = nacl.box.keyPair.fromSecretKey(encryptionSecretKey);
      const encryptionPubkey = encodeHex(encryptionKeyPair.publicKey);

      // Create identity for localStorage
      const identity = {
        identityHash: dump.identity_hash,
        name: dump.sigchain?.[0]?.name || '',
        createdAt: Date.now(),
        storageMethod: StorageMethod.PASSWORD,
        encryptedKeys,
        signingPubkey,
        encryptionPubkey,
      };

      // Check if identity already exists
      if (this.getIdentity(dump.identity_hash)) {
        throw new Error('Identity already exists');
      }

      this._saveIdentity(identity);

      // Register sigchain with API if we have events
      if (dump.sigchain && dump.sigchain.length > 0) {
        try {
          // Try to create identity on server (may already exist)
          await api.request('POST', '/identities', { event: dump.sigchain[0] });
        } catch (e) {
          console.warn('Could not register identity with API:', e);
        }
      }

      return identity;
    },
  };

  // ============================================
  // PROTECTION: encrypted backup + social recovery
  // ============================================

  // Backups leave the browser and sit in a mailbox or a drive for years: derive their key much harder than the
  // working copy of the keys (OWASP asks for 600k+ for PBKDF2-SHA256). Same values as Python's crypto.py.
  const BACKUP_KDF_ITERATIONS = 1000000;
  const MAX_KDF_ITERATIONS = 20000000;
  const MIN_BACKUP_PASSWORD = 12;
  const MIN_TRUSTEES = 3;
  const COMMON_PASSWORDS = ['password', 'passwordpassword', '123456789012', 'qwertyuiopas', 'qwertyqwerty',
    'iloveyouiloveyou', 'administrator', 'letmeinletmein'];

  function weakPasswordReason(password) {
    if ([...password].length < MIN_BACKUP_PASSWORD) {
      return `Use at least ${MIN_BACKUP_PASSWORD} characters (a few random words work well).`;
    }
    if (new Set(password).size < 6 || /^\d+$/.test(password) || COMMON_PASSWORDS.includes(password.toLowerCase())) {
      return 'That password is too easy to guess; use a longer, less predictable one.';
    }
    return null;
  }

  // What the browser remembers about an identity's protection (the backup file itself is never kept here).
  const ProtectionState = {
    key(hash) { return `nodetide_protection_${hash}`; },
    load(hash) {
      try { return JSON.parse(localStorage.getItem(this.key(hash))) || {}; } catch { return {}; }
    },
    save(hash, patch) {
      try { localStorage.setItem(this.key(hash), JSON.stringify({ ...this.load(hash), ...patch })); } catch { /* storage unavailable */ }
    },
  };

  // ============================================
  // PASSKEY: unlock this browser's wallet with a WebAuthn authenticator instead of typing the password
  // ============================================
  // The identity password stays the root secret (and the fallback). With a passkey it is stored wrapped under a key
  // the authenticator derives with the WebAuthn PRF extension: an AES-GCM key from HKDF(PRF(salt)). Whoever has only
  // the browser's storage cannot unwrap it; unwrapping needs this authenticator and its user verification (Touch ID,
  // PIN, ...). A synced passkey (iCloud Keychain, 1Password, ...) carries the PRF secret to the user's other devices,
  // but the wrapped password lives only in this browser: the passkey is a convenience, the backup file is the safety net.

  const Passkey = {
    INFO: 'nodetide-passkey-unlock-v1',

    supported() { return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create); },

    _b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
    _unb64(text) {
      const pad = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4);
      return Uint8Array.from(atob(pad), c => c.charCodeAt(0));
    },

    async _key(prfOutput) {
      const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
      return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(this.INFO) },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    },

    async _prf(credentialId, saltBytes) {
      const assertion = await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: saltBytes } } },
        timeout: 60000,
      } });
      const results = assertion.getClientExtensionResults().prf;
      if (!results || !results.results || !results.results.first) {
        throw new Error('This passkey cannot derive a key (no PRF support); the password still works');
      }
      return results.results.first;
    },

    async enroll(identityHash, password) {
      /** Make a passkey for this identity and wrap the (already verified) password under it. */
      if (!this.supported()) throw new Error('This browser has no passkey support');
      const identity = KeyStore.getIdentity(identityHash);
      await KeyStore._unlockBoth(identity, password); // refuse a wrong password before storing it
      const created = await navigator.credentials.create({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: window.location.hostname, name: 'Nodetide' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: identity.name || identityHash.slice(0, 12), displayName: identity.name || 'Nodetide identity' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        extensions: { prf: {} },
        timeout: 60000,
      } });
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const prf = await this._prf(created.rawId, salt); // some authenticators only evaluate PRF on get
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await this._key(prf), new TextEncoder().encode(password));
      const passkey = { credentialId: this._b64(created.rawId), salt: this._b64(salt), iv: this._b64(iv), wrapped: this._b64(wrapped), createdAt: Date.now() };
      KeyStore.updateIdentity(identityHash, { passkey });
      return passkey;
    },

    async password(identityHash) {
      /** The identity password, unwrapped by the authenticator (asks for the user's verification). */
      const identity = KeyStore.getIdentity(identityHash);
      const p = identity && identity.passkey;
      if (!p) throw new Error('No passkey is set up for this identity');
      let prf;
      try {
        prf = await this._prf(this._unb64(p.credentialId), this._unb64(p.salt));
      } catch (e) {
        if (e.name === 'NotAllowedError') throw new Error('The passkey was not confirmed');
        throw e;
      }
      try {
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: this._unb64(p.iv) }, await this._key(prf), this._unb64(p.wrapped));
        return new TextDecoder().decode(plain);
      } catch {
        throw new Error('The passkey did not match the stored data; use the password');
      }
    },

    remove(identityHash) { KeyStore.updateIdentity(identityHash, { passkey: null }); },
  };

  // ============================================
  // WALLET: claims, verification and attestations, kept in this browser
  // ============================================
  // Nothing is held by a server. The claim values, attestations and verification state live in localStorage as one
  // blob encrypted (PBKDF2 + AES-GCM) with the identity's password; the unlocked keys, the password and the decrypted
  // blob exist only in memory (WalletSession) and are dropped after WALLET_IDLE_MS or on reload.
  // Byte-for-byte compatible with python/src/nodetide/core/claims.py and auth.py.

  const WALLET_IDLE_MS = 15 * 60 * 1000;
  const CLAIM_DOMAIN = 'nodetide-claim-v1\u0000';
  const AUTH_DOMAIN = 'nodetide-auth-v1\u0000';
  const EMAIL_LOCAL_RE = /^[^\s@\u0000-\u001f]{1,64}$/;
  const DOMAIN_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  const PHONE_RE = /^\+[1-9][0-9]{6,14}$/;

  const WalletSession = {
    _s: new Map(),
    get(hash) {
      const s = this._s.get(hash);
      if (!s) return null;
      clearTimeout(s.timer);
      s.timer = setTimeout(() => this.lock(hash), WALLET_IDLE_MS);
      return s;
    },
    set(hash, session) {
      this.lock(hash);
      session.timer = setTimeout(() => this.lock(hash), WALLET_IDLE_MS);
      this._s.set(hash, session);
      const store = window.Alpine && Alpine.store('wallet');
      if (store) store.sync();
    },
    isUnlocked(hash) { return this._s.has(hash); },
    lock(hash) {
      const s = this._s.get(hash);
      if (s) clearTimeout(s.timer);
      this._s.delete(hash);
      const store = window.Alpine && Alpine.store('wallet');
      if (store) store.sync();
    },
  };

  const Wallet = {
    storageKey(hash) { return `nodetide_wallet_${hash}`; },
    emptyData() { return { claims: {}, attestations: [], issuer_chains: {}, verifications: {}, history: {} }; },

    async unlock(hash, password) {
      const identity = KeyStore.getIdentity(hash);
      if (!identity) throw new Error('Identity not found');
      if (!identity.encryptedMasterKeys) throw new Error('This browser does not hold this identity\'s master key');
      password = await KeyStore._pw(identity, password);
      const { master, device } = await KeyStore._unlockBoth(identity, password);
      let data = this.emptyData();
      const stored = localStorage.getItem(this.storageKey(hash));
      if (stored) {
        try { data = { ...data, ...(await Crypto.decryptWithPassword(JSON.parse(stored), password)) }; } catch {
          throw new Error('The stored wallet data could not be decrypted');
        }
      }
      WalletSession.set(hash, { master, device, password, data, identity });
      return data;
    },

    async unlockWithPasskey(hash) {
      return this.unlock(hash, await Passkey.password(hash));
    },

    session(hash) {
      const s = WalletSession.get(hash);
      if (!s) throw new Error('Unlock the wallet first');
      return s;
    },

    async save(hash) {
      const s = this.session(hash);
      const blob = await Crypto.encryptWithPassword(s.data, s.password);
      localStorage.setItem(this.storageKey(hash), JSON.stringify(blob));
    },

    // ---- values ----
    nfc(text) { return text.normalize('NFC'); },

    normalizeValue(type, value) {
      if (type === 'email') {
        if (typeof value !== 'string') throw new Error('email must be a string');
        const text = this.nfc(value.trim());
        const at = text.lastIndexOf('@');
        if (at < 0) throw new Error('invalid email address');
        const local = text.slice(0, at), domain = text.slice(at + 1);
        if (!EMAIL_LOCAL_RE.test(local)) throw new Error('invalid email address');
        let ascii;
        try { ascii = new URL('http://' + domain).hostname.toLowerCase(); } catch { throw new Error('invalid email domain'); }
        const labels = ascii.split('.');
        if (!domain || labels.length < 2 || !labels.every(l => DOMAIN_LABEL_RE.test(l))) throw new Error('invalid email domain');
        const result = `${local}@${ascii}`;
        if (result.length > 254) throw new Error('email address is too long');
        return result;
      }
      if (type === 'phone') {
        if (typeof value !== 'string') throw new Error('phone must be a string');
        const text = value.replace(/[\s().-]/g, '');
        if (!PHONE_RE.test(text)) throw new Error('phone must be an E.164 number such as +359881234567');
        return text;
      }
      if (type === 'legal_name') {
        const out = {};
        for (const key of ['given_name', 'family_name']) {
          const part = value && value[key];
          if (typeof part !== 'string' || !part.trim() || part.length > 100) throw new Error(`${key} must be a non-empty string`);
          out[key] = this.nfc(part.trim());
        }
        return out;
      }
      throw new Error(`The browser wallet does not handle ${type} claims yet`);
    },

    async commitment(claimId, type, saltHex, value) {
      const enc = new TextEncoder();
      const parts = [
        enc.encode(CLAIM_DOMAIN + claimId + '\u0000' + type + '\u0000'), decodeHex(saltHex),
        enc.encode('\u0000' + canonicalize(this.normalizeValue(type, value))),
      ];
      const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let offset = 0;
      for (const p of parts) { bytes.set(p, offset); offset += p.length; }
      return sha256(bytes);
    },

    newClaimId() {
      for (;;) {
        const raw = crypto.getRandomValues(new Uint8Array(16));
        const id = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        if (/^[A-Za-z0-9]/.test(id)) return id;
      }
    },

    async chain(hash) {
      /** The whole chain, split: `events` is the control chain, `content` the claim track; `commitment` is what a control event signed now must carry. */
      const c = await api.request('GET', `/identities/${hash}/sigchain`);
      const all = c.events || [];
      const events = all.filter(e => !CONTENT_TYPES.includes(e.type));
      const content = all.filter(e => CONTENT_TYPES.includes(e.type)).sort((a, b) => a.seq - b.seq);
      const head = await sha256(canonicalize(events[events.length - 1]));
      const hashes = await Promise.all(content.map(e => sha256(canonicalize(e))));
      return {
        events, content, all, head, contentHead: hashes.length ? hashes[hashes.length - 1] : null,
        commitment: content.length ? { count: content.length, root: await merkleRootHex(hashes) } : null,
      };
    },

    committedCount(events) {
      let n = 0;
      for (const e of events) if (e.content && typeof e.content.count === 'number') n = Math.max(n, e.content.count);
      return n;
    },

    async ensureCommitted(hash) {
      /** A light verifier can only rely on content that a control event commits to: publish a checkpoint if some is not yet. */
      const s = this.session(hash);
      const chain = await this.chain(hash);
      if (!chain.content.length || this.committedCount(chain.events) >= chain.content.length) return chain;
      const event = {
        version: 1, type: 'checkpoint', alg: 'ed25519', hash_alg: 'sha256', timestamp: Math.floor(Date.now() / 1000),
        prev: chain.head, signed_by: s.master.signing.publicKey, content: chain.commitment,
      };
      event.signature = Crypto.sign(canonicalize(event), s.master.signing.secretKey);
      await api.submitEvent(hash, event);
      return this.chain(hash);
    },

    async claimProof(hash, claimId) {
      /** The claim's event with its Merkle path to the control event that commits it (null if it is not committed yet). */
      const chain = await this.chain(hash);
      const seq = chain.content.findIndex(e => e.claim_id === claimId);
      if (seq < 0) return null;
      try { return await api.request('GET', `/identities/${hash}/content/${seq}`); } catch { return null; }
    },

    // ---- claims ----
    async addClaim(hash, type, value) {
      const s = this.session(hash);
      const normalized = this.normalizeValue(type, value);
      // The chain only holds salted commitments, so only the holder can notice that a value is already claimed.
      // (Email local parts are case-sensitive in theory and never in practice, so Alice@ and alice@ count as one.)
      const key = v => (type === 'email' ? String(v).toLowerCase() : canonicalize(v));
      const same = Object.values(s.data.claims).find(d => !d.renounced_at && d.claim_type === type && key(d.value) === key(normalized));
      if (same) throw new Error(`This ${type === 'legal_name' ? 'name' : type} is already in your wallet; renounce that claim first if you want to claim it anew`);
      const claimId = this.newClaimId();
      const salt = encodeHex(crypto.getRandomValues(new Uint8Array(16)));
      const commitment = await this.commitment(claimId, type, salt, normalized);
      const chain = await this.chain(hash);
      const event = {
        version: 1, type: 'add_claim', alg: 'ed25519', hash_alg: 'sha256', timestamp: Math.floor(Date.now() / 1000),
        prev: chain.contentHead, seq: chain.content.length, control_ref: chain.head,
        signed_by: s.master.signing.publicKey, claim_id: claimId, claim_type: type, commitment, expires: null,
      };
      event.signature = Crypto.sign(canonicalize(event), s.master.signing.secretKey);
      // keep the value before the chain commits to it: a commitment without its value could never be shown again
      s.data.claims[claimId] = { identity: hash, claim_id: claimId, claim_type: type, value: normalized, salt };
      this.note(s, claimId, 'created', 'Added to this wallet');
      await this.save(hash);
      try {
        await api.submitEvent(hash, event);
      } catch (e) {
        delete s.data.claims[claimId];
        delete s.data.history[claimId];
        await this.save(hash);
        throw e;
      }
      return s.data.claims[claimId];
    },

    note(s, claimId, kind, detail) {
      /** A line in this claim's local history (what only this browser knows: codes requested, renounced). */
      (s.data.history[claimId] = s.data.history[claimId] || []).push({ t: Math.floor(Date.now() / 1000), kind, detail });
    },

    async renounceClaim(hash, claimId) {
      /**
       * Give a claim up, verified or not: a revoke_claim event on the chain. The value, its attestations and its history
       * stay here (hidden by default) so its timeline can still be read; it no longer counts, is never offered for a
       * sign-in, and the same value can be claimed again.
       */
      const s = this.session(hash);
      const doc = s.data.claims[claimId];
      if (!doc || doc.renounced_at) throw new Error('Unknown or already renounced claim');
      const { head, commitment } = await this.chain(hash);
      const event = {
        version: 1, type: 'revoke_claim', alg: 'ed25519', hash_alg: 'sha256', timestamp: Math.floor(Date.now() / 1000),
        prev: head, signed_by: s.master.signing.publicKey, claim_id: claimId, reason: 'renounced by the holder',
        ...(commitment ? { content: commitment } : {}),
      };
      event.signature = Crypto.sign(canonicalize(event), s.master.signing.secretKey);
      await api.submitEvent(hash, event);
      doc.renounced_at = event.timestamp;
      doc.renounced_event = await sha256(canonicalize(event));
      delete s.data.verifications[claimId];
      this.note(s, claimId, 'renounced', 'You renounced this claim');
      await this.save(hash);
    },

    async publishAttestation(hash, claimId) {
      /**
       * Put a verified claim's attestation on the node, where the explorer and anyone can see it. It reveals that this
       * identity holds an attested claim of that type and who attested it; the value is not in it and stays private.
       */
      const s = this.session(hash);
      const doc = s.data.claims[claimId];
      if (!doc || doc.renounced_at) throw new Error('Unknown or renounced claim');
      const atts = s.data.attestations.filter(a => a.claim_id === claimId);
      if (!atts.length) throw new Error('This claim has no attestation yet');
      const { all: events } = await this.chain(hash);
      let published = 0;
      for (const att of atts) {
        const issuer = s.data.issuer_chains[att.issuer];
        await api.request('POST', '/attestations', {
          attestation: att, subject_sigchain: events, ...(issuer ? { issuer_sigchain: issuer.sigchain } : {}),
        });
        published += 1;
      }
      doc.published_at = Math.floor(Date.now() / 1000);
      this.note(s, claimId, 'published', `Attestation published on the node (public: anyone can see that this claim is attested, not its value)`);
      await this.save(hash);
      return published;
    },

    async timeline(hash, claimId) {
      /** Everything known about one claim, oldest first, and the raw material behind it. */
      const s = this.session(hash);
      const doc = s.data.claims[claimId];
      if (!doc) throw new Error('Unknown claim');
      const { all: events } = await this.chain(hash);
      const entries = [];
      const raw = [];
      let addedHash = null;
      for (const e of events) {
        if (e.claim_id !== claimId) continue;
        const eventHash = await sha256(canonicalize(e));
        if (e.type === 'add_claim') {
          addedHash = eventHash;
          entries.push({ t: e.timestamp, rank: 0, source: 'chain', label: `Claimed on your identity chain (${e.claim_type})`, hash: eventHash });
          raw.push({ title: 'add_claim event (signed by your key, on the chain)', hash: eventHash, json: e });
        } else if (e.type === 'revoke_claim') {
          entries.push({ t: e.timestamp, rank: 3, source: 'chain', label: 'Renounced on your identity chain', hash: eventHash });
          raw.push({ title: 'revoke_claim event (on the chain)', hash: eventHash, json: e });
        }
      }
      for (const h of s.data.history[claimId] || []) {
        if (h.kind === 'renounced') continue; // the chain event above says it
        entries.push({ t: h.t, rank: 1, source: 'this browser', label: h.detail });
      }
      for (const a of s.data.attestations.filter(x => x.claim_id === claimId)) {
        const issuer = s.data.issuer_chains[a.issuer];
        const who = (issuer && issuer.name) || a.issuer.slice(0, 12);
        entries.push({ t: a.issued_at, rank: 2, source: 'issuer', label: `Verified by ${who} (${a.method}, ${a.assurance} assurance)` });
        entries.push({ t: a.expires_at, rank: 4, source: 'issuer', label: 'Attestation expires', future: a.expires_at > Math.floor(Date.now() / 1000) });
        raw.push({ title: `attestation (signed by ${who}; the value is not in it)`, json: a });
      }
      entries.sort((x, y) => (x.t - y.t) || (x.rank - y.rank)); // same second: claimed, then this browser, then issuer, then renounced
      const base = window.location.origin + '/explorer/#';
      return {
        entries, raw,
        explorer: { event: addedHash ? `${base}/event/${addedHash}` : null, identity: `${base}/identity/${hash}` },
      };
    },

    // ---- verification service ----
    async verifierUrl() {
      const own = Settings.get('verifierUrl', '');
      if (own) return own.replace(/\/+$/, '');
      try {
        const cfg = await api.request('GET', '/web-config');
        if (cfg.verifier_url) return cfg.verifier_url.replace(/\/+$/, '');
      } catch { /* not configured */ }
      throw new Error('No verification service is configured (Settings -> Verification service URL)');
    },

    async verifier(method, path, body) {
      const base = await this.verifierUrl();
      const response = await fetch(base + path, {
        method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body),
      });
      const json = await response.json().catch(() => ({}));
      return { status: response.status, json };
    },

    async ensureDeviceMayAuthenticate(hash) {
      /** Older web identities were given capabilities that do not exist; re-authorize the device with the real ones. */
      const s = this.session(hash);
      const { events, head, commitment } = await this.chain(hash);
      let caps = [];
      for (const e of events) {
        if (e.type === 'add_device' && e.device_pubkey === s.device.signing.publicKey) caps = e.capabilities || [];
      }
      if (caps.includes('authenticate') && caps.includes('manage_claims')) return;
      const event = {
        version: 1, type: 'add_device', alg: 'ed25519', hash_alg: 'sha256', timestamp: Math.floor(Date.now() / 1000),
        prev: head, signed_by: s.master.signing.publicKey, device_pubkey: s.device.signing.publicKey,
        device_encryption_pubkey: s.device.encryption.publicKey, label: 'Web Browser', capabilities: DEVICE_CAPABILITIES, expires: null,
        ...(commitment ? { content: commitment } : {}),
      };
      event.signature = Crypto.sign(canonicalize(event), s.master.signing.secretKey);
      await api.submitEvent(hash, event);
    },

    async assertion(hash, request, claims) {
      const s = this.session(hash);
      const { head } = await this.chain(hash);
      const iat = Math.floor(Date.now() / 1000);
      const body = {
        type: 'AUTH_ASSERTION', identity: hash, device: s.device.signing.publicKey, aud: request.aud, nonce: request.nonce,
        iat, exp: Math.min(iat + 300, iat + 600, request.expires_at), chain_head: head,
      };
      if (claims) body.claims = claims;
      return { ...body, sig: Crypto.sign(AUTH_DOMAIN + canonicalize(body), s.device.signing.secretKey) };
    },

    async startVerification(hash, claimId) {
      const s = this.session(hash);
      const doc = s.data.claims[claimId];
      if (!doc || doc.renounced_at) throw new Error('Unknown or renounced claim');
      if (!['email', 'phone'].includes(doc.claim_type)) throw new Error('Only email and phone claims are verified with a code');
      await this.ensureDeviceMayAuthenticate(hash);
      await this.ensureCommitted(hash); // the claim is committed before it is attested, so a light verifier can rely on it
      const challenge = await this.verifier('POST', '/api/auth/challenge', {});
      if (challenge.status === 503) throw new Error('The verification service is not ready yet: ' + (challenge.json.message || 'its issuer is not set up'));
      if (challenge.status !== 201) throw new Error(challenge.json.message || `The verification service refused a challenge (${challenge.status})`);
      const assertion = await this.assertion(hash, challenge.json, { purpose: 'claim_verification', claim_id: claimId });
      const { all } = await this.chain(hash);
      const started = await this.verifier('POST', `/api/verify/${doc.claim_type}/start`, { document: doc, assertion, sigchain: all });
      if (started.status !== 202) throw new Error(started.json.message || `Verification not started (${started.status})`);
      s.data.verifications[claimId] = { verification_id: started.json.verification_id, expires_at: started.json.expires_at, kind: doc.claim_type };
      this.note(s, claimId, 'code', `A code was requested from the verification service (valid until ${new Date(started.json.expires_at * 1000).toLocaleTimeString()})`);
      await this.save(hash);
      return { expiresAt: started.json.expires_at, message: started.json.message || '' };
    },

    async confirmVerification(hash, claimId, code) {
      const s = this.session(hash);
      const pending = s.data.verifications[claimId];
      if (!pending) throw new Error('Start the verification first');
      const confirmed = await this.verifier('POST', `/api/verify/${pending.kind}/confirm`, {
        verification_id: pending.verification_id, code: String(code).trim(),
      });
      if (confirmed.status !== 201) throw new Error(confirmed.json.message || `The code was not accepted (${confirmed.status})`);
      const att = confirmed.json.attestation;
      const doc = s.data.claims[claimId];
      if (att.subject !== hash || att.claim_id !== claimId || att.commitment !== (await this.commitment(claimId, doc.claim_type, doc.salt, doc.value))) {
        throw new Error('The attestation does not match this claim; it was not kept');
      }
      const info = await this.verifier('GET', '/api/verify/issuer');
      if (info.status === 200 && info.json.issuer === att.issuer) {
        s.data.issuer_chains[att.issuer] = { name: info.json.name || null, sigchain: info.json.sigchain, owner_sigchains: info.json.owner_sigchains || {} };
      }
      s.data.attestations = s.data.attestations.filter(a => !(a.claim_id === att.claim_id && a.method === att.method)).concat([att]);
      delete s.data.verifications[claimId];
      await this.save(hash);
      return att;
    },

    // ---- sign in with this wallet (the node's OIDC page opens /signin?link=<challenge url>) ----
    challengeUrl(link) {
      let text = (link || '').trim();
      if (text.startsWith('nodetide://')) text = new URL(text.replace('nodetide://', 'https://x/')).searchParams.get('challenge_url') || '';
      let url;
      try { url = new URL(text); } catch { throw new Error('That is not a sign-in address'); }
      if (url.origin !== window.location.origin) throw new Error('This wallet signs in only to its own node (' + window.location.host + ')');
      return url.href;
    },

    async signinPreview(hash, link) {
      const s = this.session(hash);
      const response = await fetch(this.challengeUrl(link));
      if (!response.ok) throw new Error('Cannot fetch the sign-in challenge (' + response.status + '); it may have expired');
      const challenge = await response.json();
      const asked = (challenge.display.claims_requested || []).map(c => c.claim_type);
      const now = Math.floor(Date.now() / 1000);
      const candidates = [];
      for (const type of new Set(asked)) {
        const rows = [];
        for (const att of s.data.attestations) {
          const doc = s.data.claims[att.claim_id];
          if (!doc || doc.renounced_at || doc.claim_type !== type || att.expires_at <= now) continue;
          rows.push({ att, doc });
        }
        // best assurance, then latest expiry; the first of a type is the default
        const rank = { low: 0, substantial: 1, high: 2 };
        rows.sort((a, b) => (rank[b.att.assurance] - rank[a.att.assurance]) || (b.att.expires_at - a.att.expires_at));
        rows.forEach((r, i) => candidates.push({
          attestation_id: null, att: r.att, claim_id: r.doc.claim_id, claim_type: type, method: r.att.method,
          assurance: r.att.assurance, expires_at: r.att.expires_at,
          value: typeof r.doc.value === 'string' ? r.doc.value : Object.values(r.doc.value).join(' '), default: i === 0,
        }));
      }
      for (const c of candidates) c.attestation_id = await sha256(canonicalize(c.att));
      return {
        challenge, candidates, client: challenge.display.client_name, issuer: challenge.display.issuer,
        claimsRequested: challenge.display.claims_requested || [],
        candidateView: candidates.map(({ att, ...rest }) => rest),
      };
    },

    async signinApprove(hash, preview, shareIds) {
      const s = this.session(hash);
      await this.ensureDeviceMayAuthenticate(hash);
      const chosen = preview.candidates.filter(c => shareIds.includes(c.attestation_id));
      const types = chosen.map(c => c.claim_type);
      if (new Set(types).size !== types.length) throw new Error('Choose one value per claim type (for example one email), not several');
      await this.ensureCommitted(hash);
      // Light by default: the control chain, and for each shown claim its event with a Merkle path. If a claim cannot be
      // proven that way (not committed), fall back to sending the whole chain.
      let light = true;
      const presentations = [];
      for (const c of chosen) {
        const item = { document: s.data.claims[c.claim_id], attestation: c.att };
        const issuer = s.data.issuer_chains[c.att.issuer];
        if (issuer) item.issuer_sigchain = issuer.sigchain;
        const proof = await this.claimProof(hash, c.claim_id);
        if (proof) { item.claim_event = proof.event; item.claim_proof = proof.proof; } else { light = false; }
        presentations.push(item);
      }
      const assertion = await this.assertion(hash, preview.challenge.request, null);
      const chain = await this.chain(hash);
      const response = await fetch(preview.challenge.respond_url, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assertion, sigchain: light ? chain.events : chain.all, presentations }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.message || body.error || 'The sign-in was refused (' + response.status + ')');
      return body;
    },

    // ---- backup support ----
    async exportData(hash, identityPassword) {
      const stored = localStorage.getItem(this.storageKey(hash));
      if (!stored) return this.emptyData();
      try { return { ...this.emptyData(), ...(await Crypto.decryptWithPassword(JSON.parse(stored), identityPassword)) }; } catch {
        throw new Error('The stored wallet data could not be decrypted');
      }
    },

    async importData(hash, data, password) {
      const blob = await Crypto.encryptWithPassword({ ...this.emptyData(), ...data }, password);
      localStorage.setItem(this.storageKey(hash), JSON.stringify(blob));
    },
  };

  const SessionKeys = {
    _keys: new Map(),
    set(identityHash, keyPair) { this._keys.set(identityHash, keyPair); },
    get(identityHash) { return this._keys.get(identityHash) || null; },
    isUnlocked(identityHash) { return this._keys.has(identityHash); },
    lock(identityHash) { this._keys.delete(identityHash); },
    lockAll() { this._keys.clear(); },
  };

  const Settings = {
    getAll() {
      const data = localStorage.getItem(STORAGE_KEYS.SETTINGS);
      try { return data ? JSON.parse(data) : {}; } catch { return {}; }
    },
    get(key, defaultValue) {
      const settings = this.getAll();
      return key in settings ? settings[key] : defaultValue;
    },
    set(key, value) {
      const settings = this.getAll();
      settings[key] = value;
      localStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(settings));
    },
  };

  // ============================================
  // API CLIENT
  // ============================================

  const api = {
    baseUrl: '/api',
    sessionToken: null,

    setSession(token) { this.sessionToken = token; },
    clearSession() { this.sessionToken = null; },

    async request(method, path, body) {
      const headers = { 'Content-Type': 'application/json' };
      if (this.sessionToken) headers['Authorization'] = `Bearer ${this.sessionToken}`;

      const options = { method, headers };
      if (body) options.body = JSON.stringify(body);

      const response = await fetch(`${this.baseUrl}${path}`, options);
      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        const err = new Error(error.error || error.message || 'Request failed');
        err.status = response.status;
        throw err;
      }
      return response.json();
    },

    async createIdentity(keyPair, name, distributionPoints = null) {
      console.log('[api.createIdentity] called with distributionPoints:', distributionPoints);
      const timestamp = Math.floor(Date.now() / 1000);
      const event = {
        // Base SigchainEvent fields
        version: 1,
        type: 'genesis',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp,
        prev: null,
        signed_by: keyPair.signing.publicKey,
        // GenesisEvent fields
        pubkey: keyPair.signing.publicKey,
        encryption_pubkey: keyPair.encryption.publicKey,
        identity_type: 'personal',
        name: name || null,
        ephemeral: false,
        ownership_proof: null,
        distribution_points: distributionPoints,
      };
      console.log('[api.createIdentity] event.distribution_points:', event.distribution_points);
      const signable = canonicalize(event);
      event.signature = Crypto.sign(signable, keyPair.signing.secretKey);
      console.log('[api.createIdentity] sending event to API...');
      return this.request('POST', '/identities', { event });
    },

    async getIdentity(identityHash) {
      return this.request('GET', `/identities/${identityHash}`);
    },

    async createSession(identityHash, keyPair, expiresIn = 3600) {
      const timestamp = Math.floor(Date.now() / 1000);
      const request = {
        identity: identityHash,
        device_pubkey: keyPair.signing.publicKey,
        timestamp,
        expires_in: expiresIn,
      };
      request.signature = Crypto.sign(canonicalize(request), keyPair.signing.secretKey);
      const result = await this.request('POST', '/session', request);
      this.sessionToken = result.token;
      return result;
    },

    async listServerIdentities() {
      return this.request('GET', '/identities');
    },

    async submitGenesisEvent(event) {
      return this.request('POST', '/identities', { event });
    },

    async publishMessage(message) {
      return this.request('POST', '/messages', { message });
    },

    async listMessages(sender = null, limit = 50) {
      const params = new URLSearchParams();
      if (sender) params.set('sender', sender);
      params.set('limit', limit);
      return this.request('GET', `/messages?${params}`);
    },

    async getTrustDelegations(identityHash) {
      return this.request('GET', `/trust/delegations?from=${identityHash}`);
    },

    async submitEvent(identityHash, event) {
      return this.request('POST', `/identities/${identityHash}/events`, { event });
    },

    createSetDistributionEvent(keyPair, prevHash, distributionPoints) {
      const timestamp = Math.floor(Date.now() / 1000);
      const event = {
        version: 1,
        type: 'set_distribution',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp,
        prev: prevHash,
        signed_by: keyPair.signing.publicKey,
        distribution_points: distributionPoints,
      };
      // Sign the event
      const signable = canonicalize(event);
      event.signature = Crypto.sign(signable, keyPair.signing.secretKey);
      return event;
    },
  };

  // ============================================
  // QR CODE
  // ============================================

  function createIdentityQR(identityHash, distributionPoints = [], signingKey = null) {
    // Create a compact JSON payload with identity info
    const payload = {
      v: 1,  // version
      id: identityHash,
    };
    if (distributionPoints && distributionPoints.length > 0) {
      payload.dp = distributionPoints;
    }
    if (signingKey) {
      payload.pk = signingKey;
    }
    return JSON.stringify(payload);
  }

  // ============================================
  // ALPINE.JS INITIALIZATION
  // ============================================

  document.addEventListener('alpine:init', () => {
    // Global app state
    Alpine.store('app', {
      initialized: false,
      online: navigator.onLine,
      currentView: 'identities',
      loading: false,
      error: null,
      success: null,

      init() {
        this.initialized = true;
        window.addEventListener('online', () => this.online = true);
        window.addEventListener('offline', () => this.online = false);
      },

      setView(view) {
        this.currentView = view;
        this.error = null;
        this.success = null;
      },

      showError(message) {
        this.error = message;
        setTimeout(() => this.error = null, 5000);
      },

      showSuccess(message) {
        this.success = message;
        setTimeout(() => this.success = null, 3000);
      },
    });

    // Shared identity state (reactive across all components)
    Alpine.store('identity', {
      identities: [],
      activeIdentity: null,
      activeHash: null,

      init() {
        this.reload();
      },

      reload() {
        this.identities = KeyStore.listIdentities();
        this.activeHash = KeyStore.getActiveIdentity();
        if (this.activeHash) {
          this.activeIdentity = this.identities.find(i => i.identityHash === this.activeHash) || null;
        } else {
          this.activeIdentity = null;
        }
        const protection = Alpine.store('protection');
        if (protection) protection.refresh();
      },

      setActive(identityHash) {
        KeyStore.setActiveIdentity(identityHash);
        this.reload();
      },

      isUnlocked(identityHash) {
        return SessionKeys.isUnlocked(identityHash);
      },
    });

    // Wallet: is the active identity's wallet unlocked (keys and data in memory only)?
    Alpine.store('wallet', {
      unlocked: false,
      init() { this.sync(); },
      sync() {
        const hash = Alpine.store('identity') && Alpine.store('identity').activeHash;
        this.unlocked = !!hash && WalletSession.isUnlocked(hash);
      },
    });

    // Protection: the banner shows until the identity has an encrypted backup AND social recovery
    Alpine.store('protection', {
      hash: null,
      backupAt: null,
      recoveryDone: false,
      recoveryChecked: false,
      showBackup: false,
      showRecovery: false,
      showHelp: false,
      showLost: false,

      init() { this.refresh(); },

      get show() { return !!this.hash && !(this.backupAt && this.recoveryDone); },
      // Does a form have to ask for the identity password? Not when a passkey or an unlocked wallet can supply it.
      get needsPassword() {
        const identity = Alpine.store('identity').activeIdentity;
        return !(identity && identity.passkey) && !Alpine.store('wallet').unlocked;
      },
      get passwordHint() {
        const identity = Alpine.store('identity').activeIdentity;
        return Alpine.store('wallet').unlocked ? 'The unlocked wallet confirms this for you.'
          : (identity && identity.passkey ? 'Your passkey will ask you to confirm.' : '');
      },
      get backupDone() { return !!this.backupAt; },

      async refresh() {
        const hash = Alpine.store('identity').activeHash;
        this.hash = hash;
        if (!hash) return;
        this.backupAt = ProtectionState.load(hash).backupAt || null;
        this.recoveryDone = false;
        this.recoveryChecked = false;
        try {
          const identity = await api.getIdentity(hash);
          if (this.hash === hash) this.recoveryDone = !!identity.recovery;
        } catch { /* unknown counts as not done */ }
        if (this.hash === hash) this.recoveryChecked = true;
      },

      openBackup() { this.showBackup = true; },
      openRecovery() { this.showRecovery = true; },
    });

    // Sign in with this wallet
    Alpine.data('signinUI', () => ({
      link: '',
      password: '',
      preview: null,
      picks: {},
      done: null,

      get hash() { return Alpine.store('identity').activeHash; },
      get unlocked() { return Alpine.store('wallet').unlocked; },

      init() {
        const url = new URL(window.location.href);
        if (url.pathname === '/signin' && url.searchParams.get('link')) {
          this.link = url.searchParams.get('link');
          history.replaceState(null, '', '/');
          Alpine.store('app').setView('signin');
          this.$nextTick(() => this.load());
        }
      },

      async load() {
        if (!this.unlocked || !this.link) return;
        const app = Alpine.store('app');
        try {
          this.preview = await Wallet.signinPreview(this.hash, this.link);
          this.picks = {};
          for (const c of this.preview.candidateView) if (c.default) this.picks[c.claim_type] = c.attestation_id;
        } catch (e) {
          app.showError(e.message);
        }
      },

      get hasPasskey() { const i = Alpine.store('identity').activeIdentity; return !!(i && i.passkey); },

      async unlockWithPasskey() {
        const app = Alpine.store('app');
        app.loading = true;
        try {
          await Wallet.unlockWithPasskey(this.hash);
          await this.load();
        } catch (e) {
          app.showError('Could not unlock: ' + e.message);
        } finally {
          app.loading = false;
        }
      },

      async unlock() {
        const app = Alpine.store('app');
        app.loading = true;
        try {
          await Wallet.unlock(this.hash, this.password);
          this.password = '';
          await this.load();
        } catch (e) {
          app.showError('Could not unlock: ' + e.message);
        } finally {
          app.loading = false;
        }
      },

      async approve() {
        const app = Alpine.store('app');
        app.loading = true;
        try {
          const ids = Object.values(this.picks).filter(Boolean);
          this.done = await Wallet.signinApprove(this.hash, this.preview, ids);
          this.preview = null;
          app.showSuccess(this.done.message || 'Signed in. You can go back to the site.');
        } catch (e) {
          app.showError(e.message);
        } finally {
          app.loading = false;
        }
      },

      cancel() { this.preview = null; this.link = ''; Alpine.store('app').setView('wallet'); },
    }));

    // Wallet view: claims, verification, attestations
    Alpine.data('walletUI', () => ({
      password: '',
      email: '',
      phone: '',
      codes: {},
      claims: [],
      busyId: null,
      note: '',
      showRenounced: false,
      renouncedCount: 0,
      open: {},
      details: {},

      get hash() { return Alpine.store('identity').activeHash; },
      get unlocked() { return Alpine.store('wallet').unlocked; },
      get hasPasskey() { const i = Alpine.store('identity').activeIdentity; return !!(i && i.passkey); },
      get canPasskey() { return Passkey.supported(); },

      async unlockWithPasskey() {
        const app = Alpine.store('app');
        app.loading = true;
        try {
          await Wallet.unlockWithPasskey(this.hash);
          this.refresh();
        } catch (e) {
          app.showError('Could not unlock: ' + e.message);
        } finally {
          app.loading = false;
        }
      },

      async addPasskey() {
        await this.run('passkey', async () => {
          await Passkey.enroll(this.hash, Wallet.session(this.hash).password);
          Alpine.store('identity').reload();
        }, 'Passkey added. You can unlock this wallet with it.');
      },

      async removePasskey() {
        Passkey.remove(this.hash);
        Alpine.store('identity').reload();
        Alpine.store('app').showSuccess('Passkey removed from this browser. The password still works.');
      },

      refresh() {
        const s = this.hash && WalletSession.get(this.hash);
        const all = !s ? [] : Object.values(s.data.claims);
        this.renouncedCount = all.filter(d => d.renounced_at).length;
        this.claims = all.filter(d => this.showRenounced || !d.renounced_at).sort((a, b) => !!a.renounced_at - !!b.renounced_at).map(doc => {
          const att = s.data.attestations.find(a => a.claim_id === doc.claim_id);
          const pending = s.data.verifications[doc.claim_id];
          return {
            id: doc.claim_id, type: doc.claim_type, published: !!doc.published_at, renounced: !!doc.renounced_at, renouncedAt: doc.renounced_at || null,
            value: typeof doc.value === 'string' ? doc.value : Object.values(doc.value).join(' '),
            verified: !!att, method: att ? att.method : null, assurance: att ? att.assurance : null,
            issuer: att ? (s.data.issuer_chains[att.issuer] && s.data.issuer_chains[att.issuer].name) || att.issuer.slice(0, 12) : null,
            pending: !!pending, codeable: ['email', 'phone'].includes(doc.claim_type) && !doc.renounced_at,
          };
        });
      },

      async unlock() {
        const app = Alpine.store('app');
        app.loading = true;
        try {
          await Wallet.unlock(this.hash, this.password);
          this.password = '';
          this.refresh();
        } catch (e) {
          app.showError('Could not unlock: ' + e.message);
        } finally {
          app.loading = false;
        }
      },

      lock() { WalletSession.lock(this.hash); this.claims = []; },

      async run(busyId, work, success) {
        const app = Alpine.store('app');
        app.loading = true;
        this.busyId = busyId;
        try {
          const result = await work();
          this.refresh();
          if (success) app.showSuccess(typeof success === 'function' ? success(result) : success);
        } catch (e) {
          app.showError(e.message);
        } finally {
          this.busyId = null;
          app.loading = false;
        }
      },

      async addEmail() {
        const value = this.email;
        await this.run('add', async () => { await Wallet.addClaim(this.hash, 'email', value); this.email = ''; }, 'Email claim added. Verify it below.');
      },
      async addPhone() {
        const value = this.phone;
        await this.run('add', async () => { await Wallet.addClaim(this.hash, 'phone', value); this.phone = ''; }, 'Phone claim added. Verify it below.');
      },
      async publish(id) {
        const claim = this.claims.find(c => c.id === id);
        if (!window.confirm(`Publish the attestation of your ${claim.type} on the node? Anyone can then see, for example in the explorer, that this identity has a ${claim.type} verified by ${claim.issuer}. The ${claim.type} itself stays private.`)) return;
        await this.run(id, async () => { await Wallet.publishAttestation(this.hash, id); await this.loadDetails(id); }, 'Attestation published.');
      },

      async renounce(id) {
        const claim = this.claims.find(c => c.id === id);
        if (!window.confirm(`Renounce the ${claim.type} ${claim.value}? ${claim.verified ? 'Its verification stops counting. ' : ''}This is recorded on your identity's chain. The claim is hidden, not forgotten: you can still read its timeline.`)) return;
        await this.run(id, () => Wallet.renounceClaim(this.hash, id), 'Claim renounced.');
      },

      async toggle(id) {
        this.open = { ...this.open, [id]: !this.open[id] };
        if (this.open[id]) await this.loadDetails(id);
      },

      async loadDetails(id) {
        try {
          this.details = { ...this.details, [id]: await Wallet.timeline(this.hash, id) };
        } catch (e) {
          Alpine.store('app').showError('Could not read the timeline: ' + e.message);
        }
      },

      when(t) { return new Date(t * 1000).toLocaleString(); },
      pretty(json) { return JSON.stringify(json, null, 2); },
      async verify(id) {
        await this.run(id, () => Wallet.startVerification(this.hash, id), r => r.message || 'A code was sent. Type it below.');
      },
      async confirm(id) {
        await this.run(id, async () => { const a = await Wallet.confirmVerification(this.hash, id, this.codes[id] || ''); this.codes[id] = ''; return a; }, 'Verified.');
      },
    }));

    // Backup and recovery dialogs (opened from the banner)
    Alpine.data('protectionUI', () => ({
      backup: { identityPassword: '', password: '', confirm: '' },
      recovery: { identityPassword: '', trustees: '', threshold: 2 },

      async makeBackup() {
        const store = Alpine.store('protection');
        Alpine.store('app').loading = true;
        try {
          const file = await KeyStore.createBackup(store.hash, this.backup.identityPassword, this.backup.password, this.backup.confirm);
          const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `nodetide-backup-${store.hash.slice(0, 8)}.json`;
          a.click();
          URL.revokeObjectURL(url);
          this.backup = { identityPassword: '', password: '', confirm: '' };
          store.showBackup = false;
          store.refresh();
          Alpine.store('app').showSuccess('Backup downloaded. Keep the file and its password apart, away from this computer.');
        } catch (e) {
          Alpine.store('app').showError('Backup failed: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      // Social recovery: a trustee vouching for someone, and the person who lost their keys
      help: { code: '', password: '', seen: null },
      lost: { identityHash: '', password: '', code: '', waiting: false, collected: 0, threshold: 0 },

      async lookUp() {
        try {
          this.help.seen = await KeyStore.lookupRecovery(this.help.code);
        } catch (e) {
          this.help.seen = null;
          Alpine.store('app').showError('Could not read that recovery: ' + e.message);
        }
      },

      async vouch() {
        const store = Alpine.store('protection');
        Alpine.store('app').loading = true;
        try {
          const r = await KeyStore.trusteeSign(Alpine.store('identity').activeHash, this.help.password, this.help.code);
          this.help = { code: '', password: '', seen: null };
          store.showHelp = false;
          Alpine.store('app').showSuccess(`Signed. ${r.collected} of ${r.threshold} trustees have signed so far.`);
        } catch (e) {
          Alpine.store('app').showError('Could not sign: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      async askForRecovery() {
        Alpine.store('app').loading = true;
        try {
          const r = await KeyStore.startRecovery(this.lost.identityHash, this.lost.password);
          this.lost.code = r.code;
          this.lost.threshold = r.threshold;
          this.lost.waiting = true;
        } catch (e) {
          Alpine.store('app').showError('Could not start the recovery: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      async checkRecovery() {
        Alpine.store('app').loading = true;
        try {
          const r = await KeyStore.finishRecovery(this.lost.password);
          if (!r.done) {
            this.lost.collected = r.collected;
            this.lost.threshold = r.threshold;
            Alpine.store('app').showSuccess(`${r.collected} of ${r.threshold} trustees have signed.`);
            return;
          }
          Alpine.store('identity').reload();
          this.lost = { identityHash: '', password: '', code: '', waiting: false, collected: 0, threshold: 0 };
          Alpine.store('protection').showLost = false;
          Alpine.store('app').showSuccess('Control of the identity is restored with a new key. Make a new backup now.');
        } catch (e) {
          Alpine.store('app').showError('Recovery failed: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      // Organizations owned by this identity
      org: { password: '', request: '', result: null, service: '' },
      dev: { password: '', orgHash: '', request: '' },

      orgs: [],
      orgsLoaded: false,

      async loadOrgs() {
        const hash = Alpine.store('identity').activeHash;
        if (!hash) { this.orgs = []; return; }
        try { this.orgs = await KeyStore.ownedOrganizations(hash); } catch { this.orgs = []; }
        this.orgsLoaded = true;
      },

      async fetchRequest(quiet) {
        /** Ask the verification service for the founding request, so nobody has to copy JSON around. */
        try {
          const base = await Wallet.verifierUrl();
          const response = await fetch(base + '/api/issuer/request');
          const body = await response.json();
          if (!body.genesis) {
            if (!quiet) Alpine.store('app').showError(body.status === 'founded' ? 'That organization is already founded.' : 'The verification service has no founding request.');
            return;
          }
          if (body.status === 'founded') { if (!quiet) Alpine.store('app').showSuccess('The verification service is already set up.'); return; }
          this.org.request = JSON.stringify(body);
          this.org.service = body.name || 'the verification service';
        } catch (e) {
          if (!quiet) Alpine.store('app').showError('Could not reach the verification service: ' + e.message);
        }
      },

      async approveOrganization() {
        Alpine.store('app').loading = true;
        try {
          this.org.result = await KeyStore.approveOrganization(
            Alpine.store('identity').activeHash, this.org.password, this.org.request);
          this.org.password = '';
          this.loadOrgs();
          Alpine.store('app').showSuccess(this.org.result.complete
            ? 'The organization is founded.' : 'Approved. Pass the result on to the next owner.');
        } catch (e) {
          Alpine.store('app').showError('Could not do that: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      async authorizeDevice() {
        Alpine.store('app').loading = true;
        try {
          await KeyStore.authorizeDevice(Alpine.store('identity').activeHash, this.dev.password, this.dev.orgHash.trim().toLowerCase(), this.dev.request);
          this.dev.password = '';
          Alpine.store('app').showSuccess('The organization lists the verifier\'s signing key.');
        } catch (e) {
          Alpine.store('app').showError('Could not do that: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      async setRecovery() {
        const store = Alpine.store('protection');
        Alpine.store('app').loading = true;
        try {
          await KeyStore.setRecovery(store.hash, this.recovery.identityPassword, this.recovery.trustees, this.recovery.threshold);
          this.recovery = { identityPassword: '', trustees: '', threshold: 2 };
          store.showRecovery = false;
          await store.refresh();
          Alpine.store('app').showSuccess('Recovery is set up: those trustees can restore control of your identity.');
        } catch (e) {
          Alpine.store('app').showError('Recovery setup failed: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },
    }));

    // Identity manager
    Alpine.data('identityManager', () => ({
      showCreateModal: false,
      showUnlockModal: false,
      unlockingIdentity: null,
      createForm: { name: '', method: 'password', password: '', confirmPassword: '', distributionPoints: '' },
      unlockPassword: '',

      // Use store for shared state
      get identities() { return Alpine.store('identity').identities; },
      get activeIdentity() { return Alpine.store('identity').activeIdentity; },

      init() {
        // Reload store on init to ensure fresh data
        Alpine.store('identity').reload();
      },

      get webauthnSupported() { return Passkey.supported(); },

      async createIdentity() {
        const { name, method, confirmPassword, distributionPoints } = this.createForm;
        let password = this.createForm.password;

        if (method === 'webauthn') {
          if (!Passkey.supported()) {
            Alpine.store('app').showError('This browser has no passkey support');
            return;
          }
          // No password to remember: a random secret, held only wrapped by the passkey
          password = Passkey._b64(crypto.getRandomValues(new Uint8Array(32)));
        } else if (method === 'password') {
          if (!password || password.length < 8) {
            Alpine.store('app').showError('Password must be at least 8 characters');
            return;
          }
          if (password !== confirmPassword) {
            Alpine.store('app').showError('Passwords do not match');
            return;
          }
        }

        // Parse distribution points (one per line or comma-separated)
        const distPoints = distributionPoints
          ? distributionPoints.split(/[\n,]/).map(s => s.trim()).filter(s => s)
          : null;
        console.log('[createIdentity] parsed distPoints:', distPoints);

        Alpine.store('app').loading = true;

        try {
          console.log('[createIdentity] calling KeyStore.createIdentityWithPassword...');
          const result = await KeyStore.createIdentityWithPassword(name, password, distPoints);
          if (method === 'webauthn') {
            try {
              await Passkey.enroll(result.identity.identityHash, password);
            } catch (e) {
              KeyStore.deleteIdentity(result.identity.identityHash); // nothing was published yet; leave no half-made identity
              throw e;
            }
            KeyStore.updateIdentity(result.identity.identityHash, { storageMethod: StorageMethod.WEBAUTHN });
          }
          console.log('[createIdentity] identity created locally, hash:', result.identity.identityHash);
          console.log('[createIdentity] identity.distributionPoints:', result.identity.distributionPoints);

          try {
            // Submit genesis event to create identity on server
            console.log('[createIdentity] syncing genesis event to server');
            await api.submitGenesisEvent(result.identity.genesisEvent);
            console.log('[createIdentity] api.submitGenesisEvent succeeded');

            // Submit AddDevice event to register the device key
            console.log('[createIdentity] syncing addDeviceEvent to server');
            await api.submitEvent(result.identity.identityHash, result.identity.addDeviceEvent);
            console.log('[createIdentity] api.submitEvent (addDevice) succeeded');
          } catch (e) {
            console.warn('[createIdentity] Failed to register identity with API:', e);
          }

          // Store device key for operations (not master key)
          SessionKeys.set(result.identity.identityHash, result.keyPair);
          Alpine.store('identity').setActive(result.identity.identityHash);

          this.showCreateModal = false;
          this.createForm = { name: '', method: 'password', password: '', confirmPassword: '', distributionPoints: '' };

          Alpine.store('app').showSuccess('Identity created successfully');
        } catch (e) {
          Alpine.store('app').showError(e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      openUnlock(identity) {
        this.unlockingIdentity = identity;
        this.unlockPassword = '';
        this.showUnlockModal = true;
      },

      async unlockIdentity() {
        if (!this.unlockingIdentity) return;

        Alpine.store('app').loading = true;

        try {
          const keyPair = await KeyStore.unlockIdentity(
            this.unlockingIdentity.identityHash,
            this.unlockPassword
          );

          SessionKeys.set(this.unlockingIdentity.identityHash, keyPair);
          Alpine.store('identity').setActive(this.unlockingIdentity.identityHash);

          // Ensure identity exists on server before creating session
          try {
            await api.getIdentity(this.unlockingIdentity.identityHash);
          } catch (e) {
            if (e.status === 404) {
              // Identity not on server, sync it using stored genesis event
              const localIdentity = KeyStore.getIdentity(this.unlockingIdentity.identityHash);
              if (localIdentity?.genesisEvent) {
                await api.submitGenesisEvent(localIdentity.genesisEvent);
              } else {
                // Fallback: create new genesis (hash will differ!)
                await api.createIdentity(keyPair, localIdentity?.name || null, localIdentity?.distributionPoints || null);
              }
            }
          }

          // Now create session
          try {
            await api.createSession(this.unlockingIdentity.identityHash, keyPair);
          } catch (e) {
            console.warn('Failed to create API session:', e);
          }

          this.showUnlockModal = false;
          this.unlockingIdentity = null;

          Alpine.store('app').showSuccess('Identity unlocked');
        } catch (e) {
          Alpine.store('app').showError(e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      isUnlocked(identityHash) { return SessionKeys.isUnlocked(identityHash); },

      lockIdentity(identityHash) {
        SessionKeys.lock(identityHash);
        if (KeyStore.getActiveIdentity() === identityHash) api.clearSession();
        Alpine.store('identity').reload();
      },

      setActive(identityHash) {
        Alpine.store('identity').setActive(identityHash);
      },

      deleteIdentity(identityHash) {
        if (!confirm('Are you sure you want to delete this identity?')) return;
        KeyStore.deleteIdentity(identityHash);
        SessionKeys.lock(identityHash);
        Alpine.store('identity').reload();
        Alpine.store('app').showSuccess('Identity deleted');
      },

      formatDate(timestamp) { return new Date(timestamp).toLocaleString(); },
      truncateHash(hash) { return hash ? hash.slice(0, 8) + '...' + hash.slice(-8) : ''; },
    }));

    // Identity detail
    Alpine.data('identityDetail', () => ({
      sigchain: [],
      devices: [],
      recovery: null,
      distributionPoints: [],
      loading: false,
      lastLoadedHash: null,
      showDistributionModal: false,
      editDistributionPoints: '',

      // Use store for identity
      get identity() { return Alpine.store('identity').activeIdentity; },

      init() {
        // Watch for view changes to reload when becoming visible
        this.$watch('$store.app.currentView', (view) => {
          if (view === 'identity') {
            this.load();
          }
        });
        // Also watch for active identity changes
        this.$watch('$store.identity.activeHash', () => {
          if (Alpine.store('app').currentView === 'identity') {
            this.load();
          }
        });
        // Initial load if we're on this view
        if (Alpine.store('app').currentView === 'identity') {
          this.load();
        }
      },

      async load() {
        const activeHash = Alpine.store('identity').activeHash;
        if (!activeHash) {
          return;
        }

        // Skip if already loaded this hash
        if (this.lastLoadedHash === activeHash && this.sigchain.length > 0) {
          return;
        }

        this.loading = true;
        this.lastLoadedHash = activeHash;

        try {
          const data = await api.getIdentity(activeHash);
          console.log('[load] API response:', data);
          console.log('[load] data.sigchain:', data.sigchain);
          this.sigchain = data.sigchain || [];
          this.devices = data.devices || [];
          this.recovery = data.recovery || null;
          // Consumer-side: extract distribution_points from events
          this.distributionPoints = SigchainUtils.getLatestField(this.sigchain, 'distribution_points', []);
          console.log('[load] loaded sigchain.length:', this.sigchain.length);
        } catch (e) {
          console.warn('[load] Failed to load identity from API:', e);
          // Identity not on server - try to register it if unlocked
          const keyPair = SessionKeys.get(activeHash);
          console.log('[load] keyPair available:', !!keyPair);
          if (keyPair) {
            console.log('[load] Identity not on server, attempting to register...');
            try {
              const localIdentity = KeyStore.getIdentity(activeHash);
              console.log('[load] localIdentity:', localIdentity?.name, 'hasGenesisEvent:', !!localIdentity?.genesisEvent);

              let createResult;
              if (localIdentity?.genesisEvent) {
                // Use stored genesis event to ensure hash matches
                createResult = await api.submitGenesisEvent(localIdentity.genesisEvent);
              } else {
                // Fallback: create new genesis (may have different hash)
                console.log('[load] No stored genesis, creating new one');
                createResult = await api.createIdentity(keyPair, localIdentity?.name || null, localIdentity?.distributionPoints || null);
              }
              console.log('[load] createIdentity result:', createResult);
              console.log('[load] server identity_hash:', createResult.identity_hash);
              const serverHash = createResult.identity_hash;
              if (serverHash !== activeHash) {
                console.warn('[load] Hash mismatch! local:', activeHash, 'server:', serverHash);
              }
              console.log('[load] Identity registered, reloading...');
              // Reload to get the sigchain
              const data = await api.getIdentity(serverHash);
              this.sigchain = data.sigchain || [];
              this.devices = data.devices || [];
              this.recovery = data.recovery || null;
              this.distributionPoints = SigchainUtils.getLatestField(this.sigchain, 'distribution_points', []);
              Alpine.store('app').showSuccess('Identity synced to server');
              return;
            } catch (syncErr) {
              console.error('[load] Failed to sync identity to server:', syncErr);
              Alpine.store('app').showError('Failed to sync identity: ' + syncErr.message);
            }
          } else {
            console.log('[load] Identity not unlocked, cannot sync');
          }
          this.sigchain = [];
          this.devices = [];
          this.recovery = null;
          this.distributionPoints = [];
        } finally {
          this.loading = false;
        }
      },

      openDistributionModal() {
        const activeHash = Alpine.store('identity').activeHash;
        if (!SessionKeys.isUnlocked(activeHash)) {
          Alpine.store('app').showError('Identity must be unlocked first');
          return;
        }
        this.editDistributionPoints = this.distributionPoints.join('\n');
        this.showDistributionModal = true;
      },

      async saveDistributionPoints() {
        const activeHash = Alpine.store('identity').activeHash;
        console.log('[saveDistributionPoints] activeHash:', activeHash);
        console.log('[saveDistributionPoints] this.sigchain.length:', this.sigchain.length);
        console.log('[saveDistributionPoints] this.sigchain:', this.sigchain);

        const keyPair = SessionKeys.get(activeHash);
        if (!keyPair) {
          Alpine.store('app').showError('Identity must be unlocked');
          return;
        }

        const points = this.editDistributionPoints
          .split(/[\n,]/)
          .map(s => s.trim())
          .filter(s => s);

        // Get prev hash (last event in sigchain)
        const prevHash = this.sigchain.length > 0
          ? await this.getEventHash(this.sigchain[this.sigchain.length - 1])
          : null;
        console.log('[saveDistributionPoints] prevHash:', prevHash);

        if (!prevHash) {
          Alpine.store('app').showError('Cannot determine sigchain head');
          return;
        }

        Alpine.store('app').loading = true;

        try {
          const event = api.createSetDistributionEvent(keyPair, prevHash, points);
          await api.submitEvent(activeHash, event);

          this.distributionPoints = points;
          this.sigchain.push(event);
          this.showDistributionModal = false;
          Alpine.store('app').showSuccess('Distribution points updated');
        } catch (e) {
          Alpine.store('app').showError('Failed to update: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      async getEventHash(event) {
        // Compute SHA-256 hash of canonical JSON
        const canonical = JSON.stringify(event, Object.keys(event).sort());
        return await Crypto.sha256Hex(canonical);
      },

      get activeDevices() { return this.devices; },
    }));

    // QR manager
    Alpine.data('qrManager', () => ({
      identityHash: null,
      scanning: false,

      async showIdentityQR(identityHash, distributionPoints = [], signingKey = null) {
        if (!identityHash) return;
        this.identityHash = identityHash;

        await this.$nextTick();
        const container = this.$refs.qrContainer;
        if (container && typeof QRCode !== 'undefined') {
          container.innerHTML = '';
          const canvas = document.createElement('canvas');
          container.appendChild(canvas);
          const qrData = createIdentityQR(identityHash, distributionPoints, signingKey);
          console.log('[showIdentityQR] QR data:', qrData);
          QRCode.toCanvas(canvas, qrData, {
            width: 200,
            margin: 2,
            color: { dark: '#1a1a2e', light: '#ffffff' },
          });
        }
      },

      async copyIdentityHash() {
        if (!this.identityHash) return;
        try {
          await navigator.clipboard.writeText(this.identityHash);
          Alpine.store('app').showSuccess('Copied to clipboard');
        } catch {
          Alpine.store('app').showError('Failed to copy');
        }
      },

      startScan() { Alpine.store('app').showError('QR scanning not yet implemented'); },
      stopScan() { this.scanning = false; },
    }));

    // Trust manager
    Alpine.data('trustManager', () => ({
      targetIdentity: '',
      delegations: [],
      loading: false,
      delegateForm: { weight: 0.5, scope: '' },

      async lookup() {
        if (!this.targetIdentity) return;
        this.loading = true;
        try {
          const data = await api.getTrustDelegations(this.targetIdentity);
          this.delegations = data.delegations || [];
        } catch (e) {
          Alpine.store('app').showError('Failed to load trust data');
        } finally {
          this.loading = false;
        }
      },

      delegate() { Alpine.store('app').showError('Not yet implemented'); },
    }));

    // Directory manager - shows all identities on server
    Alpine.data('directoryManager', () => ({
      identities: [],
      loading: false,

      init() {
        this.$watch('$store.app.currentView', (view) => {
          if (view === 'directory') this.load();
        });
        if (Alpine.store('app').currentView === 'directory') {
          this.load();
        }
      },

      async load() {
        this.loading = true;
        try {
          const data = await api.listServerIdentities();
          this.identities = data.identities || [];
        } catch (e) {
          console.warn('Failed to load server identities:', e);
          this.identities = [];
        } finally {
          this.loading = false;
        }
      },
    }));

    // Messages manager
    Alpine.data('messagesManager', () => ({
      messages: [],
      messageText: '',
      loading: false,
      publishing: false,
      filterMine: false, // Show only my messages
      senderInfo: {}, // Cache of sender identity info

      init() {
        this.$watch('$store.app.currentView', (view) => {
          if (view === 'messages') this.load();
        });
        if (Alpine.store('app').currentView === 'messages') {
          this.load();
        }
      },

      async load() {
        this.loading = true;
        try {
          const sender = this.filterMine ? Alpine.store('identity').activeHash : null;
          const data = await api.listMessages(sender);
          this.messages = data.messages || [];

          // Fetch identity info for all unique senders
          const senders = [...new Set(this.messages.map(m => m.sender))];
          for (const senderHash of senders) {
            if (!this.senderInfo[senderHash]) {
              try {
                const identity = await api.getIdentity(senderHash);
                this.senderInfo[senderHash] = identity;
              } catch {
                // Identity not found or error - use hash as fallback
                this.senderInfo[senderHash] = { name: null, identity_hash: senderHash };
              }
            }
          }
        } catch (e) {
          console.warn('Failed to load messages:', e);
          this.messages = [];
        } finally {
          this.loading = false;
        }
      },

      getSenderName(senderHash) {
        const info = this.senderInfo[senderHash];
        if (info?.name) return info.name;
        return senderHash?.slice(0, 12) + '...';
      },

      isOwnMessage(senderHash) {
        return senderHash === Alpine.store('identity').activeHash;
      },

      toggleFilter() {
        this.filterMine = !this.filterMine;
        this.load();
      },

      async publish() {
        const activeHash = Alpine.store('identity').activeHash;
        if (!activeHash) {
          Alpine.store('app').showError('No identity selected');
          return;
        }

        const keyPair = SessionKeys.get(activeHash);
        if (!keyPair) {
          Alpine.store('app').showError('Identity must be unlocked');
          return;
        }

        if (!this.messageText.trim()) {
          Alpine.store('app').showError('Message cannot be empty');
          return;
        }

        this.publishing = true;
        try {
          const timestamp = Math.floor(Date.now() / 1000);
          const message = {
            type: 'public',
            sender: activeHash,
            content: {
              content_type: 'text/plain',
              body: this.messageText.trim(),
            },
            created_at: timestamp,
            reply_to: null,
            request_receipt: 'none',
            request_transit_report: false,
          };

          // Sign the message (use canonicalize for proper key sorting)
          const signable = canonicalize(message);
          console.log('[publish] signable:', signable);
          console.log('[publish] signing with pubkey:', keyPair.signing.publicKey);
          message.signature = Crypto.sign(signable, keyPair.signing.secretKey);
          console.log('[publish] signature:', message.signature);

          await api.publishMessage(message);
          Alpine.store('app').showSuccess('Message published');
          this.messageText = '';
          this.load(); // Refresh list
        } catch (e) {
          console.error('[publish] error:', e);
          Alpine.store('app').showError('Failed to publish: ' + e.message);
        } finally {
          this.publishing = false;
        }
      },
    }));

    // Settings manager
    Alpine.data('settingsManager', () => ({
      apiUrl: '/api',
      autoLock: 5,
      showDumpModal: false,
      showRestoreModal: false,
      dumpPassword: '',
      dumpConfirmPassword: '',
      restorePassword: '',
      restoreLocalPassword: '',
      restoreLocalConfirmPassword: '',
      restoreFile: null,

      init() {
        this.apiUrl = Settings.get('apiUrl', '/api');
        this.autoLock = Settings.get('autoLock', 5);
      },

      save() {
        Settings.set('apiUrl', this.apiUrl);
        Settings.set('autoLock', this.autoLock);
        api.baseUrl = this.apiUrl;
        Alpine.store('app').showSuccess('Settings saved');
      },

      exportData() {
        const identities = KeyStore.listIdentities();
        const data = { version: 1, exportedAt: new Date().toISOString(), identities };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nodetide-backup-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      },

      async importData(event) {
        const file = event.target.files[0];
        if (!file) return;
        try {
          const text = await file.text();
          const data = JSON.parse(text);
          if (data.version !== 1) throw new Error('Unsupported version');
          let imported = 0;
          for (const identity of data.identities) {
            if (!KeyStore.getIdentity(identity.identityHash)) {
              KeyStore._saveIdentity(identity);
              imported++;
            }
          }
          Alpine.store('app').showSuccess(`Imported ${imported} identities`);
        } catch (e) {
          Alpine.store('app').showError('Import failed: ' + e.message);
        }
      },

      openDumpModal() {
        // The old dump holds only the device key; the backup holds the master key too and is encrypted much harder.
        if (Alpine.store('identity').activeHash) {
          Alpine.store('protection').openBackup();
          return;
        }
        const activeHash = Alpine.store('identity').activeHash;
        if (!activeHash) {
          Alpine.store('app').showError('No active identity');
          return;
        }
        if (!SessionKeys.isUnlocked(activeHash)) {
          Alpine.store('app').showError('Identity must be unlocked first');
          return;
        }
        this.dumpPassword = '';
        this.dumpConfirmPassword = '';
        this.showDumpModal = true;
      },

      async dumpIdentity() {
        if (this.dumpPassword.length < 8) {
          Alpine.store('app').showError('Password must be at least 8 characters');
          return;
        }
        if (this.dumpPassword !== this.dumpConfirmPassword) {
          Alpine.store('app').showError('Passwords do not match');
          return;
        }

        const activeHash = Alpine.store('identity').activeHash;
        Alpine.store('app').loading = true;

        try {
          const dump = await KeyStore.dumpIdentity(activeHash, this.dumpPassword);
          const blob = new Blob([JSON.stringify(dump, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `identity-${activeHash.slice(0, 8)}-${Date.now()}.json`;
          a.click();
          URL.revokeObjectURL(url);

          this.showDumpModal = false;
          Alpine.store('app').showSuccess('Identity dumped successfully');
        } catch (e) {
          Alpine.store('app').showError('Dump failed: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      openRestoreModal() {
        this.restorePassword = '';
        this.restoreLocalPassword = '';
        this.restoreLocalConfirmPassword = '';
        this.restoreFile = null;
        this.showRestoreModal = true;
      },

      handleRestoreFile(event) {
        this.restoreFile = event.target.files[0];
      },

      async restoreIdentity() {
        if (!this.restoreFile) {
          Alpine.store('app').showError('Please select a dump file');
          return;
        }
        if (!this.restorePassword) {
          Alpine.store('app').showError('Please enter the dump password');
          return;
        }
        if (this.restoreLocalPassword.length < 8) {
          Alpine.store('app').showError('Local password must be at least 8 characters');
          return;
        }
        if (this.restoreLocalPassword !== this.restoreLocalConfirmPassword) {
          Alpine.store('app').showError('Local passwords do not match');
          return;
        }

        Alpine.store('app').loading = true;

        try {
          const text = await this.restoreFile.text();
          const dump = JSON.parse(text);

          if (dump.format === 'nodetide-identity-backup') {
            await KeyStore.restoreFromBackup(dump, this.restorePassword, this.restoreLocalPassword);
          } else {
            await KeyStore.restoreIdentity(dump, this.restorePassword, this.restoreLocalPassword);
          }

          Alpine.store('identity').reload();
          this.showRestoreModal = false;
          Alpine.store('app').showSuccess('Identity restored successfully');
        } catch (e) {
          Alpine.store('app').showError('Restore failed: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },
    }));
  });

  // Register service worker
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', async () => {
      try {
        await navigator.serviceWorker.register('/sw.js');
      } catch (e) {
        console.warn('ServiceWorker registration failed:', e);
      }
    });
  }

})();
