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
    return JSON.stringify(sortRecursive(obj));
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
        capabilities: ['sign', 'encrypt', 'decrypt'],
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

      if (identity.storageMethod === StorageMethod.PASSWORD) {
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

    _saveIdentity(identity) {
      const identities = this.listIdentities();
      identities.push(identity);
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify(identities));
    },

    async _unlockBoth(identity, password) {
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

      const keys = await this._unlockBoth(identity, identityPassword);
      const payload = {
        name: identity.name, distribution_points: identity.distributionPoints || null, created_at: identity.createdAt,
        master_keys: keys.master, device_keys: keys.device,
        genesis_event: identity.genesisEvent, add_device_event: identity.addDeviceEvent,
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
      const chain = await api.request('GET', `/identities/${identityHash}/sigchain`);
      const events = chain.events || [];
      if (!events.length) throw new Error('Cannot determine the sigchain head');
      const event = {
        version: 1,
        type: 'set_recovery',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp: Math.floor(Date.now() / 1000),
        prev: await sha256(canonicalize(events[events.length - 1])),
        signed_by: master.signing.publicKey,
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
      const chain = await api.request('GET', `/identities/${owner.identityHash}/sigchain`);
      const events = chain.events || [];
      const state = await sha256(canonicalize(events[events.length - 1]));
      const { signature, approvals, ...signable } = event;
      const message = { purpose: 'nodetide-owner-approval-v1', owner: owner.identityHash, state, event: signable };
      return {
        identity: owner.identityHash, state, key: master.signing.publicKey,
        signature: Crypto.sign(canonicalize(message), master.signing.secretKey),
      };
    },

    _parseDeviceRequest(text) {
      let request;
      try { request = JSON.parse(text); } catch { throw new Error('The device request is the JSON the verifier shows at /api/issuer/request'); }
      for (const f of ['device_pubkey', 'device_encryption_pubkey']) {
        if (!/^[0-9a-f]{64}$/.test(request[f] || '')) throw new Error(`The device request has no valid ${f}`);
      }
      return request;
    },

    async organizationDevice(ownerHash, ownerPassword, orgHash, name, requestText) {
      /**
       * Create an organization owned by this identity (orgHash empty) and/or authorize a device key for it.
       * The organization's own key is made here and thrown away: from then on only its owners can change anything.
       */
      const owner = this.getIdentity(ownerHash);
      if (!owner || !owner.encryptedMasterKeys) throw new Error('This browser does not hold the owner identity\'s master key');
      const request = requestText && requestText.trim() ? this._parseDeviceRequest(requestText) : null;
      if (!orgHash && !(name || '').trim()) throw new Error('Give the new organization a name');
      if (orgHash && !request) throw new Error('Paste the device request to authorize');
      const { master } = await this._unlockBoth(owner, ownerPassword);
      const timestamp = Math.floor(Date.now() / 1000);

      if (!orgHash) {
        const throwaway = Crypto.generateKeyPair();
        const genesis = {
          version: 1, type: 'genesis', alg: 'ed25519', hash_alg: 'sha256', timestamp, prev: null,
          signed_by: throwaway.signing.publicKey, pubkey: throwaway.signing.publicKey,
          encryption_pubkey: throwaway.encryption.publicKey, identity_type: 'organization', name: name.trim(),
          ephemeral: false, ownership_proof: null, distribution_points: null,
          owners: [{ identity: ownerHash, weight: 100 }],
        };
        genesis.signature = Crypto.sign(canonicalize(genesis), throwaway.signing.secretKey);
        genesis.approvals = [await this._ownerApproval(owner, master, genesis)];
        orgHash = await sha256(canonicalize(genesis));
        await api.submitGenesisEvent(genesis);
      }

      let authorized = false;
      if (request) {
        const chain = await api.request('GET', `/identities/${orgHash}/sigchain`);
        const events = chain.events || [];
        const event = {
          version: 1, type: 'add_device', alg: 'ed25519', hash_alg: 'sha256', timestamp,
          prev: await sha256(canonicalize(events[events.length - 1])), signed_by: 'owners', signature: '',
          device_pubkey: request.device_pubkey, device_encryption_pubkey: request.device_encryption_pubkey,
          label: request.label || 'attestation signer', capabilities: request.capabilities || ['sign_identity'], expires: null,
        };
        event.approvals = [await this._ownerApproval(owner, master, event)];
        await api.submitEvent(orgHash, event);
        authorized = true;
      }
      return { orgHash, authorized };
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
      const chain = await api.request('GET', `/identities/${trusteeHash}/sigchain`);
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
      const recovery = {
        version: 1, type: 'social_recovery', alg: 'ed25519', hash_alg: 'sha256', timestamp,
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
        label: 'Web Browser', capabilities: ['sign', 'encrypt', 'decrypt'], expires: null,
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
      org: { password: '', orgHash: '', name: '', request: '', result: null },

      async createOrganization() {
        Alpine.store('app').loading = true;
        try {
          this.org.result = await KeyStore.organizationDevice(
            Alpine.store('identity').activeHash, this.org.password, (this.org.orgHash || '').trim().toLowerCase(),
            this.org.name, this.org.request);
          this.org.password = '';
          Alpine.store('app').showSuccess(this.org.result.authorized ? 'Done: the organization lists the verifier\'s key.' : 'Organization created.');
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

      get webauthnSupported() { return false; }, // Simplified - disabled for now

      async createIdentity() {
        const { name, method, password, confirmPassword, distributionPoints } = this.createForm;

        if (method === 'password') {
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
