/**
 * Nodetide Explorer - browse the public information a node knows.
 *
 * Plain JavaScript, no dependencies. Every value that comes from the node is
 * inserted as text nodes (nothing is ever parsed as HTML), and links are built
 * only from validated 64-character hex hashes.
 *
 * Add ?node=https://other-node.example to browse another node's API instead of
 * the one serving this page (the API allows cross-origin reads).
 */
(function () {
  'use strict';

  var HASH_RE = /^[0-9a-f]{64}$/;
  var PAGE_SIZE = 25;
  var REFRESH_MS = 15000;

  // ------------------------------------------------------------------ node

  var NODE = (function () {
    var raw = new URLSearchParams(location.search).get('node');
    if (!raw) return '';
    try {
      var u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
      return u.origin === location.origin ? '' : u.origin;
    } catch (e) {
      return '';
    }
  })();

  // ------------------------------------------------------------------- DOM

  function append(el, kids) {
    for (var i = 0; i < kids.length; i++) {
      var k = kids[i];
      if (k === null || k === undefined || k === false) continue;
      if (Array.isArray(k)) append(el, k);
      else el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
    }
  }

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (name) {
        var v = attrs[name];
        if (v === null || v === undefined || v === false) return;
        if (name === 'class') el.className = v;
        else if (name.indexOf('on') === 0) el.addEventListener(name.slice(2), v);
        else el.setAttribute(name, v === true ? '' : String(v));
      });
    }
    append(el, Array.prototype.slice.call(arguments, 2));
    return el;
  }

  var main = document.getElementById('main');

  // --------------------------------------------------------------- formats

  function shortHash(hash) {
    return hash && hash.length > 18 ? hash.slice(0, 8) + '…' + hash.slice(-6) : hash || '';
  }

  function absTime(ts) {
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  }

  function relTime(ts) {
    var diff = Math.round(Date.now() / 1000 - ts);
    if (diff < 0) return 'in the future';
    if (diff < 45) return 'just now';
    if (diff < 3600) return Math.round(diff / 60) + ' min ago';
    if (diff < 86400) return Math.round(diff / 3600) + ' h ago';
    if (diff < 86400 * 30) return Math.round(diff / 86400) + ' d ago';
    return absTime(ts).slice(0, 10);
  }

  function timeEl(ts) {
    if (ts === null || ts === undefined) return h('span', { class: 'muted' }, '—');
    return h('time', { datetime: new Date(ts * 1000).toISOString(), title: absTime(ts) }, relTime(ts));
  }

  function num(n) {
    return Number(n || 0).toLocaleString();
  }

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : '') }, text);
  }

  // ----------------------------------------------------------------- links

  function route(path, params) {
    var qs = new URLSearchParams();
    Object.keys(params || {}).forEach(function (k) {
      var v = params[k];
      if (v !== undefined && v !== null && v !== '') qs.set(k, v);
    });
    var s = qs.toString();
    return '#' + path + (s ? '?' + s : '');
  }

  function hashLink(kind, hash) {
    if (!HASH_RE.test(hash || '')) return h('span', { class: 'hash' }, hash || '—');
    return h('a', { class: 'hash', href: '#/' + kind + '/' + hash, title: hash }, shortHash(hash));
  }

  function identityCell(hash, name) {
    return h('span', null, name ? h('strong', null, name, ' ') : null, hashLink('identity', hash));
  }

  function keyText(key) {
    return h('span', { class: 'mono', title: key }, shortHash(key));
  }

  function copyButton(text) {
    var btn = h('button', { type: 'button', class: 'link', title: 'Copy' }, 'copy');
    btn.addEventListener('click', function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = 'copied';
        setTimeout(function () { btn.textContent = 'copy'; }, 1200);
      });
    });
    return btn;
  }

  function fullHash(hash) {
    return h('span', null, h('span', { class: 'mono' }, hash), copyButton(hash));
  }

  // ------------------------------------------------------------------- API

  function ApiError(status, message) {
    this.status = status;
    this.message = message;
  }

  function api(path, params) {
    var qs = new URLSearchParams();
    Object.keys(params || {}).forEach(function (k) {
      var v = params[k];
      if (v !== undefined && v !== null && v !== '') qs.set(k, v);
    });
    var q = qs.toString();
    var url = NODE + '/api/explorer' + path + (q ? '?' + q : '');
    return fetch(url, { headers: { Accept: 'application/json' } }).then(
      function (resp) {
        if (resp.ok) return resp.json();
        return resp.json().catch(function () { return {}; }).then(function (body) {
          var msg = body.message || resp.statusText || 'Request failed';
          if (resp.status === 404 && path === '/stats') msg = 'This node does not provide the explorer API.';
          throw new ApiError(resp.status, msg);
        });
      },
      function () {
        throw new ApiError(0, 'Cannot reach ' + (NODE || 'this node') + '.');
      }
    );
  }

  // ------------------------------------------------------------ components

  function table(headers, rows, emptyText) {
    if (!rows.length) return h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, emptyText || 'Nothing here yet.'));
    var head = h('tr', null, headers.map(function (hd) {
      return h('th', { class: hd.num ? 'num' : null }, hd.label || hd);
    }));
    var body = rows.map(function (cells) {
      return h('tr', null, cells.map(function (c, i) {
        return h('td', { class: headers[i] && headers[i].num ? 'num' : null }, c);
      }));
    });
    return h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, head), h('tbody', null, body)));
  }

  function kv(pairs) {
    var dl = h('dl', { class: 'kv' });
    pairs.forEach(function (p) {
      if (p === null) return;
      dl.appendChild(h('dt', null, p[0]));
      dl.appendChild(h('dd', null, p[1]));
    });
    return dl;
  }

  function pager(path, query, page, total) {
    var pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    var base = {};
    query.forEach(function (v, k) { if (k !== 'page') base[k] = v; });
    function go(p) { return route(path, Object.assign({}, base, { page: p > 1 ? p : '' })); }
    var from = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
    var to = Math.min(total, page * PAGE_SIZE);
    return h('div', { class: 'pager' },
      h('span', null, num(from) + '–' + num(to) + ' of ' + num(total)),
      page > 1 ? h('a', { href: go(page - 1) }, '← Newer') : h('span', null, ''),
      page < pages ? h('a', { href: go(page + 1) }, 'Older →') : h('span', null, '')
    );
  }

  function pageOf(query) {
    var p = parseInt(query.get('page') || '1', 10);
    return p >= 1 ? p : 1;
  }

  function eventTypeBadge(type) {
    return badge(type.replace(/_/g, ' '));
  }

  function errorBox(e) {
    var message = e instanceof ApiError ? e.message : 'Something went wrong while rendering this page.';
    return h('div', { class: 'notice error' }, message);
  }

  function filterLine(text, clearHref) {
    return h('p', { class: 'muted' }, text, ' ', h('a', { href: clearHref }, 'clear filter'));
  }

  // ----------------------------------------------------------------- pages

  function eventRows(items, withIdentity) {
    return items.map(function (e) {
      var cells = [
        h('span', { class: 'mono' }, '#' + e.index),
        h('span', null, eventTypeBadge(e.type), ' ', h('a', { href: '#/event/' + e.event_hash }, e.summary)),
      ];
      if (withIdentity) cells.push(identityCell(e.identity_hash, e.identity_name));
      cells.push(timeEl(e.timestamp));
      return cells;
    });
  }

  function eventHeaders(withIdentity) {
    var hd = ['#', 'Event'];
    if (withIdentity) hd.push('Identity');
    hd.push('When');
    return hd;
  }

  function messageCard(m) {
    return h('div', { class: 'msg' },
      h('div', { class: 'meta' },
        identityCell(m.sender, m.sender_name),
        timeEl(m.created_at),
        m.content_type ? badge(m.content_type) : null,
        h('a', { href: '#/message/' + m.message_hash }, 'open')
      ),
      h('p', null, m.preview, m.truncated ? ' …' : '')
    );
  }

  function statCard(label, value, href) {
    var inner = [h('div', { class: 'n' }, num(value)), h('div', { class: 'l' }, label)];
    return href
      ? h('a', { class: 'card stat', href: href }, inner)
      : h('div', { class: 'card stat' }, inner);
  }

  function home() {
    return Promise.all([
      api('/stats'),
      api('/events', { limit: 8 }),
      api('/messages', { limit: 5 }),
      api('/identities', { limit: 5, sort: 'created' }),
    ]).then(function (r) {
      var stats = r[0], events = r[1], messages = r[2], ids = r[3];
      var types = Object.keys(stats.event_types).map(function (t) {
        return h('a', { href: route('/events', { type: t }) }, badge(t.replace(/_/g, ' ') + ' ' + num(stats.event_types[t])), ' ');
      });
      return h('div', null,
        h('h1', null, 'What this node knows'),
        h('p', { class: 'sub' }, 'Public information only. ',
          stats.last_event_at ? ['Latest identity event ', timeEl(stats.last_event_at), '.'] : 'No identities yet.'),
        h('div', { class: 'grid' },
          statCard('Identities', stats.identities, '#/identities'),
          statCard('Sigchain events', stats.events, '#/events'),
          statCard('Public messages', stats.public_messages, '#/messages'),
          statCard('Attestations', stats.attestations, '#/attestations'),
          statCard('Trust delegations', stats.trust_delegations, '#/trust'),
          statCard('Relayed identities', stats.relayed_identities, '#/network')
        ),
        types.length ? h('p', null, h('span', { class: 'muted' }, 'Event types: '), types) : null,
        h('div', { class: 'two-col' },
          h('div', null,
            h('h2', null, 'Latest events'),
            table(eventHeaders(true), eventRows(events.items, true), 'No events yet.'),
            h('p', null, h('a', { href: '#/events' }, 'All events →'))
          ),
          h('div', null,
            h('h2', null, 'Latest public messages'),
            messages.items.length ? messages.items.map(messageCard) : h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'No public messages yet.')),
            h('p', null, h('a', { href: '#/messages' }, 'All messages →'))
          )
        ),
        h('h2', null, 'Newest identities'),
        identityTable(ids.items),
        h('p', null, h('a', { href: '#/identities' }, 'All identities →'))
      );
    });
  }

  function identityTable(items) {
    return table(
      ['Identity', 'Type', { label: 'Events', num: true }, { label: 'Keys', num: true }, 'Last activity'],
      items.map(function (i) {
        return [
          identityCell(i.identity_hash, i.name),
          badge(i.identity_type),
          num(i.event_count),
          num(i.device_count),
          timeEl(i.last_event_at),
        ];
      }),
      'No identities match.'
    );
  }

  function identities(m, query) {
    var page = pageOf(query);
    var q = query.get('q') || '';
    var sort = query.get('sort') || 'recent';
    return api('/identities', { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, q: q, sort: sort }).then(function (data) {
      var input = h('input', { type: 'search', placeholder: 'Filter by name or hash prefix', value: q, maxlength: 100, 'aria-label': 'Filter identities' });
      var select = h('select', { 'aria-label': 'Sort' }, [
        ['recent', 'Recent activity'], ['created', 'Newest'], ['events', 'Most events'], ['name', 'Name'],
      ].map(function (o) { return h('option', { value: o[0], selected: o[0] === sort }, o[1]); }));
      var form = h('form', { class: 'controls', onsubmit: function (ev) {
        ev.preventDefault();
        location.hash = route('/identities', { q: input.value.trim(), sort: select.value });
      } }, input, select, h('button', { type: 'submit' }, 'Apply'));
      return h('div', null,
        h('h1', null, 'Identities'),
        form,
        identityTable(data.items),
        pager('/identities', query, page, data.total)
      );
    });
  }

  function claimValue(value) {
    if (value && typeof value === 'object' && 'given_name' in value) return value.given_name + ' ' + value.family_name;
    return typeof value === 'string' ? value : JSON.stringify(value);
  }

  function assuranceBadge(a) {
    return badge(a, a === 'high' ? 'good' : a === 'substantial' ? 'warn' : null);
  }

  function attestationLine(a) {
    var state = a.revoked ? badge('revoked', 'bad') : a.expired ? badge('expired', 'warn') : null;
    return h('div', null,
      a.issuer ? identityCell(a.issuer, a.issuer_name) : 'self-contained proof', ' ',
      badge(a.method.replace(/_/g, ' ')), ' ', assuranceBadge(a.assurance), ' ', state, ' ',
      h('span', { class: 'muted' }, 'until '), timeEl(a.expires_at));
  }

  function claimsSection(claims) {
    if (!claims.length) return h('p', { class: 'muted' }, 'No claims. This identity is pseudonymous.');
    return table(['Claim', 'Status', 'Value', 'Attestations', 'Made'], claims.map(function (c) {
      var kind = c.status === 'active' ? 'good' : c.status === 'revoked' ? 'bad' : 'warn';
      return [
        badge(c.claim_type),
        h('span', null, badge(c.status, kind), c.revoke_reason ? [' ', h('span', { class: 'muted' }, c.revoke_reason)] : null),
        c.published ? claimValue(c.value) : h('span', { class: 'muted', title: c.commitment }, 'private (commitment ' + shortHash(c.commitment) + ')'),
        c.attestations.length ? c.attestations.map(attestationLine) : h('span', { class: 'muted' }, 'none'),
        timeEl(c.created_at),
      ];
    }), 'No claims.');
  }

  function attestationsPage(m, query) {
    var page = pageOf(query);
    return api('/attestations', { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, subject: query.get('subject'), issuer: query.get('issuer'), claim_type: query.get('claim_type') }).then(function (data) {
      return h('div', null,
        h('h1', null, 'Attestations'),
        h('p', { class: 'sub' }, 'Statements by an issuer that a claim was verified. They say nothing about the claim\'s value unless the holder published it. Whether to trust an issuer is up to you.'),
        table(['Subject', 'Claim', 'Issuer', 'Method', 'Assurance', 'Status', 'Issued'],
          data.items.map(function (a) {
            var status = a.revoked ? badge('revoked', 'bad') : a.expired ? badge('expired', 'warn') : badge('valid', 'good');
            return [identityCell(a.subject, a.subject_name), badge(a.claim_type), a.issuer ? identityCell(a.issuer, a.issuer_name) : '—',
              a.method.replace(/_/g, ' '), assuranceBadge(a.assurance), status, timeEl(a.issued_at)];
          }), 'No attestations yet.'),
        pager('/attestations', query, page, data.total));
    });
  }

  function identityPage(m) {
    var hash = m[1];
    return api('/identities/' + hash).then(function (d) {
      var verified = d.verified
        ? badge('sigchain verified', 'good')
        : badge('verification failed' + (d.verify_error ? ': ' + d.verify_error : ''), 'bad');

      var deviceRows = d.devices.map(function (dev) {
        var statusKind = dev.status === 'active' ? 'good' : dev.status === 'revoked' ? 'bad' : 'warn';
        return [
          h('span', null, dev.label, ' ', dev.is_master ? badge('master', 'good') : null),
          keyText(dev.pubkey),
          dev.capabilities.join(', ') || '—',
          h('span', null, badge(dev.status, statusKind), dev.revoke_reason ? [' ', h('span', { class: 'muted' }, dev.revoke_reason)] : null),
          timeEl(dev.added_at),
          dev.expires ? timeEl(dev.expires) : h('span', { class: 'muted' }, 'never'),
        ];
      });

      var masterRows = d.master_history.map(function (k) {
        return [keyText(k.pubkey), k.via.replace(/_/g, ' '), timeEl(k.since), hashLink('event', k.event_hash)];
      });

      var recovery = d.recovery ? kv([
        ['Trustees', d.recovery.primary_trustees.map(function (t) { return h('div', null, identityCell(t.identity_hash, t.name)); })],
        ['Threshold', d.recovery.primary_threshold + ' of ' + d.recovery.primary_trustees.length],
        d.recovery.backup_trustees.length ? ['Backup trustees', d.recovery.backup_trustees.map(function (t) { return h('div', null, identityCell(t.identity_hash, t.name)); })] : null,
        d.recovery.backup_threshold ? ['Backup threshold', String(d.recovery.backup_threshold)] : null,
      ]) : h('p', { class: 'muted' }, 'No recovery trustees configured.');

      var relay = d.relay ? kv([
        ['Relayed since', timeEl(d.relay.added_at)],
        ['Last poll', d.relay.last_polled_at ? [timeEl(d.relay.last_polled_at), ' ', d.relay.last_poll_success ? badge('ok', 'good') : badge('failed', 'bad')] : 'never'],
        d.relay.poll_error ? ['Poll error', d.relay.poll_error] : null,
      ]) : null;

      var c = d.counts;
      return h('div', null,
        h('h1', null, d.name || 'Unnamed identity'),
        h('p', { class: 'sub' }, badge(d.identity_type), ' ', d.ephemeral ? [badge('ephemeral', 'warn'), ' '] : null, verified),
        h('div', { class: 'card' }, kv([
          ['Identity hash', fullHash(d.identity_hash)],
          ['Created', [timeEl(d.created_at), ' ', h('span', { class: 'muted' }, absTime(d.created_at))]],
          ['Last event', timeEl(d.last_event_at)],
          ['Head event', hashLink('event', d.head_hash)],
          ['Master key', fullHash(d.master_pubkey)],
          ['Encryption key', h('span', { class: 'mono' }, d.encryption_pubkey)],
          ['Distribution points', d.distribution_points.length
            ? d.distribution_points.map(function (p) { return h('div', { class: 'mono' }, p); })
            : h('span', { class: 'muted' }, 'none published')],
        ])),
        h('h2', null, 'Activity'),
        h('div', { class: 'grid' },
          statCard('Public messages', c.public_messages, c.public_messages ? route('/messages', { sender: hash }) : null),
          statCard('Attestations about it', c.attestations_about, c.attestations_about ? route('/attestations', { subject: hash }) : null),
          statCard('Attestations it issued', c.attestations_issued, c.attestations_issued ? route('/attestations', { issuer: hash }) : null),
          statCard('Trusts as attester', c.delegations_from, c.delegations_from ? route('/trust', { from: hash }) : null),
          statCard('Trusted by', c.delegations_to, c.delegations_to ? route('/trust', { to: hash }) : null)
        ),
        h('h2', null, 'Keys'),
        table(['Label', 'Public key', 'Capabilities', 'Status', 'Added', 'Expires'], deviceRows),
        h('h2', null, 'Master key history'),
        table(['Master key', 'Via', 'Since', 'Event'], masterRows),
        h('h2', null, 'Claims'),
        claimsSection(d.claims),
        h('h2', null, 'Recovery'),
        h('div', { class: 'card' }, recovery),
        relay ? [h('h2', null, 'Relay subscription'), h('div', { class: 'card' }, relay)] : null,
        h('h2', null, 'Sigchain (' + num(d.event_count) + ' events)'),
        table(eventHeaders(false), eventRows(d.events.slice().reverse().map(function (e) {
          return { index: e.index, type: e.type, summary: e.summary, event_hash: e.event_hash, timestamp: e.timestamp };
        }), false))
      );
    });
  }

  function events(m, query) {
    var page = pageOf(query);
    var type = query.get('type') || '';
    var identity = query.get('identity') || '';
    return Promise.all([
      api('/events', { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, type: type, identity: identity }),
      api('/stats'),
    ]).then(function (r) {
      var data = r[0], stats = r[1];
      var select = h('select', { 'aria-label': 'Event type', onchange: function () {
        location.hash = route('/events', { type: select.value, identity: identity });
      } }, [h('option', { value: '' }, 'All event types')].concat(
        Object.keys(stats.event_types).map(function (t) {
          return h('option', { value: t, selected: t === type }, t.replace(/_/g, ' ') + ' (' + num(stats.event_types[t]) + ')');
        })));
      return h('div', null,
        h('h1', null, 'Events'),
        h('div', { class: 'controls' }, select),
        identity ? filterLine('Only events of ' + shortHash(identity) + '.', route('/events', { type: type })) : null,
        table(eventHeaders(true), eventRows(data.items, true), 'No events match.'),
        pager('/events', query, page, data.total)
      );
    });
  }

  function eventPage(m) {
    return api('/events/' + m[1]).then(function (e) {
      return h('div', null,
        h('h1', null, e.summary),
        h('p', { class: 'sub' }, eventTypeBadge(e.type), ' event #', e.index, ' of ', e.chain_length, ' in ', identityCell(e.identity_hash, e.identity_name)),
        h('div', { class: 'card' }, kv([
          ['Event hash', fullHash(e.event_hash)],
          ['Identity', identityCell(e.identity_hash, e.identity_name)],
          ['Time', [timeEl(e.timestamp), ' ', h('span', { class: 'muted' }, absTime(e.timestamp))]],
          ['Signed by', fullHash(e.signed_by)],
          ['Previous event', e.prev_hash ? hashLink('event', e.prev_hash) : h('span', { class: 'muted' }, 'none (genesis)')],
          ['Next event', e.next_hash ? hashLink('event', e.next_hash) : h('span', { class: 'muted' }, 'none (chain head)')],
        ])),
        h('details', { open: true }, h('summary', null, 'Raw event'), h('pre', null, JSON.stringify(e.raw, null, 2)))
      );
    });
  }

  function messages(m, query) {
    var page = pageOf(query);
    var sender = query.get('sender') || '';
    return api('/messages', { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, sender: sender }).then(function (data) {
      return h('div', null,
        h('h1', null, 'Public messages'),
        h('p', { class: 'sub' }, 'Signed, unencrypted messages. Private and group messages are never shown.'),
        sender ? filterLine('Only messages from ' + shortHash(sender) + '.', '#/messages') : null,
        data.items.length ? data.items.map(messageCard) : h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'No public messages.')),
        pager('/messages', query, page, data.total)
      );
    });
  }

  function signatureBadge(status) {
    switch (status) {
      case 'valid': return badge('signature valid', 'good');
      case 'unknown_sender': return badge('sender unknown to this node: signature not checked', 'warn');
      case 'malformed': return badge('malformed message', 'bad');
      default: return badge('no current key of the sender matches the signature', 'bad');
    }
  }

  function messagePage(m) {
    return api('/messages/' + m[1]).then(function (msg) {
      var replyTo = msg.reply_to;
      return h('div', null,
        h('h1', null, 'Public message'),
        h('p', { class: 'sub' }, signatureBadge(msg.signature_status)),
        h('div', { class: 'card' }, kv([
          ['Message hash', fullHash(msg.message_hash)],
          ['From', identityCell(msg.sender, msg.sender_name)],
          ['Written', [timeEl(msg.created_at), ' ', h('span', { class: 'muted' }, absTime(msg.created_at))]],
          msg.received_at ? ['Received by node', timeEl(msg.received_at)] : null,
          msg.content_type ? ['Content type', msg.content_type] : null,
          replyTo ? ['In reply to', HASH_RE.test(replyTo) ? hashLink('message', replyTo) : replyTo] : null,
        ])),
        h('h2', null, 'Content'),
        h('pre', null, msg.text),
        h('details', null, h('summary', null, 'Raw message'), h('pre', null, JSON.stringify(msg.raw, null, 2)))
      );
    });
  }

  function trust(m, query) {
    var page = pageOf(query);
    var filters = ['from', 'to'].filter(function (k) { return query.get(k); });
    var filterNote = filters.length
      ? filterLine('Filtered by ' + filters.map(function (k) { return k + ' ' + shortHash(query.get(k)); }).join(', ') + '.', '#/trust')
      : null;
    return api('/trust/delegations', { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, from: query.get('from'), to: query.get('to') }).then(function (data) {
      return h('div', null,
        h('h1', null, 'Trust'),
        h('p', { class: 'sub' }, 'Who trusts whom to issue attestations. A weight of 1 is full trust; the scope limits which claim types it covers.'),
        filterNote,
        table(['From', 'To', { label: 'Weight', num: true }, 'Scope', { label: 'Depth limit', num: true }, 'When'],
          data.items.map(function (d) {
            return [identityCell(d.from, d.from_name), identityCell(d.to, d.to_name), String(d.weight),
              d.scope ? d.scope.join(', ') : 'all claim types', d.depth_limit === null ? '—' : String(d.depth_limit), timeEl(d.timestamp)];
          }), 'No delegations.'),
        pager('/trust', query, page, data.total));
    });
  }

  function network() {
    return api('/network').then(function (d) {
      var rows = d.relayed.map(function (r) {
        return [
          h('span', null, identityCell(r.identity_hash, r.name), ' ', r.known ? null : badge('sigchain not fetched yet', 'warn')),
          r.distribution_points.length ? r.distribution_points.map(function (p) { return h('div', { class: 'mono' }, p); }) : h('span', { class: 'muted' }, 'none'),
          r.last_polled_at ? h('span', null, timeEl(r.last_polled_at), ' ', r.last_poll_success ? badge('ok', 'good') : badge('failed', 'bad'), r.poll_error ? [' ', h('span', { class: 'muted' }, r.poll_error)] : null) : 'never',
          timeEl(r.added_at),
        ];
      });
      return h('div', null,
        h('h1', null, 'Network'),
        h('div', { class: 'card' }, kv([
          ['Mode', d.mode === 'relay' ? 'Relay (polls other nodes)' : 'Standard node'],
          d.polling ? ['Polling', (d.polling.suspended ? 'suspended' : d.polling.running ? 'running' : 'stopped') + ', every ' + d.polling.poll_interval + ' s'] : null,
        ])),
        h('h2', null, 'Relayed identities (' + num(d.relayed.length) + ')'),
        table(['Identity', 'Distribution points', 'Last poll', 'Subscribed'], rows, 'This node does not relay any identities.')
      );
    });
  }

  function searchTarget(r) {
    return '#/' + r.kind + '/' + r.id;
  }

  function searchPage(m, query) {
    var q = query.get('q') || '';
    return api('/search', { q: q }).then(function (data) {
      return h('div', null,
        h('h1', null, 'Search'),
        h('p', { class: 'sub' }, 'Results for “' + q + '”'),
        table(['Type', 'Match', 'Detail'], data.results.map(function (r) {
          return [badge(r.kind), h('a', { href: searchTarget(r), class: 'hash', title: r.id }, shortHash(r.id)), r.label || ''];
        }), 'Nothing found. Try a name, or the start of an identity, event or message hash.')
      );
    });
  }

  // An address with only the start of a hash (a copied short form, "42031f7e"): find the one identity or event it
  // names and go there; if several match, list them; if none, say so.
  function prefixPage(kind) {
    return function (m) {
      var prefix = m[1];
      return api('/search', { q: prefix }).then(function (data) {
        var found = data.results.filter(function (r) { return r.kind === kind; });
        if (found.length === 1) {
          location.replace('#/' + kind + '/' + found[0].id);
          return h('p', { class: 'muted' }, 'Opening ' + shortHash(found[0].id) + '…');
        }
        return h('div', null,
          h('h1', null, found.length ? 'Several ' + kind + 's start with ' + prefix : 'No ' + kind + ' starts with ' + prefix),
          found.length ? table(['Match', 'Detail'], found.map(function (r) {
            return [h('a', { href: '#/' + kind + '/' + r.id, class: 'hash', title: r.id }, shortHash(r.id)), r.label || ''];
          }), '') : h('p', null, h('a', { href: '#/' }, 'Back to the overview')));
      });
    };
  }

  function notFound() {
    return h('div', null, h('h1', null, 'Page not found'), h('p', null, h('a', { href: '#/' }, 'Back to the overview')));
  }

  // ---------------------------------------------------------------- router

  var ROUTES = [
    [/^\/?$/, home, ''],
    [/^\/identities$/, identities, 'identities'],
    [/^\/identity\/([0-9a-f]{64})$/, identityPage, 'identities'],
    [/^\/identity\/([0-9a-f]{4,63})$/, prefixPage('identity'), 'identities'],
    [/^\/events$/, events, 'events'],
    [/^\/event\/([0-9a-f]{64})$/, eventPage, 'events'],
    [/^\/event\/([0-9a-f]{4,63})$/, prefixPage('event'), 'events'],
    [/^\/messages$/, messages, 'messages'],
    [/^\/message\/([0-9a-f]{64})$/, messagePage, 'messages'],
    [/^\/attestations$/, attestationsPage, 'attestations'],
    [/^\/trust$/, trust, 'trust'],
    [/^\/network$/, network, 'network'],
    [/^\/search$/, searchPage, ''],
  ];

  var renderToken = 0;
  var currentPath = '/';

  function parseHash() {
    var raw = location.hash.replace(/^#/, '') || '/';
    var i = raw.indexOf('?');
    return {
      path: i === -1 ? raw : raw.slice(0, i),
      query: new URLSearchParams(i === -1 ? '' : raw.slice(i + 1)),
    };
  }

  function render(silent) {
    var token = ++renderToken;
    var parsed = parseHash();
    currentPath = parsed.path;

    var matched = null;
    for (var i = 0; i < ROUTES.length; i++) {
      var m = ROUTES[i][0].exec(parsed.path);
      if (m) { matched = { m: m, fn: ROUTES[i][1], nav: ROUTES[i][2] }; break; }
    }

    document.querySelectorAll('[data-nav]').forEach(function (a) {
      a.classList.toggle('active', !!matched && a.getAttribute('data-nav') === matched.nav);
    });

    if (!matched) { main.replaceChildren(notFound()); return; }
    if (!silent) main.replaceChildren(h('p', { class: 'muted' }, 'Loading…'));

    Promise.resolve()
      .then(function () { return matched.fn(matched.m, parsed.query); })
      .then(function (node) { if (token === renderToken) main.replaceChildren(node); })
      .catch(function (e) { if (token === renderToken) main.replaceChildren(errorBox(e)); });
  }

  window.addEventListener('hashchange', function () { render(false); window.scrollTo(0, 0); });

  setInterval(function () {
    if (document.visibilityState === 'visible' && (currentPath === '/' || currentPath === '')) render(true);
  }, REFRESH_MS);

  // ------------------------------------------------------ search / node form

  var searchForm = document.getElementById('search-form');
  var searchInput = document.getElementById('search-input');
  searchForm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var q = searchInput.value.trim();
    if (!q) return;
    api('/search', { q: q }).then(function (data) {
      if (data.results.length === 1) location.hash = searchTarget(data.results[0]);
      else location.hash = route('/search', { q: q });
    }).catch(function (e) { main.replaceChildren(errorBox(e)); });
  });

  var nodeInfo = document.getElementById('node-info');
  var nodeForm = document.getElementById('node-form');
  var nodeInput = document.getElementById('node-input');
  var nodeReset = document.getElementById('node-reset');
  nodeInfo.textContent = 'Browsing ' + (NODE || location.origin);
  nodeReset.hidden = !NODE;
  nodeReset.addEventListener('click', function () { location.href = location.pathname + '#/'; });
  nodeForm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var raw = nodeInput.value.trim();
    if (!raw) return;
    try {
      var u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('scheme');
      location.href = location.pathname + '?node=' + encodeURIComponent(u.origin) + '#/';
    } catch (e) {
      nodeInput.setCustomValidity('Enter an http(s) address');
      nodeInput.reportValidity();
      nodeInput.setCustomValidity('');
    }
  });

  render(false);
})();
