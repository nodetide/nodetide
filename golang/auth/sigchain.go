package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// This file is the Go port of the sigchain verification in
// python/src/nodetide/core/identity.py (v2, see sigchain-v2.md). Both are held to
// the same verdicts by protocol-vectors/chain-v2.json.
//
// An identity has two tracks. The CONTROL chain (genesis, devices, rotation,
// recovery, owners, revoke_claim, checkpoint) is linked by prev and small. The
// CONTENT track (add_claim, set_claim_order) is bulk; control events commit to
// it with {count, root} (a Merkle root), so a verifier can check keys and trust
// from the control chain alone and prove single content events with a path.

// defaultCapabilities is what an ADD_DEVICE event grants when it lists none
// (matches DeviceCapability in the Python implementation).
var defaultCapabilities = []string{
	"sign_messages", "sign_files", "sign_identity", "encrypt", "authenticate", "manage_claims",
}

var contentTypes = map[string]bool{"add_claim": true, "set_claim_order": true}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MalformedError marks a structurally invalid sigchain (as opposed to one that
// is well-formed but fails verification).
type MalformedError struct{ msg string }

func (e *MalformedError) Error() string { return e.msg }

func malformed(format string, args ...any) error {
	return &MalformedError{msg: fmt.Sprintf(format, args...)}
}

// IsMalformed reports whether err is a MalformedError.
func IsMalformed(err error) bool {
	var m *MalformedError
	return errors.As(err, &m)
}

// Device is an active device key in a sigchain.
type Device struct {
	Pubkey       string
	Label        string
	Capabilities []string
	AddedAt      int64
	Expires      *int64
}

// HasCapability reports whether the device holds capability c.
func (d Device) HasCapability(c string) bool {
	return hasString(d.Capabilities, c)
}

func hasString(list []string, want string) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}

// Options tune ParseSigchainWith.
type Options struct {
	// Resolve returns the verified chain of another identity, or nil. It is needed
	// for organizations with owners and for social recovery (the owners' and the
	// trustees' chains). The Go node has no identity store, so callers build it
	// from chains supplied with the request.
	Resolve func(identity string) *Sigchain
	// CheckCurrent additionally requires the newest event's approvals and
	// recovery signatures to use the signers' current keys (what a node demands
	// of a NEW event; older events only need the key the signer had).
	CheckCurrent bool
}

type deviceState struct {
	caps    []string
	expires int64 // 0 = never
	label   string
	addedAt int64
}

// authState is who may do what as of one control event.
type authState struct {
	master  string
	devices map[string]deviceState
	revoked map[string]bool
}

func (a authState) clone() authState {
	out := authState{master: a.master, devices: map[string]deviceState{}, revoked: map[string]bool{}}
	for k, v := range a.devices {
		out.devices[k] = v
	}
	for k, v := range a.revoked {
		out.revoked[k] = v
	}
	return out
}

// mayManageClaims: the master, or a device holding manage_claims that is not revoked or expired at time at.
func (a authState) mayManageClaims(signer string, at int64) bool {
	if signer == a.master {
		return true
	}
	d, known := a.devices[signer]
	return known && !a.revoked[signer] && hasString(d.caps, "manage_claims") && !(d.expires != 0 && d.expires < at)
}

type commitment struct {
	count int
	root  string
}

type recoveryConfig struct {
	trustees  []string
	threshold int64
}

// DeviceStatus is what the chain says about one device key.
type DeviceStatus struct {
	Known          bool
	Capabilities   []string
	Revoked        bool
	UntrustedSince *int64
}

// Sigchain is a verified chain of identity events: the control chain, and the
// content events this object holds (all of them, none, or single ones proven by
// AttachContent).
type Sigchain struct {
	events        []map[string]any // control
	hashes        []string
	content       []map[string]any
	contentHashes []string
	sparse        map[int]map[string]any

	master      string
	commitments []commitment
	states      []authState
	status      map[string]*DeviceStatus
	owners      []ownerEntry // nil for an identity without owners
	claims      map[string]claimInfo
	revokedIDs  map[string]bool
}

type claimInfo struct {
	seq       int
	claimType string
	event     map[string]any
}

// ParseSigchain parses and verifies a decoded JSON array of events (use
// DecodeJSON so numbers are json.Number), with no way to look up other
// identities' chains (so an organization with owners, or a social recovery,
// cannot be checked: use ParseSigchainWith).
func ParseSigchain(raw []any) (*Sigchain, error) {
	return ParseSigchainWith(raw, Options{})
}

// ParseSigchainWith parses and verifies a chain: control events and content
// events may come in one list in any order. A chain given without its content
// (a light chain) verifies on its control events; IsPartial then reports it.
//
// Event hashes are computed over the event exactly as received, which equals
// the Python implementation's hash for events it serialized itself.
func ParseSigchainWith(raw []any, opts Options) (*Sigchain, error) {
	if len(raw) == 0 {
		return nil, malformed("empty sigchain")
	}
	var control, content []map[string]any
	for i, item := range raw {
		ev, ok := item.(map[string]any)
		if !ok {
			return nil, malformed("event %d: not an object", i)
		}
		typ, ok := stringField(ev, "type")
		if !ok {
			return nil, malformed("event %d: missing type", i)
		}
		if contentTypes[typ] {
			content = append(content, ev)
		} else {
			control = append(control, ev)
		}
	}
	if len(control) == 0 {
		return nil, malformed("no control events")
	}
	sc := &Sigchain{sparse: map[int]map[string]any{}, status: map[string]*DeviceStatus{}, claims: map[string]claimInfo{}, revokedIDs: map[string]bool{}}
	if err := sc.verifyControl(control, opts); err != nil {
		return nil, err
	}
	if err := sc.verifyContent(content, opts); err != nil {
		return nil, err
	}
	return sc, nil
}

func (sc *Sigchain) checkEnvelope(ev map[string]any, label string, checkSignature bool) error {
	if _, ok := stringField(ev, "signed_by"); !ok {
		return malformed("%s: missing signed_by", label)
	}
	sig, ok := stringField(ev, "signature")
	if !ok {
		return malformed("%s: missing signature", label)
	}
	if alg, present := ev["alg"]; present && alg != "ed25519" {
		return malformed("%s: unsupported alg", label)
	}
	if alg, present := ev["hash_alg"]; present && alg != "sha256" {
		return malformed("%s: unsupported hash_alg", label)
	}
	if !checkSignature {
		return nil
	}
	signedBy, _ := stringField(ev, "signed_by")
	msg, err := Canonical(without(ev, "signature", "approvals")) // owner approvals are collected after the event is signed
	if err != nil {
		return malformed("%s: %v", label, err)
	}
	if !verifyHex(signedBy, msg, sig) {
		return fmt.Errorf("%s: signature invalid", label)
	}
	return nil
}

func without(ev map[string]any, drop ...string) map[string]any {
	out := make(map[string]any, len(ev))
	for k, v := range ev {
		skip := false
		for _, d := range drop {
			if k == d {
				skip = true
			}
		}
		if !skip {
			out[k] = v
		}
	}
	return out
}

// revokedBy lists the devices an event revokes with their untrusted_since.
func revokedBy(ev map[string]any, typ string, known []string) map[string]*int64 {
	out := map[string]*int64{}
	since := optInt(ev, "untrusted_since")
	switch typ {
	case "revoke_device":
		if pub, ok := stringField(ev, "device_pubkey"); ok {
			out[pub] = since
		}
	case "rotate_master":
		switch rd := ev["revoke_devices"].(type) {
		case string:
			if rd == "all" {
				for _, k := range known {
					out[k] = since
				}
			}
		case []any:
			for _, k := range rd {
				if s, ok := k.(string); ok {
					out[s] = since
				}
			}
		}
	}
	return out
}

func optInt(ev map[string]any, key string) *int64 {
	if v, ok := intField(ev, key); ok {
		return &v
	}
	return nil
}

// checkRevocationFields mirrors check_revocation_fields in the Python reference.
func checkRevocationFields(ev map[string]any, typ string) string {
	if raw, present := ev["untrusted_since"]; present && raw != nil {
		v, ok := intField(ev, "untrusted_since")
		if !ok || v < 0 {
			return "untrusted_since is a time"
		}
		if ts, _ := intField(ev, "timestamp"); v > ts {
			return "untrusted_since cannot be in the future"
		}
	}
	if typ == "rotate_master" {
		rd, present := ev["revoke_devices"]
		if !present || rd == nil {
			if raw, ok := ev["untrusted_since"]; ok && raw != nil {
				return "untrusted_since without devices to revoke"
			}
			return ""
		}
		switch t := rd.(type) {
		case string:
			if t != "all" {
				return `revoke_devices is "all" or a list of device keys`
			}
		case []any:
			if len(t) > 64 {
				return `revoke_devices is "all" or a list of device keys`
			}
			for _, k := range t {
				s, ok := k.(string)
				if !ok || !hex64.MatchString(s) {
					return `revoke_devices is "all" or a list of device keys`
				}
			}
		default:
			return `revoke_devices is "all" or a list of device keys`
		}
	}
	return ""
}

func (sc *Sigchain) verifyControl(control []map[string]any, opts Options) error {
	st := authState{devices: map[string]deviceState{}, revoked: map[string]bool{}}
	var rec *recoveryConfig
	prevHash := ""
	var governance string
	managed := false

	for i, ev := range control {
		label := fmt.Sprintf("event %d", i)
		typ, _ := stringField(ev, "type")
		governed := false
		if sb, _ := stringField(ev, "signed_by"); sb == governedMarker {
			governed = true
		}
		if err := sc.checkEnvelope(ev, label, i == 0 || !governed); err != nil {
			return err
		}
		hash, err := eventHash(ev)
		if err != nil {
			return malformed("%s: %v", label, err)
		}
		signedBy, _ := stringField(ev, "signed_by")

		if i == 0 {
			if typ != "genesis" {
				return fmt.Errorf("first event must be genesis")
			}
			pub, ok := stringField(ev, "pubkey")
			if !ok {
				return malformed("genesis: missing pubkey")
			}
			if pub != signedBy {
				return fmt.Errorf("genesis must be self-signed")
			}
			if prev := ev["prev"]; prev != nil {
				return fmt.Errorf("genesis must not have prev")
			}
			if c := ev["content"]; c != nil {
				return fmt.Errorf("Genesis cannot commit to content")
			}
			st.master = pub
			sc.master = pub
			sc.status[pub] = &DeviceStatus{Known: true, Capabilities: []string{"sign", "encrypt"}}
			sc.events = append(sc.events, ev)
			sc.hashes = append(sc.hashes, hash)
			// organizations
			if raw, has := ev["owners"]; has && raw != nil {
				if it, _ := stringField(ev, "identity_type"); it != "organization" {
					return fmt.Errorf("Only an organization identity has owners")
				}
				if g, present := ev["governance"]; present && g != nil {
					gs, _ := g.(string)
					if gs != "self" && gs != "managed" {
						return fmt.Errorf("Genesis: governance is self or managed")
					}
					governance = gs
				}
				owners, err := parseOwnerList(raw, opts)
				if err != nil {
					return fmt.Errorf("Genesis: %v", err)
				}
				approved, total, err := approvalScore(ev, owners, opts, opts.CheckCurrent && len(control) == 1)
				if err != nil {
					return fmt.Errorf("Genesis: %v", err)
				}
				if approved != total {
					return fmt.Errorf("Genesis: every founding owner must approve")
				}
				sc.owners = owners
				managed = governance == "managed"
			} else {
				if ap, ok := ev["approvals"].([]any); ok && len(ap) > 0 {
					return fmt.Errorf("Genesis: approvals without owners")
				}
				if g, present := ev["governance"]; present && g != nil {
					return fmt.Errorf("Genesis: governance without owners")
				}
			}
			sc.states = append(sc.states, st.clone())
			prevHash = hash
			continue
		}

		if prev, _ := ev["prev"].(string); prev != prevHash {
			return fmt.Errorf("%s: prev hash mismatch", label)
		}
		if ev["seq"] != nil {
			return fmt.Errorf("%s: a content event does not belong in the control chain", label)
		}
		last := i == len(control)-1
		known := func() []string {
			keys := []string{sc.hashesGenesisPub()}
			for k := range st.devices {
				keys = append(keys, k)
			}
			return keys
		}

		applyRevocations := func() {
			for pub, since := range revokedBy(ev, typ, known()) {
				st.revoked[pub] = true
				if s, ok := sc.status[pub]; ok {
					s.Revoked, s.UntrustedSince = true, since
				} else {
					sc.status[pub] = &DeviceStatus{Revoked: true, UntrustedSince: since}
				}
			}
		}
		addDevice := func() {
			if pub, ok := stringField(ev, "device_pubkey"); ok {
				expires, _ := intField(ev, "expires")
				ts, _ := intField(ev, "timestamp")
				label, _ := stringField(ev, "label")
				st.devices[pub] = deviceState{caps: capabilitiesOf(ev), expires: expires, label: label, addedAt: ts}
				sc.status[pub] = &DeviceStatus{Known: true, Capabilities: capabilitiesOf(ev)}
			}
		}

		if governed {
			if sc.owners == nil {
				return fmt.Errorf("%s: only an organization is governed by owners", label)
			}
			allowed := typ == "rotate_master" || typ == "set_owners" || (managed && (typ == "add_device" || typ == "revoke_device"))
			if !allowed {
				return fmt.Errorf("%s: %s cannot be decided by owners", label, typ)
			}
			if sig, _ := stringField(ev, "signature"); sig != "" {
				return fmt.Errorf("%s: a governed event has no signature of its own", label)
			}
			approved, total, err := approvalScore(ev, sc.owners, opts, opts.CheckCurrent && last)
			if err != nil {
				return fmt.Errorf("%s: %v", label, err)
			}
			if 2*approved <= total {
				return fmt.Errorf("%s: owners approve %d of %d, which is not over half", label, approved, total)
			}
			switch typ {
			case "add_device":
				addDevice()
			case "revoke_device":
				if msg := checkRevocationFields(ev, typ); msg != "" {
					return fmt.Errorf("%s: %s", label, msg)
				}
				applyRevocations()
			case "rotate_master":
				if msg := checkRevocationFields(ev, typ); msg != "" {
					return fmt.Errorf("%s: %s", label, msg)
				}
				applyRevocations()
				np, ok := stringField(ev, "new_pubkey")
				if !ok {
					return malformed("%s: missing new_pubkey", label)
				}
				st.master, sc.master = np, np
			case "set_owners":
				owners, err := parseOwnerList(ev["owners"], opts)
				if err != nil {
					return fmt.Errorf("%s: %v", label, err)
				}
				sc.owners = owners
			}
		} else {
			if ap, ok := ev["approvals"].([]any); ok && len(ap) > 0 {
				return fmt.Errorf("%s: approvals belong on governed events only", label)
			}
			if sc.owners != nil && (typ == "set_owners" || typ == "set_recovery" || typ == "social_recovery" ||
				(managed && (typ == "rotate_master" || typ == "add_device" || typ == "revoke_device"))) {
				return fmt.Errorf("%s: an organization's %s is decided by its owners", label, typ)
			}
			if typ == "set_owners" {
				return fmt.Errorf("%s: only an organization has owners", label)
			}
			switch typ {
			case "add_device", "revoke_device", "set_recovery", "resolve_fork", "set_distribution":
				if signedBy != st.master {
					return fmt.Errorf("%s: must be signed by master key", label)
				}
				switch typ {
				case "add_device":
					addDevice()
				case "revoke_device":
					if msg := checkRevocationFields(ev, typ); msg != "" {
						return fmt.Errorf("%s: %s", label, msg)
					}
					applyRevocations()
				case "set_recovery":
					cfg, err := parseRecoveryConfig(ev, sc.hashes[0])
					if err != nil {
						return fmt.Errorf("%s: %v", label, err)
					}
					rec = cfg
				}
			case "revoke_claim", "checkpoint":
				// Master, or a currently valid device with manage_claims
				ts, _ := intField(ev, "timestamp")
				if !st.mayManageClaims(signedBy, ts) {
					return fmt.Errorf("%s: signer may not manage claims", label)
				}
				if typ == "revoke_claim" {
					claimID, ok := stringField(ev, "claim_id")
					if !ok {
						return malformed("%s: missing claim_id", label)
					}
					if sc.revokedIDs[claimID] {
						return fmt.Errorf("%s: claim already revoked", label)
					}
					sc.revokedIDs[claimID] = true
				}
			case "rotate_master":
				if signedBy != st.master {
					return fmt.Errorf("%s: rotation must be signed by old master", label)
				}
				np, ok := stringField(ev, "new_pubkey")
				if !ok {
					return malformed("%s: missing new_pubkey", label)
				}
				if msg := checkRevocationFields(ev, typ); msg != "" {
					return fmt.Errorf("%s: %s", label, msg)
				}
				applyRevocations()
				st.master, sc.master = np, np
			case "social_recovery":
				if err := checkRecoveryEvent(ev, sc.hashes[0], rec, opts, opts.CheckCurrent && last); err != nil {
					return fmt.Errorf("%s: %v", label, err)
				}
				np, _ := stringField(ev, "new_pubkey")
				st.master, sc.master = np, np
			case "genesis":
				return malformed("%s: unexpected genesis", label)
			default:
				return malformed("%s: unknown event type %q", label, typ)
			}
		}
		sc.events = append(sc.events, ev)
		sc.hashes = append(sc.hashes, hash)
		sc.states = append(sc.states, st.clone())
		prevHash = hash
	}
	return sc.computeCommitments()
}

func (sc *Sigchain) hashesGenesisPub() string {
	pub, _ := stringField(sc.events[0], "pubkey")
	return pub
}

// computeCommitments reads each control event's content commitment (an event
// without one commits what its predecessor did) and checks their shape.
func (sc *Sigchain) computeCommitments() error {
	prev := commitment{count: 0, root: emptyMerkleRoot}
	for i, ev := range sc.events {
		if raw, present := ev["content"]; present && raw != nil {
			c, ok := raw.(map[string]any)
			if !ok || len(c) != 2 {
				return fmt.Errorf("event %d: malformed content commitment", i)
			}
			count, okCount := intField(c, "count")
			root, okRoot := stringField(c, "root")
			if !okCount || !okRoot {
				return fmt.Errorf("event %d: malformed content commitment", i)
			}
			if int(count) < prev.count {
				return fmt.Errorf("event %d: content commitment goes backwards", i)
			}
			prev = commitment{count: int(count), root: root}
		}
		sc.commitments = append(sc.commitments, prev)
	}
	return nil
}

func (sc *Sigchain) lastCommitted() int {
	if len(sc.commitments) == 0 {
		return 0
	}
	return sc.commitments[len(sc.commitments)-1].count
}

func (sc *Sigchain) verifyContent(content []map[string]any, opts Options) error {
	// order the content events by seq so a list in any order is accepted
	sort.SliceStable(content, func(a, b int) bool {
		x, _ := intField(content[a], "seq")
		y, _ := intField(content[b], "seq")
		return x < y
	})
	hashes := make([]string, len(content))
	for i, ev := range content {
		h, err := eventHash(ev)
		if err != nil {
			return malformed("content event %d: %v", i, err)
		}
		hashes[i] = h
	}
	for i, c := range sc.commitments {
		if c.count <= len(hashes) {
			root, err := MerkleRoot(hashes[:c.count])
			if err != nil || root != c.root {
				return fmt.Errorf("event %d: content commitment does not match the content", i)
			}
		}
	}
	partial := len(content) < sc.lastCommitted()
	if partial && len(content) == 0 {
		return nil // light: the control chain checks out; the content it commits to is not here to check
	}

	indexOf := map[string]int{}
	for k, h := range sc.hashes {
		indexOf[h] = k
	}
	lastControl := len(sc.events) - 1
	committedByRef := make([]int, len(sc.events))
	prevHash := ""
	prevK := 0
	type claim struct {
		seq int
		typ string
	}
	claims := map[string]claim{}

	for i, ev := range content {
		tag := fmt.Sprintf("Content event %d", i)
		typ, _ := stringField(ev, "type")
		seq, hasSeq := intField(ev, "seq")
		if !contentTypes[typ] || !hasSeq {
			return fmt.Errorf("%s: not a content event", tag)
		}
		if err := sc.checkEnvelope(ev, tag, false); err != nil {
			return err
		}
		prev, _ := ev["prev"].(string)
		if int(seq) != i || prev != prevHash {
			return fmt.Errorf("%s: seq or prev does not continue the content track", tag)
		}
		ref, _ := stringField(ev, "control_ref")
		k, ok := indexOf[ref]
		if !ok {
			return fmt.Errorf("%s: behind: it names a control event this chain does not have", tag)
		}
		if k < prevK {
			return fmt.Errorf("%s: control_ref goes backwards", tag)
		}
		if i < sc.commitments[k].count {
			return fmt.Errorf("%s: already committed before the control event it names", tag)
		}
		if k < lastControl && i >= sc.commitments[k+1].count {
			return fmt.Errorf("%s: not committed by the control event that follows its control_ref", tag)
		}
		signedBy, _ := stringField(ev, "signed_by")
		ts, _ := intField(ev, "timestamp")
		if !sc.states[k].mayManageClaims(signedBy, ts) {
			return fmt.Errorf("%s: signer may not manage claims", tag)
		}
		msg, err := Canonical(without(ev, "signature"))
		sig, _ := stringField(ev, "signature")
		if err != nil || !verifyHex(signedBy, msg, sig) {
			return fmt.Errorf("%s: signature invalid", tag)
		}
		committedByRef[k]++

		switch typ {
		case "add_claim":
			id, ok := stringField(ev, "claim_id")
			if !ok {
				return malformed("%s: missing claim_id", tag)
			}
			if _, dup := claims[id]; dup {
				return fmt.Errorf("%s: duplicate claim_id", tag)
			}
			ctype, _ := stringField(ev, "claim_type")
			claims[id] = claim{seq: i, typ: ctype}
			sc.claims[id] = claimInfo{seq: i, claimType: ctype, event: ev}
		case "set_claim_order":
			claimType, _ := stringField(ev, "claim_type")
			order, isList := ev["order"].([]any)
			if !isList || len(order) < 1 || len(order) > 32 {
				return fmt.Errorf("%s: a claim order lists between 1 and 32 claims", tag)
			}
			revokedByK := map[string]bool{}
			for j := 0; j <= k; j++ {
				if t, _ := stringField(sc.events[j], "type"); t == "revoke_claim" {
					id, _ := stringField(sc.events[j], "claim_id")
					revokedByK[id] = true
				}
			}
			seen := map[string]bool{}
			for _, item := range order {
				id, isString := item.(string)
				if !isString || seen[id] {
					return fmt.Errorf("%s: a claim is listed twice", tag)
				}
				seen[id] = true
				c, exists := claims[id]
				if !exists {
					return fmt.Errorf("%s: orders an unknown claim", tag)
				}
				if revokedByK[id] {
					return fmt.Errorf("%s: orders a revoked claim", tag)
				}
				if c.typ != claimType {
					return fmt.Errorf("%s: orders a claim of another type", tag)
				}
			}
		}
		prevHash = hashes[i]
		prevK = k
	}

	sc.content, sc.contentHashes = content, hashes
	if partial {
		return nil // still being filled: what is here has been checked
	}

	// each control event commits exactly the content signed under the control events before it
	running := 0
	for k := range sc.events {
		if k > 0 && sc.commitments[k].count != running {
			return fmt.Errorf("event %d: content exists that this control event does not commit to, or it commits more than exists", k)
		}
		running += committedByRef[k]
	}
	// a revoked claim must exist, and have been committed no later than the revocation
	for j, ev := range sc.events {
		if t, _ := stringField(ev, "type"); t == "revoke_claim" {
			id, _ := stringField(ev, "claim_id")
			c, known := claims[id]
			if !known {
				return fmt.Errorf("event %d: revokes an unknown claim", j)
			}
			if c.seq >= sc.commitments[j].count {
				return fmt.Errorf("event %d: revokes a claim its commitment does not cover", j)
			}
		}
	}
	return nil
}

// AttachContent accepts one content event on a light chain, given its Merkle
// path to the control event that commits it. The error says why not; one
// starting "behind:" means the chain lacks the control event the content names.
func (sc *Sigchain) AttachContent(ev map[string]any, proof []string) error {
	typ, _ := stringField(ev, "type")
	seq, hasSeq := intField(ev, "seq")
	if !contentTypes[typ] || !hasSeq {
		return errors.New("not a content event")
	}
	ref, _ := stringField(ev, "control_ref")
	k := -1
	for i, h := range sc.hashes {
		if h == ref {
			k = i
		}
	}
	if k < 0 {
		return errors.New("behind: the content event names a control event this chain does not have")
	}
	if k+1 >= len(sc.events) {
		return errors.New("not committed yet: no control event after the one it names")
	}
	before, after := sc.commitments[k], sc.commitments[k+1]
	if int(seq) < before.count || int(seq) >= after.count {
		return errors.New("the content event is not in the interval the control chain commits")
	}
	hash, err := eventHash(ev)
	if err != nil {
		return err
	}
	if !VerifyMerkleProof(hash, int(seq), after.count, proof, after.root) {
		return errors.New("the Merkle proof does not match the control chain's commitment")
	}
	signedBy, _ := stringField(ev, "signed_by")
	ts, _ := intField(ev, "timestamp")
	if !sc.states[k].mayManageClaims(signedBy, ts) {
		return errors.New("signer may not manage claims")
	}
	if err := sc.checkEnvelope(ev, "content event", true); err != nil {
		return err
	}
	sc.sparse[int(seq)] = ev
	if typ == "add_claim" {
		if id, ok := stringField(ev, "claim_id"); ok {
			ctype, _ := stringField(ev, "claim_type")
			sc.claims[id] = claimInfo{seq: int(seq), claimType: ctype, event: ev}
		}
	}
	return nil
}

// IdentityHash is the hash of the genesis event.
func (s *Sigchain) IdentityHash() string { return s.hashes[0] }

// HeadHash is the hash of the newest CONTROL event.
func (s *Sigchain) HeadHash() string { return s.hashes[len(s.hashes)-1] }

// Len is the number of control events.
func (s *Sigchain) Len() int { return len(s.events) }

// ContentLen is the number of content events this object holds.
func (s *Sigchain) ContentLen() int { return len(s.content) }

// IsPartial reports whether the control chain commits to content this object does not hold.
func (s *Sigchain) IsPartial() bool { return len(s.content) < s.lastCommitted() }

// Hashes returns all control event hashes in order.
func (s *Sigchain) Hashes() []string { return append([]string(nil), s.hashes...) }

// HasEvent reports whether a control event with this hash is in the chain.
func (s *Sigchain) HasEvent(hash string) bool {
	for _, h := range s.hashes {
		if h == hash {
			return true
		}
	}
	return false
}

// MasterKey is the current master public key (hex).
func (s *Sigchain) MasterKey() string { return s.master }

// Claim returns a claim this object knows (all of them on a full chain, the proven ones on a light chain).
func (s *Sigchain) Claim(id string) (claimType string, revoked bool, ok bool) {
	c, known := s.claims[id]
	if !known {
		return "", false, false
	}
	return c.claimType, s.revokedIDs[id], true
}

// ClaimIDs lists the claim ids this object knows, sorted.
func (s *Sigchain) ClaimIDs() []string {
	out := make([]string, 0, len(s.claims))
	for id := range s.claims {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Status says what the chain knows about a device key.
func (s *Sigchain) Status(pubkey string) DeviceStatus {
	if st, ok := s.status[pubkey]; ok {
		return *st
	}
	return DeviceStatus{}
}

// ActiveDevices returns the device keys that are added, not revoked and not
// expired at time now (unix seconds). Like the Python implementation, the
// genesis key is listed as a "Primary" device without the authenticate
// capability.
func (s *Sigchain) ActiveDevices(now int64) []Device {
	devices := map[string]Device{}
	var order []string
	revoked := map[string]bool{}

	put := func(d Device) {
		if _, exists := devices[d.Pubkey]; !exists {
			order = append(order, d.Pubkey)
		}
		devices[d.Pubkey] = d
	}

	for _, ev := range s.events {
		typ, _ := stringField(ev, "type")
		ts, _ := intField(ev, "timestamp")
		switch typ {
		case "genesis":
			pub, _ := stringField(ev, "pubkey")
			put(Device{
				Pubkey:       pub,
				Label:        "Primary",
				Capabilities: []string{"sign", "encrypt"},
				AddedAt:      ts,
			})
		case "add_device":
			pub, ok := stringField(ev, "device_pubkey")
			if !ok {
				continue
			}
			var expires *int64
			if e, ok := intField(ev, "expires"); ok && e != 0 {
				expires = &e
				if e < now {
					continue
				}
			}
			label, _ := stringField(ev, "label")
			put(Device{
				Pubkey:       pub,
				Label:        label,
				Capabilities: capabilitiesOf(ev),
				AddedAt:      ts,
				Expires:      expires,
			})
		case "revoke_device", "rotate_master":
			known := make([]string, 0, len(devices))
			for k := range devices {
				known = append(known, k)
			}
			for pub := range revokedBy(ev, typ, known) {
				revoked[pub] = true
			}
		}
	}

	var active []Device
	for _, pub := range order {
		d := devices[pub]
		if revoked[pub] {
			continue
		}
		if d.Expires != nil && *d.Expires < now {
			continue
		}
		active = append(active, d)
	}
	return active
}

func capabilitiesOf(ev map[string]any) []string {
	raw, present := ev["capabilities"]
	if !present {
		return append([]string(nil), defaultCapabilities...)
	}
	list, ok := raw.([]any)
	if !ok {
		return nil // null or malformed: grant nothing
	}
	caps := make([]string, 0, len(list))
	for _, c := range list {
		if s, ok := c.(string); ok {
			caps = append(caps, s)
		}
	}
	return caps
}

func eventHash(ev map[string]any) (string, error) {
	canonical, err := Canonical(ev)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// verifyHex checks an Ed25519 signature given hex-encoded key and signature.
func verifyHex(pubHex string, msg []byte, sigHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

func stringField(m map[string]any, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok
}

// intField reads an integer field decoded as json.Number.
func intField(m map[string]any, key string) (int64, bool) {
	n, ok := m[key].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return v, true
}
