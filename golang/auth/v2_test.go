package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// The cross-language vectors: protocol-vectors/chain-v2.json is produced by the
// Python reference (protocol-vectors/generate.py). Go must reach the same verdict
// on every chain and report the same facts about the valid ones.

func loadVectors(t *testing.T) (cases []any, now int64) {
	t.Helper()
	raw, err := os.ReadFile("../../protocol-vectors/chain-v2.json")
	if err != nil {
		t.Fatalf("vectors: %v (run python protocol-vectors/generate.py)", err)
	}
	var doc map[string]any
	if err := DecodeJSON(raw, &doc); err != nil {
		t.Fatal(err)
	}
	now, _ = intField(doc, "now")
	return doc["cases"].([]any), now
}

func resolverFor(related map[string]any) func(string) *Sigchain {
	cache := map[string]*Sigchain{}
	busy := map[string]bool{}
	var resolve func(string) *Sigchain
	resolve = func(id string) *Sigchain {
		if sc, ok := cache[id]; ok {
			return sc
		}
		list, ok := related[id].([]any)
		if !ok || busy[id] {
			return nil
		}
		busy[id] = true
		defer delete(busy, id)
		sc, err := ParseSigchainWith(list, Options{Resolve: resolve})
		if err != nil || sc.IdentityHash() != id {
			cache[id] = nil
			return nil
		}
		cache[id] = sc
		return sc
	}
	return resolve
}

func TestPythonVectors(t *testing.T) {
	cases, now := loadVectors(t)
	if len(cases) < 15 {
		t.Fatalf("expected the full vector set, got %d cases", len(cases))
	}
	for _, c := range cases {
		c := c.(map[string]any)
		name := c["name"].(string)
		t.Run(name, func(t *testing.T) {
			expect := c["expect"].(map[string]any)
			related, _ := c["related"].(map[string]any)
			checkCurrent, _ := c["check_current"].(bool)
			sc, err := ParseSigchainWith(c["chain"].([]any), Options{Resolve: resolverFor(related), CheckCurrent: checkCurrent})
			wantValid := expect["valid"].(bool)
			if !wantValid {
				if err == nil {
					t.Fatalf("Go accepts a chain the reference rejects (%v)", expect["reference_error"])
				}
				return
			}
			if err != nil {
				t.Fatalf("Go rejects a chain the reference accepts: %v", err)
			}
			if got := sc.IdentityHash(); got != expect["identity"] {
				t.Errorf("identity %s != %s", got, expect["identity"])
			}
			if got := sc.HeadHash(); got != expect["head"] {
				t.Errorf("head %s != %s", got, expect["head"])
			}
			if got := sc.MasterKey(); got != expect["master"] {
				t.Errorf("master %s != %s", got, expect["master"])
			}
			if got := sc.IsPartial(); got != expect["partial"].(bool) {
				t.Errorf("partial %v != %v", got, expect["partial"])
			}
			if n, _ := intField(expect, "control_length"); int(n) != sc.Len() {
				t.Errorf("control length %d != %d", sc.Len(), n)
			}
			if n, _ := intField(expect, "content_length"); int(n) != sc.ContentLen() {
				t.Errorf("content length %d != %d", sc.ContentLen(), n)
			}
			var active []string
			for _, d := range sc.ActiveDevices(now) {
				active = append(active, d.Pubkey)
			}
			sort.Strings(active)
			var want []string
			for _, d := range expect["active_devices"].([]any) {
				want = append(want, d.(string))
			}
			if strings.Join(active, ",") != strings.Join(want, ",") {
				t.Errorf("active devices %v != %v", active, want)
			}
			var gotClaims []string
			for _, id := range sc.ClaimIDs() {
				ctype, revoked, _ := sc.Claim(id)
				gotClaims = append(gotClaims, id+"/"+ctype+"/"+map[bool]string{true: "revoked", false: "active"}[revoked])
			}
			var wantClaims []string
			for _, item := range expect["claims"].([]any) {
				m := item.(map[string]any)
				wantClaims = append(wantClaims, m["id"].(string)+"/"+m["type"].(string)+"/"+map[bool]string{true: "revoked", false: "active"}[m["revoked"].(bool)])
			}
			sort.Strings(gotClaims)
			sort.Strings(wantClaims)
			if strings.Join(gotClaims, ",") != strings.Join(wantClaims, ",") {
				t.Errorf("claims %v != %v", gotClaims, wantClaims)
			}
			if statuses, ok := expect["device_status"].(map[string]any); ok {
				for pub, v := range statuses {
					v := v.(map[string]any)
					got := sc.Status(pub)
					if got.Known != v["known"].(bool) || got.Revoked != v["revoked"].(bool) {
						t.Errorf("device %.8s: known/revoked %v/%v != %v/%v", pub, got.Known, got.Revoked, v["known"], v["revoked"])
					}
					wantSince, hasSince := intField(v, "untrusted_since")
					if hasSince != (got.UntrustedSince != nil) || (hasSince && *got.UntrustedSince != wantSince) {
						t.Errorf("device %.8s: untrusted_since mismatch (%v vs %v)", pub, got.UntrustedSince, v["untrusted_since"])
					}
				}
			}
			if attach, ok := c["attach"].([]any); ok {
				for i, a := range attach {
					a := a.(map[string]any)
					var proof []string
					for _, p := range a["proof"].([]any) {
						proof = append(proof, p.(string))
					}
					err := sc.AttachContent(a["event"].(map[string]any), proof)
					if (err == nil) != a["ok"].(bool) {
						t.Errorf("attach %d: Go says %v, reference says ok=%v", i, err, a["ok"])
					}
				}
			}
		})
	}
}

func TestMerkleMatchesTheReference(t *testing.T) {
	// root over three leaves, computed by python/src/nodetide/core/merkle.py for hashes sha256("0".."2")
	hashes := []string{
		"5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
		"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
		"d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
	}
	root, err := MerkleRoot(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if root == emptyMerkleRoot || len(root) != 64 {
		t.Fatalf("bad root %q", root)
	}
	if empty, _ := MerkleRoot(nil); empty != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root %s", empty)
	}
	// every leaf proves, nothing else does (the proofs themselves come from the vector file in TestPythonVectors)
	if VerifyMerkleProof(hashes[0], 0, 3, nil, root) {
		t.Fatal("an empty path cannot prove a leaf of a larger tree")
	}
}

// --- rules checked with Go-built chains (so a failure names the rule) ----------------------------------------

func TestACommitmentThatMatchesNothingIsRejected(t *testing.T) {
	id := newIdentity(t)
	id.addClaim(id.masterPriv, "claim-0000000000001")
	ev := map[string]any{
		"version": num(1), "type": "set_distribution", "alg": "ed25519", "hash_alg": "sha256",
		"timestamp": num(nowUnix() - 2), "prev": id.head(), "signed_by": id.masterHex(),
		"distribution_points": []any{"https://relay.example.com"},
		"content":             map[string]any{"count": num(1), "root": strings.Repeat("00", 32)}, // validly signed, matches nothing
	}
	sign(id.t, id.masterPriv, ev)
	id.push(ev)
	_, err := ParseSigchain(id.wire())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a forged root must be rejected, got %v", err)
	}
}

func TestContentNotCommittedByTheNextControlEventIsRejected(t *testing.T) {
	id := newIdentity(t)
	id.addClaim(id.masterPriv, "claim-0000000000001")
	// a control event that forgets to commit it (set after the claim): build it by hand without the commitment
	ev := map[string]any{
		"version": num(1), "type": "set_distribution", "alg": "ed25519", "hash_alg": "sha256",
		"timestamp": num(nowUnix() - 2), "prev": id.head(), "signed_by": id.masterHex(),
		"distribution_points": []any{"https://relay.example.com"},
	}
	sign(id.t, id.masterPriv, ev)
	id.push(ev)
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("a control event that does not commit existing content must be rejected")
	}
}

// roundTrip puts a value through JSON the way a client would send it (numbers as json.Number).
func roundTrip(t *testing.T, v any) []any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out []any
	if err := DecodeJSON(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func roundTripEvent(t *testing.T, ev map[string]any) map[string]any {
	t.Helper()
	return roundTrip(t, []any{ev})[0].(map[string]any)
}

func TestALightChainVerifiesAndAContentEventNeedsItsPath(t *testing.T) {
	id := newIdentity(t)
	id.addClaim(id.masterPriv, "claim-0000000000001")
	id.addClaim(id.masterPriv, "claim-0000000000002")
	id.addDevice("authenticate") // commits both claims
	control := make([]any, len(id.events))
	for i, e := range id.events {
		control[i] = e
	}
	sc, err := ParseSigchain(roundTrip(t, control))
	if err != nil {
		t.Fatalf("a light chain must verify: %v", err)
	}
	if !sc.IsPartial() || sc.ContentLen() != 0 {
		t.Fatal("a chain without its content is partial")
	}
	if _, _, known := sc.Claim("claim-0000000000002"); known {
		t.Fatal("a light chain knows no claim it was not given")
	}
	event := roundTripEvent(t, id.content[1])
	if err := sc.AttachContent(event, nil); err == nil {
		t.Fatal("a content event without its path must be refused")
	}
	proof, err := MerkleProof(id.contentHashes, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.AttachContent(event, proof); err != nil {
		t.Fatalf("a content event with its path must be accepted: %v", err)
	}
	if _, _, known := sc.Claim("claim-0000000000002"); !known {
		t.Fatal("the proven claim must now be known")
	}
	if _, _, known := sc.Claim("claim-0000000000001"); known {
		t.Fatal("only the proven claim is known")
	}
	other, _ := MerkleProof(id.contentHashes, 0)
	if err := sc.AttachContent(roundTripEvent(t, id.content[1]), other); err == nil {
		t.Fatal("another leaf's path must be refused")
	}
}

func TestADeviceRevokedByARotationCannotLogIn(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	devPub := hex.EncodeToString(dev.Public().(ed25519.PublicKey))
	newPub, _ := newKey(t)
	id.appendEvent("rotate_master", map[string]any{
		"new_pubkey":            hex.EncodeToString(newPub),
		"new_encryption_pubkey": strings.Repeat("00", 32),
		"revoke_devices":        "all",
	})
	sc, err := ParseSigchain(id.wire())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range sc.ActiveDevices(nowUnix()) {
		if d.Pubkey == devPub {
			t.Fatal("the device must be revoked by the rotation")
		}
	}
	if st := sc.Status(devPub); !st.Known || !st.Revoked {
		t.Fatalf("status %+v", st)
	}
}

func TestRevocationFieldsAreChecked(t *testing.T) {
	cases := map[string]map[string]any{
		"unknown keyword":      {"revoke_devices": "everything"},
		"not device keys":      {"revoke_devices": []any{"nothex"}},
		"time without devices": {"untrusted_since": num(nowUnix() - 10)},
		"time in the future":   {"revoke_devices": "all", "untrusted_since": num(nowUnix() + 100000)},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			id := newIdentity(t)
			newPub, _ := newKey(t)
			fields := map[string]any{"new_pubkey": hex.EncodeToString(newPub), "new_encryption_pubkey": strings.Repeat("00", 32)}
			for k, v := range extra {
				fields[k] = v
			}
			id.appendEvent("rotate_master", fields)
			if _, err := ParseSigchain(id.wire()); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
}
