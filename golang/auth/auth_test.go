package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const testAud = "https://app.example.com"

func num(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

// testIdentity builds sigchains the same way the Python implementation does
// (same field set, canonical signing, sha256 event hashes).
type testIdentity struct {
	t             *testing.T
	masterPriv    ed25519.PrivateKey
	events        []map[string]any // the control chain
	hashes        []string
	content       []map[string]any // the content track (claims)
	contentHashes []string
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(t *testing.T, priv ed25519.PrivateKey, ev map[string]any) {
	t.Helper()
	msg, err := Canonical(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev["signature"] = hex.EncodeToString(ed25519.Sign(priv, msg))
}

func newIdentity(t *testing.T) *testIdentity {
	t.Helper()
	pub, priv := newKey(t)
	pubHex := hex.EncodeToString(pub)
	ev := map[string]any{
		"version":             num(1),
		"type":                "genesis",
		"alg":                 "ed25519",
		"hash_alg":            "sha256",
		"timestamp":           num(nowUnix() - 5),
		"prev":                nil,
		"signed_by":           pubHex,
		"pubkey":              pubHex,
		"encryption_pubkey":   strings.Repeat("00", 32),
		"identity_type":       "personal",
		"name":                "alice",
		"ephemeral":           false,
		"ownership_proof":     nil,
		"distribution_points": nil,
	}
	sign(t, priv, ev)
	id := &testIdentity{t: t, masterPriv: priv}
	id.push(ev)
	return id
}

func (id *testIdentity) push(ev map[string]any) {
	h, err := eventHash(ev)
	if err != nil {
		id.t.Fatal(err)
	}
	if typ, _ := ev["type"].(string); contentTypes[typ] {
		id.content = append(id.content, ev)
		id.contentHashes = append(id.contentHashes, h)
		return
	}
	id.events = append(id.events, ev)
	id.hashes = append(id.hashes, h)
}

func (id *testIdentity) head() string { return id.hashes[len(id.hashes)-1] }

// contentHead is the previous CONTENT event for the next content event (nil for the first).
func (id *testIdentity) contentHead() any {
	if len(id.contentHashes) == 0 {
		return nil
	}
	return id.contentHashes[len(id.contentHashes)-1]
}

// commitment is what a control event signed now must carry (nil while there is no content).
func (id *testIdentity) commitment() map[string]any {
	if len(id.content) == 0 {
		return nil
	}
	root, err := MerkleRoot(id.contentHashes)
	if err != nil {
		id.t.Fatal(err)
	}
	return map[string]any{"count": num(int64(len(id.content))), "root": root}
}

// contentFields are the fields every content event carries beyond the common ones.
func (id *testIdentity) contentFields(ev map[string]any) {
	ev["prev"] = id.contentHead()
	ev["seq"] = num(int64(len(id.content)))
	ev["control_ref"] = id.head()
}

func (id *testIdentity) masterHex() string {
	return hex.EncodeToString(id.masterPriv.Public().(ed25519.PublicKey))
}

// appendEvent adds a master-signed event with the common fields filled in.
func (id *testIdentity) appendEvent(typ string, fields map[string]any) {
	ev := map[string]any{
		"version":   num(1),
		"type":      typ,
		"alg":       "ed25519",
		"hash_alg":  "sha256",
		"timestamp": num(nowUnix() - 4),
		"prev":      id.head(),
		"signed_by": id.masterHex(),
	}
	for k, v := range fields {
		ev[k] = v
	}
	if c := id.commitment(); c != nil {
		ev["content"] = c
	}
	sign(id.t, id.masterPriv, ev)
	id.push(ev)
}

func (id *testIdentity) addDevice(caps ...string) ed25519.PrivateKey {
	pub, priv := newKey(id.t)
	list := make([]any, 0, len(caps))
	for _, c := range caps {
		list = append(list, c)
	}
	id.appendEvent("add_device", map[string]any{
		"device_pubkey":            hex.EncodeToString(pub),
		"device_encryption_pubkey": strings.Repeat("00", 32),
		"label":                    "phone",
		"capabilities":             list,
		"expires":                  nil,
	})
	return priv
}

func (id *testIdentity) revoke(priv ed25519.PrivateKey) {
	id.appendEvent("revoke_device", map[string]any{
		"device_pubkey": hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		"reason":        "lost",
	})
}

// wire returns the chain as a client would send it: JSON on the wire, decoded
// with UseNumber, then parsed and verified.
func (id *testIdentity) wire() []any {
	id.t.Helper()
	raw, err := json.Marshal(append(append([]map[string]any{}, id.events...), id.content...))
	if err != nil {
		id.t.Fatal(err)
	}
	var events []any
	if err := DecodeJSON(raw, &events); err != nil {
		id.t.Fatal(err)
	}
	return events
}

func (id *testIdentity) chain() *Sigchain {
	id.t.Helper()
	sc, err := ParseSigchain(id.wire())
	if err != nil {
		id.t.Fatalf("ParseSigchain: %v", err)
	}
	return sc
}

func (id *testIdentity) assertion(signer ed25519.PrivateKey, aud, nonce, head string) map[string]any {
	id.t.Helper()
	now := nowUnix()
	a := map[string]any{
		"type":       AssertionType,
		"identity":   id.hashes[0],
		"device":     hex.EncodeToString(signer.Public().(ed25519.PublicKey)),
		"aud":        aud,
		"nonce":      nonce,
		"iat":        num(now),
		"exp":        num(now + 300),
		"chain_head": head,
	}
	resign(id.t, signer, a)
	return a
}

func resign(t *testing.T, signer ed25519.PrivateKey, a map[string]any) {
	t.Helper()
	msg, err := SigningInput(a)
	if err != nil {
		t.Fatal(err)
	}
	a["sig"] = hex.EncodeToString(ed25519.Sign(signer, msg))
}

// --- canonical JSON ---------------------------------------------------------

// The same input/expected pair is asserted in python/tests/test_native_auth.py;
// both implementations must agree byte for byte.
//
// "@" stands for a backslash so no \u escape appears literally in this file.
var (
	canonicalInput = strings.NewReplacer("@", `\`).Replace(
		`{"b":[1,2,{"z":null,"a":true}],"a":"é😀@u007f@n@"","c":-5}`)
	canonicalExpected = strings.NewReplacer("@", `\`).Replace(
		`{"a":"@u00e9@ud83d@ude00@u007f@n@"","b":[1,2,{"a":true,"z":null}],"c":-5}`)
)

func TestCanonicalMatchesPython(t *testing.T) {
	var v any
	if err := DecodeJSON([]byte(canonicalInput), &v); err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != canonicalExpected {
		t.Fatalf("got  %s\nwant %s", got, canonicalExpected)
	}
}

func TestCanonicalRejectsFloats(t *testing.T) {
	var v any
	if err := DecodeJSON([]byte(`{"a":1.5}`), &v); err != nil {
		t.Fatal(err)
	}
	if _, err := Canonical(v); err == nil {
		t.Fatal("expected error for float")
	}
}

// --- sigchain ---------------------------------------------------------------

func TestParseSigchainValid(t *testing.T) {
	id := newIdentity(t)
	id.addDevice("authenticate")
	sc := id.chain()
	if sc.Len() != 2 || sc.IdentityHash() != id.hashes[0] || sc.HeadHash() != id.head() {
		t.Fatalf("unexpected chain state: len=%d", sc.Len())
	}
}

func TestParseSigchainRejectsTampering(t *testing.T) {
	id := newIdentity(t)
	id.addDevice("authenticate")
	events := id.wire()
	events[1].(map[string]any)["label"] = "evil"
	_, err := ParseSigchain(events)
	if err == nil || IsMalformed(err) {
		t.Fatalf("expected verification failure, got %v", err)
	}
}

func TestParseSigchainRejectsBadPrev(t *testing.T) {
	id := newIdentity(t)
	id.addDevice("authenticate")
	events := id.wire()
	ev := events[1].(map[string]any)
	ev["prev"] = strings.Repeat("ab", 32)
	delete(ev, "signature")
	sign(t, id.masterPriv, ev)
	if _, err := ParseSigchain(events); err == nil {
		t.Fatal("expected prev mismatch")
	}
}

func TestParseSigchainRejectsNonMasterSigner(t *testing.T) {
	id := newIdentity(t)
	id.addDevice("authenticate")
	otherPub, otherPriv := newKey(t)
	events := id.wire()
	ev := events[1].(map[string]any)
	ev["signed_by"] = hex.EncodeToString(otherPub)
	delete(ev, "signature")
	sign(t, otherPriv, ev)
	if _, err := ParseSigchain(events); err == nil {
		t.Fatal("expected authorization failure")
	}
}

func TestParseSigchainRejectsSocialRecovery(t *testing.T) {
	id := newIdentity(t)
	newPub, newPriv := newKey(t)
	ev := map[string]any{
		"version":               num(1),
		"type":                  "social_recovery",
		"alg":                   "ed25519",
		"hash_alg":              "sha256",
		"timestamp":             num(nowUnix()),
		"prev":                  id.head(),
		"signed_by":             hex.EncodeToString(newPub),
		"new_pubkey":            hex.EncodeToString(newPub),
		"new_encryption_pubkey": strings.Repeat("00", 32),
		"recovery_signatures":   []any{},
	}
	sign(t, newPriv, ev)
	id.push(ev)
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("social_recovery must not be trusted without threshold verification")
	}
}

func TestParseSigchainMalformed(t *testing.T) {
	if _, err := ParseSigchain(nil); !IsMalformed(err) {
		t.Fatalf("empty chain: %v", err)
	}
	if _, err := ParseSigchain([]any{"nope"}); !IsMalformed(err) {
		t.Fatalf("non-object event: %v", err)
	}
}

// --- assertions -------------------------------------------------------------

func TestVerifyAssertionValid(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	a := id.assertion(dev, testAud, "n1", id.head())
	res, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if res.Identity != id.hashes[0] {
		t.Fatal("identity mismatch")
	}
}

func expectCode(t *testing.T, err *VerifyError, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	if err.Code != code {
		t.Fatalf("expected %s, got %s (%s)", code, err.Code, err.Message)
	}
}

func TestVerifyAssertionWrongAudience(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	a := id.assertion(dev, "https://evil.example.com", "n1", id.head())
	_, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	expectCode(t, err, "wrong_audience")
}

func TestVerifyAssertionMasterKeyRejected(t *testing.T) {
	id := newIdentity(t)
	id.addDevice("authenticate")
	a := id.assertion(id.masterPriv, testAud, "n1", id.head())
	_, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	expectCode(t, err, "device_not_authorized")
}

func TestVerifyAssertionNeedsAuthenticateCapability(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("sign_messages")
	a := id.assertion(dev, testAud, "n1", id.head())
	_, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	expectCode(t, err, "device_not_authorized")
}

func TestVerifyAssertionRevokedDevice(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	a := id.assertion(dev, testAud, "n1", id.head())
	id.revoke(dev)
	_, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	expectCode(t, err, "device_not_authorized")
}

func TestVerifyAssertionStaleChain(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	stale := id.chain()
	id.addDevice("authenticate") // signer is ahead of the verifier
	a := id.assertion(dev, testAud, "n1", id.head())
	_, err := VerifyAssertion(a, stale, testAud, nowUnix())
	expectCode(t, err, "unknown_chain_head")
}

func TestVerifyAssertionTamperedClaims(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	a := id.assertion(dev, testAud, "n1", id.head())
	a["claims"] = map[string]any{"name": "alice"}
	resign(t, dev, a)
	res, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if res.Claims["name"] != "alice" {
		t.Fatal("claims not returned")
	}
	a["claims"] = map[string]any{"name": "mallory"}
	_, err = VerifyAssertion(a, id.chain(), testAud, nowUnix())
	expectCode(t, err, "bad_signature")
}

func TestVerifyAssertionExpired(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	a := id.assertion(dev, testAud, "n1", id.head())
	_, err := VerifyAssertion(a, id.chain(), testAud, nowUnix()+3600)
	expectCode(t, err, "expired")
	_, err = VerifyAssertion(a, id.chain(), testAud, nowUnix()-3600)
	expectCode(t, err, "expired")
}

func TestVerifyAssertionDomainSeparation(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	a := id.assertion(dev, testAud, "n1", id.head())
	body := map[string]any{}
	for k, v := range a {
		if k != "sig" {
			body[k] = v
		}
	}
	bare, err := Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	a["sig"] = hex.EncodeToString(ed25519.Sign(dev, bare)) // no domain prefix
	_, verr := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	expectCode(t, verr, "bad_signature")
}

func TestVerifyAssertionMissingFields(t *testing.T) {
	for _, field := range []string{"identity", "device", "aud", "nonce", "chain_head", "sig", "iat", "exp"} {
		id := newIdentity(t)
		dev := id.addDevice("authenticate")
		a := id.assertion(dev, testAud, "n1", id.head())
		delete(a, field)
		_, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
		if err == nil || err.Code != "invalid_assertion" {
			t.Fatalf("%s: got %v", field, err)
		}
	}
}

func TestVerifyAssertionMalformedSignature(t *testing.T) {
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	a := id.assertion(dev, testAud, "n1", id.head())
	a["sig"] = "not-hex"
	_, err := VerifyAssertion(a, id.chain(), testAud, nowUnix())
	expectCode(t, err, "bad_signature")
}

// --- HTTP -------------------------------------------------------------------

func post(t *testing.T, fn http.HandlerFunc, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	fn(rr, req)
	var out map[string]any
	if err := DecodeJSON(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad response %q: %v", rr.Body.String(), err)
	}
	return rr.Code, out
}

func TestChallengeDefaultsToNodeAudience(t *testing.T) {
	h := NewHandler("https://node.test")
	code, out := post(t, h.Challenge, map[string]any{})
	if code != 201 || out["aud"] != "https://node.test" || out["type"] != RequestType {
		t.Fatalf("got %d %v", code, out)
	}
	if n, _ := out["nonce"].(string); len(n) < 22 {
		t.Fatalf("nonce too short: %q", n)
	}
}

func TestChallengeValidation(t *testing.T) {
	h := NewHandler("")
	cases := []map[string]any{
		{}, // no audience anywhere
		{"aud": testAud, "callback": "https://evil.test/x"},
		{"aud": testAud, "claims": "name"},
		{"aud": testAud, "expires_in": 0},
	}
	for i, body := range cases {
		if code, out := post(t, h.Challenge, body); code != 400 {
			t.Fatalf("case %d: got %d %v", i, code, out)
		}
	}
}

func TestVerifyFlowAndReplay(t *testing.T) {
	h := NewHandler("")
	id := newIdentity(t)
	dev := id.addDevice("authenticate")

	code, req := post(t, h.Challenge, map[string]any{"aud": testAud})
	if code != 201 {
		t.Fatalf("challenge: %d %v", code, req)
	}
	a := id.assertion(dev, testAud, req["nonce"].(string), id.head())
	body := map[string]any{"assertion": a, "sigchain": id.events}

	code, out := post(t, h.Verify, body)
	if code != 200 || out["valid"] != true || out["identity"] != id.hashes[0] {
		t.Fatalf("verify: %d %v", code, out)
	}

	code, out = post(t, h.Verify, body)
	if code != 401 || out["error"] != "unknown_challenge" {
		t.Fatalf("replay: %d %v", code, out)
	}
}

func TestVerifyBadSignatureDoesNotBurnNonce(t *testing.T) {
	h := NewHandler("")
	id := newIdentity(t)
	dev := id.addDevice("authenticate")

	_, req := post(t, h.Challenge, map[string]any{"aud": testAud})
	good := id.assertion(dev, testAud, req["nonce"].(string), id.head())
	bad := map[string]any{}
	for k, v := range good {
		bad[k] = v
	}
	bad["sig"] = strings.Repeat("00", 64)

	code, out := post(t, h.Verify, map[string]any{"assertion": bad, "sigchain": id.events})
	if code != 401 || out["error"] != "bad_signature" {
		t.Fatalf("bad sig: %d %v", code, out)
	}
	code, out = post(t, h.Verify, map[string]any{"assertion": good, "sigchain": id.events})
	if code != 200 {
		t.Fatalf("good after bad: %d %v", code, out)
	}
}

func TestVerifyUnknownNonceAndMissingChain(t *testing.T) {
	h := NewHandler("")
	id := newIdentity(t)
	dev := id.addDevice("authenticate")

	a := id.assertion(dev, testAud, "never-issued", id.head())
	code, out := post(t, h.Verify, map[string]any{"assertion": a, "sigchain": id.events})
	if code != 401 || out["error"] != "unknown_challenge" {
		t.Fatalf("unknown nonce: %d %v", code, out)
	}

	_, req := post(t, h.Challenge, map[string]any{"aud": testAud})
	a = id.assertion(dev, testAud, req["nonce"].(string), id.head())
	code, out = post(t, h.Verify, map[string]any{"assertion": a})
	if code != 400 {
		t.Fatalf("missing sigchain: %d %v", code, out)
	}
}

func TestVerifyStaleChainReturns409(t *testing.T) {
	h := NewHandler("")
	id := newIdentity(t)
	dev := id.addDevice("authenticate")
	staleEvents := append([]map[string]any(nil), id.events...)
	id.addDevice("authenticate")

	_, req := post(t, h.Challenge, map[string]any{"aud": testAud})
	a := id.assertion(dev, testAud, req["nonce"].(string), id.head())

	code, out := post(t, h.Verify, map[string]any{"assertion": a, "sigchain": staleEvents})
	if code != 409 || out["error"] != "stale_state" {
		t.Fatalf("stale: %d %v", code, out)
	}
	code, out = post(t, h.Verify, map[string]any{"assertion": a, "sigchain": id.events})
	if code != 200 {
		t.Fatalf("fresh: %d %v", code, out)
	}
}

func TestChallengeStoreFullAndExpiry(t *testing.T) {
	s := NewStore(2)
	if _, err := s.New(testAud, "", nil, 60); err != nil {
		t.Fatal(err)
	}
	r2, err := s.New(testAud, "", nil, 60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.New(testAud, "", nil, 60); err != ErrStoreFull {
		t.Fatalf("expected ErrStoreFull, got %v", err)
	}
	if !s.Consume(r2.Nonce) || s.Consume(r2.Nonce) {
		t.Fatal("nonce must be single use")
	}

	orig := nowUnix
	defer func() { nowUnix = orig }()
	nowUnix = func() int64 { return orig() + 3600 }
	if s.Cleanup() != 1 || s.Len() != 0 {
		t.Fatalf("expected expired challenge to be removed, len=%d", s.Len())
	}
}

// --- claims ------------------------------------------------------------------

func (id *testIdentity) addClaim(signer ed25519.PrivateKey, claimID string) {
	pub := signer.Public().(ed25519.PublicKey)
	ev := map[string]any{
		"version":    num(1),
		"type":       "add_claim",
		"alg":        "ed25519",
		"hash_alg":   "sha256",
		"timestamp":  num(nowUnix() - 3),
		"signed_by":  hex.EncodeToString(pub),
		"claim_id":   claimID,
		"claim_type": "email",
		"commitment": strings.Repeat("ab", 32),
		"expires":    nil,
	}
	id.contentFields(ev)
	sign(id.t, signer, ev)
	id.push(ev)
}

func (id *testIdentity) revokeClaim(signer ed25519.PrivateKey, claimID string) {
	pub := signer.Public().(ed25519.PublicKey)
	ev := map[string]any{
		"version":   num(1),
		"type":      "revoke_claim",
		"alg":       "ed25519",
		"hash_alg":  "sha256",
		"timestamp": num(nowUnix() - 2),
		"prev":      id.head(),
		"signed_by": hex.EncodeToString(pub),
		"claim_id":  claimID,
		"reason":    nil,
	}
	if c := id.commitment(); c != nil {
		ev["content"] = c
	}
	sign(id.t, signer, ev)
	id.push(ev)
}

func TestClaimEventsAreAccepted(t *testing.T) {
	id := newIdentity(t)
	id.addClaim(id.masterPriv, "claim-0000000000001")
	dev := id.addDevice("manage_claims")
	id.addClaim(dev, "claim-0000000000002")
	id.revokeClaim(dev, "claim-0000000000001")
	// genesis, add_device and revoke_claim are control events; the two claims are content
	if sc := id.chain(); sc.Len() != 3 || sc.ContentLen() != 2 {
		t.Fatalf("expected 3 control and 2 content events, got %d and %d", sc.Len(), sc.ContentLen())
	}
}

func TestClaimEventsNeedAuthorizedSigner(t *testing.T) {
	// device without manage_claims
	id := newIdentity(t)
	dev := id.addDevice("sign_messages")
	id.addClaim(dev, "claim-0000000000001")
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("device without manage_claims must be rejected")
	}

	// revoked device
	id = newIdentity(t)
	dev = id.addDevice("manage_claims")
	id.revoke(dev)
	id.addClaim(dev, "claim-0000000000001")
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("revoked device must be rejected")
	}

	// a stranger
	id = newIdentity(t)
	_, stranger := newKey(t)
	id.addClaim(stranger, "claim-0000000000001")
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("unknown key must be rejected")
	}
}

func TestClaimEventsRejectDuplicatesAndOrphans(t *testing.T) {
	id := newIdentity(t)
	id.addClaim(id.masterPriv, "claim-0000000000001")
	id.addClaim(id.masterPriv, "claim-0000000000001")
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("duplicate claim_id must be rejected")
	}

	id = newIdentity(t)
	id.revokeClaim(id.masterPriv, "claim-never-existed--")
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("revoking an unknown claim must be rejected")
	}

	id = newIdentity(t)
	id.addClaim(id.masterPriv, "claim-0000000000001")
	id.revokeClaim(id.masterPriv, "claim-0000000000001")
	id.revokeClaim(id.masterPriv, "claim-0000000000001")
	if _, err := ParseSigchain(id.wire()); err == nil {
		t.Fatal("double revoke must be rejected")
	}
}

func TestDefaultDeviceCapabilitiesIncludeManageClaims(t *testing.T) {
	id := newIdentity(t)
	// A device added without a capability list gets every capability (as in Python).
	pub, priv := newKey(t)
	id.appendEvent("add_device", map[string]any{
		"device_pubkey":            hex.EncodeToString(pub),
		"device_encryption_pubkey": strings.Repeat("00", 32),
		"label":                    "default caps",
		"expires":                  nil,
	})
	id.addClaim(priv, "claim-0000000000001")
	if _, err := ParseSigchain(id.wire()); err != nil {
		t.Fatalf("default capabilities should include manage_claims: %v", err)
	}
}

func (id *testIdentity) setClaimOrder(signer ed25519.PrivateKey, claimType string, order ...string) {
	pub := signer.Public().(ed25519.PublicKey)
	items := make([]any, len(order))
	for i, o := range order {
		items[i] = o
	}
	ev := map[string]any{
		"version":    num(1),
		"type":       "set_claim_order",
		"alg":        "ed25519",
		"hash_alg":   "sha256",
		"timestamp":  num(nowUnix() - 1),
		"signed_by":  hex.EncodeToString(pub),
		"claim_type": claimType,
		"order":      items,
	}
	id.contentFields(ev)
	sign(id.t, signer, ev)
	id.push(ev)
}

func TestClaimOrderEventIsAccepted(t *testing.T) {
	id := newIdentity(t)
	id.addClaim(id.masterPriv, "claim-0000000000001")
	id.addClaim(id.masterPriv, "claim-0000000000002")
	id.setClaimOrder(id.masterPriv, "email", "claim-0000000000002", "claim-0000000000001")
	dev := id.addDevice("manage_claims")
	id.setClaimOrder(dev, "email", "claim-0000000000001")
	if sc := id.chain(); sc.Len() != 2 || sc.ContentLen() != 4 {
		t.Fatalf("expected 2 control and 4 content events, got %d and %d", sc.Len(), sc.ContentLen())
	}
}

func TestClaimOrderEventIsChecked(t *testing.T) {
	cases := map[string]func(id *testIdentity){
		"unknown claim": func(id *testIdentity) { id.setClaimOrder(id.masterPriv, "email", "claim-0000000000009") },
		"listed twice": func(id *testIdentity) {
			id.setClaimOrder(id.masterPriv, "email", "claim-0000000000001", "claim-0000000000001")
		},
		"empty":      func(id *testIdentity) { id.setClaimOrder(id.masterPriv, "email") },
		"wrong type": func(id *testIdentity) { id.setClaimOrder(id.masterPriv, "phone", "claim-0000000000001") },
		"revoked": func(id *testIdentity) {
			id.revokeClaim(id.masterPriv, "claim-0000000000001")
			id.setClaimOrder(id.masterPriv, "email", "claim-0000000000001")
		},
		"device without manage_claims": func(id *testIdentity) {
			dev := id.addDevice("sign_messages")
			id.setClaimOrder(dev, "email", "claim-0000000000001")
		},
	}
	for name, mutate := range cases {
		id := newIdentity(t)
		id.addClaim(id.masterPriv, "claim-0000000000001")
		mutate(id)
		if _, err := ParseSigchain(id.wire()); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}
