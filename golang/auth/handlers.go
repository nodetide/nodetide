package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	maxBodyBytes      = 4 << 20
	maxAudLength      = 512
	maxCallbackLength = 2048
	maxClaims         = 16
)

// Handler serves the native SSO endpoints.
//
// Unlike the Python node, the Go node has no identity store yet, so the
// sigchain must be supplied with every verify request.
type Handler struct {
	Store *Store
	// Audience is the origin used when a challenge request names none
	// (NODETIDE_AUTH_AUDIENCE).
	Audience string
}

// NewHandler creates a Handler with an empty challenge store.
func NewHandler(audience string) *Handler {
	return &Handler{Store: NewStore(MaxPendingChallenges), Audience: audience}
}

// StartCleanup periodically removes expired challenges. It runs until the
// process exits.
func (h *Handler) StartCleanup(every time.Duration) {
	go func() {
		for range time.Tick(every) {
			h.Store.Cleanup()
		}
	}()
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	body := map[string]any{"error": code, "message": message, "code": status}
	if details != nil {
		body["details"] = details
	}
	writeJSON(w, status, body)
}

// readObject reads an optional JSON object body.
func readObject(w http.ResponseWriter, r *http.Request) (map[string]any, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return nil, errors.New("Could not read body")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	var data map[string]any
	if err := DecodeJSON(raw, &data); err != nil || data == nil {
		return nil, errors.New("Body must be a JSON object")
	}
	return data, nil
}

// Challenge handles POST /api/auth/challenge.
//
//	{"aud": "https://app.example.com", "callback": "...",
//	 "claims": ["name"], "expires_in": 300}
func (h *Handler) Challenge(w http.ResponseWriter, r *http.Request) {
	data, err := readObject(w, r)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error(), nil)
		return
	}

	aud := h.Audience
	if v, present := data["aud"]; present && v != nil && v != "" {
		s, ok := v.(string)
		if !ok {
			writeError(w, 400, "invalid_request", "aud must be a string", nil)
			return
		}
		aud = s
	}
	if aud == "" {
		writeError(w, 400, "invalid_request", "aud is required", nil)
		return
	}
	if len(aud) > maxAudLength {
		writeError(w, 400, "invalid_request", "aud too long", nil)
		return
	}

	callback := ""
	if v, present := data["callback"]; present && v != nil {
		s, ok := v.(string)
		if !ok || len(s) > maxCallbackLength {
			writeError(w, 400, "invalid_request", "Invalid callback", nil)
			return
		}
		if s != aud && !strings.HasPrefix(s, strings.TrimRight(aud, "/")+"/") {
			writeError(w, 400, "invalid_request", "callback must be under aud", nil)
			return
		}
		callback = s
	}

	var claims []string
	if v, present := data["claims"]; present && v != nil {
		list, ok := v.([]any)
		if !ok || len(list) > maxClaims {
			writeError(w, 400, "invalid_request", "claims must be a list of strings", nil)
			return
		}
		for _, c := range list {
			s, ok := c.(string)
			if !ok {
				writeError(w, 400, "invalid_request", "claims must be a list of strings", nil)
				return
			}
			claims = append(claims, s)
		}
	}

	lifetime := int64(DefaultRequestLifetime)
	if v, present := data["expires_in"]; present {
		var secs int64
		n, isNumber := v.(json.Number)
		if isNumber {
			var convErr error
			secs, convErr = n.Int64()
			isNumber = convErr == nil
		}
		if !isNumber || secs < 1 {
			writeError(w, 400, "invalid_request", "expires_in must be a positive integer", nil)
			return
		}
		lifetime = secs
	}

	req, err := h.Store.New(aud, callback, claims, lifetime)
	if errors.Is(err, ErrStoreFull) {
		writeError(w, 429, "rate_limited", "Too many outstanding challenges", nil)
		return
	}
	if err != nil {
		writeError(w, 500, "internal_error", "Could not create challenge", nil)
		return
	}
	writeJSON(w, 201, req)
}

// maxRelatedChains bounds how many other identities' chains one request may bring.
const maxRelatedChains = 32

// resolverFromRequest looks up other identities' chains (the owners of an
// organization, the trustees of a recovery) among the request's
// "related_sigchains": {identity hash: [events]}. This node has no identity
// store, so whoever logs in brings them; each is verified like any chain and
// must really be the identity it is filed under.
func resolverFromRequest(data map[string]any) func(string) *Sigchain {
	related, _ := data["related_sigchains"].(map[string]any)
	if len(related) == 0 || len(related) > maxRelatedChains {
		return nil
	}
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

// Verify handles POST /api/auth/verify.
//
//	{"assertion": {...}, "sigchain": [...], "related_sigchains": {"<identity>": [...]}?}
//
// The sigchain may be the control chain alone (a light chain): that is enough to
// check a login. "related_sigchains" is only needed for organizations with owners
// and for identities restored by social recovery.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	data, err := readObject(w, r)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error(), nil)
		return
	}

	assertion, ok := data["assertion"].(map[string]any)
	if !ok {
		writeError(w, 400, "invalid_request", "Missing assertion", nil)
		return
	}
	nonce, nonceOK := assertion["nonce"].(string)
	_, identityOK := assertion["identity"].(string)
	if !nonceOK || !identityOK {
		writeError(w, 400, "invalid_request", "Assertion needs string nonce and identity", nil)
		return
	}

	req, found := h.Store.Peek(nonce)
	if !found {
		writeError(w, 401, "unknown_challenge", "Challenge is unknown, already used, or expired", nil)
		return
	}

	rawChain, present := data["sigchain"]
	if !present || rawChain == nil {
		writeError(w, 400, "invalid_request", "sigchain is required (this node has no identity store)", nil)
		return
	}
	events, ok := rawChain.([]any)
	if !ok {
		writeError(w, 400, "invalid_request", "sigchain must be a list of events", nil)
		return
	}
	chain, err := ParseSigchainWith(events, Options{Resolve: resolverFromRequest(data)})
	if err != nil {
		if IsMalformed(err) {
			writeError(w, 400, "invalid_request", "Malformed sigchain", nil)
		} else {
			writeError(w, 401, "invalid_sigchain", err.Error(), nil)
		}
		return
	}

	res, verr := VerifyAssertion(assertion, chain, req.Aud, nowUnix())
	if verr == nil {
		if exp, _ := intField(assertion, "exp"); exp > req.ExpiresAt+ClockSkew {
			res, verr = nil, fail("invalid_assertion", "Assertion outlives its challenge")
		}
	}
	if verr != nil {
		if verr.Code == "unknown_chain_head" {
			writeError(w, 409, "stale_state", verr.Message, map[string]any{
				"head_hash": chain.HeadHash(),
				"length":    chain.Len(),
			})
			return
		}
		writeError(w, 401, verr.Code, verr.Message, nil)
		return
	}

	if !h.Store.Consume(nonce) {
		writeError(w, 401, "unknown_challenge", "Challenge is unknown, already used, or expired", nil)
		return
	}

	claims := res.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	writeJSON(w, 200, map[string]any{
		"valid":    true,
		"identity": res.Identity,
		"device":   res.Device,
		"claims":   claims, // self-asserted; not verified by this endpoint
	})
}
