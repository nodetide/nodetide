package auth

import (
	"errors"
	"fmt"
)

// Organizations with owners and social recovery: both depend on OTHER
// identities' chains (the owners' and the trustees' keys as of a named state),
// which the caller supplies through Options.Resolve.
// Port of the "Organization identities" and "Social recovery" sections of
// python/src/nodetide/core/identity.py.

const (
	governedMarker = "owners"
	maxOwners      = 16
	maxOwnerWeight = 1_000_000
)

type ownerEntry struct {
	identity string
	weight   int64
}

// masterAt is the master key right after the control event with hash state.
func (s *Sigchain) masterAt(state string) (string, bool) {
	key := ""
	for i, ev := range s.events {
		typ, _ := stringField(ev, "type")
		switch typ {
		case "genesis":
			key, _ = stringField(ev, "pubkey")
		case "rotate_master", "social_recovery":
			key, _ = stringField(ev, "new_pubkey")
		}
		if s.hashes[i] == state {
			return key, true
		}
	}
	return "", false
}

func parseOwnerList(raw any, opts Options) ([]ownerEntry, error) {
	list, ok := raw.([]any)
	if !ok || len(list) < 1 || len(list) > maxOwners {
		return nil, fmt.Errorf("an organization has between 1 and %d owners", maxOwners)
	}
	seen := map[string]bool{}
	var owners []ownerEntry
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok || len(m) != 2 {
			return nil, errors.New("an owner is {identity, weight}")
		}
		identity, ok := stringField(m, "identity")
		if !ok || identity == "" {
			return nil, errors.New("an owner needs an identity hash")
		}
		weight, ok := intField(m, "weight")
		if !ok || weight < 1 || weight > maxOwnerWeight {
			return nil, fmt.Errorf("an owner's weight is a whole number from 1 to %d", maxOwnerWeight)
		}
		if seen[identity] {
			return nil, errors.New("an owner is listed twice")
		}
		seen[identity] = true
		if opts.Resolve == nil {
			return nil, errors.New("owner identities are needed to check an organization")
		}
		chain := opts.Resolve(identity)
		if chain == nil {
			return nil, fmt.Errorf("unknown owner identity %.12s", identity)
		}
		if it, _ := stringField(chain.events[0], "identity_type"); it != "personal" || chain.owners != nil {
			return nil, errors.New("an owner must be a personal identity")
		}
		owners = append(owners, ownerEntry{identity: identity, weight: weight})
	}
	return owners, nil
}

func approvalMessage(ev map[string]any, owner, state string) ([]byte, error) {
	return Canonical(map[string]any{
		"purpose": "nodetide-owner-approval-v1",
		"owner":   owner,
		"state":   state,
		"event":   without(ev, "signature", "approvals"),
	})
}

// approvalScore returns the weight that approved ev and the total weight.
func approvalScore(ev map[string]any, owners []ownerEntry, opts Options, fresh bool) (approved, total int64, err error) {
	weights := map[string]int64{}
	for _, o := range owners {
		total += o.weight
		weights[o.identity] = o.weight
	}
	if opts.Resolve == nil {
		return 0, total, errors.New("owner identities are needed to check an organization")
	}
	approvals, _ := ev["approvals"].([]any)
	done := map[string]bool{}
	for _, item := range approvals {
		a, ok := item.(map[string]any)
		if !ok {
			return 0, total, errors.New("approval from someone who is not an owner")
		}
		identity, _ := stringField(a, "identity")
		if _, isOwner := weights[identity]; !isOwner {
			return 0, total, errors.New("approval from someone who is not an owner")
		}
		if done[identity] {
			return 0, total, errors.New("an owner approved twice")
		}
		chain := opts.Resolve(identity)
		if chain == nil {
			return 0, total, fmt.Errorf("unknown owner identity %.12s", identity)
		}
		state, _ := stringField(a, "state")
		key, found := chain.masterAt(state)
		if !found {
			return 0, total, errors.New("approval names a chain state the owner does not have")
		}
		if k, _ := stringField(a, "key"); k != key {
			return 0, total, errors.New("approval key is not the owner's key at that state")
		}
		if fresh && key != chain.MasterKey() {
			return 0, total, errors.New("approval uses a key the owner has since replaced")
		}
		msg, merr := approvalMessage(ev, identity, state)
		sig, _ := stringField(a, "signature")
		if merr != nil || !verifyHex(key, msg, sig) {
			return 0, total, errors.New("owner approval signature invalid")
		}
		done[identity] = true
		approved += weights[identity]
	}
	return approved, total, nil
}

func parseRecoveryConfig(ev map[string]any, identity string) (*recoveryConfig, error) {
	list, ok := ev["primary_trustees"].([]any)
	if !ok {
		return nil, errors.New("trustees are distinct identity hashes")
	}
	seen := map[string]bool{}
	var trustees []string
	for _, item := range list {
		s, ok := item.(string)
		if !ok || seen[s] {
			return nil, errors.New("trustees are distinct identity hashes")
		}
		seen[s] = true
		trustees = append(trustees, s)
	}
	if seen[identity] {
		return nil, errors.New("you cannot be your own trustee")
	}
	threshold, ok := intField(ev, "primary_threshold")
	if !ok || threshold < 1 || threshold > int64(len(trustees)) {
		return nil, errors.New("the threshold is between 1 and the number of trustees")
	}
	return &recoveryConfig{trustees: trustees, threshold: threshold}, nil
}

func recoveryMessage(identity, prev, newPub, newEnc, trustee, state string) ([]byte, error) {
	return Canonical(map[string]any{
		"purpose":               "nodetide-social-recovery-v1",
		"identity":              identity,
		"prev":                  prev,
		"new_pubkey":            newPub,
		"new_encryption_pubkey": newEnc,
		"trustee":               trustee,
		"state":                 state,
	})
}

// checkRecoveryEvent verifies a social_recovery event: signed by the new key
// and backed by enough trustees named in the latest set_recovery.
func checkRecoveryEvent(ev map[string]any, identity string, cfg *recoveryConfig, opts Options, fresh bool) error {
	if cfg == nil {
		return errors.New("no recovery was set up")
	}
	newPub, _ := stringField(ev, "new_pubkey")
	newEnc, _ := stringField(ev, "new_encryption_pubkey")
	if signedBy, _ := stringField(ev, "signed_by"); signedBy != newPub {
		return errors.New("a recovery is signed by the new key")
	}
	prev, _ := stringField(ev, "prev")
	records, _ := ev["recovery_signatures"].([]any)
	done := map[string]bool{}
	for _, item := range records {
		rec, ok := item.(map[string]any)
		trustee, hasTrustee := stringField(rec, "trustee_identity")
		if !ok || !hasTrustee {
			return errors.New("a recovery signature names its trustee")
		}
		if opts.Resolve == nil {
			return errors.New("trustee identities are needed to check a recovery")
		}
		chain := opts.Resolve(trustee)
		if chain == nil {
			return fmt.Errorf("unknown trustee %.12s", trustee)
		}
		state, _ := stringField(rec, "state")
		key, found := chain.masterAt(state)
		if !found {
			return errors.New("recovery signature names a chain state the trustee does not have")
		}
		if k, _ := stringField(rec, "key"); k != key {
			return errors.New("recovery signature key is not the trustee's key at that state")
		}
		if fresh && key != chain.MasterKey() {
			return errors.New("recovery signature uses a key the trustee has since replaced")
		}
		msg, merr := recoveryMessage(identity, prev, newPub, newEnc, trustee, state)
		sig, _ := stringField(rec, "signature")
		if merr != nil || !verifyHex(key, msg, sig) {
			return errors.New("trustee recovery signature invalid")
		}
		if !hasString(cfg.trustees, trustee) {
			return errors.New("recovery signature from someone who is not a trustee")
		}
		if done[trustee] {
			return errors.New("a trustee signed twice")
		}
		done[trustee] = true
	}
	need := cfg.threshold
	if need < 1 {
		need = 1
	}
	if int64(len(done)) < need {
		return fmt.Errorf("%d of %d trustees signed", len(done), cfg.threshold)
	}
	return nil
}
