"""The cross-language vectors (protocol-vectors/chain-v2.json) checked by the Python reference itself.

golang/auth/v2_test.go and the Kotlin protocol module run the same file; this keeps the reference honest about it, so a
change to the chain rules that is not reflected in the vectors (or the other implementations) fails somewhere.
"""

import json
from pathlib import Path

import pytest

from nodetide.core.identity import Sigchain, SigchainEvent

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "protocol-vectors" / "chain-v2.json").read_text())
NOW = VECTORS["now"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_vector(case):
    related = {h: Sigchain.from_list(events) for h, events in case["related"].items()}
    chain = Sigchain.from_list(case["chain"])
    ok, err = chain.verify(related.get, check_current=case["check_current"])
    expect = case["expect"]
    assert ok is expect["valid"], err
    if not ok:
        return
    assert chain.identity_hash == expect["identity"] and chain.head_hash == expect["head"]
    assert chain.get_current_master_key() == expect["master"]
    assert chain.is_partial is expect["partial"]
    assert (len(chain.events), len(chain.content)) == (expect["control_length"], expect["content_length"])
    assert sorted(d.pubkey for d in chain.get_active_devices(NOW)) == expect["active_devices"]
    assert sorted(({"id": c.claim_id, "type": c.claim_type, "revoked": c.revoked_at is not None} for c in chain.get_claims()),
                  key=lambda c: c["id"]) == expect["claims"]
    for pub, status in expect.get("device_status", {}).items():
        assert chain.device_status(pub) == status
    for item in case.get("attach", []):
        error = chain.attach_content(SigchainEvent.from_dict(item["event"]), item["proof"])
        assert (error is None) is item["ok"], error
