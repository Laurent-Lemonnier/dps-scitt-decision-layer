#!/usr/bin/env python3
"""The failing cases of the DPS and AIR composition: each is the valid set changed in one place, run through the same
checks (build.verify). A case is as expected when the place it names is among those that fail, and a documented case
(the join not established, or unresolved) when every verifier passes and the binding is reported with the word the
case names. Each case is published as a directory out/negatives/<case>/ holding the documents the verification ran on,
as they were at that moment, the description (what.txt) and, apart from them, the verdicts (result.json);
out/negatives/summary.json gathers the verdicts. Exit 0 when every case is as expected. Deterministic."""
import hashlib
import json
import sys

import cbor2

import build as B

N = {}


def case(name, where, what):
    def deco(fn):
        N[name] = (where, what, fn)
        return fn
    return deco


def reissue_air1(art, **kw):
    """Sequence 1 as the operator would issue it again with these payload changes (hashes and signature recomputed), so
    the record verifies on its own; sequence 0 and its chain_hash are kept."""
    art["airs"][1] = B.issue(B.air_payload_1(art["record_bytes"], art["sig_bytes"], art["spec_bytes"], **kw), 1,
                             art["airs"][0]["protected"]["chain_hash"])


@case("N1-content-hash-wrong", "air", "the header's content_hash is another digest, the record signed again: 5.8 step 1 (and step 2, which starts from it)")
def n1(art):
    a = art["airs"][1]
    art["airs"][1] = B.reissue(a, header={"content_hash": hashlib.sha256(b"another payload").digest()})
    B.recite(art)


@case("N2-payload-reordered-header-kept", "air", "the payload re-serialised with its members in another order (not RFC 8785), the header and signature kept: 5.8 step 1, 5.6 canonical form, step 3")
def n2(art):
    a = art["airs"][1]
    other = json.dumps(a["payload"], ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode("utf-8")
    other = other.replace(b'{"action_subtype":"refund","action_timestamp_ms":', b'{"action_timestamp_ms":', 1) \
        .replace(b',"action_type":"payment_execution",', b',"action_type":"payment_execution","action_subtype":"refund",', 1)
    assert other != a["payload_bytes"] and json.loads(other) == a["payload"]      # same values, another member order
    protected_bytes = cbor2.dumps(a["protected"], canonical=True)
    cose = cbor2.dumps(cbor2.CBORTag(18, [protected_bytes, {}, other, a["signature"]]))
    art["airs"][1] = {**a, "cose": cose, "payload_bytes": other}


@case("N2b-chain-hash-wrong", "air", "the header's chain_hash is another digest, the record signed again: 5.8 step 2 alone")
def n2b(art):
    a = art["airs"][1]
    art["airs"][1] = B.reissue(a, header={"chain_hash": hashlib.sha256(b"another chain").digest()})
    B.recite(art)


@case("N3-sequence-gap", "air", "sequence 1 is numbered 2, the record signed again: 5.8 step 4")
def n3(art):
    art["airs"][1] = B.reissue(art["airs"][1], header={"sequence_number": 2})
    B.recite(art)


@case("N4-first-record-nonzero-prev", "air", "sequence 0 carries a non-zero prev_chain_hash (chain_hash recomputed, signed again): 5.8 step 4 on the first record, and on the second, whose prev_chain_hash no longer matches")
def n4(art):
    a = art["airs"][0]
    prev = hashlib.sha256(b"a chain that is not this one").digest()
    content = a["protected"]["content_hash"]
    art["airs"][0] = B.reissue(a, header={"prev_chain_hash": prev, "chain_hash": B.AIR.chain_hash(
        content, prev, a["protected"]["action_timestamp_ms"], a["protected"]["agent_id"])})


@case("N5-payload-changed-after-signing", "air", "the payload's outcome_summary changed after signing, content_hash and chain_hash made consistent, the signature kept: 5.8 step 3 alone")
def n5(art):
    a = art["airs"][1]
    p = dict(a["payload"], outcome_summary="Refund urn:example:refund:R-55120 succeeded, 150.00 EUR")
    art["airs"][1] = B.reissue(a, payload=p, keep_signature=True)
    B.recite(art)


@case("N6-record-edited-after-citation", "joins", "the decision record's context is edited after the AIR cited its bytes (seal_hash recomputed, so the record is consistent on its own): the typed digest no longer names the bytes held")
def n6(art):
    art["record"]["context_at_decision"] = "Ticket 4410 reports two identical charges; the customer also asked for a voucher."
    art["record"]["seal_hash"] = "0" * 64
    art["record"]["seal_hash"] = B.sha256(B.compact(art["record"]))
    art["record_bytes"] = B.compact(art["record"])


@case("N7-executed-input-not-approved", "joins", "the agent executed a specification of 150.00 EUR; the person approved 120.00 EUR; the AIR verifies and cites the record, its input_hash is not the approved bytes")
def n7(art):
    other = B.compact({**B.SPEC, "parameters": {**B.PARAMS, "amount_minor": 15000}})
    reissue_air1(art, input_bytes=other)
    B.recite(art)


@case("N8-no-external-refs", "documented:NOT_BOUND", "a valid DPS record and a valid AIR with empty external_refs: the join is not established, nothing fails")
def n8(art):
    reissue_air1(art, external_refs=[])
    B.recite(art)


@case("N9-unknown-ref-type", "documented:UNRESOLVED", "the AIR cites the record under a type this reader does not know (org.decisionprovenancestandard.decision_record_v2): unresolved, reported, nothing fails")
def n9(art):
    ref = B.typed_digest("decision_record_v2", art["record_bytes"])
    reissue_air1(art, external_refs=[ref, {"ref_type": "refund_ref", "ref_value": B.OUTCOME_1["refund_ref"],
                                           "ref_system": "urn:example:payments:gateway"}])
    B.recite(art)


@case("N10-action-before-approval", "joins", "the action is timestamped 09:06:00Z, before the approval at 09:07:00Z and the request at 09:08:00Z (record reissued, chain intact)")
def n10(art):
    reissue_air1(art, action_at="2026-11-03T09:06:00.000Z", captured_at="2026-11-03T09:06:00.400Z")
    B.recite(art)


@case("N11-header-agent-id-differs", "air", "the header's agent_id names another agent, chain_hash recomputed with it and the record signed again: 5.6 (header agent_id equals CWT sub; payload agent_id equals the header's), and the chain is no longer one agent's")
def n11(art):
    a = art["airs"][1]
    other = "urn:example:agent:other-agent"
    art["airs"][1] = B.reissue(a, header={"agent_id": other, "chain_hash": B.AIR.chain_hash(
        a["protected"]["content_hash"], a["protected"]["prev_chain_hash"], a["protected"]["action_timestamp_ms"], other)})
    B.recite(art)


@case("N12-required-member-null", "air", "jurisdiction is null in a REQUIRED position (record reissued, hashes and signature recomputed): 6.1, all REQUIRED members non-null")
def n12(art):
    a = art["airs"][1]
    art["airs"][1] = B.reissue(a, payload=dict(a["payload"], jurisdiction=None))
    B.recite(art)


def failures(r):
    f = {}
    if any(r["schema_errors"].values()):
        f["schema"] = {k: v[:2] for k, v in r["schema_errors"].items() if v}
    if any(r["ees_schema"]["payload_errors"].values()):
        f["ees_schema"] = {k: v[:2] for k, v in r["ees_schema"]["payload_errors"].items() if v}
    air = {k: [f"{c['section']}: {c['check'][:90]}" for c in v["checks"] if not c["ok"]]
           for k, v in r["air"].items() if k != "chain" and v["verdict"] != "VERIFIED"}
    if air or r["air"]["chain"]["verdict"] != "VERIFIED":
        f["air"] = {**air, "chain": r["air"]["chain"]["verdict"]}
    bad = {d: s for d, s in r["dps_action_binding"].items() if s != "verified"}
    if bad:
        f["dps_action_binding"] = {d: [s, r["dps_action_binding_findings"].get(d, [])[:2]] for d, s in bad.items()}
    if r["dps_issuer_seal"]["status"] != "verified":
        f["dps_issuer_seal"] = r["dps_issuer_seal"]
    if r["dps_person_approval"]["status"] != "verified":
        f["dps_person_approval"] = r["dps_person_approval"]
    j = {k[:3].strip(): v for k, v in r["joins"].items() if v is not True}
    if j:
        f["joins"] = j
    return f


def main():
    out = B.HERE / "out" / "negatives"
    out.mkdir(parents=True, exist_ok=True)
    summary, ok = {}, True
    for name, (where, what, fn) in N.items():
        art = B.build()
        fn(art)
        r = B.verify(art)
        f = failures(r)
        if where.startswith("documented:"):
            word = where.split(":", 1)[1]
            # every verifier passes; the only joins not true are the ones reported as not applicable or not established
            expected = (set(f) <= {"joins"} and all(isinstance(v, str) for v in f.get("joins", {}).values())
                        and r["binding"].startswith(word))
        else:
            expected = where in f
        ok = ok and expected
        summary[name] = {"what": what, "caught_by": sorted(f), "expected_place": where, "as_expected": expected,
                         "binding": r["binding"], "detail": f}
        publish(out / name, art, what, summary[name])
        print(("ok   " if expected else "FAIL ") + f"{name}: caught by {', '.join(sorted(f)) or 'nothing'}; binding {r['binding'].split(':')[0]}")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    return 0 if ok else 1


def publish(d, art, what, entry):
    """One directory per case: the documents the verification ran on, as they were at that moment (the DPS documents
    as JSON, the AIRs as COSE bytes, hex, payload and header, as in ../out), the description (what.txt) and, apart from
    them, the verdicts (result.json)."""
    d.mkdir(parents=True, exist_ok=True)
    for stale in d.iterdir():
        stale.unlink()
    for k in ("record", "attachment", "sig"):
        (d / f"{k}.json").write_text(json.dumps(art[k], ensure_ascii=False, indent=1) + "\n")
    B.write_airs(d, art["airs"])
    (d / "what.txt").write_text(what + "\n")
    (d / "result.json").write_text(json.dumps(entry, ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    sys.exit(main())
