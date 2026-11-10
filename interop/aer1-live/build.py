#!/usr/bin/env python3
"""A real AER-1 receipt and a decision record, composed, at the request of the author of draft-zambo-aer1 (10 November
2026): "compose it with a decision record ... and tell me what joins and what does not".

  The receipt is real: zambo.dev issued it on 10 November 2026 at 10:51:44.721Z for a live_price call (BTC); it is kept
  in receipt.json as served by the public API (SOURCE.txt). It is read with the AER-1 verifier written from the text of
  draft-zambo-aer1-26 (../aer1/aer1_verify_independent.py), as is and step by step. No code of the author's is run, and
  nothing is fetched: the Nostr anchor and the evidence bytes it names are described, not checked.

  The decision is synthetic, under test keys: "read the BTC price through live_price for a valuation", in the Decision
  Provenance Standard's action binding 0.3.0 and signatures 0.2.0, written twice.
    (a) after the fact: the record is written after the call, its attempt cites this receipt by id and its result names
        the receipt's output_hash; the approval is dated after the receipt's created_at, and the checks say so.
    (b) under the decision: what it would have taken for both sides to join, shown on a SYNTHETIC receipt in the same
        layout (not issued by zambo.dev): the request_id among the committed inputs, execution_context naming the
        record, the approval before the call.

The report (out/summary.json) gives each join with what binds it, and the order of approval and effect as the clocks
state it, never upgraded: an approval dated after the effect is reported as such, and one dated before it rests on the
issuer's clock alone.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path(os.environ.get("DPS_STANDARD") or "/root/claude-ops/dps/wt-007f8c9")
_candidates = [HERE.parents[1] / "examples/release-decision/decision-record.json",
               HERE.parents[2] / "exemple-release/decision-record.json"]
TEMPLATE = pathlib.Path(os.environ.get("DPS_RECORD_TEMPLATE") or next(p for p in _candidates if p.exists()))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AB = load("ab", REPO / "extensions/action-binding/tests/run_checks.py")
SIG = load("sig", REPO / "extensions/signatures/tests/run_checks.py")
AER = load("aer_independent", HERE.parent / "aer1" / "aer1_verify_independent.py")

# ---------------------------------------------------------------- the real receipt

RECEIPT_RAW = (HERE / "receipt.json").read_bytes()
RECEIPT_FILE_SHA256 = "9e6aff78d4d0f64685d069988f2bccdbcc6f771b76cf33aeb86292b88c0aa8d6"
SOURCE_URL = "https://zambo.dev/api/receipt/e9106453-b8b2-4784-992b-1211bfc1a353"
RETRIEVED_AT = "2026-11-10T10:57:15Z"
EXPECTED_ID = "e9106453-b8b2-4784-992b-1211bfc1a353"          # the id in the author's mail of 10 November 2026
INPUT_LAYOUT = "zambo-json-sorted-keys-utf8-v1"
TABLE1 = {"id", "receipt_schema_version", "created_at", "tool", "provenance_class", "canonical_bytes", "output_hash",
          "metadata_hash", "verification_status", "supersedes"}
DRAFT_OPTIONAL = {"execution_context": "3.2", "input_hash": "3.3", "field_provenance": "3.4", "negative_record": "3.4",
                  "reversal": "3.4", "method_descriptor": "3.4", "workflow": "8.6"}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sorted_utf8(doc):
    """The layout the receipt's input_hash_layout names, read from its name: members sorted, no whitespace, UTF-8."""
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def payload_of(rec):
    try:
        return json.loads(base64.b64decode(rec.get("canonical_bytes", ""), validate=True))
    except Exception:
        return None


def step(status, rule, detail=None):
    return {"status": status, "rule": rule, **({"detail": detail} if detail else {})}


def receipt_report(rec):
    """The receipt read with the verifier written from the text: once as is, then each Section 6 step on its own, so
    that one presentation point does not hide the others; then what the text does not cover, described."""
    r = {}
    verdict, reason, _f = AER.structural(copy.deepcopy(rec), strict_id=True)
    r["independent_verifier_as_is"] = {"verdict": verdict, "reason": reason, "tier": "strict"}
    s = {}
    rid = rec.get("id")
    s["id"] = step("pass" if isinstance(rid, str) and AER.UUID_V4.fullmatch(rid) else "fail",
                   "Section 3: lowercase UUID, not nil; strict tier: version 4 with RFC 4122 variant bits")
    try:
        AER.check_timestamp(rec.get("created_at"), "created_at")
        s["created_at"] = step("pass", "Section 3, Section 6 step 4: RFC 3339, a real calendar date, no leap second",
                               "form and calendar validity only, not that the time is true (Section 13)")
    except AER.Reject as e:
        s["created_at"] = step("fail", "Section 3: RFC 3339", str(e))
    tool = rec.get("tool")
    s["tool"] = step("pass" if isinstance(tool, dict) and all(isinstance(tool.get(k), str) and tool.get(k)
                                                              for k in ("name", "version", "scope")) else "fail",
                     "Table 1: an object with name, version and scope")
    s["provenance_class"] = step("pass" if rec.get("provenance_class") in AER.PROVENANCE else "fail",
                                 "Section 5: one of the three classes", rec.get("provenance_class"))
    raw = None
    try:
        raw = AER.decode_canonical_bytes(rec.get("canonical_bytes"))
        s["canonical_bytes"] = step("pass", "Section 4: canonical base64, strict UTF-8", f"{len(raw)} bytes")
    except AER.Reject as e:
        s["canonical_bytes"] = step("fail", "Section 4", str(e))
    oh = rec.get("output_hash", "")
    s["output_hash"] = step("pass" if raw is not None and oh == "sha256:" + sha256(raw) else "fail",
                            "Section 4, Section 6 step 3: sha256 of the decoded canonical bytes equals output_hash",
                            None if raw is not None and oh == "sha256:" + sha256(raw) else
                            "verification failed: output_hash does not match sha256(canonical_bytes)")
    if "canonical_byte_length" in rec:
        s["canonical_byte_length"] = step("pass" if raw is not None and rec["canonical_byte_length"] == len(raw) else "fail",
                                          "profile member, not in the draft: the decoded length")
    if isinstance(tool, dict):
        block = {"created_at": rec.get("created_at"), "id": rid, "output_hash": oh,
                 "provenance_class": rec.get("provenance_class"), "receipt_schema_version": rec.get("receipt_schema_version"),
                 "tool": {"name": tool.get("name"), "scope": tool.get("scope"), "version": tool.get("version")}}
        ok = rec.get("metadata_hash") == "sha256:" + sha256(AER.canonical_json(block).encode("utf-8"))
        s["metadata_hash"] = step("pass" if ok else "fail", "Section 3.1, Section 6 step 4: the metadata block "
                                  "recomputed from the stored members (id, created_at, tool, provenance_class, schema "
                                  "version, output_hash)", None if ok else "verification failed: metadata_hash does "
                                  "not match the recomputed metadata block")
    p = payload_of(rec) if raw is not None else None
    if isinstance(p, dict):
        ok = p.get("receipt_schema_version") == rec.get("receipt_schema_version") and \
            (p.get("issuer_claims") or {}).get("provenance_class") == rec.get("provenance_class")
        s["committed_version_and_class"] = step("pass" if ok else "fail", "kit rule 11 (read with the draft): the "
                                                "version and provenance class inside the canonical bytes equal the "
                                                "outer members")
        same = [k for k in ("caller", "side_effects", "tool") if k in p and p[k] == rec.get(k)]
        s["outer_copies_of_committed_members"] = step("pass" if len(same) == len([k for k in ("caller", "side_effects", "tool") if k in p]) else "fail",
                                                      "profile: the outer caller, side_effects and tool equal the "
                                                      "committed ones", ", ".join(same))
    vs = rec.get("verification_status")
    s["verification_status"] = step("pass" if vs == "verified" else "not the draft's value",
                                    "Table 1: \"verified\" when the stored record passes Section 6",
                                    None if vs == "verified" else f"{vs!r}: Section 6 names \"commitment_matches\" as "
                                    "the passing value of the deprecated version 1 API, which served this record "
                                    f"(api_version {rec.get('api_version')})")
    if "input_hash" in rec:
        if isinstance(p, dict) and "inputs" in p:
            ok = rec["input_hash"] == "sha256:" + sha256(AER.canonical_json(p["inputs"]).encode("utf-8"))
            s["input_hash"] = step("confirmed" if ok else "fail", "Section 3.3: the recorded input, in the canonical "
                                   "bytes, under the published layout")
        else:
            cand = {"symbol": (rec.get("provenance") or {}).get("request", {}).get("symbol")}
            matches = rec["input_hash"] == "sha256:" + sha256(sorted_utf8(cand))
            s["input_hash"] = step("not confirmed", "Section 3.3: a verifier that cannot reproduce the recorded input "
                                   "under a published layout MUST NOT report the commitment as confirmed",
                                   "the canonical bytes record no input, and the layout is named "
                                   f"({rec.get('input_hash_layout')!r}), not published in the receipt. "
                                   f"Reconstruction: {json.dumps(cand)} from provenance.request.symbol and job_summary "
                                   "(both outside every commitment), serialized as the layout's name reads (sorted "
                                   "members, no whitespace, UTF-8): " + ("its sha256 equals input_hash" if matches else
                                   "its sha256 differs from input_hash") + ". input_hash is outside metadata_hash "
                                   "(Section 3.3) and outside the canonical bytes: anyone holding the receipt can "
                                   "change it without affecting any other check")
            s["input_hash"]["reconstruction_matches"] = matches
    # The draft's anchor report (Section 6), and the profile's anchor described offline
    rep = AER.anchor_report(rec, raw or b"", True)
    s["anchor_report"] = step(rep["outcome"], "Section 6 per-anchor report: present / evaluated / outcome", json.dumps(rep))
    a = rec.get("anchor")
    if isinstance(a, dict) and "envelope" in a:
        env = a["envelope"]
        s["profile_anchor_offline"] = {
            "status": "consistent offline; the Nostr event not checked",
            "rule": "not Section 10: the anchor is in the profile's shape " + repr(a.get("schema_version")) + ", not "
                    "Table 4's (type, version, receipt_id, anchored_digest, anchor_type, anchored_at, proof)",
            "envelope_bytes_are_the_canonical_json_of_envelope": a.get("envelope_bytes") == AER.canonical_json(env),
            "envelope_receipt_uuid_is_the_id": env.get("receipt_uuid") == rid,
            "envelope_output_sha256_is_output_hash": env.get("output_sha256") == oh,
            "envelope_evidence_sha256_is_evidence_sha256": env.get("evidence_sha256") == rec.get("evidence_sha256"),
            "envelope_anchored_at_is_created_at": env.get("anchored_at") == rec.get("created_at"),
            "envelope_bytes_sha256": sha256(str(a.get("envelope_bytes", "")).encode("utf-8")),
            "nostr": {"event_id": a.get("event_id"), "pubkey": a.get("pubkey"), "relays": a.get("relays"),
                      "status_stated": a.get("status"), "published_at_stated": a.get("published_at"),
                      "checked": "no: no relay was contacted; the event's signature, its content and its created_at "
                                 "are not verified here (Section 10.1 step 3 needs the relay)"}}
    if "evidence_sha256" in rec:
        s["evidence"] = step("not checked", "profile: the upstream response's digest",
                             f"{rec.get('evidence_byte_length')} bytes from {rec.get('evidence_source_url')}, digest "
                             f"{rec['evidence_sha256']} ("
                             + ("equal to" if rec['evidence_sha256'] == (rec.get('provenance') or {}).get('response_sha256')
                                else "different from") + " provenance.response_sha256); the bytes were not fetched")
    s["issuer"] = step("not authenticated", "draft -26 core: no signature member; the receipt's own checks say so",
                       ((rec.get("checks") or {}).get("issued_by_zambo_dev") or {}).get("detail"))
    r["steps"] = s
    # The same object with the two presentation points set aside, to show the rest of the procedure's verdict
    probe = copy.deepcopy(rec)
    changes = []
    if probe.get("verification_status") == "commitment_matches":
        probe["verification_status"] = "verified"
        changes.append("verification_status \"commitment_matches\" read as \"verified\" (the v1 API's passing value)")
    v2, why2, _ = AER.structural(probe, strict_id=True)
    r["independent_verifier_probe"] = {"changes": changes, "verdict": v2, "reason": why2,
                                      "note": "a probe on a copy, not the receipt: what the rest of the procedure says"}
    # id verdict (Section 6): against the id the author's mail gave
    r["id_verdict"] = {"value": "matched" if rid == EXPECTED_ID else "mismatched", "expected_id": EXPECTED_ID,
                       "source": "the author's mail of 10 November 2026 (the issuer's own channel: it binds the record "
                                 "to the issuer's assertion and no further, Section 6)"}
    st = (rec.get("steps") or [{}])[0]
    r["times_stated"] = {"created_at (in metadata_hash)": rec.get("created_at"),
                         "steps[0].started_at (unbound)": st.get("started_at"),
                         "steps[0].completed_at (unbound)": st.get("completed_at"),
                         "provenance.queried_at (unbound)": (rec.get("provenance") or {}).get("queried_at"),
                         "anchor.published_at (unbound, relay confirmation)": (rec.get("anchor") or {}).get("published_at"),
                         "reading": "the upstream price was fetched 2.4 s before the step started; the committed output "
                                    "text says 'cache age 2s'. Only created_at is bound (metadata_hash); none is "
                                    "independently timed here"}
    r["members_outside_the_draft"] = sorted(k for k in rec if k not in TABLE1 and k not in DRAFT_OPTIONAL and k != "anchor")
    r["execution_context_members"] = sorted((rec.get("execution_context") or {}).keys())
    r["issuer_self_report"] = {k: v.get("status") for k, v in (rec.get("checks") or {}).items() if isinstance(v, dict)}
    r["receipt_profile"] = rec.get("receipt_profile")
    return r


def receipt_ok(r):
    s = r["steps"]
    return all(s[k]["status"] == "pass" for k in ("id", "created_at", "tool", "provenance_class", "canonical_bytes",
                                                    "output_hash", "metadata_hash")) \
        and s.get("committed_version_and_class", {"status": "pass"})["status"] == "pass" \
        and r["independent_verifier_probe"]["verdict"] == "pass"


# ---------------------------------------------------------------- the decision (synthetic, test keys)

def key_from_seed(text):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode()).digest())


def raw_public(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def uuid4_from(text):
    return str(uuid.UUID(bytes=hashlib.sha256(text.encode()).digest()[:16], version=4))


approver_key = key_from_seed("dps-scitt-decision-layer aer1-live: valuation lead key (test only)")
issuer_key = key_from_seed("dps-scitt-decision-layer aer1-live: issuer seal key (test only)")
APPROVER, APPROVER_KEY, ISSUER_KEY = "valuation-lead-1", "valuation-lead-1-key-1", "example-valuation-desk-seal-1"
TARGET = "https://zambo.dev hosted MCP, tool live_price 4.0.0, scope public"
POLICY = {"policy_id": "urn:example:policy:market-data-reads", "version": "2026-11-01",
          "applies_to": {"operation": "market_data.price.read", "target": TARGET},
          "approvers": [{"actor_ref": APPROVER, "role": "valuation lead"}], "single_use": True,
          "max_approval_age_seconds": 1800,
          "execution": "through a tool that issues an AER-1 receipt of the call; the request_id is sent with the call "
                       "where the tool records it"}
POLICY_BYTES = compact(POLICY)
POLICY_VERSION = "sha256:" + sha256(POLICY_BYTES)
POLICY_REF = POLICY["policy_id"] + "#" + POLICY["version"]
PARAMS = {"symbol": "BTC"}
TRUST = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
         "tsas": [], "checkpoint_sources": [],
         "keys": [{"key_ref": APPROVER_KEY, "holder": APPROVER, "role": "person", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(approver_key).hex(), "not_before": "2026-11-01T00:00:00Z",
                   "not_after": "2027-10-31T23:59:59Z", "identity_source_ref": "urn:example:directory:people"},
                  {"key_ref": ISSUER_KEY, "holder": "Example Valuation Desk", "role": "organisation", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-11-01T00:00:00Z",
                   "not_after": "2027-10-31T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}

REAL = AER.parse_strict(RECEIPT_RAW)
CALLER_URN = "urn:aer1:caller:" + payload_of(REAL)["caller"]["id"]
VARIANTS = {
    "after-the-fact": {
        "decision_id": "DR-2026-11101",
        "request_id": "urn:example:valuation-request:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:example:aer1-live:a")),
        # the call (the receipt's own times), then the record, written after it was read through the public API
        "T": {"attempt": REAL["steps"][0]["started_at"], "result": RETRIEVED_AT, "proposal": "2026-11-10T10:58:00Z",
              "review": "2026-11-10T10:59:00Z", "approval": "2026-11-10T11:00:00Z", "request": "2026-11-10T11:00:30Z",
              "recheck": "2026-11-10T11:00:35Z", "closed": "2026-11-10T11:01:00Z", "sealed": "2026-11-10T11:01:30Z",
              "valid_until": "2026-11-10T11:30:00Z"},
        "executor_ref": CALLER_URN, "requested_by": "urn:example:valuation-desk:record-writer",
        "recheck": ("unavailable", "no recheck before the call: the call was made at 10:51:44.650Z, before this record "
                                   "and its approval; recorded after the fact"),
    },
    "under-the-decision": {
        "decision_id": "DR-2026-11102",
        "request_id": "urn:example:valuation-request:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:example:aer1-live:b")),
        "T": {"proposal": "2026-11-10T10:40:00Z", "review": "2026-11-10T10:44:00Z", "approval": "2026-11-10T10:45:00Z",
              "request": "2026-11-10T10:51:40Z", "recheck": "2026-11-10T10:51:42Z", "attempt": "2026-11-10T10:51:44.650Z",
              "receipt": "2026-11-10T10:51:44.721Z", "result": "2026-11-10T10:51:50Z", "closed": "2026-11-10T10:55:00Z",
              "sealed": "2026-11-10T10:55:30Z", "valid_until": "2026-11-10T11:15:00Z"},
        "executor_ref": "urn:example:valuation-agent-runtime:1.0", "requested_by": "urn:example:service:valuation-agent",
        "recheck": ("authorised", None),
    },
}


def spec_of(v):
    return {"operation": "market_data.price.read", "target": TARGET, "parameters": PARAMS,
            "input_version_refs": ["urn:example:valuation:portfolio-2026-11"], "policy_version": POLICY_VERSION,
            "valid_until": v["T"]["valid_until"]}


def view_of(name, v, receipt):
    text = (f"Read the BTC spot price through {TARGET}, symbol BTC, for the valuation of portfolio 2026-11\n"
            f"policy {POLICY_REF} ({POLICY_VERSION})\nvalid until {v['T']['valid_until']}\n")
    if name == "after-the-fact":
        text += (f"This call was already made: AER-1 receipt {receipt['id']}, created_at {receipt['created_at']}, "
                 f"output_hash {receipt['output_hash']} (BTC $74,135.08 USD). This review comes after the call.\n")
    else:
        text += f"The request_id is sent with the call; the receipt is to name decision {v['decision_id']}.\n"
    return text.encode("utf-8")


def make_record(name, v):
    T = v["T"]
    record = json.loads(TEMPLATE.read_bytes())
    after = name == "after-the-fact"
    record.update({
        "decision_id": v["decision_id"], "created_at": T["proposal"], "charter_id": "CH-EXAMPLE-VALUATION-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "team-leader", "decision_class": "market-data-read",
        "consent_posture": {"posture_class": "no personal data: a public market price"},
        "decision_statement": ("Adopt, for the valuation of portfolio 2026-11, the BTC price read through live_price at "
                               "10:51:44Z on 10 November 2026 (AER-1 receipt e9106453), a call made before this "
                               "record was written." if after else
                               "Read the BTC price through live_price for the valuation of portfolio 2026-11, "
                               "sending the request_id with the call."),
        "context_at_decision": "The valuation of portfolio 2026-11 needs a BTC spot price with a receipt of the read.",
        "options_considered": ["Read the price through live_price, which issues an AER-1 receipt (chosen).",
                               "Use the last closing price of the market-data feed: no receipt of the read."],
        "required_inputs_used": ["portfolio 2026-11 positions"] + (["AER-1 receipt e9106453"] if after else []),
        "assumptions_depended_on": ["The price live_price returns is the upstream spot price it names."],
        "success_criteria": ["One read of the BTC price, with its receipt cited by the record."],
        "accountable_owner": {"full_name": "Valuation Lead One", "role": "Valuation lead", "employer": "Example Valuation Desk"},
        "re_decision_trigger": "The valuation is re-run on another day.",
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:valuation-drafting",
                               "system_name": "valuation-agent", "version": "1"},
        "affirmation_record": {"timestamp": T["approval"], "actor_identity": APPROVER,
                               "method": "Ed25519 signature over the DPS person_approval assertion"},
        "accountable_owner_signoff": {"signed_by": APPROVER, "signed_at": T["closed"]},
        "review_log": [{"reviewer": APPROVER, "reviewed_at": T["approval"], "outcome": "approved"}],
        "closed_at": T["closed"], "record_location": f"urn:example:decision-records:{v['decision_id']}", "supersedes": None,
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Valuation Lead One", "attestor_role_title": "Valuation lead",
        "attestor_employer": "Example Valuation Desk", "attestation_timestamp": T["closed"], "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-VALUATION-1: the valuation agent drafted the "
                                   "proposal, I reviewed it as shown, approved the specification whose digest the "
                                   "attachment names, and I am the accountable owner of this decision."
                                   + (" The call it adopts was made before I reviewed it." if after else "")})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    return record


def synthetic_receipt(v, record, *, request_id=None, pointer=True, created_at=None):
    """(b) A SYNTHETIC receipt in the real one's layout, built here, never issued by zambo.dev: the same tool, side
    effects and output text (marked SYNTHETIC inside the committed bytes), plus what joining needs: the inputs with the
    request_id in the canonical bytes, and execution_context naming the record (outside metadata_hash, Section 3.2)."""
    real_p = payload_of(REAL)
    inputs = {**PARAMS, "idempotency_key": request_id or v["request_id"]}
    payload = {"caller": {"id": v["executor_ref"], "type": "service"}, "inputs": inputs,
               "issuer_claims": {"provenance_class": REAL["provenance_class"]},
               "output": {"text": "SYNTHETIC, not issued by zambo.dev. " + real_p["output"]["text"]},
               "receipt_schema_version": "0.4", "side_effects": real_p["side_effects"], "tool": real_p["tool"]}
    raw = sorted_utf8(payload)
    rec = {"id": uuid4_from("aer1-live synthetic receipt (b) " + (request_id or v["request_id"])),
           "created_at": created_at or v["T"]["receipt"], "receipt_schema_version": "0.4", "tool": REAL["tool"],
           "provenance_class": REAL["provenance_class"], "canonical_bytes": b64(raw), "canonical_byte_length": len(raw),
           "output_hash": "sha256:" + sha256(raw), "verification_status": "verified",
           "input_hash": "sha256:" + sha256(sorted_utf8(inputs)), "input_hash_layout": INPUT_LAYOUT}
    block = {"created_at": rec["created_at"], "id": rec["id"], "output_hash": rec["output_hash"],
             "provenance_class": rec["provenance_class"], "receipt_schema_version": "0.4",
             "tool": {k: REAL["tool"][k] for k in ("name", "scope", "version")}}
    rec["metadata_hash"] = "sha256:" + sha256(AER.canonical_json(block).encode("utf-8"))
    rec["execution_context"] = {"source": "api.coinbase.com", "environment": "zambo.dev hosted MCP"}
    if pointer:
        rec["execution_context"]["decision_record"] = {"decision_id": record["decision_id"],
                                                       "record_digest": "sha256:" + record["seal_hash"],
                                                       "request_id": v["request_id"]}
    rec["synthetic"] = "built by interop/aer1-live/build.py with test values; not a receipt of zambo.dev"
    return rec


def make_attachment(name, v, record, receipt):
    T = v["T"]
    spec_bytes = compact(spec_of(v))
    sd = sha256(spec_bytes)
    view = view_of(name, v, receipt)
    rc_result, rc_detail = v["recheck"]
    att = {
        "profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": record["decision_id"],
        "action_specifications": [{"spec_digest": sd, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                                   "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
                                   "summary": {"operation": "market_data.price.read", "target": TARGET,
                                               "policy_version": POLICY_VERSION,
                                               "input_version_refs": ["urn:example:valuation:portfolio-2026-11"]}}],
        "stages": [
            {"stage_id": "p1", "kind": "proposal", "at": T["proposal"], "origin": "ai", "spec_digest": sd,
             "deployer_role_pointer": "urn:example:role:valuation-drafting", "system_name": "valuation-agent", "version": "1"},
            {"stage_id": "v1", "kind": "review", "at": T["review"], "reviewer_ref": APPROVER, "shown_spec_digest": sd,
             "proposal_ref": "p1", "shown_view_ref": "urn:example:valuation-console:view:2026-11", "shown_view_digest": sha256(view)},
            {"stage_id": "o1", "kind": "outcome", "at": T["approval"], "review_ref": "v1", "outcome": "approved",
             "actor_ref": APPROVER, "method": "Ed25519 signature over the DPS person_approval assertion",
             "approved_spec_digest": sd, "request_limit": 1, "authority": {"authority_ref": POLICY_REF},
             "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": T["approval"],
                           "text_ref": "urn:example:rationale:valuation-2026-11"},
             "core_ref": {"field": "review_log", "index": 0}},
            {"stage_id": "q1", "kind": "request", "at": T["request"], "request_id": v["request_id"], "authorised_by": "o1",
             "spec_digest": sd, "requested_by": v["requested_by"]},
            {"stage_id": "c1", "kind": "recheck", "at": T["recheck"], "request_ref": "q1", "result": rc_result,
             "authority_source_ref": POLICY_REF, **({"detail": rc_detail} if rc_detail else {})},
            {"stage_id": "x1", "kind": "attempt", "at": T["attempt"], "request_ref": "q1", "recheck_ref": "c1",
             "spec_digest": sd, "executor_ref": v["executor_ref"], "trace_refs": [f"urn:aer1:receipt:{receipt['id']}"]},
            {"stage_id": "r1", "kind": "result", "at": T["result"], "attempt_ref": "x1", "observed": "succeeded",
             "basis": "independent_observation",
             "evidence_ref": f"urn:aer1:receipt:{receipt['id']}#output_hash={receipt['output_hash']}"},
        ]}
    return att, sd, view


def seal(att, sealed_at):
    att["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": ISSUER_KEY,
                               "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": sealed_at,
                               "value_b64": "A" * 88}
    att["issuer_signature"]["value_b64"] = b64(issuer_key.sign(SIG.seal_signed_bytes(AB.seal_assertion(att))))
    return att


def sign_approval(record, att, sd, view):
    o1 = next(s for s in att["stages"] if s["stage_id"] == "o1")
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval",
          "decision_id": record["decision_id"], "stage_id": "o1", "outcome": "approved", "shown_spec_digest": sd,
          "shown_view_digest": sha256(view), "approved_spec_digest": sd, "signed_at": o1["at"],
          "signature": {"algorithm": "Ed25519", "key_ref": APPROVER_KEY, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(approver_key.sign(SIG.person_signed_bytes(ps)))
    return {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}


def build(name):
    v = copy.deepcopy(VARIANTS[name])
    record = make_record(name, v)
    receipt = copy.deepcopy(REAL) if name == "after-the-fact" else synthetic_receipt(v, record)
    att, sd, view = make_attachment(name, v, record, receipt)
    seal(att, v["T"]["sealed"])
    return {"variant": name, "record": record, "receipt": receipt, "attachment": att, "spec_digest": sd,
            "view": view, "sig": sign_approval(record, att, sd, view)}


def reissue(art, mutate_stages=None, view=None):
    """The issuer rewrites the attachment (and the reviewer signs again where the view or the approval time moved):
    the seal and the signature are made again, so that a failure, if any, is in the joins."""
    att = art["attachment"]
    if mutate_stages:
        mutate_stages({s["stage_id"]: s for s in att["stages"]})
    if view is not None:
        art["view"] = view
        next(s for s in att["stages"] if s["stage_id"] == "v1")["shown_view_digest"] = sha256(view)
    seal(att, att["issuer_signature"]["sealed_at"])
    art["sig"] = sign_approval(art["record"], att, art["spec_digest"], art["view"])


# ---------------------------------------------------------------- checks

DIMENSIONS = ("specification_digests", "specification_statements", "record_statements", "action_binding",
              "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")


def schema_errors(art):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    from referencing.jsonschema import DRAFT202012

    def local(uri):
        hits = [p for p in REPO.rglob(uri.rsplit("/", 1)[-1]) if ".git" not in p.parts]
        if not hits:
            raise NoSuchResource(ref=uri)
        return Resource.from_contents(json.loads(hits[0].read_text()), default_specification=DRAFT202012)
    registry = Registry(retrieve=local)
    docs = {"record": ("standard/v5.0/schemas/decision-record.schema.json", art["record"]),
            "attachment": ("extensions/action-binding/schemas/execution-evidence.schema.json", art["attachment"]),
            "signatures": ("extensions/signatures/schemas/signatures-attachment.schema.json", art["sig"]),
            "trust_policy": ("extensions/anchoring/schemas/trust-policy.schema.json", TRUST)}
    return {k: [e.message[:160] for e in Draft202012Validator(json.loads((REPO / p).read_text()), registry=registry).iter_errors(d)]
            for k, (p, d) in docs.items()}


def dps_report(art):
    record, att = art["record"], art["attachment"]
    record_bytes = compact(record)
    r = {"schema_errors": schema_errors(art)}
    report = AB.reference_report([att], {record["decision_id"]: record_bytes}, TRUST, art["sig"])
    res = report["results"][0]
    r["trust_policy"] = report["trust_policy"]["status"]
    ab = AB.check_attachment(att, record_bytes)
    r["action_binding"] = {d: ab[d][0] for d in DIMENSIONS}
    r["action_binding_findings"] = {d: ab[d][1] for d in DIMENSIONS if ab[d][1]}
    r["issuer_seal"] = {k: res["issuer_signature"].get(k, {}).get("status") if isinstance(res["issuer_signature"].get(k), dict)
                        else res["issuer_signature"].get(k) for k in ("status", "key_state", "holder", "attests")}
    _pol, persons, _s, _t = SIG.run_context({"attachment": art["sig"], "export": None, "policy": TRUST,
                                             "action_binding": {record["decision_id"]: att}})
    r["person_approval"] = {k: persons[0][k]["status"] if isinstance(persons[0][k], dict) else persons[0][k]
                            for k in ("status", "signature", "subject", "key_state", "identity")}
    return r


HOLDS_BOUND, HOLDS_UNBOUND, NOT_HOLD, ABSENT, NA = "holds, bound", "holds, unbound", "does not hold", "absent", "not applicable"


def joins(art):
    """Each join between the two documents, with what binds it on the receipt's side."""
    rec, att, record = art["receipt"], art["attachment"], art["record"]
    st = {s["stage_id"]: s for s in att["stages"]}
    x, res, q, v1, o1 = st["x1"], st["r1"], st["q1"], st["v1"], st["o1"]
    spec = json.loads(base64.b64decode(att["action_specifications"][0]["content"]["bytes_b64"]))
    p = payload_of(rec) or {}
    j = {}
    j["id_cited"] = {"status": HOLDS_BOUND if f"urn:aer1:receipt:{rec.get('id')}" in x.get("trace_refs", []) else NOT_HOLD,
                     "what": "the DPS attempt cites the receipt by id (urn:aer1:receipt:<id>)",
                     "binding": "DPS side under the issuer's seal; the id is in the receipt's metadata block (metadata_hash)"}
    ev = res.get("evidence_ref", "")
    j["output_hash_named"] = {"status": HOLDS_BOUND if ev == f"urn:aer1:receipt:{rec.get('id')}#output_hash={rec.get('output_hash')}" else NOT_HOLD,
                              "what": "the DPS result names the receipt's output_hash",
                              "binding": "DPS side under the issuer's seal; output_hash commits to the canonical bytes"}
    caller = (p.get("caller") or {}).get("id")
    j["executor_names_caller"] = {"status": HOLDS_BOUND if caller and x.get("executor_ref") in (caller, f"urn:aer1:caller:{caller}") else NOT_HOLD,
                                  "what": "the DPS attempt's executor_ref names the caller committed in the receipt",
                                  "binding": "the caller is in the canonical bytes; "
                                             + (f"here an anonymous caller (basis {p['caller'].get('basis')}, rotates "
                                                f"{p['caller'].get('rotates_at')}): pseudonymous, not an identity"
                                                if (p.get("caller") or {}).get("type") == "anonymous" else "a declared service id")}
    inputs = p.get("inputs")
    if isinstance(inputs, dict):
        key = inputs.get("idempotency_key")
        j["request_id_committed"] = {"status": HOLDS_BOUND if key == q["request_id"] else NOT_HOLD,
                                     "what": "the receipt records the DPS request_id among its inputs (idempotency key)",
                                     "binding": "inside the canonical bytes, under output_hash"}
        rest = {k: val for k, val in inputs.items() if k != "idempotency_key"}
        j["input_is_approved"] = {"status": HOLDS_BOUND if rest == spec["parameters"] else NOT_HOLD,
                                  "what": "the receipt's recorded input is the approved parameters, exactly",
                                  "binding": "inside the canonical bytes, under output_hash; input_hash confirmed by the verifier"}
    else:
        j["request_id_committed"] = {"status": ABSENT, "what": "the receipt records the DPS request_id among its inputs (idempotency key)",
                                     "binding": "the canonical bytes record no input at all; nothing in the receipt names the request"}
        ih = rec.get("input_hash")
        j["input_is_approved"] = {"status": (HOLDS_UNBOUND if ih == "sha256:" + sha256(sorted_utf8(spec["parameters"])) else NOT_HOLD) if ih else ABSENT,
                                  "what": "the receipt's recorded input is the approved parameters",
                                  "binding": "only through input_hash, which is outside metadata_hash and outside the "
                                             "canonical bytes (Section 3.3): sha256 of the approved parameters under the "
                                             "layout as its name reads; not confirmed by the verifier, and anyone holding "
                                             "the receipt can change it"}
    ec = (rec.get("execution_context") or {}).get("decision_record")
    if ec is None:
        status, detail = ABSENT, "execution_context names " + ", ".join(sorted((rec.get("execution_context") or {}).keys())) + "; no decision record"
    elif ec.get("decision_id") == record["decision_id"] and ec.get("record_digest") == "sha256:" + record["seal_hash"] \
            and ec.get("request_id") == q["request_id"]:
        status, detail = HOLDS_UNBOUND, "consistent: producer-asserted, outside metadata_hash (Section 3.2), not a binding"
    else:
        status, detail = NOT_HOLD, "inconsistent with the record: producer-asserted, outside metadata_hash (Section 3.2)"
    j["pointer_to_record"] = {"status": status, "what": "the receipt's execution_context names the decision record", "binding": detail}
    created = rec.get("created_at")
    j["attempt_before_receipt"] = {"status": HOLDS_BOUND if AB.when(x["at"]) <= AB.when(created) else NOT_HOLD,
                                   "what": f"the DPS attempt ({x['at']}) is dated no later than the receipt's created_at ({created})",
                                   "binding": "issuer's clock against the receipt store's clock; created_at is in metadata_hash"}
    j["result_after_receipt"] = {"status": HOLDS_BOUND if AB.when(res["at"]) >= AB.when(created) else NOT_HOLD,
                                 "what": f"the DPS result naming output_hash ({res['at']}) is dated no earlier than created_at",
                                 "binding": "a stage cannot name an output_hash before the receipt holding it was created"}
    shown_receipt = rec.get("id", "") in art["view"].decode("utf-8") or rec.get("output_hash", "") in art["view"].decode("utf-8")
    if shown_receipt and art["view"] and sha256(art["view"]) == v1.get("shown_view_digest"):
        j["review_after_receipt"] = {"status": HOLDS_BOUND if AB.when(v1["at"]) >= AB.when(created) else NOT_HOLD,
                                     "what": f"the review ({v1['at']}) was shown a view naming the receipt, so it is dated no earlier than created_at",
                                     "binding": "the view's digest is in the person's signed bytes; the receipt's id and created_at are in metadata_hash"}
    else:
        j["review_after_receipt"] = {"status": NA, "what": "the review was shown a view naming the receipt",
                                     "binding": "the view names no receipt"}
    # Order of approval and effect, as the clocks state it; never upgraded to "approved before"
    if AB.when(o1["at"]) > AB.when(created):
        rel = "approval_after_effect"
    elif j["review_after_receipt"]["status"] == NOT_HOLD:
        rel = "contradicted: the approval is dated before the effect, but its review was shown the receipt of that effect"
    else:
        rel = "issuer_dated_before_effect"
    order = {"relation": rel, "approval_at": o1["at"], "effect_at (receipt created_at)": created,
             "time_basis": "the issuer's stage times and the receipt store's created_at; no independent timestamp over "
                           "either, so an approval dated before the effect is the issuer's statement, never verified"}
    return j, order


def summarize(name, art, receipt_rep=None):
    r = {"variant": name}
    r["receipt"] = receipt_rep or receipt_report(art["receipt"])
    r["dps"] = dps_report(art)
    r["joins"], r["order"] = joins(art)
    return r


def flat(r):
    """One value per place a verdict can change, so that a failing case is located by what differs from its base."""
    f = {f"receipt.{k}": v["status"] for k, v in r["receipt"]["steps"].items()}
    f["receipt.independent_verifier_probe"] = r["receipt"]["independent_verifier_probe"]["verdict"]
    d = r["dps"]
    f["dps.schema"] = "errors" if any(d["schema_errors"].values()) else "valid"
    f.update({f"dps.{k}": v for k, v in d["action_binding"].items()})
    f["dps.issuer_seal"] = d["issuer_seal"]["status"]
    f["dps.person_approval"] = d["person_approval"]["status"]
    f.update({f"join.{k}": v["status"] for k, v in r["joins"].items()})
    f["order"] = r["order"]["relation"]
    return f


EXPECTED = {
    "after-the-fact": {"join.id_cited": HOLDS_BOUND, "join.output_hash_named": HOLDS_BOUND,
                       "join.executor_names_caller": HOLDS_BOUND, "join.request_id_committed": ABSENT,
                       "join.input_is_approved": HOLDS_UNBOUND, "join.pointer_to_record": ABSENT,
                       "join.attempt_before_receipt": HOLDS_BOUND, "join.result_after_receipt": HOLDS_BOUND,
                       "join.review_after_receipt": HOLDS_BOUND, "order": "approval_after_effect",
                       "dps.stage_order": "failed", "dps.authorisation_recheck": "failed"},
    "under-the-decision": {"join.id_cited": HOLDS_BOUND, "join.output_hash_named": HOLDS_BOUND,
                           "join.executor_names_caller": HOLDS_BOUND, "join.request_id_committed": HOLDS_BOUND,
                           "join.input_is_approved": HOLDS_BOUND, "join.pointer_to_record": HOLDS_UNBOUND,
                           "join.attempt_before_receipt": HOLDS_BOUND, "join.result_after_receipt": HOLDS_BOUND,
                           "join.review_after_receipt": NA, "order": "issuer_dated_before_effect",
                           "dps.stage_order": "verified", "dps.authorisation_recheck": "verified"},
}


def as_expected(name, r):
    f = flat(r)
    bad = {k: (f.get(k), v) for k, v in EXPECTED[name].items() if f.get(k) != v}
    rest = [k for k in f if k.startswith("dps.") and k not in EXPECTED[name] and f[k] not in ("verified", "valid")]
    receipt = receipt_ok(r["receipt"])
    if name == "under-the-decision":
        receipt = receipt and r["receipt"]["independent_verifier_as_is"]["verdict"] == "pass" \
            and r["receipt"]["steps"]["input_hash"]["status"] == "confirmed"
    return not bad and not rest and receipt, {"differs": bad, "dps_not_verified": rest, "receipt_ok": receipt}


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    (out / "decision-record.json").write_bytes(compact(art["record"]))
    (out / "action-binding-attachment.json").write_bytes(compact(art["attachment"]))
    (out / "signatures-attachment.json").write_bytes(compact(art["sig"]))
    (out / "review-view.txt").write_bytes(art["view"])
    if art["variant"] == "under-the-decision":
        (out / "aer1-receipt.SYNTHETIC.json").write_text(json.dumps(art["receipt"], ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    assert sha256(RECEIPT_RAW) == RECEIPT_FILE_SHA256, "receipt.json is not the bytes as served"
    out = HERE / "out"
    out.mkdir(exist_ok=True)
    (out / "trust-policy.json").write_bytes(compact(TRUST))
    (out / "policy.json").write_bytes(POLICY_BYTES)
    real = receipt_report(REAL)
    real["source"] = {"file": "receipt.json", "sha256": RECEIPT_FILE_SHA256, "bytes": len(RECEIPT_RAW),
                      "url": SOURCE_URL, "retrieved": RETRIEVED_AT}
    (out / "receipt-verification.json").write_text(json.dumps(real, ensure_ascii=False, indent=1) + "\n")
    summary, ok = {"receipt_file_sha256": RECEIPT_FILE_SHA256, "receipt_ok": receipt_ok(real)}, receipt_ok(real)
    for name in VARIANTS:
        art = build(name)
        write(out / name, art)
        r = summarize(name, art, real if name == "after-the-fact" else None)
        if name == "after-the-fact":
            r["receipt"] = "see receipt-verification.json"
        good, why = as_expected(name, {**r, "receipt": real if name == "after-the-fact" else r["receipt"]})
        r["as_expected"], r["expectation_check"] = good, why
        ok = ok and good
        summary[name] = r
    summary["as_expected"] = ok
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    sys.exit(0 if ok else 1)
