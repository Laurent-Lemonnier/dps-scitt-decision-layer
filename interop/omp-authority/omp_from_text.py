#!/usr/bin/env python3
"""An evaluator and a reader of Operating Model Protocol (OMP) records, written from the text alone:

  draft-veridom-omp-core-00   Invariant 3, Verifiable Delegation Binding: sections 3.3, 4, 5, 8, 9, Appendix A
  draft-veridom-omp-00        sections 5, 7, 8 and 11: the routing tree, the Audit Trace and its sealing, which
                              core-00 section 3 calls "unchanged from -00"

No code of the authors was read or run, and they had published no vector when this was written.

The text does not define everything a record needs. Each place where it leaves a choice is numbered in the
ambiguity log of README.md (A1, A2, ...) and named here beside the line that makes the choice. A check that rests on
one of these choices says so in its `basis` ("stand_in:A4"): it is this folder's reading, never the protocol's own.

evaluate()      Section 3.3, as an emitter runs it: the same inputs give the same result (Section 5, case 20).
check_trace()   what a third party holding the trace and the documents it names can check again.
"""
import base64
import hashlib
import json
import re
from datetime import date, datetime, timedelta, timezone

# ---------------------------------------------------------------- Appendix A of core-00, in its order

RESULTS = ("BOUND", "AUTHORITY_UNBOUND", "EXEMPT")
PERMISSIONS = ("ALLOWED", "BLOCKED")
ROUTING = ("AUTONOMOUS", "ASSISTED", "ESCALATED")
SELECTION_MODES = ("pre_registered", "policy_resolved", "manual_selected_at_decision", "post_hoc_attached")
ROOT_TYPES = ("statutory", "corporate_delegation", "professional_registration")
REVOCATION = ("ACTIVE", "SUSPENDED", "REVOKED", "UNKNOWN")
FAILURE_REASONS = (
    "NO_VALID_DELEGATION_INSTRUMENT", "OFFICER_ID_MISMATCH", "EFFECTIVE_DATE_FUTURE", "INSTRUMENT_EXPIRED",
    "INSTRUMENT_REVOKED", "INSTRUMENT_SUSPENDED", "REVOCATION_STATUS_UNKNOWN", "MANDATE_SCOPE_MISMATCH",
    "JURISDICTION_OUT_OF_SCOPE", "MONETARY_THRESHOLD_EXCEEDED", "INSTRUMENT_HASH_MISMATCH",
    "BINDING_TIMESTAMP_OUTSIDE_WINDOW", "REGISTRY_PROOF_MISSING", "POST_HOC_ATTACHMENT_DETECTED")
EXEMPTION_BASES = ("AUTONOMOUS_ROUTING_STATE", "WATCHTOWER_PROFILE_EXEMPT")

# The members of the DelegationInstrument, core-00 section 4.1. Every one is shown there; only the members of
# scope_constraints are called optional (4.4.3), and two are typed "... or null".
INSTRUMENT_MEMBERS = (
    "instrument_id", "officer_id", "role_identifier", "mandate_scope", "scope_constraints", "effective_date",
    "expiry_date", "revocation_status_at_decision", "issuing_authority_id", "authority_root_type", "instrument_hash",
    "instrument_reference", "instrument_selection_mode", "instrument_selected_at",
    "authority_registry_snapshot_hash", "registry_inclusion_proof", "binding_timestamp")
NULLABLE = ("expiry_date", "registry_inclusion_proof")
SCOPE_MEMBERS = ("decision_types", "jurisdictions", "product_scope", "risk_threshold", "monetary_limit")

# The Audit Trace of omp-00 section 7 ("Every field is mandatory unless explicitly marked OPTIONAL"; none is).
TRACE_MEMBERS_00 = (
    "trace_id", "trace_version", "created_at", "vertical", "deployment_id", "schema_version",
    "interaction_id", "interaction_received", "interaction_hash", "channel", "requester_id",
    "intent_class", "intent_confidence", "intent_top3", "classifier_version",
    "confidence_score", "confidence_components", "routing_threshold",
    "watchtowers_evaluated", "watchtower_override", "override_watchtower_id",
    "routing_path", "routing_rationale", "routing_decided_at",
    "autonomous_dispatch", "assisted_resolution", "escalation_record",
    "tst_time", "tst_tsa_identity", "tst_raw", "tst_serial", "tst_hash_alg", "tst_message_imprint", "tst_certificate",
    "source_state_hash", "trace_content_hash", "trace_chain_hash", "sealed_at", "seal_version")
# What core-00 section 4 adds beside them.
TRACE_MEMBERS_CORE = ("routing_state", "named_accountable_officer", "authority_binding")
# A9: the text names no member for the decision's type, jurisdiction, product and value, which Section 5 cases 11 to
# 13 compare with the instrument's scope. This folder carries them in one member of its own.
TRACE_MEMBERS_OURS = ("decision_context",)
# A8: omp-00 section 7 fixes schema_version to "VERIDOM-SCHEMA-001-v1.0" and says an implementation that extends the
# schema MUST use a distinct string; core-00 adds authority_binding and names no string. Ours, so nobody takes these
# records for the authors'.
SCHEMA_VERSION = "X-DSDL-OMP-CORE-00-FROM-TEXT-1"
SEAL_VERSION = "SHA256-RFC3161-CHAIN-v1"
# omp-00 section 8.2, the members left out of the content hash, as listed there...
SEAL_EXCLUDED_8_2 = ("trace_content_hash", "trace_chain_hash", "sealed_at", "seal_version", "tst_time",
                     "tst_tsa_identity", "tst_raw", "tst_serial", "tst_certificate")
# ...and A7: tst_message_imprint "must equal trace_content_hash" (section 7) and is not in that list, so the hash
# would cover its own value. It is left out too; tst_hash_alg, a constant, stays in as the text has it.
SEAL_EXCLUDED_OURS = ("tst_message_imprint",)

# A6, A10, A11: what the text leaves to "profiles" or does not state. No such profile exists for this domain; these
# are this folder's stand-ins, passed to every function so that a case can change them.
PROFILE = {
    "name": "stand-in for a profile that does not exist (EU insurance distribution, synthetic case)",
    "accepted_root_types": ["corporate_delegation", "professional_registration"],       # 4.4.2: "Each OMP profile specifies"
    "binding_window_seconds": 300,                # A6: Section 5 case 15 names a window and gives none
    "registry_inclusion_proof_required": False,   # 4.4.4 "Profiles MAY require"; Section 5 case 16 "when required"
    "post_hoc_result": "AUTHORITY_UNBOUND",       # 4.4.1 "Profiles MAY define"; the other value is not in Appendix A
}


class Unsupported(ValueError):
    pass


# ---------------------------------------------------------------- canonical JSON, hashes, times

def jcs(value):
    """RFC 8785 for the values these records hold. A12: omp-00 section 11 also asks for floating-point values
    "with minimum 15 significant digits", which RFC 8785 does not allow (it fixes the ECMAScript form); RFC 8785 is
    followed. A number that Python and ECMAScript would write differently is refused, not guessed."""
    return _jcs(value).encode("utf-8")


def _jcs(v):
    if isinstance(v, dict):
        return "{" + ",".join(_jcs(k) + ":" + _jcs(x)
                              for k, x in sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        if abs(v) >= 2 ** 53:
            raise Unsupported("an integer beyond 2^53 has no exact ECMAScript form")
        return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise Unsupported("a non-finite number")
        if v == int(v) and abs(v) < 1e21:
            return str(int(v))
        text = repr(v)
        if "e" in text or "E" in text:
            raise Unsupported(f"the number {text} needs an exponent, which this reader does not write")
        return text
    raise Unsupported(f"a value of type {type(v).__name__}")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def tagged(data):
    """core-00 writes its hashes "sha256:hexstring" (section 4.1). Lower case is this folder's (A2)."""
    return "sha256:" + sha256_hex(data)


TAGGED = re.compile(r"^sha256:[0-9a-f]{64}$")
BARE = re.compile(r"^[0-9a-f]{64}$")
INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def instant(text):
    if not isinstance(text, str) or not INSTANT.match(text):
        raise ValueError(f"not a UTC instant: {text!r}")
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def day(text):
    if not isinstance(text, str) or not DAY.match(text):
        raise ValueError(f"not a date: {text!r}")
    return date.fromisoformat(text)


def iso_ms(dt):
    """omp-00 section 11: UTC, ISO 8601, millisecond precision."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------- the hashes the text names

def instrument_hash(authority_document):
    """core-00 4.4.4: "SHA-256 of the canonical form of the authority document". A1: the text does not say what the
    canonical form of an authority document is (the author's mail of 2 November 2026: "Canonicalisation will be
    stated with the vectors"). Here the authority document is a JSON document and its canonical form is RFC 8785,
    the one canonicalisation the two drafts cite."""
    return tagged(jcs(authority_document))


def registry_snapshot_hash(snapshot):
    """core-00 4.4.4: "the hash of the registry state at decision time". A4: the registry, its state and the hash
    over it are not defined. Here a state is one JSON document (see build.registry_state) and its hash is SHA-256
    over RFC 8785."""
    return tagged(jcs(snapshot))


def binding_subject(authority_binding):
    """A5: what binding_timestamp ("RFC 3161 token reference") is a token over, and what a reference is, are not
    stated. The member sits inside the object the trace's own token covers, so it cannot name that token (its serial
    number and bytes exist only once the trace is hashed). Here it is a second token, asked for when the binding is
    evaluated, over the RFC 8785 bytes of the authority_binding object without its binding_timestamp member; the
    member carries "sha256:" + the SHA-256 of the token's DER bytes, and the token is kept beside the trace."""
    ab = json.loads(json.dumps(authority_binding))
    ab.pop("binding_timestamp", None)
    if isinstance(ab.get("delegation_instrument"), dict):
        ab["delegation_instrument"].pop("binding_timestamp", None)
    return jcs(ab)


def trace_content_hash(trace):
    """omp-00 8.2, with A7. A2: the output is written as bare lower-case hex in the -00 members (section 7 types them
    "sha256") and "sha256:" + hex in the core-00 members (section 4.1)."""
    return sha256_hex(trace_content_bytes(trace))


def trace_content_bytes(trace):
    """The bytes omp-00 8.2 hashes, and 8.3 has time-stamped: the token's imprint is their SHA-256."""
    left_out = SEAL_EXCLUDED_8_2 + SEAL_EXCLUDED_OURS
    return jcs({k: v for k, v in trace.items() if k not in left_out})


def genesis_hash(deployment_id):
    """omp-00 8.4: previous_H_c = SHA256('VERIDOM-GENESIS-' + deployment_id)."""
    return sha256_hex(("VERIDOM-GENESIS-" + deployment_id).encode("utf-8"))


def chain_hash(content_hash, previous):
    """omp-00 8.4: H_c = SHA256(trace_content_hash + '|' + previous_H_c). A2: the two are joined as their hex text."""
    return sha256_hex((content_hash + "|" + previous).encode("ascii"))


# ---------------------------------------------------------------- RFC 3161 tokens

def read_tst(raw, pinned_cert_der):
    """Reads a TimeStampToken and verifies it with the one certificate the verifier pins: SignedData over a TSTInfo,
    one signer, the message-digest attribute over the TSTInfo, an ECDSA P-256 / SHA-256 signature over the signed
    attributes. Returns the imprint, the genTime, the serial number and the signer's name; raises ValueError."""
    from asn1crypto import cms, tsp
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    info = cms.ContentInfo.load(raw, strict=True)
    if info["content_type"].native != "signed_data":
        raise ValueError("not CMS SignedData")
    sd = info["content"]
    encap = sd["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise ValueError("the content is not a TSTInfo")
    if len(sd["signer_infos"]) != 1:
        raise ValueError("a time-stamp token has exactly one signer")
    econtent = encap["content"].contents
    tst = tsp.TSTInfo.load(econtent, strict=True)
    signer = sd["signer_infos"][0]
    attrs = signer["signed_attrs"]
    digest = next((a["values"][0].native for a in attrs if a["type"].native == "message_digest"), None)
    if digest != hashlib.sha256(econtent).digest():
        raise ValueError("the message-digest attribute is not the digest of the TSTInfo")
    if tst["message_imprint"]["hash_algorithm"]["algorithm"].native != "sha256":
        raise ValueError("the message imprint is not SHA-256")
    cert = x509.load_der_x509_certificate(pinned_cert_der)
    if not any(c.chosen.dump() == pinned_cert_der for c in (sd["certificates"] or [])):
        raise ValueError("the token does not carry the pinned certificate")
    try:
        cert.public_key().verify(signer["signature"].native, b"\x31" + attrs.dump()[1:], ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("the signature does not verify with the pinned certificate")
    if not tst["gen_time"].contents.endswith(b"Z"):
        raise ValueError("the genTime is not in UTC")
    return {"imprint_hex": tst["message_imprint"]["hashed_message"].native.hex(),
            "gen_time": tst["gen_time"].native, "serial": str(tst["serial_number"].native),
            "tsa": cert.subject.rfc4514_string()}


# ---------------------------------------------------------------- Section 3.3: the evaluation

def evaluate(routing_state, officer_id, instrument, decision, decision_time, *, authority_document=None,
             registry_snapshot=None, binding_time=None, profile=PROFILE, watchtower_exempt=False):
    """Invariant 3 for one routing state. Returns {"authority_binding_result", "execution_permission",
    "failure_reasons" (Appendix A order), "review_flag", "notes"}.

    routing_state      AUTONOMOUS, ASSISTED or ESCALATED
    officer_id         the Named Accountable Officer of the trace
    instrument         the candidate DelegationInstrument (the members of section 4.1), or None
    decision           {"decision_type", "jurisdiction", "product", "amount": {"currency", "value"} or None}   (A9)
    decision_time      A3: the "decision timestamp" of Section 5 cases 6 and 7 is read as routing_decided_at,
                       "the moment of the routing state" of section 3.3
    authority_document the document the instrument hashes, when held
    registry_snapshot  the registry state at decision time, when held (A4)
    binding_time       the genTime of the binding token, when held (A5)
    """
    out = {"authority_binding_result": None, "execution_permission": None, "failure_reasons": [],
           "review_flag": False, "notes": []}
    if routing_state == "AUTONOMOUS" or watchtower_exempt:
        out.update(authority_binding_result="EXEMPT", execution_permission="ALLOWED",
                   exemption_basis="AUTONOMOUS_ROUTING_STATE" if routing_state == "AUTONOMOUS"
                   else "WATCHTOWER_PROFILE_EXEMPT")
        return out
    found = set()
    if instrument is None:
        found.add("NO_VALID_DELEGATION_INSTRUMENT")                               # Section 5 case 4
    else:
        i = instrument
        if i.get("officer_id") != officer_id:
            found.add("OFFICER_ID_MISMATCH")                                      # case 5
        # A3: effective_date and expiry_date are dates, the decision timestamp an instant; they are compared as UTC
        # calendar days, the instrument being operative on both its first and its last day.
        d = decision_time.astimezone(timezone.utc).date()
        if day(i["effective_date"]) > d:
            found.add("EFFECTIVE_DATE_FUTURE")                                    # case 6
        if i.get("expiry_date") is not None and day(i["expiry_date"]) < d:
            found.add("INSTRUMENT_EXPIRED")                                       # case 7
        # The registry's word on the instrument's state, where a snapshot is held, else the instrument's own member.
        entry = None
        if registry_snapshot is not None:
            entry = next((e for e in registry_snapshot.get("entries", [])
                          if e.get("instrument_id") == i.get("instrument_id")
                          and e.get("instrument_hash") == i.get("instrument_hash")), None)
        status = entry["status"] if entry else i.get("revocation_status_at_decision")
        if entry and entry["status"] != i.get("revocation_status_at_decision"):
            out["notes"].append(f"the registry state says {entry['status']}, the instrument member "
                                f"{i.get('revocation_status_at_decision')}: the registry state is followed")
        if status == "REVOKED":
            found.add("INSTRUMENT_REVOKED")                                       # case 8
        elif status == "SUSPENDED":
            found.add("INSTRUMENT_SUSPENDED")                                     # case 9
        elif status != "ACTIVE":
            found.add("REVOCATION_STATUS_UNKNOWN")                                # case 10
        sc = i.get("scope_constraints") or {}
        if "decision_types" in sc and decision.get("decision_type") not in sc["decision_types"]:
            found.add("MANDATE_SCOPE_MISMATCH")                                   # case 11
        # A10: product_scope has no case and no reason of its own; 4.4.3 says a decision outside the declared
        # scope_constraints MUST produce MANDATE_SCOPE_MISMATCH.
        if "product_scope" in sc and decision.get("product") not in sc["product_scope"]:
            found.add("MANDATE_SCOPE_MISMATCH")
        if "jurisdictions" in sc and decision.get("jurisdiction") not in sc["jurisdictions"]:
            found.add("JURISDICTION_OUT_OF_SCOPE")                                # case 12
        if "monetary_limit" in sc and decision.get("amount") is not None:
            limit, amount = sc["monetary_limit"], decision["amount"]
            if amount.get("currency") != limit.get("currency"):
                found.add("MANDATE_SCOPE_MISMATCH")                               # A10: another currency, no rule
                out["notes"].append("the decision's amount is in another currency than the limit")
            elif amount["value"] > limit["max_amount"]:
                found.add("MONETARY_THRESHOLD_EXCEEDED")                          # case 13
        if "risk_threshold" in sc:
            out["notes"].append("risk_threshold is a string with no comparison defined (A10): not evaluated")
        if authority_document is not None and instrument_hash(authority_document) != i.get("instrument_hash"):
            found.add("INSTRUMENT_HASH_MISMATCH")                                 # case 14
        window = profile.get("binding_window_seconds")
        late = lambda t: window is not None and not (timedelta(0) <= t - decision_time <= timedelta(seconds=window))
        if binding_time is not None and late(binding_time):
            found.add("BINDING_TIMESTAMP_OUTSIDE_WINDOW")                         # case 15, window per A6
        if profile.get("registry_inclusion_proof_required") and i.get("registry_inclusion_proof") is None:
            found.add("REGISTRY_PROOF_MISSING")                                   # case 16
        # A11: a BOUND record "requires authority_registry_snapshot_hash" (the author, 2 November 2026; section 4.1
        # shows the member in every BOUND record, 4.4.1 defines it under pre_registered only). No reason is named
        # for its absence; REGISTRY_PROOF_MISSING is the nearest.
        if not i.get("authority_registry_snapshot_hash"):
            found.add("REGISTRY_PROOF_MISSING")
        mode = i.get("instrument_selection_mode")
        if mode == "post_hoc_attached":
            found.add("POST_HOC_ATTACHMENT_DETECTED")                             # case 17, result per the profile
            out["review_flag"] = True
        else:
            # Section 9: a post-hoc attachment written as another mode is "detectable through the binding_timestamp
            # and authority_registry_snapshot_hash fields". How is not said (A13). Here: the instrument is not in the
            # registry state at decision time, or was registered or selected after the decision.
            hoc = []
            if registry_snapshot is not None and mode == "pre_registered":
                if entry is None:
                    hoc.append("the registry state at decision time does not list the instrument")
                elif instant(entry["registered_at"]) > decision_time:
                    hoc.append("the registry state dates its registration after the decision")
            if i.get("instrument_selected_at") and late(instant(i["instrument_selected_at"])):
                hoc.append("instrument_selected_at is outside the binding window around the decision")
            if hoc:
                found.add("POST_HOC_ATTACHMENT_DETECTED")
                out["review_flag"] = True
                out["notes"] += hoc
        if i.get("authority_root_type") not in profile.get("accepted_root_types", ROOT_TYPES):
            # 4.4.2: "Each OMP profile specifies which root types are acceptable"; no reason is named (A10).
            found.add("NO_VALID_DELEGATION_INSTRUMENT")
            out["notes"].append("the root type is not one the profile accepts")
    out["failure_reasons"] = [r for r in FAILURE_REASONS if r in found]
    if found:
        out.update(authority_binding_result="AUTHORITY_UNBOUND", execution_permission="BLOCKED")
    else:
        out.update(authority_binding_result="BOUND", execution_permission="ALLOWED")
    return out


def authority_binding_object(evaluation, instrument, officer_id):
    """The authority_binding member in the shape of section 4.1, 4.2 or 4.3, without its binding_timestamp.
    A14: section 4.2 shows neither the instrument that was tried nor the officer named; this folder emits exactly the
    members shown, so an AUTHORITY_UNBOUND record does not say which instrument failed."""
    r = evaluation["authority_binding_result"]
    if r == "EXEMPT":
        return {"authority_binding_result": r, "execution_permission": "ALLOWED",
                "exemption_basis": evaluation["exemption_basis"]}
    if r == "BOUND":
        return {"authority_binding_result": r, "execution_permission": "ALLOWED",
                "delegation_instrument": dict(instrument)}
    return {"authority_binding_result": r, "execution_permission": "BLOCKED",
            "failure_reasons": list(evaluation["failure_reasons"]), "attempted_officer_id": officer_id}


def set_binding_timestamp(authority_binding, reference):
    if authority_binding["authority_binding_result"] == "BOUND":
        authority_binding["delegation_instrument"]["binding_timestamp"] = reference
    elif authority_binding["authority_binding_result"] == "AUTHORITY_UNBOUND":
        authority_binding["binding_timestamp"] = reference
    return authority_binding


def get_binding_timestamp(authority_binding):
    if authority_binding.get("authority_binding_result") == "BOUND":
        return (authority_binding.get("delegation_instrument") or {}).get("binding_timestamp")
    return authority_binding.get("binding_timestamp")


# ---------------------------------------------------------------- omp-00 section 5.1: the routing tree

def route(trace):
    """omp-00 5.1 and 5.2, from the trace's own members; the threshold is the one the trace states."""
    c = trace["confidence_components"]
    w = c["weights"]
    score = 0.0 if c["C_p"] == 0.0 else w["C_m"] * c["C_m"] + w["C_p"] * c["C_p"] + w["C_d"] * c["C_d"]
    assisted = False
    for wt in trace["watchtowers_evaluated"]:
        if wt["triggered"] is True:
            if wt["severity"] == "HARD_BLOCK":
                return "ESCALATED", score
            if wt["severity"] == "FORCE_ASSISTED":
                assisted = True
    if trace["intent_confidence"] < 0.60:
        return "ESCALATED", score
    if assisted:
        return "ASSISTED", score
    if score >= trace["routing_threshold"]:
        return "AUTONOMOUS", score
    if score >= 0.50:
        return "ASSISTED", score
    return "ESCALATED", score


# ---------------------------------------------------------------- the shape of a record

def schema_findings(trace):
    """What Section 5 case 18 calls schema validation: members present, enumerations as Appendix A, formats as
    section 4.1 writes them. The authors publish no schema for core-00 that was read here."""
    bad = []
    for m in TRACE_MEMBERS_00 + TRACE_MEMBERS_CORE:
        if m not in trace:
            if m == "named_accountable_officer" and (trace.get("authority_binding") or {}).get(
                    "authority_binding_result") != "BOUND":
                continue                                    # sections 4.2 and 4.3 do not show it
            bad.append(f"member {m} is absent")
    unknown = [m for m in trace if m not in TRACE_MEMBERS_00 + TRACE_MEMBERS_CORE + TRACE_MEMBERS_OURS]
    if unknown:
        bad.append(f"members the texts do not name: {', '.join(sorted(unknown))}")
    if bad:
        return bad
    if trace["routing_state"] not in ROUTING:
        bad.append(f"routing_state {trace['routing_state']!r} is not in the enumeration")
    if trace["routing_state"] != trace["routing_path"]:
        bad.append("routing_state (core-00) and routing_path (omp-00) differ")              # A8
    if trace["seal_version"] != SEAL_VERSION:
        bad.append("seal_version is not SHA256-RFC3161-CHAIN-v1")
    for m in ("created_at", "interaction_received", "routing_decided_at", "tst_time", "sealed_at"):
        if not (isinstance(trace[m], str) and INSTANT.match(trace[m])):
            bad.append(f"{m} is not a UTC instant")
    for m in ("interaction_hash", "trace_content_hash", "trace_chain_hash", "tst_message_imprint"):
        if not (isinstance(trace[m], str) and BARE.match(trace[m])):
            bad.append(f"{m} is not 64 lower-case hex characters")
    ab = trace["authority_binding"]
    if not isinstance(ab, dict):
        return bad + ["authority_binding is not an object"]
    r = ab.get("authority_binding_result")
    if r not in RESULTS:
        return bad + [f"authority_binding_result {r!r} is not in the enumeration"]
    if ab.get("execution_permission") not in PERMISSIONS:
        bad.append(f"execution_permission {ab.get('execution_permission')!r} is not in the enumeration")
    shapes = {"BOUND": ("authority_binding_result", "execution_permission", "delegation_instrument"),
              "AUTHORITY_UNBOUND": ("authority_binding_result", "execution_permission", "failure_reasons",
                                    "attempted_officer_id", "binding_timestamp"),
              "EXEMPT": ("authority_binding_result", "execution_permission", "exemption_basis")}
    for m in shapes[r]:
        if m not in ab:
            bad.append(f"authority_binding.{m} is absent")
    extra = [m for m in ab if m not in shapes[r]]
    if extra:
        bad.append(f"authority_binding carries members section 4 does not show for {r}: {', '.join(sorted(extra))}")
    if r == "EXEMPT" and ab.get("exemption_basis") not in EXEMPTION_BASES:
        bad.append("exemption_basis is not in the enumeration")
    if r == "AUTHORITY_UNBOUND":
        fr = ab.get("failure_reasons")
        if not isinstance(fr, list) or not fr:
            bad.append("failure_reasons is not a list of one or more")
        else:
            bad += [f"failure reason {x!r} is not in the enumeration" for x in fr if x not in FAILURE_REASONS]
        if not (ab.get("attempted_officer_id") is None or isinstance(ab.get("attempted_officer_id"), str)):
            bad.append("attempted_officer_id is neither a string nor null")
        if not (isinstance(ab.get("binding_timestamp"), str) and TAGGED.match(ab["binding_timestamp"])):
            bad.append("binding_timestamp is not a token reference in this folder's form (A5)")
    if r == "BOUND":
        o = trace.get("named_accountable_officer")
        if not (isinstance(o, dict) and isinstance(o.get("officer_id"), str) and isinstance(o.get("role"), str)):
            bad.append("named_accountable_officer does not carry officer_id and role")
        i = ab.get("delegation_instrument")
        if not isinstance(i, dict):
            return bad + ["delegation_instrument is not an object"]
        for m in INSTRUMENT_MEMBERS:
            if m not in i:
                bad.append(f"delegation_instrument.{m} is absent")
            elif i[m] is None and m not in NULLABLE:
                bad.append(f"delegation_instrument.{m} is null")
        extra = [m for m in i if m not in INSTRUMENT_MEMBERS]
        if extra:
            bad.append(f"delegation_instrument carries members section 4.1 does not show: {', '.join(sorted(extra))}")
        enums = (("revocation_status_at_decision", REVOCATION), ("authority_root_type", ROOT_TYPES),
                 ("instrument_selection_mode", SELECTION_MODES))
        for m, allowed in enums:
            if m in i and i[m] not in allowed:
                bad.append(f"delegation_instrument.{m} {i[m]!r} is not in the enumeration")
        for m in ("instrument_hash", "authority_registry_snapshot_hash", "binding_timestamp"):
            if i.get(m) is not None and not (isinstance(i[m], str) and TAGGED.match(i[m])):
                bad.append(f"delegation_instrument.{m} is not sha256: and 64 lower-case hex characters")
        for m in ("effective_date", "expiry_date"):
            if i.get(m) is not None and not (isinstance(i[m], str) and DAY.match(i[m])):
                bad.append(f"delegation_instrument.{m} is not a date")
        if i.get("instrument_selected_at") is not None and not (
                isinstance(i["instrument_selected_at"], str) and INSTANT.match(i["instrument_selected_at"])):
            bad.append("delegation_instrument.instrument_selected_at is not a UTC instant")
        sc = i.get("scope_constraints")
        if not isinstance(sc, dict):
            bad.append("scope_constraints is not an object (4.4.3: REQUIRED when the result is BOUND)")
        else:
            bad += [f"scope_constraints.{m} is not a member section 4.1 shows" for m in sc if m not in SCOPE_MEMBERS]
            if any(not re.match(r"^[A-Z]{2}$", str(j)) for j in sc.get("jurisdictions", [])):
                bad.append("scope_constraints.jurisdictions holds a value that is not two capital letters")
            ml = sc.get("monetary_limit")
            if ml is not None and not (isinstance(ml, dict) and re.match(r"^[A-Z]{3}$", str(ml.get("currency")))
                                       and isinstance(ml.get("max_amount"), (int, float))
                                       and not isinstance(ml.get("max_amount"), bool)):
                bad.append("scope_constraints.monetary_limit is not a currency of three capital letters and a number")
    return bad


# ---------------------------------------------------------------- the reader

def _c(status, detail, basis="text"):
    return {"status": status, "detail": detail, "basis": basis}


def check_trace(trace, held=None, profile=PROFILE):
    """Checks one Audit Trace again. held: what the verifier has beside it:
        tsa_cert_der              the one TSA certificate it pins
        binding_token             the DER bytes of the token binding_timestamp names (A5)
        authority_document        the document instrument_hash names (A1)
        registry_snapshot         the registry state authority_registry_snapshot_hash names (A4)
        previous_chain_hash       the chain hash of the trace before this one; None for the first of a deployment
        candidate_instrument      for an AUTHORITY_UNBOUND trace only: the instrument the emitter says it tried, which
                                  the trace itself does not carry (A14)
    Returns {"checks": {name: {status, detail, basis}}, "invariant3": {...}, "verdict": text}. A check is verified,
    failed or not_checked; nothing not checked is ever reported verified."""
    held = held or {}
    checks = {}
    inv = {"stated": None, "recomputed": None, "review_flag": False, "notes": []}
    out = {"checks": checks, "invariant3": inv, "verdict": None}
    bad = schema_findings(trace)
    checks["schema"] = _c("failed", "; ".join(bad)) if bad else _c(
        "verified", "the members of omp-00 section 7 and core-00 section 4, enumerations as Appendix A",
        "text, with A5, A8, A9")
    # A record whose only defects are members missing from the instrument is still evaluated, so that the report
    # says what Invariant 3 gives for it; any other defect stops the reading here.
    if [b for b in bad if not (b.startswith("delegation_instrument.") and b.endswith((" is absent", " is null")))]:
        out["verdict"] = "refused: " + bad[0] + " (Section 5 case 18: such a record is not emitted)"
        return out
    ab = trace["authority_binding"]
    stated = {"authority_binding_result": ab["authority_binding_result"],
              "execution_permission": ab["execution_permission"],
              "failure_reasons": list(ab.get("failure_reasons", []))}
    inv["stated"] = stated

    # ---- Invariant 1 (omp-00 5.1): the routing the trace states is the one its own members give
    got, score = route(trace)
    ok = got == trace["routing_path"] and abs(score - trace["confidence_score"]) < 1e-9
    checks["routing"] = _c("verified" if ok else "failed",
                           f"the tree of omp-00 5.1 gives {got}, confidence {score:.6f}; the trace states "
                           f"{trace['routing_path']}, {trace['confidence_score']}")

    # ---- Invariant 2 (omp-00 section 8)
    content = trace_content_hash(trace)
    checks["seal.content_hash"] = _c("verified" if content == trace["trace_content_hash"] else "failed",
                                     f"recomputed {content[:16]}…, stated {trace['trace_content_hash'][:16]}…",
                                     "text, with A2, A7, A12")
    previous = held.get("previous_chain_hash") or genesis_hash(trace["deployment_id"])
    chain = chain_hash(trace["trace_content_hash"], previous)
    checks["seal.chain"] = _c("verified" if chain == trace["trace_chain_hash"] else "failed",
                              "the chain hash over the stated content hash and "
                              + ("the previous trace's" if held.get("previous_chain_hash") else "the genesis value"),
                              "text, with A2")
    tsa = held.get("tsa_cert_der")
    seal_time = None
    if tsa is None:
        checks["seal.tst"] = _c("not_checked", "no time-stamping certificate is pinned")
    else:
        try:
            t = read_tst(base64.b64decode(trace["tst_raw"], validate=True), tsa)
            problems = []
            if t["imprint_hex"] != trace["trace_content_hash"]:
                problems.append("the token's imprint is not trace_content_hash")
            if trace["tst_message_imprint"] != trace["trace_content_hash"]:
                problems.append("tst_message_imprint is not trace_content_hash")
            if instant(trace["tst_time"]) != t["gen_time"]:
                problems.append("tst_time is not the token's genTime")
            if trace["tst_serial"] != t["serial"]:
                problems.append("tst_serial is not the token's")
            if trace["tst_hash_alg"] != "SHA-256":
                problems.append("tst_hash_alg is not SHA-256")
            seal_time = t["gen_time"]
            checks["seal.tst"] = _c("failed" if problems else "verified",
                                    "; ".join(problems) or f"token of {t['tsa']}, genTime {iso_ms(t['gen_time'])}, "
                                    "over trace_content_hash", "text; the certificate pinned is the verifier's choice")
        except (ValueError, TypeError) as e:
            checks["seal.tst"] = _c("failed", f"the token is not read: {e}")
    out["seal_time"] = iso_ms(seal_time) if seal_time else None

    # ---- the three axes (core-00 3.3)
    r, perm, rs = ab["authority_binding_result"], ab["execution_permission"], trace["routing_state"]
    axes = []
    if r == "BOUND" and (perm != "ALLOWED" or rs == "AUTONOMOUS"):
        axes.append("BOUND goes with ALLOWED and an ASSISTED or ESCALATED routing state")
    if r == "AUTHORITY_UNBOUND" and (perm != "BLOCKED" or rs == "AUTONOMOUS"):
        axes.append("AUTHORITY_UNBOUND goes with BLOCKED and an ASSISTED or ESCALATED routing state")
    if r == "EXEMPT" and (perm != "ALLOWED" or (rs != "AUTONOMOUS" and ab["exemption_basis"] != "WATCHTOWER_PROFILE_EXEMPT")
                          or (rs == "AUTONOMOUS" and ab["exemption_basis"] != "AUTONOMOUS_ROUTING_STATE")):
        axes.append("EXEMPT goes with ALLOWED and an AUTONOMOUS routing state or a Watchtower exemption")
    if rs != "AUTONOMOUS" and r == "EXEMPT" and ab["exemption_basis"] == "AUTONOMOUS_ROUTING_STATE":
        axes.append("an ASSISTED or ESCALATED routing state MUST evaluate Invariant 3")
    checks["axes"] = _c("failed" if axes else "verified", "; ".join(axes) or
                        f"{rs}, {r}, {perm}: consistent with section 3.3")
    if r == "EXEMPT":
        inv["recomputed"] = {"authority_binding_result": "EXEMPT", "execution_permission": "ALLOWED", "failure_reasons": []}
        out["verdict"] = _verdict(checks, "EXEMPT: no binding is evaluated for this routing state")
        return out

    # ---- the binding token (A5)
    ref, token, binding_time = get_binding_timestamp(ab), held.get("binding_token"), None
    if token is None or tsa is None:
        checks["binding_timestamp"] = _c("not_checked", "the token the member names is not held, or no certificate "
                                         "is pinned", "stand_in:A5")
    else:
        try:
            t = read_tst(token, tsa)
            problems = []
            if tagged(token) != ref:
                problems.append("the token held is not the one binding_timestamp names")
            if t["imprint_hex"] != sha256_hex(binding_subject(ab)):
                problems.append("the token is not over this authority_binding object")
            binding_time = t["gen_time"]
            checks["binding_timestamp"] = _c("failed" if problems else "verified", "; ".join(problems) or
                                             f"token of {t['tsa']}, genTime {iso_ms(t['gen_time'])}, over the "
                                             "authority_binding object without this member", "stand_in:A5")
        except (ValueError, TypeError) as e:
            checks["binding_timestamp"] = _c("failed", f"the token is not read: {e}", "stand_in:A5")
    out["binding_time"] = iso_ms(binding_time) if binding_time else None

    # ---- the instrument and the documents it names
    # For an AUTHORITY_UNBOUND record the instrument is not in the trace (A14): what is found about the one held
    # beside it is reported under "candidate." and is not a defect of the record; it is why the binding failed.
    instrument = ab.get("delegation_instrument") if r == "BOUND" else held.get("candidate_instrument")
    doc, snap = held.get("authority_document"), held.get("registry_snapshot")
    ih, rs_ = ("instrument_hash", "registry_snapshot") if r == "BOUND" else \
        ("candidate.instrument_hash", "candidate.registry_snapshot")
    if instrument is None:
        checks[ih] = _c("not_checked", "an AUTHORITY_UNBOUND record carries no instrument (section 4.2) and none is "
                        "held beside it", "text (A14)")
        checks[rs_] = _c("not_checked", "no instrument, so no registry state is named", "text (A14)")
    else:
        if doc is None:
            checks[ih] = _c("not_checked", "the authority document is not held", "stand_in:A1")
        else:
            same = instrument_hash(doc) == instrument.get("instrument_hash")
            checks[ih] = _c("verified" if same else "failed",
                                           "the document held hashes to instrument_hash" if same else
                                           f"the document held hashes to {instrument_hash(doc)[:23]}…, the instrument "
                                           f"names {str(instrument.get('instrument_hash'))[:23]}…", "stand_in:A1")
        named = instrument.get("authority_registry_snapshot_hash")
        if not named:
            checks[rs_] = _c("failed", "the instrument names no authority_registry_snapshot_hash", "text (A11)")
            snap = None
        elif snap is None:
            checks[rs_] = _c("not_checked", "the registry state is not held", "stand_in:A4")
        elif registry_snapshot_hash(snap) != named:
            checks[rs_] = _c("failed", "the registry state held is not the one the instrument names", "stand_in:A4")
            snap = None
        else:
            checks[rs_] = _c("verified", "the registry state held hashes to authority_registry_snapshot_hash",
                             "stand_in:A4")

    # ---- Invariant 3 again, from the trace and what is held
    if instrument is None and r == "AUTHORITY_UNBOUND" and "NO_VALID_DELEGATION_INSTRUMENT" not in stated["failure_reasons"]:
        checks["invariant3"] = _c("not_checked", "the reasons are the emitter's sealed statement: the record does "
                                  "not carry what was evaluated (A14)", "text (A14)")
    else:
        officer = (trace.get("named_accountable_officer") or {}).get("officer_id") if r == "BOUND" \
            else ab.get("attempted_officer_id")
        try:
            again = evaluate(rs, officer, instrument, trace.get("decision_context") or {},
                             instant(trace["routing_decided_at"]), authority_document=doc, registry_snapshot=snap,
                             binding_time=binding_time, profile=profile)
        except (ValueError, KeyError, TypeError) as e:
            checks["invariant3"] = _c("failed", f"the evaluation cannot be run on this record: {e}")
            out["verdict"] = _verdict(checks, None)
            return out
        inv["recomputed"] = {k: again[k] for k in ("authority_binding_result", "execution_permission", "failure_reasons")}
        inv["review_flag"], inv["notes"] = again["review_flag"], again["notes"]
        same = (again["authority_binding_result"] == r and again["execution_permission"] == perm
                and (r == "BOUND" or set(again["failure_reasons"]) == set(stated["failure_reasons"])))
        detail = (f"evaluated again: {again['authority_binding_result']}, {again['execution_permission']}"
                  + (f" ({', '.join(again['failure_reasons'])})" if again["failure_reasons"] else "")
                  + f"; stated: {r}, {perm}"
                  + (f" ({', '.join(stated['failure_reasons'])})" if stated["failure_reasons"] else ""))
        checks["invariant3"] = _c("verified" if same else "failed", detail, "text, with A3, A6, A9, A10, A11, A13")
    if r == "BOUND":
        o = trace["named_accountable_officer"]["officer_id"]
        res = trace.get("assisted_resolution") or {}
        if rs == "ASSISTED" and res.get("officer_id") not in (None, o):
            checks["officer"] = _c("failed", "the officer of the resolution is not the Named Accountable Officer",
                                   "stand_in:A15")
    lead = {"BOUND": "BOUND", "AUTHORITY_UNBOUND": "AUTHORITY_UNBOUND, sealed"}[r]
    out["verdict"] = _verdict(checks, lead)
    return out


def _verdict(checks, lead):
    failed = [k for k, v in checks.items() if v["status"] == "failed" and not k.startswith("candidate.")]
    open_ = [k for k, v in checks.items() if v["status"] == "not_checked"]
    if failed:
        return "refused: " + ", ".join(failed) + " failed"
    return (lead or "read") + ("; not checked: " + ", ".join(open_) if open_ else
                               "; every check made, those on a stand-in named as such")
