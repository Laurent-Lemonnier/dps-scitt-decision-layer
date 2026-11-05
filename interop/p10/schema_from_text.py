"""StatementPayloadSchemaV0 r9 (frozen/StatementPayloadSchemaV0_r9.md), read from the text for the second pass of the
P10 S2b outside reading: the decode pipeline of section 9 (stages 0 to 3), the Statement rules of sections 3 to 7, the
five predicates of section 8 (8.1 to 8.6, with the local checks of 8.7) and the projection into the ratified S2a
`Payload` as section 8 and the prereg's section 15.2 name it. Nothing after S2a ACCEPT (8.8 to 8.11) is implemented:
S2b does not run it.

Only the standard library. JSON is parsed by the standard `json` module with hooks that refuse duplicate member names,
numbers and the non-JSON constants; RFC 8785 (JCS) serialization is written here from the RFC, for the value types a
P10 Statement may hold (objects, arrays, strings, true, false: section 5 allows no JSON numbers and no null)."""
import hashlib
import json
import pathlib
import re

KIND_BY_URI = {
    "https://volmax-studio.rs/p10/predicate/profile-commitment/v0.1": "profileCommit",
    "https://volmax-studio.rs/p10/predicate/instance-commitment/v0.1": "instanceCommit",
    "https://volmax-studio.rs/p10/predicate/evidence-admission/v0.1": "admission",
    "https://volmax-studio.rs/p10/predicate/closure/v0.1": "closure",
    "https://volmax-studio.rs/p10/predicate/adjudication/v0.1": "adjudication",
}
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CONTENT_TYPE = "application/vnd.in-toto+json"
HASH_ENVELOPE_LABELS = (258, 259, 260)
# Section 6.5 and stage 0: a protected crit may list only parameters S2b understands. The text names no list; this
# reading takes the protected labels S2b processes: alg (1), content_type (3) and CWT Claims (15). See READINGS.
UNDERSTOOD_CRIT = {1, 3, 15}

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REF = re.compile(r"(?:0|[1-9][0-9]*)\Z")
REQUEST_ID = re.compile(r"(?:[0-9a-f]{2})*\Z")
U64_MAX = 2 ** 64 - 1

READINGS = [
    ("schema r9 section 9 stage 0, protected crit", "the text requires that a protected crit list only understood "
     "parameters but does not list them; this reading understands alg (1), content_type (3) and CWT Claims (15), the "
     "protected labels S2b processes, and reads a crit that is not a non-empty array of integers or text strings as a "
     "stage-0 failure. SPS-19-crit-ok lists 1, SPS-19-crit-unknown lists 99; understanding alg alone gives the same "
     "results, so the vectors do not separate the two lists"),
    ("schema r9 section 9, stage 0 on which rows", "stage 0 (conformant COSE_Sign1, crit, labels 258/259/260) is "
     "applied to every row, subject or not, since the table says only stages 1 to 3 are limited to subject entries; "
     "no vector has a non-subject row that fails stage 0 alone, so the vectors do not separate this from the "
     "subject-only reading"),
    ("schema r9 sections 4 and 5, null and numbers", "'null is forbidden anywhere in a P10 Statement' and 'no JSON "
     "numbers anywhere' are read as whole-Statement rules of stage 1 (row unavailable), also when the null or number "
     "sits inside the predicate, not as stage-2 predicate rules (payload = none); SPS-6-number (a number inside "
     "ordered_admission_refs) expects the row unavailable"),
    ("schema r9 section 8.7 with prereg section 6.2.7, order inside a subject entry", "stage 0, payload bytes, stage "
     "1, then the signature observation, then stages 2 and 3 (the order of section 8.7's list); so a subject row that "
     "fails stage 1 has no observation and its key is not used (no KeyMaterialFingerprintMismatch from it). Prereg "
     "6.2.7 says the bytes feed schema decoding 'after signature processing'; no vector separates the two orders"),
    ("schema r9 sections 8.2, 8.4, 8.5, the predicate's instance_subject", "checked against the CWT sub before S2a "
     "only for instance-commitment (section 8.2 says so); for closure the text states no local check (S2a closureAt "
     "compares it), and for adjudication the comparison is A1 of AdjudicationBindingV0, after S2a ACCEPT (section 10, "
     "SPS-18: binding mutations are expected only after ACCEPT); so neither changes the projection here. Checking it "
     "locally for every kind, or for none, gives the same results: the vectors do not separate these readings"),
    ("schema r9 section 5, the reference bound", "a decimal reference above 2^64 - 1 is a stage-2 failure (payload = "
     "none), like a reference outside the grammar; both give the same transcript"),
]


class StageFailure(Exception):
    def __init__(self, stage, reason):
        super().__init__(f"stage {stage}: {reason}")
        self.stage, self.reason = stage, reason


# ---------------------------------------------------------------- RFC 8785 for P10 Statement values

def jcs(value):
    """RFC 8785 section 3.2: objects with members sorted by their names' UTF-16 code units, arrays in order, no
    whitespace, strings as ECMAScript JSON.stringify writes them (section 3.2.2.2), true and false. Numbers and null
    never occur in a P10 Statement (schema section 5) and are refused."""
    out = []

    def s(x):
        if x is True:
            out.append("true")
        elif x is False:
            out.append("false")
        elif isinstance(x, str):
            out.append('"')
            for ch in x:
                c = ord(ch)
                if 0xD800 <= c <= 0xDFFF:
                    raise ValueError("lone surrogate")
                if ch == '"':
                    out.append('\\"')
                elif ch == "\\":
                    out.append("\\\\")
                elif ch in "\b\f\n\r\t":
                    out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
                elif c < 0x20:
                    out.append(f"\\u{c:04x}")
                else:
                    out.append(ch)
            out.append('"')
        elif isinstance(x, list):
            out.append("[")
            for i, e in enumerate(x):
                if i:
                    out.append(",")
                s(e)
            out.append("]")
        elif isinstance(x, dict):
            out.append("{")
            for i, k in enumerate(sorted(x, key=lambda k: k.encode("utf-16-be", "surrogatepass"))):
                if i:
                    out.append(",")
                s(k)
                out.append(":")
                s(x[k])
            out.append("}")
        else:
            raise ValueError(f"not a P10 Statement value: {type(x).__name__}")
    s(value)
    return "".join(out).encode("utf-8")


# ---------------------------------------------------------------- strict JSON (section 5, decode steps 1 and 2)

class _Refused(ValueError):
    pass


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise _Refused("duplicate member name")
        d[k] = v
    return d


def _no_number(_):
    raise _Refused("a JSON number")


def _no_constant(_):
    raise _Refused("NaN or Infinity")


def _walk(x):
    if x is None:
        raise _Refused("null")
    if isinstance(x, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
            raise _Refused("lone surrogate")
    elif isinstance(x, list):
        for e in x:
            _walk(e)
    elif isinstance(x, dict):
        for k, v in x.items():
            _walk(k)
            _walk(v)


def parse_statement_bytes(b):
    """Section 5's decode procedure, steps 1, 2 and 4 to 5: UTF-8 without BOM, strict JSON (no duplicate names, no
    comments, no trailing bytes, no lone surrogates), and no null or number anywhere (sections 4 and 5); then the
    JCS re-serialization must equal the input byte for byte."""
    if b.startswith(b"\xef\xbb\xbf"):
        raise StageFailure(1, "BOM")
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        raise StageFailure(1, "invalid UTF-8")
    try:
        v = json.loads(text, object_pairs_hook=_pairs, parse_int=_no_number, parse_float=_no_number,
                       parse_constant=_no_constant)
        _walk(v)
    except _Refused as e:
        raise StageFailure(1, str(e))
    except ValueError as e:
        raise StageFailure(1, f"not strict JSON: {e}")
    try:
        canon = jcs(v)
    except ValueError as e:
        raise StageFailure(1, str(e))
    if canon != b:
        raise StageFailure(1, "not the JCS form of its own value")
    return v


# ---------------------------------------------------------------- the limitations constant of section 8.6

def limitations_constant(schema_path):
    """The JCS bytes of the bare 14-element array as section 8.6 prints them, taken from the frozen text itself and
    checked against the length (5718) and digest (7c925266...) the same section states."""
    text = pathlib.Path(schema_path).read_text(encoding="utf-8")
    anchor = text.index("Full candidate canonical bytes (JCS of the bare `limitations` array, 5718 bytes")
    start = text.index("```json\n", anchor) + len("```json\n")
    line = text[start:text.index("\n", start)].encode("utf-8")
    if len(line) != 5718 or hashlib.sha256(line).hexdigest() != \
            "7c9252664b112621087d0a74b3f8fd5ec50f9ed912cc0d1a611bc227d3d15214":
        raise RuntimeError("the section 8.6 constant does not match its stated length and digest")
    value = json.loads(line)
    if jcs(value) != line or len(value) != 14:
        raise RuntimeError("the section 8.6 constant is not its own JCS form")
    return value, hashlib.sha256(jcs(value)).hexdigest()


# ---------------------------------------------------------------- stages 0 to 3 (section 9)

def stage0(prot):
    """Stage 0 beyond what the replay already reads (tag 18, readable protected header, iss/sub): crit and the
    COSE Hash Envelope labels. Raises StageFailure(0, ...)."""
    for lbl in HASH_ENVELOPE_LABELS:
        if lbl in prot:
            raise StageFailure(0, f"protected label {lbl} (RFC 9995 hash envelope)")
    if 2 in prot:
        crit = prot[2]
        if not isinstance(crit, list) or not crit or any(isinstance(c, bool) or not isinstance(c, (int, str))
                                                         for c in crit):
            raise StageFailure(0, "crit is not a non-empty array of labels")
        if any(c not in UNDERSTOOD_CRIT for c in crit):
            raise StageFailure(0, "crit lists a parameter not understood")


def stage1(prot, payload_bytes, sub):
    """Content type, strict canonical Statement, skeleton, subject binding, predicateType. Returns (kind,
    predicate) or raises StageFailure(1, ...)."""
    if prot.get(3) != CONTENT_TYPE:
        raise StageFailure(1, "protected content_type missing or not application/vnd.in-toto+json")
    st = parse_statement_bytes(payload_bytes)
    if not isinstance(st, dict) or set(st) != {"_type", "subject", "predicateType", "predicate"}:
        raise StageFailure(1, "Statement members")
    if st["_type"] != STATEMENT_TYPE:
        raise StageFailure(1, "_type")
    if not isinstance(st["predicate"], dict):
        raise StageFailure(1, "predicate is not an object")
    subj = st["subject"]
    if not isinstance(subj, list) or len(subj) != 1:
        raise StageFailure(1, "subject is not an array of length 1")
    d = subj[0]
    if not isinstance(d, dict) or set(d) != {"digest", "name"}:
        raise StageFailure(1, "subject descriptor members")
    if not isinstance(d["name"], str) or d["name"].encode("utf-8") != sub.encode("utf-8"):
        raise StageFailure(1, "subject[0].name differs from the CWT sub")
    dg = d["digest"]
    if not isinstance(dg, dict) or set(dg) != {"sha256"} or not isinstance(dg["sha256"], str) \
            or not HEX64.match(dg["sha256"]):
        raise StageFailure(1, "subject digest")
    if dg["sha256"] != hashlib.sha256(sub.encode("utf-8")).hexdigest():
        raise StageFailure(1, "subject digest is not SHA-256 of the subject")
    kind = KIND_BY_URI.get(st["predicateType"]) if isinstance(st["predicateType"], str) else None
    if kind is None:
        raise StageFailure(1, "predicateType is not one of the five URIs")
    return kind, st["predicate"]


def _members(p, names):
    if set(p) != set(names):
        raise StageFailure(2, f"predicate members {sorted(p)}")


def _hex32(x, what):
    if not isinstance(x, str) or not HEX64.match(x):
        raise StageFailure(2, f"{what} is not 64 lowercase hex")
    return bytes.fromhex(x)


def _ref(x, what):
    if not isinstance(x, str) or not REF.match(x):
        raise StageFailure(2, f"{what} is not a decimal reference")
    n = int(x)
    if n > U64_MAX:
        raise StageFailure(2, f"{what} above 2^64 - 1")
    return n


def _str(x, what):
    if not isinstance(x, str):
        raise StageFailure(2, f"{what} is not a string")
    return x


IC_DIGESTS = ["log_identity_digest", "leaf_encoding_profile_digest", "claim_digest", "profile_digest",
              "evidence_scope_digest", "admission_rule_digest", "coverage_rule_digest",
              "authorized_admitter_set_digest", "subject_derivation_digest"]
ADJ_DIGESTS = ["capability_proof_digest", "claim_digest", "codec_digest", "evidence_digest", "limitations_digest",
               "log_identity_digest", "preclosure_transcript_digest", "proof_digest", "verifier_digest",
               "witness_0_digest", "witness_1_digest"]
ADJ_MEMBERS = ADJ_DIGESTS + ["evidence_admission_refs", "evidence_closure_ref", "instance_commitment_ref",
                             "instance_subject", "limitations", "must_understand", "outcome", "profile_commitment_ref"]


def stage23(kind, p, sub, limitations):
    """Stage 2 (the predicate of the derived kind, section 8 with 8.7's local checks) and stage 3 (projection into
    the S2a Payload). Returns the projected payload as a tuple (kind, value) or raises StageFailure(2, ...)."""
    if kind == "profileCommit":
        _members(p, ["profile_digest"])
        return ("profileCommit", _hex32(p["profile_digest"], "profile_digest"))
    if kind == "instanceCommit":
        _members(p, IC_DIGESTS + ["issuer_id", "instance_owner_iss", "instance_subject", "request_id"])
        rid = _str(p["request_id"], "request_id")
        if not REQUEST_ID.match(rid):
            raise StageFailure(2, "request_id grammar")
        if _str(p["instance_subject"], "instance_subject").encode("utf-8") != sub.encode("utf-8"):
            raise StageFailure(2, "instance_subject differs from the CWT sub (section 8.2)")
        ic = {"requestId": bytes.fromhex(rid), "issuerId": _str(p["issuer_id"], "issuer_id").encode("utf-8"),
              "instanceSubject": p["instance_subject"].encode("utf-8"),
              "instanceOwnerIss": _str(p["instance_owner_iss"], "instance_owner_iss").encode("utf-8")}
        for k in IC_DIGESTS:
            ic[k] = _hex32(p[k], k)
        return ("instanceCommit", ic)
    if kind == "admission":
        _members(p, ["item"])
        it = p["item"]
        if not isinstance(it, dict) or set(it) != {"kind", "value"}:
            raise StageFailure(2, "item members")
        if it["kind"] not in ("first", "second") or not isinstance(it["value"], bool):
            raise StageFailure(2, "item kind or value")
        return ("admission", (it["kind"], it["value"]))
    if kind == "closure":
        _members(p, ["checkpoint_preclosure_transcript_digest", "closed_evidence_set_digest", "instance_subject",
                     "ordered_admission_refs", "terminal"])
        if p["terminal"] is not True:
            raise StageFailure(2, "terminal is not the literal true")
        refs = p["ordered_admission_refs"]
        if not isinstance(refs, list):
            raise StageFailure(2, "ordered_admission_refs is not an array")
        return ("closure", {"instanceSubject": _str(p["instance_subject"], "instance_subject").encode("utf-8"),
                            "terminal": True,
                            "orderedAdmissionRefs": [_ref(r, "ordered_admission_refs") for r in refs],
                            "closedEvidenceSetDigest": _hex32(p["closed_evidence_set_digest"], "closed_evidence_set_digest"),
                            "checkpointPreclosureTranscriptDigest": _hex32(p["checkpoint_preclosure_transcript_digest"],
                                                                           "checkpoint_preclosure_transcript_digest")})
    if kind == "adjudication":
        _members(p, ADJ_MEMBERS)
        for k in ADJ_DIGESTS:
            _hex32(p[k], k)
        lim_value, lim_digest = limitations
        if p["limitations"] != lim_value or jcs(p["limitations"]) != jcs(lim_value):
            raise StageFailure(2, "limitations is not the section 8.6 constant")
        if p["limitations_digest"] != lim_digest:
            raise StageFailure(2, "limitations_digest is not SHA-256(JCS(limitations))")
        if p["must_understand"] != ["limitations"]:
            raise StageFailure(2, "must_understand is not [\"limitations\"]")
        if p["outcome"] != {"kind": "NotDemonstrated", "reason": "underdetermined"}:
            raise StageFailure(2, "outcome literal")
        _str(p["instance_subject"], "instance_subject")
        ear = p["evidence_admission_refs"]
        if not isinstance(ear, list):
            raise StageFailure(2, "evidence_admission_refs is not an array")
        for r in ear:
            _ref(r, "evidence_admission_refs")
        return ("adjudication", (_ref(p["profile_commitment_ref"], "profile_commitment_ref"),
                                 _ref(p["instance_commitment_ref"], "instance_commitment_ref"),
                                 _ref(p["evidence_closure_ref"], "evidence_closure_ref")))
    raise StageFailure(2, f"unknown kind {kind}")
