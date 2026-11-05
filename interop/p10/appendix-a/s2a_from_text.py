#!/usr/bin/env python3
"""S2a coverage conditions read from the text, run on the published S2a vectors.

- decode_tb: a strict decoder for the transcript tB, written from the grammar the
  frozen S2b prereg r7 transcribes in its section 15.2 (S2a's codec source was not read).
- subset_c7_c10 / main: first step, conditions C7-C10 only (out/s2a-subset.json).
- coverage_from_text / main_full: C1, C1a-C1c, C2-C13 of S2a prereg v0.2.6 section 7,
  with sections 6, 6a, 6b, 13 and the interpretations I-3, I-5..I-8, I-15 of
  profile/IMPLEMENTATION_BINDING.md; plus the TB7 harness rule (section 6a, I-10) and
  the section 9 claim-digest binding for S2-N33 (out/s2a-coverage.json).
Python 3 standard library only.

READINGS (logged in README.md):
- inst.bin is the `ic` production of section 15.2 without the payload tags (its
  first bytes are nat(8) "req-0001", the requestId); S2a section 6 does not give its layout.
- admissible(item) is true for every fixture item (I-15).
- the order inside C1 follows I-8 (contiguity, row/detail, log identity, profile digest,
  pB decode and fields), then C1a, C1b, C1c; C2 rows, payloads, keys; C3..C13 in table order.
- the pre-closure view (I-5): entries strictly before the closure leaf that are owner-signed,
  verified lifecycle entries of matching payload kind, or RelevantAdmissions, in leaf order.
- C5 (I-3): a valid owner adjudication whose reference names a non-admission entry with another iss.
"""
import hashlib
import json
import os
import re
import sys

from appendix_a_checks import jcs_bytes, pb_check

MAGIC = b"P10S2-Transcript-v0:"
KINDS = ["profileCommit", "instanceCommit", "admission", "closure", "adjudication"]
SIGS = ["verified", "badSignature", "keyUnavailable"]


class Dec:
    def __init__(self, b):
        self.b, self.i = b, 0

    def nat(self):
        n = 0
        while True:
            if self.i >= len(self.b):
                raise ValueError("truncated nat")
            x = self.b[self.i]
            self.i += 1
            if x == 0xFF:
                n += 255
                continue
            return n + x

    def bytes_(self):
        n = self.nat()
        out = []
        for _ in range(n):
            v = self.nat()
            if v > 255:
                raise ValueError("byte value above 255")
            out.append(v)
        return bytes(out)

    def bool_(self):
        v = self.nat()
        if v not in (0, 1):
            raise ValueError("bool")
        return v == 1

    def ic(self):
        names = ["requestId", "issuerId", "instanceSubject", "instanceOwnerIss", "logIdentityDigest",
                 "leafEncodingProfileDigest", "claimDigest", "profileDigest", "evidenceScopeDigest",
                 "admissionRuleDigest", "coverageRuleDigest", "authorizedAdmitterSetDigest",
                 "subjectDerivationDigest"]
        return {k: self.bytes_() for k in names}

    def payload(self):
        if self.nat() == 0:
            return ("profileCommit", self.bytes_())
        if self.nat() == 0:
            return ("instanceCommit", self.ic())
        if self.nat() == 0:
            t = self.nat()
            if t not in (0, 1):
                raise ValueError("item tag")
            return ("admission", ("first" if t == 0 else "second", self.bool_()))
        if self.nat() == 0:
            sub = self.bytes_()
            term = self.bool_()
            refs = [self.nat() for _ in range(self.nat())]
            return ("closure", {"instanceSubject": sub, "terminal": term, "refs": refs,
                                "closedEvidenceSetDigest": self.bytes_(), "preclosureDigest": self.bytes_()})
        return ("adjudication", (self.nat(), self.nat(), self.nat()))

    def end(self):
        if self.i != len(self.b):
            raise ValueError("trailing bytes")


def decode_tb(b):
    if not b.startswith(MAGIC):
        raise ValueError("magic")
    d = Dec(b)
    d.i = len(MAGIC)
    t = {"logIdentityDigest": d.bytes_(), "keyResolutionDigest": d.bytes_(), "size": d.nat(), "root": d.bytes_()}
    rows = []
    for _ in range(d.nat()):
        idx = d.nat()
        st = d.nat()
        if st == 0:
            rows.append((idx, d.bytes_()))
        elif st == 1:
            rows.append((idx, None))
        else:
            raise ValueError("row status")
    det = []
    for _ in range(d.nat()):
        idx = d.nat()
        iss = d.bytes_()
        kind = KINDS[d.nat()]
        sig = SIGS[d.nat()]
        opt = d.nat()
        if opt not in (0, 1):
            raise ValueError("option")
        det.append({"idx": idx, "iss": iss.decode("utf-8"), "kind": kind, "sig": sig,
                    "payload": d.payload() if opt == 1 else None})
    d.end()
    t["rows"], t["detailed"] = rows, det
    return t


def decode_inst(b):
    d = Dec(b)
    ic = d.ic()
    d.end()
    return ic


def subset_c7_c10(t, inst, pb):
    """First failing condition among C7, C8, C9, C10 (S2a section 7 order), or None."""
    owner = inst["instanceOwnerIss"].decode("utf-8")
    authorized = set(pb["authorized_admitters"])
    det = t["detailed"]
    relevant = {e["idx"] for e in det if e["kind"] == "admission" and e["iss"] in authorized
                and e["sig"] == "verified" and e["payload"] is not None}
    closures = [e for e in det if e["kind"] == "closure" and e["iss"] == owner and e["sig"] == "verified"
                and e["payload"] is not None]
    if len(closures) != 1:
        return "outside_subset:closures=%d" % len(closures)
    k = closures[0]
    refs = k["payload"][1]["refs"]
    if any(refs[i] >= refs[i + 1] for i in range(len(refs) - 1)):
        return "c7_refsNotStrictlyAscending"
    if any(r not in relevant for r in refs):
        return "c8_refNotRelevantAdmission"
    before = sorted(i for i in relevant if i < k["idx"])
    if sorted(refs) != before:
        return "c9_refsNotExactRelevantSet"
    if any(k["idx"] < i < t["size"] for i in relevant):
        return "c10_relevantAdmissionAfterClosure"
    return None


KIND_TOK = {"profileCommit": "profile_commit", "instanceCommit": "instance_commit", "admission": "admission",
            "closure": "closure", "adjudication": "adjudication"}
TOKEN = re.compile(r"^[A-Za-z0-9_.:-]+$")


def H(obj):
    return hashlib.sha256(jcs_bytes(obj)).digest()


def evidence_tok(e):
    if e in ("outside", "inconsistent"):
        return e
    f, s = e
    return "f%ds%s" % (int(f), "_" if s is None else str(int(s)))


def bundle(items):
    """S2a prereg section 13."""
    F = {b for w, b in items if w == "first"}
    S = {b for w, b in items if w == "second"}
    if not F:
        return "outside"
    if len(F) == 2 or len(S) == 2:
        return "inconsistent"
    return (next(iter(F)), next(iter(S)) if S else None)


def coverage_from_text(t, inst, pb_bytes, mdig):
    """Reconstruction of coverageCheck from S2a prereg v0.2.6 sections 6, 6a, 6b, 7, 13 and the
    interpretations I-5..I-8, I-15 of profile/IMPLEMENTATION_BINDING.md. Returns (outcome, code)."""
    owner = inst["instanceOwnerIss"].decode("utf-8")
    issuer = inst["issuerId"].decode("utf-8")
    subj = inst["instanceSubject"]
    # C1: contiguity, row/detail correspondence, log identity, profile digest, strict pB, fields
    if [i for i, _ in t["rows"]] != list(range(t["size"])):
        return "reject", "c1_rowsNotContiguous"
    det = t["detailed"]
    subj_rows = {i for i, s in t["rows"] if s == subj}
    if sorted(e["idx"] for e in det) != sorted(subj_rows):
        return "reject", "c1_rowDetailMismatch(name of this reading)"
    if t["logIdentityDigest"] != inst["logIdentityDigest"]:
        return "reject", "c1_logIdentity"
    if hashlib.sha256(pb_bytes).digest() != inst["profileDigest"]:
        return "reject", "c1_profileDigest"
    code, _ = pb_check(pb_bytes, mdig)
    if code in ("c1_profileDecode", "c1_profileFields", "c1_leafSpec"):
        return "reject", code
    pb = json.loads(pb_bytes)
    adm = pb["authorized_admitters"]
    # C1a
    if not TOKEN.match(issuer) or not TOKEN.match(owner):
        return "reject", "c1a_issuerNotToken"
    if owner != issuer:
        return "reject", "c1a_ownerNotIssuer"
    sd = "p10s2sub:" + H({"issuer_id": issuer, "request_id": inst["requestId"].hex(), "v": "SubjectDeriveV0"}).hex()
    if subj != sd.encode():
        return "reject", "c1a_subjectDerivation"
    # C1b
    if owner in adm:
        return "reject", "c1_ownerInAdmitters"
    if inst["authorizedAdmitterSetDigest"] != H({"authorized_admitters": adm}):
        return "reject", "c1b_admittersDigest"
    if t["keyResolutionDigest"] != H({"key_resolution": pb["key_resolution"]}):
        return "reject", "c1b_keyResolutionDigest"
    # C1c
    vmd = pb["verifier_manifest_digest"]
    for field, obj, c in (
            ("subjectDerivationDigest", {"rule": "SubjectDeriveV0", "verifier_manifest_digest": vmd}, "c1c_subjectDerivationDigest"),
            ("leafEncodingProfileDigest", {"rule": "LeafEncodeV0", "spec_digest": pb["leaf_encoding_spec_digest"]}, "c1c_leafEncodingProfileDigest"),
            ("evidenceScopeDigest", {"rule": pb["evidence_scope_rule_id"], "verifier_manifest_digest": vmd}, "c1c_evidenceScopeDigest"),
            ("admissionRuleDigest", {"rule": pb["admission_rule_id"], "verifier_manifest_digest": vmd}, "c1c_admissionRuleDigest"),
            ("coverageRuleDigest", {"rule": pb["coverage_rule_id"], "verifier_manifest_digest": vmd}, "c1c_coverageRuleDigest")):
        if inst[field] != H(obj):
            return "reject", c
    # C2
    if any(s is None for _, s in t["rows"]):
        return "halt", "c2_rowUnavailable"
    if any(e["payload"] is None for e in det):
        return "halt", "c2_subjectPayloadUnavailable"
    if any(e["sig"] == "keyUnavailable" and (e["iss"] in adm or e["iss"] == owner) for e in det):
        return "halt", "c2_keyUnavailable"

    def ok_owner(e, kind):
        return e["iss"] == owner and e["sig"] == "verified" and e["kind"] == kind and e["payload"][0] == kind

    relevant = sorted(e["idx"] for e in det if e["kind"] == "admission" and e["iss"] in adm
                      and e["sig"] == "verified" and e["payload"][0] == "admission")
    first_rel = relevant[0] if relevant else float("inf")
    by_idx = {e["idx"]: e for e in det}
    # C3
    pcs = [e for e in det if ok_owner(e, "profileCommit")]
    if not pcs:
        return "halt", "c3_noProfileCommitment"
    if len(pcs) >= 2:
        return "reject", "c3_multipleProfileCommitments"
    p = pcs[0]
    if p["payload"][1] != inst["profileDigest"]:
        return "reject", "c3_profileDigestMismatch"
    if p["idx"] > first_rel:
        return "reject", "c3_profileAfterFirstAdmission"
    # C4
    tup = (inst["instanceOwnerIss"], inst["requestId"], subj)
    ics = [e for e in det if ok_owner(e, "instanceCommit")
           and (e["payload"][1]["instanceOwnerIss"], e["payload"][1]["requestId"], e["payload"][1]["instanceSubject"]) == tup]
    if not ics:
        return "halt", "c4_noInstanceCommitment"
    if len(ics) >= 2:
        return "reject", "c4_multipleCommitments"
    ci = ics[0]
    if ci["payload"][1] != inst:
        return "reject", "c4_commitmentMismatch"
    if ci["idx"] > first_rel:
        return "reject", "c4_commitmentAfterFirstAdmission"
    # C5: a valid owner adjudication citing a non-owner lifecycle entry (I-3)
    adjs = [e for e in det if ok_owner(e, "adjudication")]
    for a in adjs:
        for r in a["payload"][1]:
            c = by_idx.get(r)
            if c is not None and c["kind"] != "admission" and c["iss"] != owner:
                return "reject", "c5_citesNonOwnerLifecycle"
    # C6 (I-5, I-6, section 6b PreclosureDigestV0)
    def view_before(k):
        v = []
        for e in sorted(det, key=lambda x: x["idx"]):
            if e["idx"] >= k:
                break
            if e["idx"] in relevant or (e["iss"] == owner and e["sig"] == "verified" and e["kind"] != "admission"
                                         and e["payload"][0] == e["kind"]):
                v.append([str(e["idx"]), KIND_TOK[e["kind"]], e["iss"]])
        return v
    closures = [e for e in det if ok_owner(e, "closure") and e["payload"][1]["instanceSubject"] == subj
                and e["payload"][1]["terminal"]
                and e["payload"][1]["preclosureDigest"] == H({"preclosure_view": view_before(e["idx"])})]
    if not closures:
        return "halt", "c6_noValidClosure"
    if len(closures) >= 2:
        return "reject", "c6_multipleClosures"
    k = closures[0]
    refs = k["payload"][1]["refs"]
    # C7-C10
    if any(refs[i] >= refs[i + 1] for i in range(len(refs) - 1)):
        return "reject", "c7_refsNotStrictlyAscending"
    if any(r not in relevant for r in refs):
        return "reject", "c8_refNotRelevantAdmission"
    if sorted(refs) != [i for i in relevant if i < k["idx"]]:
        return "reject", "c9_refsNotExactRelevantSet"
    if any(k["idx"] < i < t["size"] for i in relevant):
        return "reject", "c10_relevantAdmissionAfterClosure"
    # C11
    after = [a for a in adjs if k["idx"] < a["idx"] < t["size"]]
    if not after:
        return "halt", "c11_noAdjudicationAfterClosure"
    if any(tuple(a["payload"][1]) != (p["idx"], ci["idx"], k["idx"]) for a in after):
        return "reject", "c11_adjudicationRefsMismatch"
    # C12, C13
    e = bundle([by_idx[r]["payload"][1] for r in refs])
    if e == "outside":
        return "reject", "c12_evidenceOutsideE"
    if k["payload"][1]["closedEvidenceSetDigest"] != H({"evidence": evidence_tok(e)}):
        return "reject", "c13_closedEvidenceDigest"
    return "accept", evidence_tok(e)


LEAN_ACCEPT = {".accept (.obs false (some false))": "f0s0", ".accept (.obs false none)": "f0s_",
               ".accept P10.S1.Evidence.inconsistent": "inconsistent"}


def main_full():
    here = os.path.dirname(os.path.abspath(__file__))
    s2 = os.path.join(here, "repos", "p10-coverage-lean-s2")
    vec = os.path.join(s2, "vectors")
    with open(os.path.join(s2, "manifest", "VerifierManifestS2aV0.json"), "rb") as f:
        mdig = hashlib.sha256(f.read()).hexdigest()
    index = {}
    with open(os.path.join(vec, "INDEX.tsv"), encoding="utf-8") as f:
        next(f)
        for line in f:
            vid, _, cond, lean, tb7 = line.rstrip("\n").split("\t")
            index[vid] = (lean, tb7)
    rows = {}
    for vid in sorted(index):
        p = os.path.join(vec, vid)
        if not os.path.exists(os.path.join(p, "inst.bin")):
            continue
        lean, tb7 = index[vid]
        inst = decode_inst(open(os.path.join(p, "inst.bin"), "rb").read())
        pbb = open(os.path.join(p, "pB.json"), "rb").read()
        if not os.path.exists(os.path.join(p, "tB.bin")):
            got = ("halt", "tb5_checkpointMaterialUnavailable")
        else:
            got = coverage_from_text(decode_tb(open(os.path.join(p, "tB.bin"), "rb").read()), inst, pbb, mdig)
        if got[0] == "accept":
            agree = LEAN_ACCEPT.get(lean) == got[1]
        else:
            agree = lean == ".%s .%s" % got
        # TB7 harness (S2a section 6a, I-10): manifest reference must resolve, digest must equal
        pb = json.loads(pbb)
        if not os.path.exists(os.path.join(s2, "manifest", pb["verifier_manifest_ref"])):
            tb7_got = "HALT"
        elif pb["verifier_manifest_digest"] != mdig:
            tb7_got = "REJECT"
        else:
            tb7_got = "PASS"
        tb7_agree = tb7 == "-" or tb7 == tb7_got
        # S2-N33: section 9 end-to-end binding of the claim digest to iB (ClaimDigestV0)
        e2e = None
        if os.path.exists(os.path.join(p, "iB.json")):
            ib = json.loads(open(os.path.join(p, "iB.json"), "rb").read())
            e2e = inst["claimDigest"] == H({"claim": ib["claim"]})
        rows[vid] = {"expected": lean, "got": list(got), "agree": agree, "tb7_expected": tb7, "tb7_got": tb7_got,
                     "tb7_agree": tb7_agree, "e2e_claim_digest_binds": e2e}
    out = {"vectors": len(rows), "agree": sum(r["agree"] for r in rows.values()),
           "disagree": {k: (r["expected"], r["got"]) for k, r in rows.items() if not r["agree"]},
           "tb7_agree": sum(r["tb7_agree"] for r in rows.values()),
           "e2e_false": sorted(k for k, r in rows.items() if r["e2e_claim_digest_binds"] is False),
           "rows": rows}
    with open(os.path.join(here, "out", "s2a-coverage.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print("S2a coverage from text: %d vectors, %d agree; disagree: %s" % (out["vectors"], out["agree"], out["disagree"]))
    print("TB7: %d/%d agree; e2e claim digest not bound: %s" % (out["tb7_agree"], out["vectors"], out["e2e_false"]))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    vec = os.path.join(here, "repos", "p10-coverage-lean-s2", "vectors")
    index = {}
    with open(os.path.join(vec, "INDEX.tsv"), encoding="utf-8") as f:
        next(f)
        for line in f:
            vid, _, cond, lean, tb7 = line.rstrip("\n").split("\t")
            index[vid] = lean
    rows = {}
    decoded = 0
    for vid in sorted(index):
        p = os.path.join(vec, vid)
        if not os.path.exists(os.path.join(p, "tB.bin")):
            continue
        with open(os.path.join(p, "tB.bin"), "rb") as f:
            t = decode_tb(f.read())
        decoded += 1
        with open(os.path.join(p, "inst.bin"), "rb") as f:
            inst = decode_inst(f.read())
        with open(os.path.join(p, "pB.json"), "rb") as f:
            pb = json.loads(f.read())
        got = subset_c7_c10(t, inst, pb)
        lean = index[vid]
        in_scope = lean.startswith(".accept") or any(c in lean for c in ("c7_", "c8_", "c9_", "c10_"))
        if lean.startswith(".accept"):
            agree = got is None
        elif in_scope:
            agree = got is not None and got in lean
        else:
            agree = None
        rows[vid] = {"expected": lean, "subset_result": got, "in_scope": in_scope, "agree": agree}
    scope = [r for r in rows.values() if r["in_scope"]]
    out = {"decoded_tB": decoded, "in_scope": len(scope), "agree": sum(1 for r in scope if r["agree"]),
           "disagree": sorted(k for k, r in rows.items() if r["in_scope"] and not r["agree"]),
           "rows": rows}
    with open(os.path.join(here, "out", "s2a-subset.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print("tB decoded: %d; in scope (accept or C7-C10): %d; agree %d; disagree %s"
          % (decoded, len(scope), out["agree"], out["disagree"]))
    for k, r in sorted(rows.items()):
        if r["in_scope"]:
            print(" ", k, r["expected"], "->", r["subset_result"])


if __name__ == "__main__":
    main()
    sys.exit(main_full())
