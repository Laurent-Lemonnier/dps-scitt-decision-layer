#!/usr/bin/env python3
"""Class (b) checks for the outside reading of Appendix A of
draft-nestorov-scitt-p10-underdetermination-02.

Reads only published text, manifests and vectors of the three pinned
repositories (see PINS.txt, SHA256SUMS). Python 3 standard library only.
Every rule below is taken from a document named in the comment; readings
where the text leaves room are marked READING and logged in the README.
"""
import argparse
import hashlib
import json
import os
import re
import sys

PROFILE_DIGEST = "b92c0d689b9f16f2184ba2addb8653ed881595cc3a0117c62cadadf5c6dc6558"  # A03


def sha(b):
    return hashlib.sha256(b).hexdigest()


def read(path):
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------- JSON / JCS
def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate member %r" % k)
        d[k] = v
    return d


def _no_number(s):
    raise ValueError("number not allowed: %s" % s)


def strict_json(b):
    """Strict UTF-8 JSON, no duplicate names, no numbers or constants (the
    S1 and S2a artifacts read here carry strings, arrays and objects only)."""
    return json.loads(b.decode("utf-8"), object_pairs_hook=_no_dup,
                      parse_int=_no_number, parse_float=_no_number,
                      parse_constant=_no_number)


def jcs(v):
    """RFC 8785 for strings, arrays and objects (members sorted by UTF-16
    code units). Numbers are not needed by the artifacts read here."""
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(jcs(k) + ":" + jcs(v[k]) for k in keys) + "}"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    raise ValueError("unsupported JCS value %r" % (v,))


def jcs_bytes(v):
    return jcs(v).encode("utf-8")


# ---------------------------------------------------------------- S1 wire + toy profile
# Wire format: lean-s1 TEST_VECTORS.md, "Wire format".
S1_KEYS = ["claim", "evidence", "kind", "profile", "spec", "w0", "w1"]
S1_VALUE = re.compile(r"^[A-Za-z0-9_.:-]+$")
CLAIMS = {"secondBit", "firstBit"}
EVIDENCE_TOKENS = {"f%ds%s" % (a, b) for a in (0, 1) for b in "_01"} | {"inconsistent", "outside"}
WORLD_TOKENS = {"w00", "w01", "w10", "w11", "wOut"}
# READING (TEST_VECTORS.md token list and N1-N4/M3/M-E reasons; Fixtures.lean not opened):
# W = the four two-bit worlds; wOut is a token but not in W ("not in Wπ");
# E = the six f/s observations plus "inconsistent" ("outside" is "not in Eπ").
W = ["w00", "w01", "w10", "w11"]
E = sorted(EVIDENCE_TOKENS - {"outside"})


def compatible(e, w):
    """READING: fAsB is compatible with wXY iff X = A and (B = '_' or Y = B);
    'inconsistent' is compatible with no world (N4: 'no compatible world').
    wOut: M3 says 'compatible and divergent but not in Wπ'; its bits are not
    stated, so it is treated as compatible and the M3 verdict rests on W."""
    if w == "wOut":
        return True
    if e == "inconsistent" or e == "outside":
        return e == "outside"
    a, b = e[1], e[3]
    return w[1] == a and (b == "_" or w[2] == b)


def evaluate(c, w):
    if w == "wOut":
        return None  # not stated; never needed for a verdict here
    return w[1] if c == "firstBit" else w[2]


def s1_decode(b):
    """Strict decoder: returns (instance, None) or (None, reason)."""
    try:
        obj = strict_json(b)
    except Exception as ex:  # noqa: BLE001
        return None, "decode: %s" % ex
    if not isinstance(obj, dict) or sorted(obj) != S1_KEYS:
        return None, "decode: member set"
    for k in S1_KEYS:
        if not isinstance(obj[k], str) or not S1_VALUE.match(obj[k]):
            return None, "decode: value alphabet (%s)" % k
    if jcs_bytes(obj) != b:
        return None, "decode: not canonical (re-encoding differs)"
    if obj["kind"] != "p10-s1-instance-v0":
        return None, "decode: kind"
    if obj["profile"] != "p10-s1-toy-v0":
        return None, "decode: profile id"
    if obj["claim"] not in CLAIMS:
        return None, "decode: claim token"
    if obj["evidence"] not in EVIDENCE_TOKENS:
        return None, "decode: evidence token"
    if obj["w0"] not in WORLD_TOKENS or obj["w1"] not in WORLD_TOKENS:
        return None, "decode: world token"
    return obj, None


def s1_holds(b):
    """canonical decode, spec digest = profile digest (M32), then
    CertificateTargetV0 for the NAMED witnesses (profile section 2.2)."""
    inst, why = s1_decode(b)
    if inst is None:
        return False, why
    if inst["spec"] != "sha256:" + PROFILE_DIGEST:
        return False, "spec digest differs from the profile digest"
    e, c, w0, w1 = inst["evidence"], inst["claim"], inst["w0"], inst["w1"]
    if e not in E:
        return False, "evidence not in E"
    for w in (w0, w1):
        if w not in W:
            return False, "witness %s not in W" % w
    for w in (w0, w1):
        if not compatible(e, w):
            return False, "witness %s not Compatible with %s" % (w, e)
    if evaluate(c, w0) == evaluate(c, w1):
        return False, "same claim value under %s" % c
    return True, "CertificateTargetV0 holds"


def determinate(e, c, comp):
    ws = [w for w in W if comp(e, w)]
    return bool(ws) and len({evaluate(c, w) for w in ws}) == 1


def underdetermined(e, c, comp):
    ws = [w for w in W if comp(e, w)]
    return len({evaluate(c, w) for w in ws}) > 1


def fuc(c, comp):
    return any(underdetermined(e, c, comp) for e in E) and any(determinate(e, c, comp) for e in E)


# ---------------------------------------------------------------- checks
def check_pins(root):
    exp = {
        "p10-underdetermination-profile/P10_Underdetermination_Profile_v0.1.1.md": PROFILE_DIGEST,
        "p10-underdetermination-lean-s1/manifest/VerifierManifestS1.json": "06bf9129bf480c79ed5281ec2e944ac5613d1c340552ce5a415f5bf4c8965907",
        "p10-coverage-lean-s2/manifest/VerifierManifestS2aV0.json": "f8380b19b43334925e7f7621e1f7d7912f36c789199d3f8d069b87f5ea176d46",
        "p10-coverage-lean-s2/manifest/VectorManifestS2aV0.json": "dd2d567e04fae52244feec988a56df26e4721f833f072dd7073959d9170e39ec",
        "p10-coverage-lean-s2/profile/LeafEncodeV0_SPEC.md": "d142e636a9a92fdc57bbc49e77e077607ff12e96c19b79ad539b2f6b17b16008",
    }
    out = {p: (sha(read(os.path.join(root, p))) == d) for p, d in exp.items()}
    # every vectors/ file listed in VectorManifestS2aV0 (A10) hashes to its listed value
    s2 = os.path.join(root, "p10-coverage-lean-s2")
    vm = strict_json(read(os.path.join(s2, "manifest/VectorManifestS2aV0.json")))["files"]
    listed = {p: d for p, d in vm.items() if p.startswith("vectors/")}
    bad = sorted(p for p, d in listed.items() if sha(read(os.path.join(s2, p))) != d)
    on_disk = set()
    for dp, _, fs in os.walk(os.path.join(s2, "vectors")):
        for f in fs:
            on_disk.add(os.path.relpath(os.path.join(dp, f), s2))
    return {"files": out, "all_equal": all(out.values()) and not bad,
            "s2a_vector_files_listed": len(listed), "s2a_vector_files_mismatch": bad,
            "s2a_vector_files_unlisted": sorted(on_disk - set(listed))}


def check_s1_vectors(root):
    base = os.path.join(root, "p10-underdetermination-lean-s1", "vectors")
    cases = [("P1", "p1.instance.json", True)]
    for f in sorted(os.listdir(os.path.join(base, "negative"))):
        cases.append((f[:-5], "negative/" + f, False))
    rows = []
    for cid, rel, expect in cases:
        ok, why = s1_holds(read(os.path.join(base, rel)))
        rows.append({"vector": rel, "expected_accept": expect, "accept": ok, "reason": why,
                     "agree": ok == expect})
    return {"rows": rows, "agree": sum(r["agree"] for r in rows), "total": len(rows)}


def check_s1_toy_m2():
    always = lambda e, w: True  # noqa: E731
    res = {}
    for c in sorted(CLAIMS):
        res[c] = {"fuc_reconstructed_profile": fuc(c, compatible),
                  "fuc_with_compatible_true": fuc(c, always),
                  "any_determinate_with_compatible_true": any(determinate(e, c, always) for e in E)}
    res["expected"] = ("M2: FUC false for every claim with Compatible := true. Sanity: FUC true for the P1 claim "
                       "secondBit on the reconstructed profile (firstBit is fixed by every observation, so it is "
                       "never underdetermined there)")
    res["agree"] = res["secondBit"]["fuc_reconstructed_profile"] and \
        not any(res[c]["fuc_with_compatible_true"] for c in CLAIMS)
    return res


def check_s1_statement(root):
    s1 = os.path.join(root, "p10-underdetermination-lean-s1")
    st = strict_json(read(os.path.join(s1, "vectors/out/p1.statement.json")))
    inst = strict_json(read(os.path.join(s1, "vectors/p1.instance.json")))
    p = st["predicate"]
    # values from TEST_VECTORS.md "Bound fields"
    tv = {"claim": "f99c1403b75ef3fd5da1298767838e15159713ece3b954886fe0c02e04ffc821",
          "evidence": "a8cf4ba58abe5f0245b1f3d6e1b5b4c8e718ce8dfdfb1137ec1f3a33e5e0fab0",
          "w0": "15304eb2956a2f07fbf4028dfd7f421c99f9a03da473fec9d75b997132747f32",
          "w1": "6fc3108dc0bf1f6cf7fe5df39b513c3b7be7312111a0ef0c4a05839194db5d5b"}
    rec = {
        "claim": sha(jcs_bytes({"claim": inst["claim"]})),
        "evidence": sha(jcs_bytes({"evidence": inst["evidence"]})),
        "w0": sha(jcs_bytes({"world": inst["w0"]})),
        "w1": sha(jcs_bytes({"world": inst["w1"]})),
    }
    digests = {k: rec[k] == tv[k] for k in tv}
    digests["claim_in_statement"] = p["claim"]["digest"] == rec["claim"]
    digests["evidence_in_statement"] = p["evidence"]["digest"] == rec["evidence"]
    digests["instance_sha256"] = p["instance"]["sha256"] == sha(read(os.path.join(s1, "vectors/p1.instance.json")))
    wit = json.dumps(p.get("witnesses"))
    digests["witness_digests_in_statement"] = rec["w0"] in wit and rec["w1"] in wit
    # M6: a one-token witness change must change the digest it is bound to
    digests["m6_mutated_witness_changes_digest"] = sha(jcs_bytes({"world": "w11"})) != rec["w1"]
    # limitations_digest: the rule is not stated in the files read; try the JCS of the array
    lim_jcs = sha(jcs_bytes(p["limitations"]))
    lim = {"limitations_digest_recorded": p["limitations_digest"],
           "sha256_jcs_limitations_array": lim_jcs,
           "reproduced_by_jcs_array": lim_jcs == p["limitations_digest"]}
    altered = json.loads(json.dumps(p["limitations"]))
    altered[0]["text"] = altered[0]["text"].replace("A formally", "a formally")
    lim["m6_m31_altered_text_changes_jcs_digest"] = sha(jcs_bytes(altered)) != lim_jcs
    # M35: verifier manifest digest recorded in the statement vs the A06 file digest
    mdig = sha(read(os.path.join(s1, "manifest/VerifierManifestS1.json")))
    m35 = {"manifest_file_sha256": mdig,
           "statement_records_it": mdig in json.dumps(p.get("verifier"))}
    return {"digests": digests, "limitations": lim, "m35": m35}


def check_s1_limitations(root):
    s1 = os.path.join(root, "p10-underdetermination-lean-s1")
    st = strict_json(read(os.path.join(s1, "vectors/out/p1.statement.json")))
    prof = read(os.path.join(root, "p10-underdetermination-profile/P10_Underdetermination_Profile_v0.1.1.md")).decode("utf-8")
    p = st["predicate"]

    def must_understand_ok(pred):
        # TEST_VECTORS.md: limitations is must-understand; reject a predicate without it
        return "limitations" in pred and "limitations" in pred.get("must_understand", [])

    ids = [x["id"] for x in p["limitations"]]
    verbatim = {x["id"]: (x["text"] in prof) for x in p["limitations"] if "verbatim" in x.get("source", "")}
    stripped = dict(p)
    del stripped["limitations"]
    return {"ids": ids, "profile_verbatim": verbatim,
            "ap1_present": "AP1" in ids, "coverage_instance_present": "COVERAGE_INSTANCE" in ids,
            "accept_as_published": must_understand_ok(p),
            "accept_without_limitations": must_understand_ok(stripped)}


PB_FIELDS = sorted(["artifact_version", "normative_profile_digest", "s1_profile_token", "fixture_id",
                    "verifier_manifest_ref", "verifier_manifest_digest", "key_resolution",
                    "authorized_admitters", "log_identity_scheme", "leaf_encoding",
                    "leaf_encoding_spec_digest", "subject_derivation", "checkpoint_vds",
                    "evidence_scope_rule_id", "admission_rule_id", "coverage_rule_id"])


def pb_check(b, manifest_digest):
    """S2a prereg v0.2.6 section 6a ProfileArtifactS2V0 and the C1 field checks."""
    try:
        obj = strict_json(b)
    except Exception as ex:  # noqa: BLE001
        return "c1_profileDecode", str(ex)
    if not isinstance(obj, dict) or sorted(obj) != PB_FIELDS:
        return "c1_profileDecode", "field set"
    if jcs_bytes(obj) != b:
        return "c1_profileDecode", "not canonical"
    adm = obj["authorized_admitters"]
    if not (isinstance(adm, list) and all(isinstance(x, str) for x in adm)
            and all(adm[i].encode("utf-16-be") < adm[i + 1].encode("utf-16-be") for i in range(len(adm) - 1))):
        return "c1_profileDecode", "authorized_admitters not strictly ascending"
    fixed = {"artifact_version": "P10-S2-ProfileArtifact-v0", "log_identity_scheme": "LogIdentityV0",
             "leaf_encoding": "LeafEncodeV0", "subject_derivation": "SubjectDeriveV0"}
    for k, v in fixed.items():
        if obj[k] != v:
            return "c1_profileDecode", "%s value" % k
    # C1: fixture_id = compiled constant (value READ from P1, not stated), spec and profile tokens
    if obj["fixture_id"] != "p10-s2-fx-v0" or obj["normative_profile_digest"] != "sha256:" + PROFILE_DIGEST \
            or obj["s1_profile_token"] != "p10-s1-toy-v0":
        return "c1_profileFields", "fixture_id / normative_profile_digest / s1_profile_token"
    if obj["leaf_encoding_spec_digest"] != "571765530870e4a6c028a54ec48aab8153411a15cfe30c44611c11c02925f9d5":
        return "c1_leafSpec", "leaf_encoding_spec_digest"
    if obj["verifier_manifest_digest"] != manifest_digest:
        return "tb7_manifestDigest", "verifier_manifest_digest differs from VerifierManifestS2aV0"
    return "ok", ""


def check_s2a_pb(root):
    s2 = os.path.join(root, "p10-coverage-lean-s2")
    mdig = sha(read(os.path.join(s2, "manifest/VerifierManifestS2aV0.json")))
    index = {}
    with open(os.path.join(s2, "vectors/INDEX.tsv"), encoding="utf-8") as f:
        next(f)
        for line in f:
            vid, prereg, cond, lean, tb7 = line.rstrip("\n").split("\t")
            index[vid] = {"condition": cond, "lean": lean, "tb7": tb7}
    rows = {}
    pb_digests = {}
    for vid in sorted(index):
        path = os.path.join(s2, "vectors", vid, "pB.json")
        if not os.path.exists(path):
            continue
        b = read(path)
        pb_digests.setdefault(sha(b), []).append(vid)
        code, why = pb_check(b, mdig)
        lean = index[vid]["lean"]
        if code == "ok":
            expect_pb_fail = ("c1_profileFields" in lean or "c1_profileDecode" in lean or index[vid]["tb7"] == "REJECT")
            agree = not expect_pb_fail
        elif code == "tb7_manifestDigest":
            agree = index[vid]["tb7"] == "REJECT"
        else:
            agree = code in lean
        rows[vid] = {"pB_level": code, "detail": why, "expected": lean, "tb7": index[vid]["tb7"], "agree": agree}
    return {"verifier_manifest_sha256": mdig, "rows": rows,
            "agree": sum(r["agree"] for r in rows.values()), "total": len(rows),
            "distinct_pB": len(pb_digests),
            "not_ok": {k: v["pB_level"] for k, v in rows.items() if v["pB_level"] != "ok"}}


def check_preclosure_k(root):
    text = read(os.path.join(root, "p10-coverage-lean-s2/profile/S2_PREREG_v0.2.6.md")).decode("utf-8")
    rows = {}
    for line in text.splitlines():
        m = re.match(r"^\| S2-(K[1-7]) .*?`(\[.*?\]|\{\"preclosure_view\":\[\]\})`.*`([0-9a-f]{64})` \|\s*$", line)
        if not m:
            continue
        kid, lit, dig = m.groups()
        view = [] if lit.startswith("{") else json.loads(lit)
        got = sha(jcs_bytes({"preclosure_view": view}))
        rows[kid] = {"expected": dig, "got": got, "agree": got == dig}
    return {"rows": rows, "agree": sum(r["agree"] for r in rows.values()), "total": len(rows)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "repos"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "checks-b.json"))
    a = ap.parse_args()
    res = {
        "pins": check_pins(a.repos),
        "s1_vectors": check_s1_vectors(a.repos),
        "s1_toy_m2": check_s1_toy_m2(),
        "s1_statement_digests": check_s1_statement(a.repos),
        "s1_statement_limitations": check_s1_limitations(a.repos),
        "s2a_pB_strict": check_s2a_pb(a.repos),
        "s2a_preclosure_k": check_preclosure_k(a.repos),
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    s = res
    print("pins all equal:", s["pins"]["all_equal"])
    print("S1 vectors: %d/%d agree" % (s["s1_vectors"]["agree"], s["s1_vectors"]["total"]))
    print("M2 toy:", s["s1_toy_m2"]["agree"])
    print("S1 statement digests:", s["s1_statement_digests"]["digests"], s["s1_statement_digests"]["limitations"]["reproduced_by_jcs_array"], s["s1_statement_digests"]["m35"]["statement_records_it"])
    print("S1 limitations:", {k: v for k, v in s["s1_statement_limitations"].items() if k != "ids"})
    print("S2a pB: %d/%d agree; not ok: %s" % (s["s2a_pB_strict"]["agree"], s["s2a_pB_strict"]["total"], s["s2a_pB_strict"]["not_ok"]))
    print("S2a K: %d/%d agree" % (s["s2a_preclosure_k"]["agree"], s["s2a_preclosure_k"]["total"]))


if __name__ == "__main__":
    sys.exit(main())
