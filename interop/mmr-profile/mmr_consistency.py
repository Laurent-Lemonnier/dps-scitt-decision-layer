#!/usr/bin/env python3.12
"""Second half of the MMR test: the receipt of consistency (sections 6 and 7 of draft-bryce-cose-receipts-mmr-profile-03),
which is where an MMR log states its size. Same rules as mmr_test.py (from the text of -03 alone, synthetic log and key;
functions imported from mmr_test.py, with its readings A and B).

Question: a consistency receipt carries tree-size-1 and tree-size-2 inside the unprotected header; the signature covers
the accumulator (the peaks) of tree-size-2. Are the two sizes bound by the signature, or can they be changed?

Three verifiers, all from section 7.1:
  literal  steps 1 to 9 as written: tree-size-2 is only used to count the peaks to discard, and the remaining peaks are
           those the proof supplies (right-peaks), so nothing compares the count;
  counted  as literal, plus: the number of right-peaks is the number of peaks of tree-size-2 left after the roots;
  strict   as counted, plus the SHOULD of 7.1: each consistency path has the length inclusion_proof_path gives for the
           stated sizes.
Every verifier also applies the MUST of 7.1.1 (as many peaks for tree-size-1 as values in the accumulator held).

Two more places where the text leaves a choice, noted and tested:
  C. The detached payload is "the consistent accumulator", a list of peaks; the text does not say how a list is turned
     into the bytes signed. Used: a CBOR array of bstr; the concatenation is run too, with the same outcome.
  D. Section 6.1 builds right-peaks by "discarding length(proofs) from the left" of the peaks of tree-size-2; section
     7.1 step 7 discards "the number of roots returned by consistent_roots". When several peaks of tree-size-1 end
     under the same peak of tree-size-2, the two differ. Both are tested; the receipt is built with the reading that
     verifies.

What it finds (consistency-results.json): the sizes are not bound by the signature. The verification of 7.1 never maps
the accumulator to positions in tree-size-2: the roots come from the peaks of tree-size-1 and their paths, and the
signature covers the list of peak values. A different tree-size-2 is therefore accepted whenever it gives the same
number of peaks and, for the strict verifier, the same path lengths (for 100 -> 200 leaves, twenty other sizes
between 131 and 224 leaves). Tree-size-1 is held by the strict verifier; the two others accept another one when a path is empty.
A chain of consistency receipts catches a wrong size at the next link (positions change); a single receipt does not.

Usage: mmr_consistency.py  -> writes consistency-results.json next to this script; exit 0 when the expectations hold.
"""
import json
import os
import sys

import cbor2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mmr_test import (KEY, PUB, VDS_MMR, build, inclusion_proof_path, included_root, peaks)  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402

PROTECTED = cbor2.dumps({1: -19, 395: VDS_MMR}, canonical=True)
ENCODINGS = {"cbor_array": lambda acc: cbor2.dumps(list(acc)), "concatenation": lambda acc: b"".join(acc)}


def mmr_size(leaves): return 2 * leaves - bin(leaves).count("1")
def tbs(acc, enc): return cbor2.dumps(["Signature1", PROTECTED, b"", ENCODINGS[enc](acc)])


def consistency_proof_paths(ifrom, ito):                                       # 6.1
    return [inclusion_proof_path(i, ito) for i in peaks(ifrom)]


def consistent_roots(ifrom, accfrom, proofs):                                  # 7.1.1
    frompeaks = peaks(ifrom)
    if len(frompeaks) != len(proofs) or len(frompeaks) != len(accfrom):
        return None
    roots = []
    for i in range(len(accfrom)):
        root = included_root(frompeaks[i], accfrom[i], proofs[i])
        if roots and roots[-1] == root:
            continue
        roots.append(root)
    return roots


def make_receipt(db, s1, s2, enc, discard="roots"):
    ifrom, ito = s1 - 1, s2 - 1
    accfrom = [db[p] for p in peaks(ifrom)]
    paths = [[db[j] for j in p] for p in consistency_proof_paths(ifrom, ito)]
    roots = consistent_roots(ifrom, accfrom, paths)
    peaks2 = [db[p] for p in peaks(ito)]
    n = len(roots) if discard == "roots" else len(paths)                      # reading D
    right = peaks2[n:]
    signature = KEY.sign(tbs(peaks2, enc))                                     # the service signs its accumulator
    proof = cbor2.dumps([s1, s2, paths, right])
    receipt = cbor2.dumps(cbor2.CBORTag(18, [PROTECTED, {396: {-2: [proof]}}, None, signature]))
    return receipt, accfrom


def verify(receipt, accfrom, enc, mode, s1=None, s2=None):
    """7.1 for a single consistency-proof; s1 and s2 override the stated sizes to test a modified receipt."""
    protected, unprotected, payload, signature = cbor2.loads(receipt).value
    t1, t2, paths, right = cbor2.loads(unprotected[396][-2][0])
    t1 = t1 if s1 is None else s1
    t2 = t2 if s2 is None else s2
    if payload is not None or t1 < 1 or t2 < t1:
        return False
    roots = consistent_roots(t1 - 1, accfrom, paths)
    if roots is None:
        return False
    if mode in ("counted", "strict") and len(peaks(t2 - 1)) - len(roots) != len(right):
        return False
    if mode == "strict" and [len(p) for p in paths] != [len(inclusion_proof_path(i, t2 - 1)) for i in peaks(t1 - 1)]:
        return False
    try:
        PUB.verify(signature, tbs(roots + list(right), enc))
        return True
    except InvalidSignature:
        return False


def main():
    LEAVES = 400
    db, _ = build(LEAVES)
    valid_sizes = [mmr_size(n) for n in range(1, LEAVES + 1)]
    pairs = [(1, 2), (3, 5), (37, 300), (100, 200), (128, 255), (128, 256), (199, 200), (200, 201), (200, 400)]
    expect, cases = [], []
    for enc in ENCODINGS:
        for l1, l2 in pairs:
            s1, s2 = mmr_size(l1), mmr_size(l2)
            per_reading = {}
            for discard in ("roots", "proofs"):
                r, accfrom = make_receipt(db, s1, s2, enc, discard)
                per_reading[discard] = verify(r, accfrom, enc, "counted")
            receipt, accfrom = make_receipt(db, s1, s2, enc, "roots")
            case = {"encoding": enc, "from_leaves": l1, "to_leaves": l2, "tree_size_1": s1, "tree_size_2": s2,
                    "D_receipt_built_discarding_roots_verifies": per_reading["roots"],
                    "D_receipt_built_discarding_len_proofs_verifies": per_reading["proofs"]}
            for mode in ("literal", "counted", "strict"):
                case[mode + "_genuine"] = verify(receipt, accfrom, enc, mode)
                case[mode + "_other_tree_size_2_accepted"] = [
                    s for s in valid_sizes if s != s2 and s >= s1 and verify(receipt, accfrom, enc, mode, s2=s)]
                case[mode + "_other_tree_size_1_accepted"] = [
                    s for s in valid_sizes if s != s1 and s <= s2 and verify(receipt, accfrom, enc, mode, s1=s)]
            cases.append(case)
            tag = f"{enc} {l1}->{l2} leaves"
            expect.append((f"{tag}: genuine receipt verifies (all three verifiers)",
                           all(case[m + "_genuine"] for m in ("literal", "counted", "strict"))))
            expect.append((f"{tag}: the strict verifier accepts no other tree-size-1",
                           not case["strict_other_tree_size_1_accepted"]))
    summary = {m: sum(1 for c in cases if c[m + "_other_tree_size_2_accepted"]) for m in ("literal", "counted", "strict")}
    # the finding, asserted so that a rerun reproduces it
    expect.append(("finding: every verifier, the strict one included, accepts another tree-size-2 for some receipts",
                   all(summary[m] > 0 for m in summary)))
    expect.append(("finding: the literal and counted verifiers accept another tree-size-1 when a path is empty",
                   any(c["literal_other_tree_size_1_accepted"] for c in cases)))
    d_differs = [f'{c["from_leaves"]}->{c["to_leaves"]}' for c in cases if c["encoding"] == "cbor_array"
                 and c["D_receipt_built_discarding_len_proofs_verifies"] != c["D_receipt_built_discarding_roots_verifies"]]
    res = {"draft": "draft-bryce-cose-receipts-mmr-profile-03", "log_leaves": LEAVES, "log_nodes": len(db),
           "cases_where_another_tree_size_2_is_accepted": summary, "D_pairs_where_6_1_and_7_1_disagree": d_differs,
           "cases": cases, "expectations": [{"what": w, "holds": h} for w, h in expect]}
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "consistency-results.json")
    with open(out, "w") as fh:
        json.dump(res, fh, indent=1); fh.write("\n")
    for w, h in expect:
        if not h:
            print("FAIL", w)
    for c in cases:
        if c["encoding"] == "cbor_array":
            print(json.dumps({k: (v if not isinstance(v, list) else (len(v), v[:6])) for k, v in c.items()
                              if k not in ("encoding",)}))
    print("other tree-size-2 accepted, cases out of", len(cases), ":", summary)
    print("D: pairs where building right-peaks per 6.1 fails 7.1:", d_differs)
    ok = all(h for _, h in expect)
    print("PASS" if ok else "FAIL", len(expect), "expectations")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
