#!/usr/bin/env python3.12
"""Does a receipt of the MMR profile (draft-bryce-cose-receipts-mmr-profile-03) bind the position of its entry, and
what does it say about the log size? The question raised on scitt@ietf.org on 15 November 2026 for RFC 9162 receipts
(Bassem Kudsi, "RFC 9942 inclusion receipts: tree-size is not authenticated by the signed root"), asked of the MMR
profile after Jon Geater's reply pointing to it.

Written from the text of -03 alone (its SHA-256 is checked below); no code of the authors read or run; the draft gives
no vectors. The log, its leaves and the signing key are synthetic. Ed25519 from `cryptography`, CBOR from `cbor2`.

Two places where the text, read literally, does not work; both readings are tested and the working one is used:
  A. Appendix A.4 `all_ones` computes `mask = (1 << (msb + 1)) - 1`, but `msb` is already the mask of the most
     significant bit (A.2), so all_ones(1), all_ones(3), all_ones(7) are False and `index_height(0)` (9.1) never ends.
     Used: `mask = (msb << 1) - 1`, which is what the prose of A.4 describes.
  B. Section 8 says `db.append(entry) -> index` without saying which index. If it is the index of the entry just
     appended, `add_leaf_hash` merges at the wrong moments and the log is malformed (peaks of heights 7, 6, 2, 1, 0, 0
     after 200 leaves). If it is the index the next entry will take (the new size), the log is well formed.
     Used: the new size.

Usage: mmr_test.py DRAFT.txt   -> writes results.json next to this script; exit code 0 when every expectation holds.
"""
import hashlib
import json
import os
import sys

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TEXT_SHA256 = "fba4838118dad19733ab6c6dbdcb92f799ccfa35db38ae3a6c1e17b84b8b56d7"
VDS_MMR = 3            # "TBD_1 (requested assignment 3)"
H = lambda b: hashlib.sha256(b).digest()


# ---- Appendix A and section 9
def most_sig_bit(pos): return 1 << (pos.bit_length() - 1)
def all_ones_as_written(pos):
    msb = most_sig_bit(pos)
    return pos == (1 << (msb + 1)) - 1
def all_ones(pos): return pos == (most_sig_bit(pos) << 1) - 1          # reading A
def index_height(i, ones=all_ones, cap=None):
    pos, n = i + 1, 0
    while not ones(pos):
        pos = pos - most_sig_bit(pos) + 1
        n += 1
        if cap and n > cap:
            return None
    return pos.bit_length() - 1
def log2floor(x): return x.bit_length() - 1
def peaks(i):
    peak, out, s = 0, [], i + 1
    while s != 0:
        highest = (1 << log2floor(s + 1)) - 1
        peak += highest
        out.append(peak - 1)
        s -= highest
    return out


# ---- section 8
def hash_pospair64(pos, a, b): return H(pos.to_bytes(8, "big") + a + b)
class DB(list):
    def __init__(self, returns_new_size=True):
        super().__init__(); self.new_size = returns_new_size
    def append_(self, e):
        self.append(e)
        return len(self) if self.new_size else len(self) - 1             # reading B (or the other one)
def add_leaf_hash(db, f):
    g = 0
    i = db.append_(f)
    while index_height(i) > g:
        ileft, iright = i - (2 << g), i - 1
        i = db.append_(hash_pospair64(i + 1, db[ileft], db[iright]))
        g += 1


# ---- sections 4.1 and 5.2
def inclusion_proof_path(i, c):
    path, g = [], index_height(i)
    while True:
        off = 2 << g
        if index_height(i + 1) > g:
            isib = i - off + 1; i += 1
        else:
            isib = i + off - 1; i += off
        if isib > c:
            return path
        path.append(isib); g += 1
def included_root(i, nodehash, proof):
    root, g = nodehash, index_height(i)
    for sib in proof:
        if index_height(i + 1) > g:
            i = i + 1; root = hash_pospair64(i + 1, sib, root)
        else:
            i = i + (2 << g); root = hash_pospair64(i + 1, root, sib)
        g += 1
    return root


# ---- section 5: the receipt (payload = the peak, detached), and 5.1: its verification
KEY = Ed25519PrivateKey.from_private_bytes(H(b"mmr-receipt-size test key, public by design"))
PUB = KEY.public_key()
PROTECTED = cbor2.dumps({1: -19, 395: VDS_MMR}, canonical=True)
def sig_structure(payload): return cbor2.dumps(["Signature1", PROTECTED, b"", payload])
def make_receipt(db, i, c):
    proof = [db[j] for j in inclusion_proof_path(i, c)]
    peak = included_root(i, db[i], proof)
    assert peak in [db[p] for p in peaks(c)], "the payload of a receipt is a peak of MMR(c+1)"
    receipt = cbor2.dumps(cbor2.CBORTag(18, [PROTECTED, {396: {-1: [cbor2.dumps([i, proof])]}}, None,
                                             KEY.sign(sig_structure(peak))]))
    return receipt, peak
def verify(leaf_hash, receipt, index=None, path=None):
    """5.1; index and path may be overridden to test a modified receipt (the signature is left as it is)."""
    protected, unprotected, payload, signature = cbor2.loads(receipt).value
    i, proof = cbor2.loads(unprotected[396][-1][0])
    i = i if index is None else index
    proof = proof if path is None else path
    if payload is not None or cbor2.loads(protected).get(395) != VDS_MMR:
        return False
    try:
        PUB.verify(signature, cbor2.dumps(["Signature1", protected, b"", included_root(i, leaf_hash, proof)]))
        return True
    except InvalidSignature:
        return False


def build(n_leaves, returns_new_size=True):
    db, leaf_index = DB(returns_new_size), []
    for n in range(n_leaves):
        leaf_index.append(len(db)); add_leaf_hash(db, H(b"entry %d" % n))
    return db, leaf_index


def sizes_where_peak(db_final, node_index, leaf_count_max):
    """The log sizes (in leaves) for which this node is a peak, i.e. for which the receipt is the one the log would
    issue. Outside that range the node is not a peak yet (absent) or no longer (buried under a parent)."""
    out = []
    for n in range(1, leaf_count_max + 1):
        size = 2 * n - bin(n).count("1")
        if node_index < size and node_index in peaks(size - 1):
            out.append(n)
    return (out[0], out[-1]) if out else None


def main():
    if len(sys.argv) < 2 or hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest() != TEXT_SHA256:
        print("give the text of draft-bryce-cose-receipts-mmr-profile-03 (sha256 %s)" % TEXT_SHA256); return 2
    expect, res = [], {"draft": "draft-bryce-cose-receipts-mmr-profile-03", "text_sha256": TEXT_SHA256}

    # A. all_ones as written
    res["A_all_ones_as_written"] = {str(p): all_ones_as_written(p) for p in (1, 3, 7, 15)}
    res["A_index_height_0_as_written_ends"] = index_height(0, all_ones_as_written, cap=10_000) is not None
    expect.append(("A: as written, index_height(0) does not end", not res["A_index_height_0_as_written_ends"]))

    # B. the two readings of append -> index
    for name, flag in (("index_of_entry", False), ("new_size", True)):
        try:
            db, _ = build(200, flag)
            hs = [index_height(p) for p in peaks(len(db) - 1)]
            res["B_append_returns_" + name] = {"nodes": len(db), "peak_heights": hs,
                                               "well_formed": len(db) == 397 and hs == sorted(set(hs), reverse=True)}
        except Exception as e:  # noqa: BLE001
            res["B_append_returns_" + name] = {"error": repr(e)}
    expect.append(("B: index of the entry gives a malformed log",
                   not res["B_append_returns_index_of_entry"].get("well_formed", False)))
    expect.append(("B: new size gives a well-formed log (200 leaves -> 397 nodes)",
                   res["B_append_returns_new_size"]["well_formed"]))

    # The test proper, on a log of 200 entries, then grown to 400
    N, GROW = 200, 400
    db, leaf_index = build(N)
    grown, _ = build(GROW)
    c = len(db) - 1
    cases = []
    for n in (0, 1, 7, 64, 100, 128, 199):
        i = leaf_index[n]; f = db[i]
        receipt, peak = make_receipt(db, i, c)
        _, unp, _, _ = cbor2.loads(receipt).value
        _, proof = cbor2.loads(unp[396][-1][0])
        peak_node = db.index(peak)
        case = {
            "entry": n, "mmr_index": i, "path_length": len(proof), "signed_peak_node": peak_node,
            "receipt_sha256": H(receipt).hex(),
            "genuine_verifies": verify(f, receipt),
            "other_indexes_accepted_0_to_%d" % (2 * len(grown)): [j for j in range(2 * len(grown))
                                                                  if j != i and verify(f, receipt, index=j)],
            "other_entry_accepted": verify(H(b"not an entry"), receipt),
            "path_shortened_accepted": bool(proof) and verify(f, receipt, path=proof[:-1]),
            "path_extended_accepted": verify(f, receipt, path=proof + [H(b"x")]),
            "log_sizes_in_entries_where_this_receipt_is_current": sizes_where_peak(grown, peak_node, GROW),
            "signed_peak_still_a_node_after_growth_to_%d" % GROW: grown[peak_node] == peak,
        }
        cases.append(case)
        expect.append((f"entry {n}: genuine receipt verifies", case["genuine_verifies"]))
        expect.append((f"entry {n}: no other index accepted", not case["other_indexes_accepted_0_to_%d" % (2 * len(grown))]))
        expect.append((f"entry {n}: other entry, shorter or longer path refused",
                       not (case["other_entry_accepted"] or case["path_shortened_accepted"] or case["path_extended_accepted"])))
    # The edge case Bassem Kudsi reported on scitt@ietf.org (15 November 2026, 15:38 UTC): when the entry is itself a
    # peak (the last leaf at an odd leaf count), the path is empty, the payload is the leaf hash and the index is not
    # used. Reproduced here at every odd leaf count from 1 to 119.
    empty = []
    for n in range(1, 120, 2):
        dbn, ln = build(n)
        i, cn = ln[-1], len(dbn) - 1
        r, _ = make_receipt(dbn, i, cn)
        empty.append(all(verify(dbn[i], r, index=j) for j in range(2 * len(dbn)) if j != i))
    res["empty_path_receipts"] = {"odd_leaf_counts_1_to_119": len(empty), "verify_at_every_other_index": sum(empty)}
    expect.append(("edge case: a receipt whose entry is a peak (empty path) verifies at every index",
                   all(empty) and len(empty) == 60))
    res["log"] = {"entries": N, "nodes": len(db), "grown_to_entries": GROW, "grown_nodes": len(grown)}
    res["cases"] = cases
    res["expectations"] = [{"what": w, "holds": h} for w, h in expect]
    res["reading"] = (
        "Each interior hash commits to its one-based position (8.2.1, hash_pospair64), so the receipt's index is bound: "
        "the same path and signature verify at the entry's index and at no other index tried, except when the path is empty "
        "(the entry is itself a peak; the index is then not used at all). The receipt states no log "
        "size: there is no size in [index, path], and the signed payload is a peak, which is the same for every log size "
        "in the range shown; once the log grows past it, the peak is buried but still a node, and the old receipt still "
        "verifies against it. Size, and freshness, come from elsewhere (a signed accumulator, a consistency receipt).")
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.json")
    with open(out, "w") as fh:
        json.dump(res, fh, indent=1); fh.write("\n")
    for w, h in expect:
        print("ok  " if h else "FAIL", w)
    for case in cases:
        print(json.dumps({k: v for k, v in case.items() if k != "receipt_sha256"}))
    ok = all(h for _, h in expect)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
