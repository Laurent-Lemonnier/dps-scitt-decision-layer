#!/usr/bin/env python3
"""A receipt that signs its tree size and leaf index, and one that does not: what an edit of the unprotected proof
does to each. Offline; the vectors are receipts of ts.isoluce.net fetched on 15 November 2026 (README.md).

For each of the two receipts of the same statement (leaf 0, tree size 38), every pair (tree_size, leaf_index) with
tree_size from 1 to 128 replaces the pair of the unprotected proof; the path, the protected header and the signature
are left as issued. The reader of this folder (verify_receipt.py) then says which copies it accepts:
  - receipt-plain.cose        (RFC 9942 as is)            : accepted for several other pairs, as the scitt@ietf.org
                                                            thread of 15 November 2026 showed;
  - receipt-signed-size.cose  (labels -65537 and -65538)  : accepted for the issued pair only.
The same plain receipt, checked against the service's signed tree head (checkpoint.cose), is also accepted for the
issued size only. Writes results.json; exit 0 when the expectations hold.
"""
import importlib.util, json, os, sys
import cbor2

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("verify_receipt", os.path.join(HERE, "verify_receipt.py"))
VR = importlib.util.module_from_spec(spec); spec.loader.exec_module(VR)
V = os.path.join(HERE, "vectors")
STATEMENT = os.path.join(HERE, "..", "one-chain", "registration", "action-binding-attachment-a1.signed-statement.cose")
rd = lambda p: open(p, "rb").read()


def keys():
    out = {}
    for k in cbor2.loads(rd(os.path.join(V, "scitt-keys.cbor"))):
        if k.get(1) == 1 and k.get(-1) == 6:
            kid = k.get(2)
            out[kid.decode() if isinstance(kid, bytes) else kid] = VR.Ed25519PublicKey.from_public_bytes(k[-2])
    return out


def edited(receipt, size, index):
    prot, unp, pay, sig = cbor2.loads(receipt).value
    _s, _i, path = cbor2.loads(unp[396][-1][0])
    return cbor2.dumps(cbor2.CBORTag(18, [prot, {396: {-1: [cbor2.dumps([size, index, path])]}}, pay, sig]))


def main():
    st, K, cp = rd(STATEMENT), keys(), rd(os.path.join(V, "checkpoint.cose"))
    res, expect = {"statement": "interop/one-chain/registration/action-binding-attachment-a1.signed-statement.cose"}, []
    for name in ("receipt-plain", "receipt-signed-size"):
        r = rd(os.path.join(V, name + ".cose"))
        g = VR.verify(st, r, K)
        size, index = g["tree_size"], g["leaf_index"]
        alone = [[s, i] for s in range(1, 129) for i in range(s) if (s, i) != (size, index) and VR.verify(st, edited(r, s, i), K).get("ok")]
        with_cp = [[s, i] for s in range(1, 129) for i in range(s) if (s, i) != (size, index)
                   and VR.verify(st, edited(r, s, i), K, checkpoint=cp).get("ok")]
        res[name] = {"issued": [size, index], "genuine_verifies": bool(g.get("ok")),
                     "size_and_index_signed": bool(g.get("size_and_index_signed")),
                     "genuine_verifies_with_checkpoint": bool(VR.verify(st, r, K, checkpoint=cp).get("ok")),
                     "other_pairs_accepted_alone": alone, "other_pairs_accepted_with_checkpoint": with_cp,
                     "pairs_tried": sum(range(1, 129)) - 1}
    p, s = res["receipt-plain"], res["receipt-signed-size"]
    expect += [("both receipts verify as issued, alone and with the checkpoint",
                all(x[k] for x in (p, s) for k in ("genuine_verifies", "genuine_verifies_with_checkpoint"))),
               ("the plain receipt is accepted for other (size, index) pairs when read alone", len(p["other_pairs_accepted_alone"]) > 0),
               ("the plain receipt is accepted for the issued pair only when read with the signed tree head", not p["other_pairs_accepted_with_checkpoint"]),
               ("the signed-size receipt says so and is accepted for the issued pair only, alone",
                s["size_and_index_signed"] and not s["other_pairs_accepted_alone"])]
    res["expectations"] = [{"what": w, "holds": bool(h)} for w, h in expect]
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(res, f, indent=1); f.write("\n")
    for w, h in expect:
        print("ok  " if h else "FAIL", w)
    print(f"plain: {len(p['other_pairs_accepted_alone'])} other pairs accepted alone of {p['pairs_tried']} tried; "
          f"signed-size: {len(s['other_pairs_accepted_alone'])}")
    ok = all(h for _, h in expect)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
