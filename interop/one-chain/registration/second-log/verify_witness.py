"""Independent check of the four receipts returned by witness.agentactioncapsule.org on 14 November 2026 for the
four Signed Statements of this folder. Written from RFC 9162 section 2.1.3.2 and the operator's description of the
entry (entry = SHA-256(Sig_structure), leaf = SHA-256(0x00 || entry)); no code of the operator read or run.
Needs cbor2 and cryptography. Usage: python3 verify_witness.py   (exit 0 when all four verify)"""
import base64, hashlib, json, pathlib, sys
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

HERE = pathlib.Path(__file__).resolve().parent
rdir, sdir, did = HERE, HERE.parent, HERE / "witness-did.2026-11-14.json"
EXPECT = {"action-binding-attachment-a1": (23909, 23910), "action-binding-attachment-a2": (23910, 23911),
          "verdict-record": (23911, 23912), "dispute-packet": (23912, 23913)}
H = lambda b: hashlib.sha256(b).digest()
jwk = json.loads(did.read_text())["verificationMethod"][0]["publicKeyJwk"]
assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"
key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4)))

def untag(raw):
    o = cbor2.loads(raw)
    return (o.tag, o.value) if isinstance(o, cbor2.CBORTag) else (None, o)

def root_from(leaf_hash, leaf_index, tree_size, path):
    """RFC 9162 section 2.1.3.2."""
    if leaf_index >= tree_size: return None
    fn, sn, r = leaf_index, tree_size - 1, leaf_hash
    for p in path:
        if sn == 0: return None
        if fn & 1 or fn == sn:
            r = H(b"\x01" + p + r)
            if not fn & 1:
                while fn and not fn & 1: fn >>= 1; sn >>= 1
        else:
            r = H(b"\x01" + r + p)
        fn >>= 1; sn >>= 1
    return r if sn == 0 else None

roots = {}
ok_all = True
for name, (exp_leaf, exp_size) in EXPECT.items():
    st = (sdir / f"{name}.signed-statement.cose").read_bytes()
    _, (sprot, _, spayload, _) = untag(st)
    entry = H(cbor2.dumps(["Signature1", sprot, b"", spayload], canonical=True))
    leaf = H(b"\x00" + entry)
    rc = (rdir / f"{name}.receipt.cose").read_bytes()
    tag, (prot, unprot, payload, sig) = untag(rc)
    ph = cbor2.loads(prot)
    proofs = unprot[396][-1]
    tree_size, leaf_index, path = cbor2.loads(proofs[0])
    root = root_from(leaf, leaf_index, tree_size, path)
    res = {"tag": tag, "protected": {k: (v if not isinstance(v, dict) else v) for k, v in ph.items()},
           "unprotected_labels": sorted(unprot), "payload_detached": payload is None, "n_proofs": len(proofs),
           "leaf_index": leaf_index, "tree_size": tree_size, "path_len": len(path),
           "index_and_size_as_stated": (leaf_index, tree_size) == (exp_leaf, exp_size)}
    sig_ok = False
    if root is not None:
        try:
            key.verify(sig, cbor2.dumps(["Signature1", prot, b"", root], canonical=True)); sig_ok = True
        except InvalidSignature: pass
    # negative controls: another statement's leaf, and one flipped bit in the path
    other = H(b"\x00" + H(b"other"))
    r2 = root_from(other, leaf_index, tree_size, path)
    neg1 = True
    if r2 is not None:
        try: key.verify(sig, cbor2.dumps(["Signature1", prot, b"", r2], canonical=True)); neg1 = False
        except InvalidSignature: pass
    bad = [bytes([path[0][0] ^ 1]) + path[0][1:]] + list(path[1:]) if path else path
    r3 = root_from(leaf, leaf_index, tree_size, bad)
    neg2 = True
    if r3 is not None and path:
        try: key.verify(sig, cbor2.dumps(["Signature1", prot, b"", r3], canonical=True)); neg2 = False
        except InvalidSignature: pass
    res.update({"inclusion_root": root.hex() if root else None, "receipt_signature": "verified" if sig_ok else "FAILED",
                "negative_other_leaf_rejected": neg1, "negative_flipped_path_rejected": neg2,
                "entry": entry.hex(), "leaf": leaf.hex(), "receipt_sha256": H(rc).hex()})
    roots[name] = (tree_size, root.hex() if root else None)
    ok_all &= sig_ok and res["index_and_size_as_stated"] and neg1 and neg2
    print(json.dumps({name: res}, indent=1, default=str))
print("ALL FOUR VERIFIED" if ok_all else "NOT ALL VERIFIED")
sys.exit(0 if ok_all else 1)
