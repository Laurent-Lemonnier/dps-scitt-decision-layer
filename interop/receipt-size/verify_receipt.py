#!/usr/bin/env python3
"""verify_receipt.py: an independent reader of a Receipt of inclusion, written from the text of RFC 9942 section
5.2.1, RFC 9162 section 2.1.3.2 and RFC 9052 section 4.4. It shares no code with the service.

  verify_receipt.py --statement signed-statement.cose --receipt receipt.cose \
      (--key-pem service-public.pem | --scitt-keys keys.cbor | --jwks jwks.json) [--expect-root HEX]
      [--checkpoint checkpoint.cose] [--json]

Steps (RFC 9942 section 5.2.1): 1. apply the inclusion proof to the bytes of the candidate entry (the registered
Signed Statement; leaf = SHA-256(0x00 || entry), RFC 9162 section 2.1.1), reaching a root; 2. verify the COSE_Sign1
signature with that root as the detached payload. Exit code 0 when both hold, 1 otherwise.

The Receipt's signature covers the root, not the tree size, which sits in the unprotected header: the same inclusion
path can reach the same root under several tree sizes, and, with the size free, under other leaf indexes (scitt@ietf.org,
"RFC 9942 inclusion receipts: tree-size is not authenticated by the signed root", 15 November 2026; reproduced on this
service's receipts). A Receipt alone therefore establishes that the statement is in the tree whose root the key signed,
not its position nor the log size. With --checkpoint, the reader also verifies a signed tree head of the service (its
checkpoint.cose: payload [tree_size, root], signed with the same key) and requires the Receipt's size and root to be
the checkpoint's: only then are the size, and through it the leaf index, bound.

Receipts of ts.isoluce.net issued after its README A16 also carry tree_size and leaf_index in the protected header
(private-use labels -65537 and -65538). When they are present the reader requires them to equal the unprotected
proof's: the signature then binds the size and the index by itself, without a checkpoint.
"""
import argparse
import base64
import hashlib
import json
import sys
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALG, KID, CWT, VDS, VDP = 1, 4, 15, 395, 396
SIGNED_TREE_SIZE, SIGNED_LEAF_INDEX = -65537, -65538   # ts.isoluce.net's private-use labels (README A16)
ED25519, EDDSA = -19, -8
RFC9162_SHA256, INCLUSION = 1, -1


def sha256(b):
    return hashlib.sha256(b).digest()


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def root_from_path(leaf, index, size, path):
    """RFC 9162 section 2.1.3.2."""
    if index >= size:
        return None, "leaf_index >= tree_size (step 1)"
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None, "path longer than the tree (step 4.a)"
        if fn & 1 or fn == sn:
            r = sha256(b"\x01" + p + r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = sha256(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None, "path shorter than the tree (step 5)"
    return r, None


def sig_structure(protected, payload):
    """RFC 9052 section 4.4: ["Signature1", body_protected, external_aad = h'', payload]."""
    return cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)


def load_keys(args):
    """kid -> Ed25519 public key, from a PEM, a COSE Key Set (SCRAPI section 2.1) or a JWK Set."""
    keys = {}
    if args.key_pem:
        pub = serialization.load_pem_public_key(open(args.key_pem, "rb").read())
        keys[None] = pub  # kid unknown: compared by thumbprint below
    if args.scitt_keys:
        for k in cbor2.loads(open(args.scitt_keys, "rb").read()):
            if k.get(1) == 1 and k.get(-1) == 6:           # OKP, Ed25519 (RFC 9053 section 7.1)
                kid = k.get(2)
                keys[kid.decode() if isinstance(kid, bytes) else kid] = Ed25519PublicKey.from_public_bytes(k[-2])
    if args.jwks:
        for k in json.load(open(args.jwks))["keys"]:
            if k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
                keys[k.get("kid")] = Ed25519PublicKey.from_public_bytes(b64url_decode(k["x"]))
    return keys


def thumbprint_kid(pub):
    """RFC 9679 sections 3 and 4.1, as SCRAPI section 2.2 recommends for kid."""
    x = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(sha256(cbor2.dumps({1: 1, -1: 6, -2: x}, canonical=True))).rstrip(b"=").decode()


def read_checkpoint(raw, keys, kid):
    """A signed tree head of the service: tagged COSE_Sign1, payload attached = bstr .cbor [tree_size, root]."""
    item = cbor2.loads(raw)
    if not isinstance(item, cbor2.CBORTag) or item.tag != 18:
        return None, "checkpoint is not tagged 18"
    protected, _unprotected, payload, signature = item.value
    pmap = cbor2.loads(protected)
    if pmap.get(ALG) != ED25519 or pmap.get(VDS) != RFC9162_SHA256 or not isinstance(payload, bytes):
        return None, "checkpoint header or payload not as expected (alg -19, vds 1, payload attached)"
    ckid = pmap.get(KID)
    ckid = ckid.decode("utf-8", "replace") if isinstance(ckid, bytes) else ckid
    if ckid != kid:
        return None, f"checkpoint kid {ckid!r} is not the receipt's kid {kid!r}"
    key = keys.get(kid) or keys.get(None)
    try:
        key.verify(signature, sig_structure(protected, payload))
    except (InvalidSignature, AttributeError):
        return None, "checkpoint signature does not verify under the receipt's key"
    body = cbor2.loads(payload)
    if not (isinstance(body, list) and len(body) == 2 and isinstance(body[0], int) and isinstance(body[1], bytes)):
        return None, "checkpoint payload is not [tree_size, root]"
    return (body[0], body[1]), None


def verify(statement, receipt, keys, expect_root=None, checkpoint=None):
    out = {"findings": []}
    item = cbor2.loads(receipt)
    if not isinstance(item, cbor2.CBORTag) or item.tag != 18:
        return {**out, "ok": False, "error": "receipt is not tagged 18 (RFC 9942 section 4.3)"}
    protected, unprotected, payload, signature = item.value
    pmap = cbor2.loads(protected)
    out["protected_header"] = {str(k): (v.decode() if isinstance(v, bytes) and k == KID else
                                        v if not isinstance(v, dict) else {str(a): b for a, b in v.items()})
                               for k, v in pmap.items()}
    if payload is not None:
        out["findings"].append("payload attached; RFC 9942 section 4.4 wants it detached so that the verifier recomputes "
                               "the root (it is ignored here and the recomputed root is used)")
    alg = pmap.get(ALG)
    if alg == EDDSA:
        out["findings"].append("alg -8 (EdDSA), deprecated by RFC 9864 in favour of -19 (Ed25519)")
    elif alg != ED25519:
        return {**out, "ok": False, "error": f"alg {alg}: this reader knows -19 (and -8)"}
    if pmap.get(VDS) != RFC9162_SHA256:
        return {**out, "ok": False, "error": f"vds {pmap.get(VDS)!r}: this reader knows RFC9162_SHA256 (1)"}
    kid = pmap.get(KID)
    kid = kid.decode("utf-8", "replace") if isinstance(kid, bytes) else kid
    out["kid"] = kid
    # the key: by kid, or the PEM key if its thumbprint is the kid (or if it is the only key given)
    key = keys.get(kid)
    if key is None and None in keys:
        if kid is None or thumbprint_kid(keys[None]) == kid or len(keys) == 1:
            key = keys[None]
            if kid is not None and thumbprint_kid(key) != kid:
                out["findings"].append("the receipt's kid is not the RFC 9679 thumbprint of the PEM key given")
    if key is None:
        return {**out, "ok": False, "error": f"no key for kid {kid!r}"}
    vdp = unprotected.get(VDP)                               # cbor2 >= 6: a frozen map inside the tag, not a dict
    proofs = vdp.get(INCLUSION) if isinstance(vdp, Mapping) else None
    if not proofs or not isinstance(proofs[0], bytes):
        return {**out, "ok": False, "error": "no inclusion proof at label 396 key -1 (RFC 9942 section 5.2.1)"}
    size, index, path = cbor2.loads(proofs[0])
    if not (isinstance(size, int) and isinstance(index, int) and isinstance(path, list)
            and all(isinstance(p, bytes) and len(p) == 32 for p in path)):
        return {**out, "ok": False, "error": "inclusion proof is not [tree_size, leaf_index, [bstr]]"}
    out.update(tree_size=size, leaf_index=index, path_length=len(path))
    # ts.isoluce.net since README A16: the protected header repeats tree_size and leaf_index, so the signature covers them
    signed = {k: pmap.get(k) for k in (SIGNED_TREE_SIZE, SIGNED_LEAF_INDEX) if k in pmap}
    if signed:
        if (len(signed) != 2 or type(signed[SIGNED_TREE_SIZE]) is not int or type(signed[SIGNED_LEAF_INDEX]) is not int
                or signed[SIGNED_TREE_SIZE] != size or signed[SIGNED_LEAF_INDEX] != index):
            return {**out, "ok": False, "error": f"the signed tree size and leaf index {signed} are not those of the "
                                                 f"unprotected proof ({size}, {index})"}
        out["size_and_index_signed"] = True
    leaf = sha256(b"\x00" + statement)                      # RFC 9162 section 2.1.1
    out["leaf_hash_hex"] = leaf.hex()
    root, why = root_from_path(leaf, index, size, path)     # RFC 9942 section 5.2.1 step 1
    if root is None:
        return {**out, "ok": False, "error": f"inclusion proof does not reach a root: {why}"}
    out["root_hex"] = root.hex()
    if expect_root and root.hex() != expect_root.lower():
        return {**out, "ok": False, "error": "root reached differs from the root expected"}
    try:
        key.verify(signature, sig_structure(protected, root))  # RFC 9942 section 5.2.1 step 2, RFC 9052 section 4.4
    except InvalidSignature:
        return {**out, "ok": False, "error": "signature does not verify over the root reached"}
    if checkpoint is not None:
        head, why = read_checkpoint(checkpoint, keys, kid)
        if head is None:
            return {**out, "ok": False, "error": why}
        cp_size, cp_root = head
        out.update(checkpoint_tree_size=cp_size, checkpoint_root_hex=cp_root.hex())
        if cp_size != size or cp_root != root:
            return {**out, "ok": False, "error": f"the receipt's tree size {size} and root are not those of the signed "
                                                 f"checkpoint (tree size {cp_size}): position and size not established"}
        out["ok"] = True
        out["meaning"] = (f"key {kid} signed that the tree of size {size} has this root, and that this statement is in "
                          f"it at leaf {index} (size bound by the signed checkpoint); nothing more (not append-only, "
                          "not non-equivocation, no registration time asserted)")
        return out
    out["ok"] = True
    if out.get("size_and_index_signed"):
        out["meaning"] = (f"key {kid} signed that the tree of size {size} has this root and that this statement is in "
                          f"it at leaf {index} (size and index in the protected header); nothing more (not append-only, "
                          "not non-equivocation, no registration time asserted)")
        return out
    out["findings"].append("tree size and leaf index are not covered by the receipt's signature; give --checkpoint "
                           "to bind them to a signed tree head")
    out["meaning"] = (f"key {kid} signed a root of its log, and this statement is in the tree with that root; the "
                      f"stated tree size {size} and leaf {index} are not established by the receipt alone (not "
                      "append-only, not non-equivocation, no registration time asserted)")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--statement", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--key-pem")
    ap.add_argument("--scitt-keys")
    ap.add_argument("--jwks")
    ap.add_argument("--expect-root")
    ap.add_argument("--checkpoint", help="a signed tree head of the service (checkpoint.cose) to bind size and index")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    keys = load_keys(args)
    if not keys:
        ap.error("give --key-pem, --scitt-keys or --jwks")
    checkpoint = open(args.checkpoint, "rb").read() if args.checkpoint else None
    result = verify(open(args.statement, "rb").read(), open(args.receipt, "rb").read(), keys, args.expect_root,
                    checkpoint)
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print("OK" if result.get("ok") else f"FAILED: {result.get('error')}")
        for f in result.get("findings", []):
            print("finding:", f)
        if result.get("ok"):
            print(result["meaning"])
    sys.exit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
