#!/usr/bin/env python3
"""The receipts ts.isoluce.net gave for this case, checked offline (README.md, Registration).

Two Signed Statements were registered on 16 November 2026: the Signed Statement of Section 6 (the receipt's canonical
bytes under the receipt's own key, out/section-6.signed-statement.cose) and, as the parent case does for its packet, the
file of the whole dispute packet under the issuer key of ../registration. For each, the Receipt kept at registration is
verified by the reader of ../../receipt-size (written from RFC 9942 Section 5.2.1, RFC 9162 Section 2.1.3.2 and RFC 9052
Section 4.4; no code of the service) against the service's key set pinned in ../../receipt-size/vectors/scitt-keys.cbor
on 15 November 2026: the inclusion proof reaches a root, the signature verifies over that root, and the tree size and
leaf index in the protected header equal those of the proof. Nothing is fetched.

-02 Section 6: "A Receipt that is only structurally valid MUST NOT be reported as verified": three altered copies of the
first Receipt (given the other statement; one bit of its signature changed; one bit of its inclusion path changed) must
each be refused. -02 Section 11: "Verifiers MUST report producer-claimed time and registration time separately": the
report gives the receipt's timestamp and the Receipt's iat as two values and compares neither with the other.

Writes registration/result.json. Exit 0 when both Receipts verify, the three altered copies are refused and the
statements carry the bytes of out/.
"""
import datetime
import hashlib
import importlib.util
import json
import pathlib
import sys

import cbor2

import letter as L

HERE = pathlib.Path(__file__).resolve().parent
REG, OUT, RS = HERE / "registration", HERE / "out", HERE.parent.parent / "receipt-size"
_spec = importlib.util.spec_from_file_location("verify_receipt", RS / "verify_receipt.py")
VR = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VR)

PAIRS = {"section-6": (OUT / "section-6.signed-statement.cose", REG / "section-6.receipt.cose"),
         "dispute-packet": (REG / "dispute-packet.signed-statement.cose", REG / "dispute-packet.receipt.cose")}


def service_keys():
    out = {}
    for k in cbor2.loads((RS / "vectors" / "scitt-keys.cbor").read_bytes()):
        if k.get(1) == 1 and k.get(-1) == 6:
            kid = k.get(2)
            out[kid.decode() if isinstance(kid, bytes) else kid] = VR.Ed25519PublicKey.from_public_bytes(k[-2])
    return out


def flip(receipt, where):
    """A copy of the Receipt with one bit changed: in its signature, or in the first hash of its inclusion path."""
    protected, unprotected, payload, signature = cbor2.loads(receipt).value
    if where == "signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
        proofs = list(unprotected[396][-1])
    else:
        size, index, path = cbor2.loads(unprotected[396][-1][0])
        path = [bytes([path[0][0] ^ 1]) + path[0][1:]] + list(path[1:]) if path else [bytes(32)]
        proofs = [cbor2.dumps([size, index, path])]
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {396: {-1: proofs}}, payload, signature]))


def main():
    keys = service_keys()
    packet = json.loads((OUT / "dispute-packet.json").read_text(encoding="utf-8"))
    res = {"service": "https://ts.isoluce.net", "service_keys": "interop/receipt-size/vectors/scitt-keys.cbor (pinned 15 November 2026)",
           "reader": "interop/receipt-size/verify_receipt.py", "receipts": {}}
    ok = True
    for name, (sp, rp) in PAIRS.items():
        statement, receipt = sp.read_bytes(), rp.read_bytes()
        v = VR.verify(statement, receipt, keys)
        claims = cbor2.loads(cbor2.loads(receipt).value[0]).get(15) or {}
        iat = claims.get(6)
        res["receipts"][name] = {
            "statement": str(sp.relative_to(HERE)), "statement_sha256": hashlib.sha256(statement).hexdigest(),
            "receipt": str(rp.relative_to(HERE)), "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
            "entry_id": hashlib.sha256(b"\x00" + statement).hexdigest(),
            "verified": bool(v.get("ok")), "size_and_index_signed": bool(v.get("size_and_index_signed")),
            "leaf_index": v.get("leaf_index"), "tree_size": v.get("tree_size"), "root_hex": v.get("root_hex"),
            "kid": v.get("kid"), "error": v.get("error"),
            "registration_time_the_service_states": datetime.datetime.fromtimestamp(iat, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if isinstance(iat, int) else None}
        ok &= bool(v.get("ok")) and bool(v.get("size_and_index_signed"))
    # what each statement carries
    s6 = L.check_statement(PAIRS["section-6"][0].read_bytes(), packet, public_key_hex=json.loads((OUT / "keys.json").read_text())["ed25519_public_key_raw_hex"])
    packet_payload = L.parse_sign1(PAIRS["dispute-packet"][0].read_bytes())[3]
    res["statements"] = {"section-6 is the Signed Statement of Section 6 for out/dispute-packet.json (letter.check_statement)": s6["result"] == "VERIFIED",
                         "the dispute-packet statement's payload is out/dispute-packet.json, byte for byte": packet_payload == (OUT / "dispute-packet.json").read_bytes()}
    ok &= all(res["statements"].values())
    # -02 Section 6: a Receipt that is only structurally valid is not verified
    st6, r6 = PAIRS["section-6"][0].read_bytes(), PAIRS["section-6"][1].read_bytes()
    altered = {"the Receipt of the Section 6 statement, given the dispute-packet statement": VR.verify(PAIRS["dispute-packet"][0].read_bytes(), r6, keys),
               "one bit of its signature changed": VR.verify(st6, flip(r6, "signature"), keys),
               "one bit of the first hash of its inclusion path changed": VR.verify(st6, flip(r6, "path"), keys)}
    res["altered_receipts_refused"] = {k: {"refused": not v.get("ok"), "error": v.get("error")} for k, v in altered.items()}
    ok &= all(x["refused"] for x in res["altered_receipts_refused"].values())
    # -02 Section 11: the two times, reported separately
    res["times"] = {"producer_claimed (the dispute receipt's timestamp; not trusted time)": packet["receipt"]["payload"]["timestamp"],
                    "registration (the iat of the Transparency Service's Receipt of the Section 6 statement; the service's statement, "
                    "an upper bound only as far as the service is trusted)": res["receipts"]["section-6"]["registration_time_the_service_states"]}
    res["all_as_expected"] = bool(ok)
    (REG / "result.json").write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
