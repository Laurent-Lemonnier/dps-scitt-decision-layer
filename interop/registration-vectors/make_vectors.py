#!/usr/bin/env python3
"""A baseline Signed Statement and fourteen variations, for trying the registration checks of a SCITT
Transparency Service.

R01 meets every MUST RFC 9943 Section 6 puts on a Signed Statement. One baseline and fourteen variations, each
testing one registration condition. The subject stays fixed unless the tested condition removes it; signatures change
when signed inputs or the signing key change. R09 adds a critical parameter together with its crit reference, and R11
changes the key and its kid. Deterministic: the two test keys come from fixed seeds, Ed25519 signatures are
deterministic, and the CBOR is written in its shortest form (except where the vector says otherwise).

  python3 make_vectors.py            # writes vectors/R*.cose, vectors/vectors.json and the two public keys

Needs cbor2 and cryptography. THE KEYS ARE TEST KEYS: their seeds are in this file, anyone can sign with them, and
they must never be configured as trust anchors outside a test.
"""
import hashlib
import json
import pathlib

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "vectors"
ISS = "https://example.org/registration-vectors"
KID = b"registration-vectors-test-1"
KID_UNKNOWN = b"registration-vectors-test-never-configured"
PAYLOAD = b'{"example":"registration vector"}'
ALG_ED25519, ALG_EDDSA = -19, -8


def key_from(label):
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("utf-8")).digest())


KEY = key_from("dps-scitt-decision-layer registration vectors, test key 1")
KEY_UNKNOWN = key_from("dps-scitt-decision-layer registration vectors, test key never configured")


SUB = "urn:example:registration-vector:R01"


def header(_vid):
    return {1: ALG_ED25519, 3: "application/json", 4: KID, 15: {1: ISS, 2: SUB}}


def statement(protected_map, *, key=KEY, unprotected=None, payload=PAYLOAD, tag=True, detach=False, spoil=False,
              long_array_head=False):
    """A COSE_Sign1 over Sig_structure("Signature1", protected, h'', payload) (RFC 9052 Section 4.4)."""
    protected = cbor2.dumps(protected_map, canonical=True)
    signature = key.sign(cbor2.dumps(["Signature1", protected, b"", payload], canonical=True))
    if spoil:
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
    body = cbor2.dumps([protected, unprotected or {}, None if detach else payload, signature], canonical=True)
    if long_array_head:  # the same four items under an array head written on two bytes (0x98 0x04) instead of one
        assert body[0] == 0x84
        body = b"\x98\x04" + body[1:]
    return (b"\xd2" + body) if tag else body


def build():
    v = []

    def add(vid, name, change, text, expectation, raw):
        v.append({"id": vid, "file": f"{vid}-{name}.cose", "change": change, "text": text, "expectation": expectation,
                  "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "_raw": raw})

    add("R01", "baseline", "none: tagged COSE_Sign1, alg -19, kid, CWT Claims with iss and sub, content type, "
        "attached payload, empty unprotected header",
        "RFC 9943 Section 6: every MUST on a Signed Statement is met",
        "eligible for registration if authentication succeeds and the service's additional policy requirements are "
        "met", statement(header("R01")))
    add("R02", "alg-eddsa", "alg is -8 (EdDSA) instead of -19",
        "RFC 9864 deprecates -8 in favour of the fully specified -19, and does not prohibit it; RFC 9943 does not "
        "mandate a particular signature algorithm",
        "left to the registration policy", statement(header("R02") | {1: ALG_EDDSA}))
    add("R03", "unprotected-not-empty", "the unprotected header carries one member",
        "RFC 9943 Section 6.3: a TS MAY accept it, and the unprotected header MUST be an empty map in what is "
        "included in the Statement Sequence",
        "if registered, the registered bytes differ from the submitted ones, and the leaf does not cover the member",
        statement(header("R03"), unprotected={99: "left by the client"}))
    add("R04", "untagged", "no tag 18 in front of the COSE_Sign1",
        "RFC 9943 Section 6.1 defines Signed_Statement = #6.18(COSE_Sign1)",
        "outside that tagged form; record the service's observed handling without treating normalization as a cited "
        "requirement",
        statement(header("R04"), tag=False))
    add("R05", "no-sub", "the CWT Claims carry iss and no sub",
        "RFC 9943 Section 6: the CWT Claims value MUST include iss and sub; Section 6.3 step 2: the TS MUST check "
        "the required protected headers", "refused", statement(header("R05") | {15: {1: ISS}}))
    add("R06", "no-cwt-claims", "no CWT Claims header (label 15) at all",
        "RFC 9943 Section 6: the protected header MUST include the CWT Claims header parameter", "refused",
        statement({k: x for k, x in header("R06").items() if k != 15}))
    add("R07", "no-kid", "no kid, and no x5t or x5chain",
        "RFC 9943 Section 6: kid MUST be present when neither x5t nor x5chain is present in the protected header",
        "refused", statement({k: x for k, x in header("R07").items() if k != 4}))
    add("R08", "detached-payload", "the payload is nil (detached); the signature is over the payload of R01",
        "draft-ietf-scitt-scrapi-11 Section 2.3: a detached payload needs an implementation-specific channel; "
        "Section 2.3.3 lists the error \"Payload Missing\"", "refused unless the service has such a channel",
        statement(header("R08"), detach=True))
    add("R09", "crit-unknown-label", "two additions that go together: a private label (-65537) in the protected "
        "header, and crit listing it",
        "RFC 9052 Section 3.1: a label listed in crit that the recipient does not understand is an error",
        "refused by a service that does not know the label", statement(header("R09") | {2: [-65537], -65537: "x"}))
    add("R10", "bad-signature", "the last bit of the signature is flipped",
        "RFC 9943 Section 6.3 step 2: the TS MUST verify the signature of the Signed Statement",
        "refused when the service knows the issuer's key (it cannot tell otherwise)", statement(header("R10"), spoil=True))
    add("R11", "issuer-never-configured", "valid, signed with a second test key the service must never be given",
        "RFC 9943 Section 5.1.1.1: a TS MUST authenticate Signed Statements as part of a Registration Policy; "
        "Section 6.3 step 2: it MUST verify the signature; Section 6: key discovery is out of scope",
        "refused when no authenticated binding to the signing key can be established; keep test key 2 untrusted in "
        "this test",
        statement(header("R11") | {4: KID_UNKNOWN}, key=KEY_UNKNOWN))
    add("R12", "kid-as-text", "kid is a text string instead of a byte string",
        "RFC 9052 Section 3.1 (Table 3) and the CDDL of RFC 9943 Section 6.1: kid is a bstr",
        "not a conforming kid; a service that finds the key anyway is lenient",
        statement(header("R12") | {4: KID.decode("ascii")}))
    add("R13", "no-alg", "no alg in the protected header",
        "RFC 9943 Section 6.1 makes alg optional; RFC 9052 Sections 3.1 and 10 allow algorithm selection to depend "
        "on the application profile or authenticated context. Signature verification remains mandatory under "
        "RFC 9943 Section 6.3",
        "policy-dependent: ts.isoluce.net's policy requires an explicit supported alg and refuses this vector", statement({k: x for k, x in header("R13").items() if k != 1}))
    add("R14", "iss-not-text", "iss is the integer 1 instead of a text string",
        "RFC 8392 Section 3.1.1: iss is a StringOrURI", "refused", statement(header("R14") | {15: {1: 1, 2: SUB}}))
    add("R15", "array-head-not-shortest", "the array of four items has its head on two bytes (0x98 0x04)",
        "The cited sections (RFC 9943 Section 6.3, RFC 9942 Section 5.2.1) do not specify whether a service "
        "preserves an otherwise valid non-shortest outer array encoding. RFC 9052 Section 9's minimum-length "
        "encoding rule applies to Sig_structure, Enc_structure and MAC_structure",
        "if registered, say whether the leaf covers the submitted bytes or a re-framed statement",
        statement(header("R15"), long_array_head=True))
    return v


def public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def main():
    OUT.mkdir(exist_ok=True)
    vectors = build()
    for item in vectors:
        (OUT / item["file"]).write_bytes(item.pop("_raw"))
    (OUT / "test-key-1.pub.pem").write_bytes(public_pem(KEY))
    (OUT / "test-key-never-configured.pub.pem").write_bytes(public_pem(KEY_UNKNOWN))
    meta = {"about": "Signed Statements for trying a Transparency Service's registration checks. Test keys only.",
            "issuer": ISS, "kid": KID.decode("ascii"), "kid_never_configured": KID_UNKNOWN.decode("ascii"),
            "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(), "vectors": vectors}
    (OUT / "vectors.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    print(len(vectors), "vectors written to", OUT)


if __name__ == "__main__":
    main()
