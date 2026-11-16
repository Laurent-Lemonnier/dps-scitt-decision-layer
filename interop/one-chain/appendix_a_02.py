#!/usr/bin/env python3
"""The interoperability vector of draft-xg-payment-dispute-profile-02, Appendix A, checked from the text.

Reads refs/draft-xg-payment-dispute-profile-02.txt (the text as posted on 16 November 2026), unfolds the envelope R
(RFC 8792, single backslash), and recomputes every value the appendix states: the seed from its label, the public key
from the seed, the two lengths, SHA-256(R), the RFC 9162 leaf hash, the signature over the canonical payload,
signer_pubkey_hash. Then gives the receipt to goshi_from_text.verify_packet(receipt_only=True), with the key derived
from the published test seed as the key resolved out of band. The vector is the author's and Raghuvar Karthik Durga's;
nothing here is ours but the check. Exit 0 when every stated value recomputes and the receipt verifies.
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("goshi_from_text", HERE / "goshi_from_text.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

STATED = {"seed_label": "actaseal-durga-interop-vector-seed-v1",
          "seed": "5def0cf4af80b8a628a00716b415573486663869fc55d89c0ac4b417e1c0e0c9",
          "public_key": "0dae9a128c629264f1dda4b6e7e1bc1679f7960c6ed59f9a9ac0f98f3fd16d8e",
          "envelope_octets": 862, "jcs_payload_octets": 659,
          "sha256_R": "b29b8545c198afad28e1039626e4685e0b874d41c4815da690034899ab37f6cf",
          "leaf_hash": "9fd30a27f4018ac40689d2d70e50b4f721c35fdd262d52ec76394c50e9131578"}


def unfold(text):
    a = text[text.index("Appendix A.  Interoperability Test Vector\n\n   This"):text.index("Appendix B.  Changes Since -01\n\n")]
    lines = [line[3:] if line.startswith("   ") else line for line in a.splitlines()]
    start = next(i for i, line in enumerate(lines) if line.startswith('{"payload"'))
    body = []
    for line in lines[start:]:
        if not line.strip():
            break
        body.append(line)
    return "".join(line[:-1] if line.endswith("\\") else line for line in body).encode("utf-8")


def main():
    R = unfold((HERE / "refs" / "draft-xg-payment-dispute-profile-02.txt").read_text(encoding="utf-8"))
    env = json.loads(R)
    seed = hashlib.sha256(STATED["seed_label"].encode()).hexdigest()
    pub = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cb = G.canonical(env["payload"])
    report = G.verify_packet({"receipt": env}, public_key_hex=pub, receipt_only=True)
    checks = {"the seed is the SHA-256 of its label": seed == STATED["seed"],
              "the public key derives from the seed": pub == STATED["public_key"],
              "the envelope R is 862 octets": len(R) == STATED["envelope_octets"],
              "the canonical payload is 659 octets": len(cb) == STATED["jcs_payload_octets"],
              "SHA-256(R) as stated": hashlib.sha256(R).hexdigest() == STATED["sha256_R"],
              "the RFC 9162 leaf hash SHA-256(0x00 || R) as stated": hashlib.sha256(b"\x00" + R).hexdigest() == STATED["leaf_hash"],
              "the receipt verifies under goshi_from_text (signature over the canonical payload, eleven members, key_id is the kid, "
              "signer_pubkey_hash is the SHA-256 of the raw key)": report["result"] == "VERIFIED"}
    out = {"vector": "draft-xg-payment-dispute-profile-02, Appendix A", "checks": checks, "receipt_report": report,
           "all_as_stated": all(checks.values())}
    print(json.dumps(out, indent=1))
    return 0 if out["all_as_stated"] else 1


if __name__ == "__main__":
    sys.exit(main())
