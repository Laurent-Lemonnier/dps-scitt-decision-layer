#!/usr/bin/env python3
"""Case 06 read by the Standard's anchoring 0.2.0 reference check, after PR #91 (a receipt labelled -8 is read, with the
deprecation named). Two readings:

  A. check_receipt as the extension runs it: the receipt from ts.agentactioncapsule.org, against a trust policy that
     lists the service's log key (from log-public-key.pem) in role transparency_service. The receipt carries no kid,
     so the policy cannot select the key: the check reports exactly that, before the deprecation finding is reached.
  B. a diagnostic with the runner's own primitives (root_from_path, sig_structure, Ed25519): which leaf definition the
     service's inclusion proof and signature actually fit, SHA-256(0x00 || statement bytes) as RFC 9162 and this
     extension define the leaf, or the service's own entry_hash, SHA-256 of the statement's Sig_structure.

Writes anchoring-result.json beside the case. Run: venv312 python anchoring_case06.py (needs asn1crypto, jsonschema).
"""
import base64
import hashlib
import importlib.util
import json
import pathlib
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = pathlib.Path(__file__).resolve().parent
CASE = HERE / "cases" / "06-transparency-receipt"
RUNNER = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/root/claude-ops/dps/wt89") / "extensions/anchoring/tests/run_checks.py"
spec = importlib.util.spec_from_file_location("anchoring_run_checks", RUNNER)
AN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(AN)

statement = (CASE / "signed-statement.cose").read_bytes()
receipt = (CASE / "receipt.cose").read_bytes()
ts = json.loads((CASE / "ts-response.json").read_text())
log_key = serialization.load_pem_public_key((CASE / "log-public-key.pem").read_bytes())
log_key_hex = log_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

policy = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:isoluce:trust-policy:case-06",
          "tsas": [], "checkpoint_sources": [],
          "keys": [{"key_ref": "ts-agentactioncapsule-log-1", "holder": "ts.agentactioncapsule.org (Action State Group)",
                    "role": "transparency_service", "algorithm": "Ed25519", "public_key_hex": log_key_hex,
                    "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z"}]}
allowed = ["ts-agentactioncapsule-log-1"]

# ---- A. the extension's own reading
info = {"raw": statement, "receipt_raw": receipt, "header": None, "error": None}
reading_a = AN.check_receipt(info, policy, allowed, "configured_source")

# ---- B. the leaf the proof and the signature fit, with the runner's primitives
protected, pmap, unprotected, payload, signature = AN.cose_sign1(receipt)
proof = AN.cbor_strict(unprotected[AN.HDR_VDP][AN.VDP_INCLUSION_PROOFS][0])
size, index, path = proof
sig_bytes = AN.cbor_strict(statement)
# the statement's Sig_structure, as the service names it: ["Signature1", protected, external_aad b"", payload]
import cbor2  # only to build the Sig_structure of the statement for the diagnostic
st = cbor2.loads(statement)
sig_structure_stmt = cbor2.dumps(["Signature1", st.value[0], b"", st.value[2]])
candidates = {
    "sha256(0x00 || statement bytes)  [RFC 9162 leaf, anchoring 0.2.0]": hashlib.sha256(b"\x00" + statement).digest(),
    "sha256(statement bytes)": hashlib.sha256(statement).digest(),
    "sha256(0x00 || Sig_structure)": hashlib.sha256(b"\x00" + sig_structure_stmt).digest(),
    "sha256(Sig_structure)  [the service's entry_hash]": hashlib.sha256(sig_structure_stmt).digest(),
    "sha256(0x00 || entry_hash), entry_hash = sha256(Sig_structure)  [RFC 6962 leaf over the service's entry]":
        hashlib.sha256(b"\x00" + hashlib.sha256(sig_structure_stmt).digest()).digest(),
}
reading_b = {"tree_size": size, "leaf_index": index, "path_length": len(path), "service_entry_hash": ts["entry_hash"],
             "alg_in_receipt": pmap.get(AN.HDR_ALG), "kid_in_receipt": pmap.get(AN.HDR_KID), "candidates": {}}
for name, leaf in candidates.items():
    root = AN.root_from_path(leaf, index, size, path)
    ok = None
    if root is not None:
        try:
            log_key.verify(signature, AN.sig_structure(protected, root))
            ok = True
        except InvalidSignature:
            ok = False
    reading_b["candidates"][name] = {"leaf": leaf.hex()[:16] + "…", "root_reached": root.hex()[:16] + "…" if root else None,
                                     "receipt_signature_verifies_over_root": ok}

result = {"case": "06-transparency-receipt", "runner": str(RUNNER), "A_check_receipt": reading_a, "B_leaf_diagnostic": reading_b,
          "what_this_shows": [
              "A: after PR #91 the extension reads a -8 receipt; here it stops earlier, on the kid: the receipt names no key, so the "
              "policy cannot select one. Nothing to change on the Standard's side; RFC 9943 section 6 makes kid, iss and sub a MUST "
              "of a Signed Statement and RFC 9942 names the service key by kid.",
              "B: the receipt's signature verifies over the root reached from leaf = SHA-256(0x00 || entry_hash) with entry_hash = "
              "SHA-256(Sig_structure of the statement): the service's entry is the Sig_structure digest, and its leaf is the RFC 6962 "
              "leaf hash of that digest. Anchoring 0.2.0, as RFC 9162 applied to the statement, takes leaf = SHA-256(0x00 || statement "
              "bytes). The receipt is sound under the service's definition; the two definitions differ on what the entry is, and that "
              "is the question for the service's author, settled here by bytes rather than by reading.",
          ]}
(CASE / "anchoring-result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
print(json.dumps(result, indent=1, ensure_ascii=False))
