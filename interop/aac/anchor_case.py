#!/usr/bin/env python3
"""Case 06: the capsule of case 01 registered in a SCITT Transparency Service, with its Receipt.

Uses the capsule library's own SCITT surface (agent_action_capsule.anchor.submit_anchor, on scitt-cose): a Signed
Statement over the capsule_id digest, registered at the Transparency Service the library names (ts.agentactioncapsule.org
unless AAC_ANCHOR_URL says otherwise), the COSE Receipt the service returns, and the Transparent Statement that embeds
it; then the library's verify_transparent over the result, with the service's log key fetched from the service.

What a Receipt shows: that the service signed this statement into its log at a tree size. Not when, not that the log is
append-only, and nothing about the capsule's content or the decision it cites: the capsule_id is a digest, and the
business content never leaves the folder. Writes everything under cases/06-transparency-receipt/.
"""
import base64
import hashlib
import json
import pathlib
import sys

import importlib

anchor = importlib.import_module("agent_action_capsule.anchor")
transparent = importlib.import_module("agent_action_capsule.transparent")

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "cases" / "01-valid"
OUT = HERE / "cases" / "06-transparency-receipt"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    capsule = json.loads((SRC / "capsule.json").read_bytes())
    (OUT / "capsule.json").write_bytes((SRC / "capsule.json").read_bytes())
    signing_key_pem, issuer_pub_pem = anchor.generate_issuer_keypair()
    result = anchor.submit_anchor(capsule["capsule_id"], signing_key_pem=signing_key_pem)
    (OUT / "signed-statement.cose").write_bytes(result.signed_statement)
    (OUT / "receipt.cose").write_bytes(result.receipt)
    (OUT / "transparent-statement.cose").write_bytes(result.transparent_statement)
    (OUT / "issuer-public-key.pem").write_bytes(result.issuer_pubkey_pem)
    (OUT / "log-public-key.pem").write_bytes(result.log_pubkey_pem)
    report = transparent.verify_transparent(statement_path=str(OUT / "transparent-statement.cose"),
                                            issuer_key_path=str(OUT / "issuer-public-key.pem"),
                                            log_key_path=str(OUT / "log-public-key.pem"),
                                            leaf_entry_hex=result.entry_hash)
    out = {"case": OUT.name, "capsule_id": capsule["capsule_id"], "ts_url": result.ts_url, "entry_hash": result.entry_hash,
           "entry_hash_is_sha256_of_statement": result.entry_hash == hashlib.sha256(result.signed_statement).hexdigest(),
           "statement_bytes": len(result.signed_statement), "receipt_bytes": len(result.receipt),
           "library_verify_transparent": {k: getattr(report, k) for k in dir(report) if not k.startswith("_") and not callable(getattr(report, k))},
           "note": "The Receipt shows that the service signed this statement into its log at a tree size: not when, not that "
                   "the log is append-only, nothing about the capsule's content. The statement carries the capsule_id digest only."}
    (OUT / "result.json").write_text(json.dumps(out, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return 0 if getattr(report, "ok", False) and getattr(report, "receipt_verified", False) else 1


if __name__ == "__main__":
    sys.exit(main())
