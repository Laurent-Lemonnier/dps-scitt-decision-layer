#!/usr/bin/env python3
"""Register the capsule_id of case 01 at the Transparency Service by hand (the same steps as submit_anchor, kept apart so
that every artefact is written) and find which bytes the service's entry_hash is the digest of."""
import base64
import hashlib
import json
import pathlib
import sys
import importlib

anchor = importlib.import_module("agent_action_capsule.anchor")
from scitt_cose.statement import build_signed_statement, attach_receipts, extract_receipts
from scitt_cose.receipt import verify_receipt
import cbor2

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "cases" / "01-valid"
OUT = HERE / "cases" / "06-transparency-receipt"
OUT.mkdir(parents=True, exist_ok=True)

capsule = json.loads((SRC / "capsule.json").read_bytes())
cid = capsule["capsule_id"]
signing_key_pem, issuer_pub_pem = anchor.generate_issuer_keypair()
ts = anchor._resolved_ts_url(None)
log_pub_pem = anchor._fetch_log_pubkey_pem(ts, 30)
statement = build_signed_statement(bytes.fromhex(cid), alg="EdDSA", private_key_pem=signing_key_pem,
                                   issuer=anchor._ISSUER, subject=cid, content_type=anchor.CAPSULE_ID_MEDIA_TYPE)
resp = anchor._post_statement(statement, ts, 30)
receipt = base64.b64decode(resp["receipt_b64"])
(OUT / "signed-statement.cose").write_bytes(statement)
(OUT / "receipt.cose").write_bytes(receipt)
(OUT / "transparent-statement.cose").write_bytes(attach_receipts(statement, [receipt]))
(OUT / "issuer-public-key.pem").write_bytes(issuer_pub_pem)
(OUT / "log-public-key.pem").write_bytes(log_pub_pem)
(OUT / "ts-response.json").write_text(json.dumps(resp, indent=1) + "\n")

entry = resp["entry_hash"]
untagged = cbor2.dumps(cbor2.loads(statement).value)
candidates = {
    "sha256(statement, tagged)": hashlib.sha256(statement).hexdigest(),
    "sha256(0x00 || statement) (RFC 9162 leaf)": hashlib.sha256(b"\x00" + statement).hexdigest(),
    "sha256(statement untagged)": hashlib.sha256(untagged).hexdigest(),
    "sha256(0x00 || untagged)": hashlib.sha256(b"\x00" + untagged).hexdigest(),
    "sha256(capsule_id bytes)": hashlib.sha256(bytes.fromhex(cid)).hexdigest(),
    "capsule_id": cid,
}
match = [k for k, v in candidates.items() if v == entry]
checks = {}
for name, leaf in (("entry_hash as returned", entry), ("sha256(statement)", candidates["sha256(statement, tagged)"])):
    r = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=log_pub_pem)
    checks[name] = {"ok": r.ok, "errors": list(getattr(r, "errors", []))[:3], **{k: getattr(r, k) for k in ("tree_size", "leaf_index", "vds") if hasattr(r, k)}}
hdr = cbor2.loads(receipt).value
protected = cbor2.loads(hdr[0]) if hdr[0] else {}
out = {"ts_url": ts, "response_keys": sorted(resp), "entry_hash": entry, "entry_hash_matches": match,
       "receipt_protected_header": {str(k): (v if isinstance(v, (int, str)) else str(v)[:60]) for k, v in dict(protected).items()},
       "receipt_unprotected_labels": sorted(str(k) for k in dict(hdr[1]).keys()), "receipt_verify": checks}
(OUT / "probe.json").write_text(json.dumps(out, indent=1, default=str) + "\n")
print(json.dumps(out, indent=1, default=str))
