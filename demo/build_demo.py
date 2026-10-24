"""Demo: an Agent Action Capsule (draft-mih-scitt-agent-action-capsule, library 0.12.0) that cites, by CPB typed digest
references, the DPS decision record and action-binding attachment of the release example; verified with the capsule
library on one side, and by recomputing the digests from the DPS documents on the other."""
import hashlib, importlib, json, pathlib, sys
H = pathlib.Path(__file__).resolve().parent
EX = H.parent / "examples" / "release-decision"
parse = importlib.import_module("agent_action_capsule.parse"); verify = importlib.import_module("agent_action_capsule.verify")
canonical = importlib.import_module("agent_action_capsule.canonical"); contracts = importlib.import_module("agent_action_capsule.contracts")
rec_bytes = (EX / "decision-record.json").read_bytes(); att_bytes = (EX / "action-binding-attachment.json").read_bytes()
record = json.loads(rec_bytes)
seal = record["seal_hash"]
att_digest = hashlib.sha256(att_bytes).hexdigest()   # unsigned attachment: its bytes as issued
spec_digest = json.loads(att_bytes)["action_specifications"][0]["spec_digest"]
NS = "net.isoluce.dps"  # provisional namespace under the author's own domain, until the Steward answers on the Standard's
capsule = {
    "spec_version": sys.argv[1] if len(sys.argv) > 1 else "0.12",
    "format_version": "4",
    "canonicalization_id": "jcs",
    "action_id": "urn:isoluce:deploy:request:0412",
    "action_type": "decide",
    "operator": "iSoluce release orchestrator",
    "developer": "iSoluce",
    "timestamp": "2026-10-23T14:21:10Z",
    "domain": "software-release",
    "disposition": {"decision": "accept", "approver": "human", "human_disposed": True,
                    "authority": "urn:isoluce:charter:CH-ISOLUCE-RELEASE-1#release-approval", "verdict_class": "executed"},
    "effect": {"status": "confirmed", "type": f"{NS}.release_deploy", "request_digest": spec_digest,
               "response_digest": hashlib.sha256(b"deploy confirmation 0412").hexdigest(),
               "external_ref": "urn:isoluce:deploy:confirmation:0412", "irreversibility_class": "one_way_recoverable",
               "effect_attestation": "host_served_observed"},
    "references": [
        {"type": f"{NS}.decision_record", "digest_alg": "SHA-256", "digest": seal, "citation_purpose": "ran_under"},
        {"type": f"{NS}.action_binding_attachment", "digest_alg": "SHA-256", "digest": att_digest,
         "citation_purpose": "acted_on"},
    ],
}
capsule["capsule_id"] = canonical.compute_capsule_id(capsule)
try:
    typed = parse.parse_capsule(capsule)
    parse_ok, parse_err = True, None
except Exception as exc:
    parse_ok, parse_err = False, f"{type(exc).__name__}: {exc}"
result = verify.verify(capsule)
findings = [(getattr(f, "severity", getattr(f, "level", "?")), getattr(f, "code", ""), getattr(f, "message", str(f))) for f in getattr(result, "findings", [])]
# the other side: a DPS verifier resolving the references from the documents it holds
resolved = {
    f"{NS}.decision_record": hashlib.sha256(json.dumps({**record, "seal_hash": "0" * 64}, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest() == seal,
    f"{NS}.action_binding_attachment": hashlib.sha256(att_bytes).hexdigest() == att_digest,
}
out = {"capsule_id": capsule["capsule_id"], "library_parse_ok": parse_ok, "library_parse_error": parse_err,
       "library_verify": {k: getattr(result, k) for k in ("ok", "valid", "status", "rung") if hasattr(result, k)},
       "library_findings": findings, "dps_side_references_resolved": resolved}
(H / "capsule.json").write_text(json.dumps(capsule, indent=1, ensure_ascii=False))
(H / "demo-result.json").write_text(json.dumps(out, indent=1, ensure_ascii=False, default=str))
print(json.dumps(out, indent=1, ensure_ascii=False, default=str)[:3000])
print("VerificationResult fields:", [a for a in dir(result) if not a.startswith("_")][:20])
