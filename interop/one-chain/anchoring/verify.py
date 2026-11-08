#!/usr/bin/env python3
"""Case 18 (and 18b through ../../one-chain-real/anchoring/verify.py): the five OpenTimestamps proofs of this chain,
re-checked offline from the pinned files, by two verifiers:

  1. the Standard's anchoring 0.2.0 reference check (extensions/anchoring/tests/run_checks.py at DPS_STANDARD): the
     attachment's timestamp over the person's signature value, and the reference check's OpenTimestamps path over the
     four document proofs, each against the header set the trust policy names (headers/, a header_file source);
  2. interop/umarise/verify_anchor.py, written from draft-fassbender-scitt-time-anchor-08, route 2 of its Appendix D.7:
     the same proof and subject against the same header set, validated from the checkpoint in headers/SOURCES.json
     (linkage, proof of work, mainnet's target limit, the difficulty rule), with the draft's six confirmations.

Nothing here contacts a calendar, an explorer or a node: the headers were fetched once (headers/SOURCES.json) and are
read as the verifier's own file. What a verified proof shows: the subject's exact bytes existed before the block named
was mined, according to the header held; the header's time is the miner's statement (miner_stated_time), never a time
the bytes existed at. It shows neither who wrote the bytes, nor that their content is true, nor the order of two
subjects anchored in one block.

Exit 0 when every proof verifies on both routes and the two agree on the block and its time; result.json is rewritten
(deterministic: no run time in it). DPS_STANDARD defaults to ../../aqta/approval-record/dps-standard.
"""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CASE = HERE.parent
INTEROP = CASE.parent
SUBJECTS = ("approval-signature.bin", "action-binding-attachment-a1.json", "action-binding-attachment-a2.json",
            "verdict-record.json", "dispute-packet.json")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def standard():
    root = pathlib.Path(os.environ.get("DPS_STANDARD", INTEROP / "aqta" / "approval-record" / "dps-standard"))
    tests = root / "extensions" / "anchoring" / "tests" / "run_checks.py"
    if not tests.exists():
        sys.exit(f"DPS_STANDARD does not hold extensions/anchoring/tests/run_checks.py: {root}")
    return root, load("anchoring_run_checks", tests)


def calendar_of(branches, ops):
    """The calendar whose commitment a Bitcoin branch continues: the pending branch whose operations are the longest
    prefix of the Bitcoin branch's. None when no pending branch is a prefix."""
    best = None
    for p_ops, tag, payload in branches:
        if tag != VA.PENDING_TAG or len(p_ops) > len(ops) or ops[:len(p_ops)] != p_ops:
            continue
        if best is None or len(p_ops) > len(best[0]):
            best = (p_ops, payload)
    if best is None:
        return None
    r = VA.Reader(best[1])
    return r.varbytes().decode("utf-8", "replace")


def proof_branches(proof):
    """Every Bitcoin attestation of the proof with its height and the calendar it came through, in the proof's order."""
    parsed = VA.ots_deserialize(proof)
    if parsed is None:
        return []
    _, _, branches = parsed
    out = []
    for ops, tag, payload in branches:
        if tag == VA.BITCOIN_TAG:
            out.append({"height": VA.Reader(payload).varint(), "calendar": calendar_of(branches, ops)})
    return out


def run(here=HERE, case=CASE):
    global VA
    VA = load("verify_anchor", INTEROP / "umarise" / "verify_anchor.py")
    std_root, RC = standard()
    sub = here / "subjects"
    missing = [n for name in SUBJECTS for n in (name, name + ".ots") if not (sub / n).exists()]
    if missing:
        sys.exit(f"{case.name}/anchoring: subject or proof file(s) absent from {sub} (not committed?): {', '.join(missing)}")
    hdr_dir = here / "headers"
    sources = json.loads((hdr_dir / "SOURCES.json").read_text())
    headers_path = hdr_dir / sources["file"]
    headers = json.loads(headers_path.read_text())
    attachment = json.loads((here / "anchoring-attachment.json").read_text())
    documents = json.loads((here / "document-proofs.json").read_text())
    policy = json.loads((here / "trust-policy-anchoring.json").read_text())
    result = {"case": case.name, "profile": "dps-anchoring 0.2.0 (reference check at DPS_STANDARD) and "
              "draft-fassbender-scitt-time-anchor-08 route 2 (interop/umarise/verify_anchor.py)",
              "standard_commit": None, "problems": [], "subjects": {}, "headers": {}, "proofs": []}
    problems = result["problems"]
    head = std_root / ".git" / "HEAD"
    try:
        result["standard_commit"] = subprocess.run(["git", "-C", str(std_root), "rev-parse", "--short", "HEAD"],
                                                   capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        result["standard_commit"] = "unknown" if not head.exists() else head.read_text().strip()

    # 1. The subjects: the pinned bytes (SHA256SUMS) are the chain's documents in out/positive/ and the signature value
    #    the signatures attachment carries. The proofs are over these bytes and nothing else.
    #    Since 8 November 2026 one subject is known to differ from out/positive/: the dispute packet, whose anchored bytes are
    #    the first reading of -01 while the chain now builds the packet with the constructions its author gave (readings.json,
    #    both digests). That difference is reported, not failed; the current bytes must be the ones readings.json records.
    sums = dict(line.split()[::-1] for line in (sub / "SHA256SUMS").read_text().splitlines() if line.strip())
    readings = json.loads((here / "readings.json").read_text()) if (here / "readings.json").exists() else {}
    positive = case / "out" / "positive"
    sig = json.loads((positive / "signatures-attachment.json").read_text())["person_signatures"][0]
    for name in SUBJECTS:
        data = (sub / name).read_bytes()
        current = base64.b64decode(sig["signature"]["value_b64"]) if name == "approval-signature.bin" else (positive / name).read_bytes()
        same_as = current == data
        result["subjects"][name] = {"sha256": sha256(data), "bytes": len(data), "in_sha256sums": sums.get(name) == sha256(data),
                                    "equals_out_positive": same_as}
        if sums.get(name) != sha256(data):
            problems.append(f"{name}: not the bytes SHA256SUMS pins")
        if not same_as and name in readings:
            rd = readings[name]
            known = rd.get("anchored_sha256") == sha256(data) and rd.get("current_sha256") == sha256(current)
            result["subjects"][name]["known_difference"] = {"anchored_sha256": rd.get("anchored_sha256"), "anchored_reading": rd.get("anchored_reading"),
                                                            "out_positive_sha256": sha256(current), "current_reading": rd.get("current_reading"),
                                                            "both_digests_as_recorded": known}
            if not known:
                problems.append(f"{name}: differs from out/positive/ and the two digests are not the ones readings.json records")
        elif not same_as:
            problems.append(f"{name}: not the bytes of out/positive/ (the chain was rebuilt differently)")
    # 2. The header set: every block hash recomputed, the set validated from the checkpoint by the umarise verifier.
    cp = sources["checkpoint"]
    for h, e in headers.items():
        hb = bytes.fromhex(e["header"])
        if len(hb) != 80 or VA.block_hash(hb) != e["block_hash"]:
            problems.append(f"header {h}: the block hash is not the double SHA-256 of the header")
        t = int.from_bytes(hb[68:72], "little")
        from datetime import datetime, timezone
        if datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") != e["miner_stated_time"]:
            problems.append(f"header {h}: miner_stated_time is not the header's nTime")
    validated = VA.validate_chain(headers, (cp["height"], cp["block_hash"]))
    result["headers"] = {"file": sources["file"], "source_ref": sources["source_ref"], "count": len(headers),
                         "from": min(map(int, headers)), "to": max(map(int, headers)),
                         "checkpoint": {"height": cp["height"], "block_hash": cp["block_hash"]},
                         "validated_from_checkpoint": sorted(validated) == sorted(map(int, headers)),
                         "what_validated_means": "80 bytes each, linked by hash, proof of work under each header's "
                         "target, target under mainnet's limit (powLimit), nBits constant between retarget boundaries, "
                         "anchored at the checkpoint; not that this is the most-work chain from genesis"}
    if not result["headers"]["validated_from_checkpoint"]:
        problems.append("the header set did not validate from the checkpoint")
    if policy.get("bitcoin_header_sources", [{}])[0].get("source_ref") != sources["source_ref"]:
        problems.append("the trust policy names another header source than headers/SOURCES.json")

    # 3. The Standard's reference check: schemas, the policy, then each proof.
    schemas = std_root / "extensions" / "anchoring" / "schemas"
    att_v = RC.Draft202012Validator(json.loads((schemas / "anchoring-attachment.schema.json").read_text()))
    pol_v = RC.Draft202012Validator(json.loads((schemas / "trust-policy.schema.json").read_text()))
    result["attachment"] = {"sha256": sha256(RC.compact(attachment)), "schema_valid": not list(att_v.iter_errors(attachment)),
                            "timestamps": len(attachment["timestamps"])}
    result["trust_policy"] = {"schema_valid": not list(pol_v.iter_errors(policy)), "reference_check": RC.check_policy(policy)}
    if not result["attachment"]["schema_valid"]:
        problems.append("anchoring-attachment.json is not valid against anchoring-attachment.schema.json")
    if not result["trust_policy"]["schema_valid"] or result["trust_policy"]["reference_check"]["status"] != "verified":
        problems.append("trust-policy-anchoring.json is not a valid policy")
    held_headers = {"source_ref": sources["source_ref"], "headers": {h: e["header"] for h, e in headers.items()}}
    checkpoint_arg = f"{cp['height']}:{cp['block_hash']}"
    ots_result_v = RC.ots_result_validator()

    def route2(name):
        r = subprocess.run([sys.executable, str(INTEROP / "umarise" / "verify_anchor.py"), "--artifact", str(sub / name),
                            "--proof", str(sub / (name + ".ots")), "--chain", str(headers_path), "--checkpoint",
                            checkpoint_arg], capture_output=True, text=True)
        try:
            return json.loads(r.stdout)
        except ValueError:
            return {"result": "error", "stderr": r.stderr.strip()[:300]}

    def record(name, subject_kind, ref, how):
        proof = (sub / (name + ".ots")).read_bytes()
        branches = proof_branches(proof)
        r2 = route2(name)
        entry = {"subject": name, "subject_kind": subject_kind, "subject_sha256": sums.get(name),
                 "proof_sha256": sha256(proof), "bitcoin_attestations": branches,
                 "anchoring_0_2_0": {"how": how, "status": ref["status"], "checks": ref["checks"],
                                     "block": ref.get("block"), "miner_stated_time": ref.get("miner_stated_time"),
                                     "findings": ref["findings"],
                                     "result_against_report_schema": [e.message for e in ots_result_v.iter_errors(
                                         dict(ref, timestamp_index=0))]},
                 "time_anchor_08_route_2": r2}
        lowest = min((b["height"] for b in branches), default=None)
        held_block = headers.get(str(lowest)) if lowest is not None else None
        core = all(ref["checks"].get(k) == "verified" for k in ("proof", "operations", "attestation", "header"))
        agree = (r2.get("result") == "valid" and ref.get("block", {}).get("height") == r2.get("block_height_H") == lowest
                 and held_block is not None and ref.get("miner_stated_time") == held_block["miner_stated_time"]
                 and r2.get("block_time_RWCP") == int.from_bytes(bytes.fromhex(held_block["header"])[68:72], "little"))
        entry["verified"] = core and agree and ref["checks"]["subject_bytes"] in ("verified", "not_checked")
        entry["what_it_shows"] = (f"these bytes existed before block {lowest} was mined, per the held header "
                                  f"(miner_stated_time {held_block['miner_stated_time']}); not who wrote them, not "
                                  "that they are true, not their order among the subjects of that block"
                                  if entry["verified"] and held_block else "nothing established")
        if not entry["verified"]:
            problems.append(f"{name}: not verified on both routes (reference {ref['status']}, route 2 {r2.get('result')})")
        result["proofs"].append(entry)

    export = {"entries": []}  # the subjects are a signature value and documents, never a seal or a link of an export
    chain_id = attachment.get("chain_id", "urn:example:chain:issuer-1")
    for i, ts in enumerate(attachment["timestamps"]):
        ref = RC.check_timestamp(ts, policy, export, chain_id, [], held_headers)
        of = ts["subject"]["of"]
        record("approval-signature.bin", f"signature value of the {of['assertion']} ({of['key_ref']}, {of['decision_id']}, "
               f"stage {of['stage_id']}), anchoring 0.2.0 subject kind signature", ref,
               "check_timestamp of the reference check over the attachment's timestamp: proof, operations, attestation "
               "and header are its checks; subject_bytes is not_checked by design (the signatures profile checks an "
               "assertion's signature; the reference check holds checkpoints only), so its status is not_checked; the "
               "value_b64 is the signature value of out/positive/signatures-attachment.json (checked above)")
        if ts["subject"]["value_b64"] != sig["signature"]["value_b64"]:
            problems.append("the attachment's signature subject is not the value the signatures attachment carries")
    for d in documents["proofs"]:
        name = pathlib.Path(d["subject"]["file"]).name
        data = (sub / name).read_bytes()
        s = result["subjects"][name]
        local = "verified" if s["in_sha256sums"] and (s["equals_out_positive"] or s.get("known_difference", {}).get("both_digests_as_recorded")) else "failed"
        out = {"subject": {"kind": d["subject"]["kind"], "document": d["subject"]["document"], "file": d["subject"]["file"]},
               "checks": {}, "findings": [], "issuer_time": {"status": "not_checked"}}
        ref = RC.check_ots(d, policy, out, local, data, held_headers)
        record(name, f"{d['subject']['document']}: document bytes, a subject kind anchoring 0.2.0 does not define", ref,
               "check_ots of the reference check (its OpenTimestamps path) over a proof the profile cannot carry: "
               "subject_bytes is verify.py's own comparison of the file with SHA256SUMS and out/positive/ (or, for a subject "
               "readings.json names, with the two digests it records: the anchored bytes and the current ones), the four other "
               "checks are the reference check's")

    result["summary"] = {"proofs": len(result["proofs"]), "verified_on_both_routes": sum(p["verified"] for p in result["proofs"]),
                         "blocks": sorted({b["height"] for p in result["proofs"] for b in p["bitcoin_attestations"]}),
                         "lowest_block_reported": sorted({p["anchoring_0_2_0"]["block"]["height"] for p in result["proofs"]
                                                          if p["anchoring_0_2_0"]["block"]}),
                         "calendars": sorted({b["calendar"] for p in result["proofs"] for b in p["bitcoin_attestations"] if b["calendar"]}),
                         "all_verified": not problems}
    (here / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    s = result["summary"]
    print(f"{case.name}/anchoring: {s['verified_on_both_routes']}/{s['proofs']} proofs verified on both routes; blocks "
          f"{s['blocks']}; lowest reported {s['lowest_block_reported']}; headers {result['headers']['from']}-"
          f"{result['headers']['to']} validated from checkpoint {cp['height']}: {result['headers']['validated_from_checkpoint']}")
    for p in result["proofs"]:
        a = p["anchoring_0_2_0"]
        print(f"  {p['subject']}: reference {a['status']} ({', '.join(k + '=' + v for k, v in a['checks'].items())}), "
              f"block {a['block']['height'] if a['block'] else None}, miner_stated_time {a['miner_stated_time']}; route 2 "
              f"{p['time_anchor_08_route_2'].get('result')} H={p['time_anchor_08_route_2'].get('block_height_H')} "
              f"confirmations={p['time_anchor_08_route_2'].get('confirmations_established')}")
    for pr in problems:
        print("  PROBLEM:", pr)
    print("all_verified:", s["all_verified"])
    return 0 if s["all_verified"] else 1


if __name__ == "__main__":
    sys.exit(run())
