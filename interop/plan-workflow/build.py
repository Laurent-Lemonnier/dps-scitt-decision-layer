#!/usr/bin/env python3
"""Case 13: the plan approved as a whole (../plan-run) and an AER-1 workflow receipt (draft-zambo-aer1-26, Section 8)
over the same run, composed. The plan side says what was approved before execution: the exact steps, by the
specification's plan_hash, under one person's signed approval. The AER-1 side says what ran: an ordered list of step
receipts under one workflow, a Merkle root over (seq, output_hash) in the seq-output-v1 construction of Section 8.1, and
the workflow's output hash. Section 8.4 says a workflow manifest "published before execution" should bind the expected
step list; here the approved specification is that binding, and the joins check it.

Built here: one AER-1 execution receipt per step (schema 0.4, in the layout of ../aer1-decision, each verified by the
independent AER-1 verifier written from the draft), and the workflow receipt over them. What neither text fixes, and
this case states: Table 3 of Section 8 lists no per-step output_hash, which seq-output-v1 consumes; the draft's own
example takes it from each step's receipt, and so does this case (the step receipt's output_hash, bare hex). The
workflow's output_hash is the Section 7.1 serialization of {"output": <the last step's outputs>}, the default the draft
gives when the producer publishes no layout.
"""
import copy
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PR = load("plan_run_build", HERE.parent / "plan-run" / "build.py")
AER = load("aer_independent", HERE.parent / "aer1" / "aer1_verify_independent.py")
sha256, compact, b64 = PR.sha256, PR.compact, PR.b64
WORKFLOW_ID = "1f6e8a2c-5b7d-4e3a-9c1f-0a2b3c4d5e6f"


def uuid4_from(text):
    h = bytearray(PR.hashlib.sha256(text.encode()).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x40
    h[8] = (h[8] & 0x3F) | 0x80
    x = h.hex()
    return f"{x[:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:]}"


def step_receipt(step, index):
    """An AER-1 0.4 execution receipt for one step, in the reference-producer layout (Section 7.1 canonical JSON of
    {caller, inputs, issuer_claims, outputs, receipt_schema_version, tool}); its workflow pointer (Section 8.6) is
    outside the canonical bytes."""
    tool = {"name": step["operation"].replace(".", "_"), "version": "1.0.0", "scope": "onboarding"}
    inputs = {"operation": step["operation"], "target": step["target"], "request_digest": step["request_digest"]}
    payload = {"caller": {"id": "sha256:" + sha256(b"example onboarding runtime 3"), "type": "service"}, "inputs": inputs,
               "issuer_claims": {"provenance_class": "OBSERVED VIA GATEWAY"}, "outputs": step["outputs"],
               "receipt_schema_version": "0.4", "tool": tool["name"]}
    raw = AER.canonical_json(payload).encode("utf-8")
    rec = {"id": uuid4_from(f"plan-workflow step {index}"), "receipt_schema_version": "0.4", "created_at": step["ended_at"][:-1] + ".000Z",
           "tool": tool, "provenance_class": "OBSERVED VIA GATEWAY", "canonical_byte_length": len(raw), "canonical_bytes": b64(raw),
           "output_hash": "sha256:" + sha256(raw), "verification_status": "verified",
           "input_hash": "sha256:" + sha256(AER.canonical_json(inputs).encode("utf-8"))}
    block = {"created_at": rec["created_at"], "id": rec["id"], "output_hash": rec["output_hash"], "provenance_class": rec["provenance_class"],
             "receipt_schema_version": "0.4", "tool": {"name": tool["name"], "scope": tool["scope"], "version": tool["version"]}}
    rec["metadata_hash"] = "sha256:" + sha256(AER.canonical_json(block).encode("utf-8"))
    rec["execution_context"] = {"framework": {"name": "example-onboarding-runtime", "version": "3"}, "source": PR.TENANT, "model": None}
    rec["workflow"] = {"id": WORKFLOW_ID, "url": f"urn:example:workflow:{WORKFLOW_ID}", "step_index": index}
    return rec


def build():
    return {"plan": PR.build(), "drop_step": None, "swap_steps": False, "extra_step": False, "substitute_output": None,
            "root_of_other_list": False, "declare_v0_compute_v1": False}


def assemble(b):
    art = PR.assemble(b["plan"])
    steps = [copy.deepcopy(m) for m in sorted(art["manifest"]["steps"], key=lambda m: m["index"])]
    receipts = [step_receipt(m, m["index"]) for m in steps]
    wsteps = [{"seq": i + 1, "tool": r["tool"]["name"], "receipt_id": r["id"], "receipt_hash": "sha256:" + sha256(compact(r)),
               "started_at": m["started_at"], "ended_at": m["ended_at"], "status": "succeeded" if m["status"] == "succeeded" else m["status"],
               "output_hash": r["output_hash"].split(":", 1)[1]} for i, (m, r) in enumerate(zip(steps, receipts))]
    if b["substitute_output"] is not None:
        wsteps[b["substitute_output"]]["output_hash"] = sha256(b"another output")
    if b["swap_steps"]:
        wsteps[1], wsteps[2] = wsteps[2], wsteps[1]
        wsteps[1]["seq"], wsteps[2]["seq"] = 2, 3
    if b["drop_step"] is not None:
        wsteps.pop(b["drop_step"])
        for i, s in enumerate(wsteps):
            s["seq"] = i + 1
    if b["extra_step"]:
        extra = dict(wsteps[-1], seq=len(wsteps) + 1, receipt_id=uuid4_from("an extra step"), tool="crm_client_delete",
                     output_hash=sha256(b"an extra step's output"))
        wsteps.append(extra)
    root_steps = wsteps
    if b["root_of_other_list"]:
        root_steps = [dict(s, output_hash=sha256(f"other {s['seq']}".encode())) for s in wsteps]
    mv = "seq-output-v1"
    root = AER.workflow_root(root_steps, mv)
    if b["declare_v0_compute_v1"]:
        mv = "receipt-id-v0"
    final_output = steps[-1]["outputs"]
    workflow = {"type": "verifiable-workflow-receipt", "version": "1", "workflow_id": WORKFLOW_ID,
                "receipt_id": uuid4_from("plan-workflow close"), "session_id": uuid4_from("plan-workflow session"),
                "goal": f"onboarding plan run {PR.RUN_ID}", "status": "completed", "steps": wsteps, "merkle_root": root,
                "merkle_version": mv, "output_hash": sha256(AER.canonical_json({"output": final_output}).encode("utf-8")),
                "verify_url": f"urn:example:workflow:{WORKFLOW_ID}"}
    art["step_receipts"] = receipts
    art["workflow"] = workflow
    return art


def verify(art, b=None):
    r = PR.verify(art, b["plan"] if b else None)
    w = art["workflow"]
    aer = {"step_receipts": [], "workflow": {}}
    for rec in art["step_receipts"]:
        # the workflow pointer of Section 8.6 sits outside the canonical bytes; the receipt is verified as issued without it
        status, reason, _ = AER.structural(copy.deepcopy({k: v for k, v in rec.items() if k != "workflow"}), strict_id=True)
        aer["step_receipts"].append(status if status == "pass" else f"{status}: {reason}")
    try:
        recomputed = AER.workflow_root(w["steps"], w.get("merkle_version"))
    except Exception as e:
        recomputed = f"error: {e}"
    seqs = [s["seq"] for s in w["steps"]]
    aer["workflow"] = {"members": all(k in w for k in ("type", "version", "workflow_id", "receipt_id", "session_id", "goal", "status",
                                                       "steps", "merkle_root", "merkle_version", "output_hash", "verify_url")),
                       "seq_one_based_no_gaps": seqs == list(range(1, len(seqs) + 1)),
                       "merkle_root_recomputed": recomputed == w["merkle_root"],
                       "receipt_ids_unique": len({s["receipt_id"] for s in w["steps"]}) == len(w["steps"])}
    r["aer1"] = aer
    r["joins"].update(joins(art))
    r["all_verified"] = (r["all_verified"] and all(x == "pass" for x in aer["step_receipts"]) and all(aer["workflow"].values())
                         and all(v is True for v in r["joins"].values()))
    return r


def joins(art):
    """What neither the plan side nor the AER-1 side says alone."""
    w, man = art["workflow"], art["manifest"]
    steps = sorted(man["steps"], key=lambda m: m["index"])
    recs = {x["id"]: x for x in art["step_receipts"]}
    spec = json.loads(PR.base64.b64decode(art["attachment"]["action_specifications"][0]["content"]["bytes_b64"]))
    approved = sorted(spec["parameters"]["steps"], key=lambda s: s["index"])
    j = {}
    j["the workflow's step list is the approved plan's, in its order: as many steps, each seq the plan index + 1, each tool "
      "the approved operation (Section 8.4: the binding published before execution is the approved specification)"] = (
        len(w["steps"]) == len(approved) and all(s["seq"] == a["index"] + 1 and s["tool"] == a["operation"].replace(".", "_")
                                                  for s, a in zip(w["steps"], approved)))
    def outputs_of(rid):
        rec = recs.get(rid)
        return json.loads(PR.base64.b64decode(rec["canonical_bytes"]))["outputs"] if rec else None
    j["each workflow step names the step receipt that carries exactly the outputs the manifest records for that step, its "
      "output_hash is that receipt's, and the receipt points back to this workflow at that index (Section 8.6)"] = (
        len(w["steps"]) == len(steps) and all(
            s["receipt_id"] in recs and outputs_of(s["receipt_id"]) == m["outputs"]
            and s["output_hash"] == recs[s["receipt_id"]]["output_hash"].split(":", 1)[1]
            and recs[s["receipt_id"]]["workflow"] == {"id": w["workflow_id"], "url": w["verify_url"], "step_index": m["index"]}
            for s, m in zip(w["steps"], steps)))
    root_from_manifest = AER.workflow_root(
        [{"seq": m["index"] + 1, "output_hash": next((x["output_hash"].split(":", 1)[1] for x in art["step_receipts"]
                                                      if x["workflow"]["step_index"] == m["index"]), "")} for m in steps], "seq-output-v1")
    j["the Merkle root recomputed from the manifest's steps and their receipts, in seq-output-v1, is the workflow's, and the "
      "workflow declares that construction"] = root_from_manifest == w["merkle_root"] and w["merkle_version"] == "seq-output-v1"
    j["the workflow's output_hash is the Section 7.1 digest of {\"output\": the last step's outputs as the manifest records them}"] = (
        w["output_hash"] == sha256(AER.canonical_json({"output": steps[-1]["outputs"]}).encode("utf-8")))
    j["the workflow names this run, and its steps ran inside the run's times as the manifest records them (the issuers' times)"] = (
        PR.RUN_ID in w["goal"] and all(s["started_at"] == m["started_at"] and s["ended_at"] == m["ended_at"]
                                       for s, m in zip(w["steps"], steps)))
    return j


def write(out, art):
    PR.write(out, art)
    (out / "aer1-step-receipts.json").write_text(json.dumps(art["step_receipts"], ensure_ascii=False, indent=1) + "\n")
    (out / "aer1-workflow-receipt.json").write_text(json.dumps(art["workflow"], ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    b = build()
    art = assemble(b)
    out = HERE / "out"
    write(out, art)
    r = verify(art, b)
    (out / "summary.json").write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(r, ensure_ascii=False, indent=1))
    sys.exit(0 if r["all_verified"] else 1)
