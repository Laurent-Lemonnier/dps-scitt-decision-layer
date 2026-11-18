#!/usr/bin/env python3
"""Open one-chain output in a self-contained HTML reader."""
import argparse
import base64
import hashlib
import json
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = "e444fffb5a6488e9898061bc02c3c52ebdbf97b8"
SOURCE = f"https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/blob/{CORPUS}/interop/one-chain"
CONTEXT = "https://w3id.org/decision/context.jsonld"
PLAN_ROOT = HERE.parents[1] / "plan-checkpoint"
PLAN_SOURCE = "https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/blob/645852e5f743574b19cd54a2b96bbb25a9c06ace/interop/plan-checkpoint/out"
A1 = "action-binding-attachment-a1.json"
RECORD = "decision-record.json"
VERDICT = "verdict-record.json"
PIECES = {
    RECORD: "Decision record",
    A1: "Approval attachment A1",
    "action-binding-attachment-a2.json": "Execution attachment A2",
    "signatures-attachment.json": "Person signature attachment",
    "action-specification.json": "Approved specification",
    "action-specification-executed.json": "Attempted specification",
    "receipts.diag.json": "Receipt diagnostic representation",
    "aee-bundle.cbor": "Native execution receipt bundle",
    "tool-response.json": "Tool response",
    "binding-statement.cose": "Statement linking execution receipts and DPS",
    VERDICT: "Verdict record",
    "verdict-record.container.json": "Verdict container",
    "dispute-packet.json": "Payment dispute packet",
}


def money(parameters):
    return {
        "value": str(Decimal(parameters["amount_minor"]) / Decimal(100)),
        "unit": parameters["currency"],
    }


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def piece(title, raw, source=None, expected_digest=None):
    return {
        "title": title,
        "sha256": digest(raw) if raw is not None else expected_digest,
        "source": source,
        "bytes": base64.b64encode(raw).decode("ascii") if raw is not None else None,
    }


def build_plan_cases():
    common = [
        ("Three Agent Action Capsules", "capsules.json"),
        ("Original plan decision", "decision-record.json", "record.json"),
        ("Original action-binding attachment", "action-binding-attachment.json", "attachment.json"),
        ("Original plan approval signatures", "signatures-attachment.json", "sig_attachment.json"),
        ("Test trust policy", "trust-policy.json", "trust.json"),
        ("Screening evidence fixture", "screening-fixture.json", "fixture.json"),
    ]
    cases = {
        "positive": ("", "The CRM and chat capsules both cite the approval to resume."),
        "n15": (
            "negatives/N15-resumed-without-the-decision",
            "The case includes the approval to resume. The CRM and chat capsules cite only the original plan approval.",
        ),
        "n18": (
            "negatives/N18-decided-after-the-step-ran",
            "The CRM step began before the approval to resume was recorded.",
        ),
    }
    result = {}
    for key, (directory, caption) in cases.items():
        positive = not directory
        folder = PLAN_ROOT / "out" / directory
        files = [
            ("Native verification report", "summary.json" if positive else "result.json"),
            ("Run manifest", "plan-run-manifest.json" if positive else "manifest.json"),
            *((label, names[0] if positive else names[-1]) for label, *names in common),
        ]
        if positive:
            files.extend([
                ("Resumption decision", "checkpoint-decision-record.json"),
                ("Resumption action-binding attachment", "checkpoint-action-binding-attachment.json"),
                ("Resumption approval signatures", "checkpoint-signatures-attachment.json"),
                ("Synthetic adjudication", "adjudication.json"),
                ("Plan policy", "policy.json"),
            ])
        else:
            files.append(("Resumption decision, signatures and adjudication", "checkpoint.json"))
        raw = {name: (folder / name).read_bytes() for _, name in files}
        report = json.loads(raw[files[0][1]])
        manifest = json.loads(raw[files[1][1]])
        capsules = json.loads(raw["capsules.json"])
        checkpoint, = manifest["checkpoints"]
        result[key] = {
            "caption": caption,
            "report": report,
            "steps": manifest["steps"],
            "case_id": manifest["decision_id"],
            "checkpoint": checkpoint,
            "cites": [
                any(ref["digest"] == checkpoint["decision_record"] for ref in capsule["references"])
                for capsule in capsules
            ],
            "artifacts": [
                {
                    "label": label,
                    "name": name,
                    "size": len(raw[name]),
                    "digest": digest(raw[name]),
                    "bytes": base64.b64encode(raw[name]).decode("ascii"),
                    "source": f"{PLAN_SOURCE}/{Path(directory) / name}",
                }
                for label, name in files
            ],
        }
    return result


def build_case(folder, key, replay_case, *, bundled=False, omit_approval=False, packet_variant=None):
    held = {}
    for name in PIECES:
        path = folder / name
        if packet_variant is not None and name == "dispute-packet.json":
            path = packet_variant / name
        if name == A1 and (omit_approval or not path.is_file()):
            continue
        held[name] = path.read_bytes()
    verdict = json.loads(held[VERDICT])
    by_digest = {digest(raw): name for name, raw in held.items()}
    inputs = [
        {"sha256": item["sha256"], "file": by_digest.get(item["sha256"])}
        for item in verdict["evidence"]
    ]
    if replay_case:
        report = replay_case(held)
        report_file = "replay-report.json"
        report_bytes = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
        report_title = "Native replay report (fixture trust)"
    else:
        report_file = "summary.json"
        report_bytes = (folder / report_file).read_bytes()
        report = json.loads(report_bytes)
        report_title = "Provided report (not rerun)"

    verdict_check = report["link3_verdict"]
    if verdict_check["record_sha256"] != digest(held[VERDICT]):
        raise ValueError("Report does not match the verdict bytes")
    stage3 = verdict_check.get("steps", {}).get("3", {})
    missing_a1 = A1 not in held

    def source(name):
        if not bundled:
            return None
        if packet_variant is not None and name == "dispute-packet.json":
            return f"{SOURCE}/goshi-02-letter/out/{name}"
        return f"{SOURCE}/out/{folder.name}/{name}"

    pieces = {}
    for name, title in PIECES.items():
        # In this fixture profile, Wright's first evidence entry is A1.
        pieces[name] = piece(title, held.get(name), source(name), inputs[0]["sha256"] if name == A1 else None)
    pieces[report_file] = piece(report_title, report_bytes, source(report_file) if not replay_case else None)
    packet_report_file = None
    if packet_variant is not None:
        # This independent packet uses a different published fixture key.
        # Keep both original reports and their scopes visible.
        packet_report_file = "goshi-02-result.json"
        packet_report_bytes = (packet_variant / "result.json").read_bytes()
        packet_report = json.loads(packet_report_bytes)
        report["link4_packet"] = packet_report["reports"]["reader"]
        report.pop("joins", None)
        report["join_note"] = "The Goshi -02 packet has its own supplied report. The build did not rerun the cross-format checks for this case."
        pieces[packet_report_file] = piece(
            "Goshi -02 verification report (supplied)",
            packet_report_bytes,
            f"{SOURCE}/goshi-02-letter/out/result.json",
        )

    approved = money(json.loads(held["action-specification.json"])["parameters"])
    attempted = money(json.loads(held["action-specification-executed.json"])["parameters"])
    # A missing A1 must not be read through the back door. Display the outcome recorded in the held A2.
    a2 = json.loads(held["action-binding-attachment-a2.json"])
    outcome = next(stage for stage in a2["stages"] if stage["kind"] == "outcome")
    classification = {
        "@context": CONTEXT,
        "id": f"urn:example:one-chain:{key}:decision",
        "type": "Decision",
        "label": json.loads(held[RECORD])["decision_statement"],
        "magnitude": approved,
        "outcome": {"approved": "Approved"}[outcome["outcome"]],
        "recordedIn": [source(RECORD) or f"ni:///sha-256;{base64.urlsafe_b64encode(bytes.fromhex(digest(held[RECORD]))).decode().rstrip('=')}"],
    }

    execution = report["link1_2_thaha_dps"]
    packet = json.loads(held["dispute-packet.json"])
    settlement = packet["manifest"].get("settlement_anchor", {}).get("anchor", {})
    scope = report["link4_packet"].get("re_derived", {})
    # The native joins bind the receipt's request to the executed parameters
    # (K1) and link the resulting tool receipt to the recorded attempt (K3).
    # A supplied report is not validation of the bytes in the current dossier.
    joins = report.get("joins", {})
    checks_passed = {label.split(" ", 1)[0] for label, passed in joins.items() if passed is True}
    execution_linked = (
        replay_case is not None
        and not missing_a1
        and execution["aee"]["result"] == "CHECKS_PERFORMED"
        and execution.get("dps_a1", {}).get("person_approval", {}).get("status") == "verified"
        and {"K1", "K3"} <= checks_passed
    )
    return {
        "key": key,
        "label": "Approval piece missing" if key == "missing" else folder.name,
        "decision": classification,
        "pieces": pieces,
        "missing": [A1] if missing_a1 else [],
        "attempted": attempted,
        "settlement": money(settlement) if "amount_minor" in settlement else None,
        "packetProfile": packet["manifest"].get("profile"),
        "packetReportFile": packet_report_file,
        "executionLinked": execution_linked,
        "rule": verdict["check"]["rule"],
        "verdict": verdict["check"]["result"],
        "verdictState": verdict_check["state"],
        "recomputed": stage3.get("re_run_result"),
        "recomputeStatus": stage3.get("result"),
        "verdictInputs": inputs,
        "signatureStatus": execution.get("dps_a1", {}).get("person_approval", {}).get("status"),
        "bindingStatus": execution["dps_a2"]["dimensions"]["action_binding"],
        "receiptStatus": execution["aee"]["result"],
        "receiptLimitations": execution["aee"]["not_performed"],
        "packetStatus": report["link4_packet"]["result"],
        "unresolvedAnchors": [
            anchor["name"] for anchor in scope.get("anchors", [])
            if anchor["state"] == "not held"
        ],
        "scope": scope.get("scope_conformance"),
        "dpsCommit": report["standard_commit"],
        "reportFile": report_file,
        "replayed": replay_case is not None,
        "bundled": bundled,
        "joins": joins if replay_case or not missing_a1 else {},
        "joinNote": report.get("join_note"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination HTML file")
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument("--interop-out", type=Path, help="one-chain output root with positive and stated-negative")
    sources.add_argument("--case-dir", type=Path, help="a directory for one case written by one-chain")
    parser.add_argument("--replay", action="store_true", help="rerun native checks with the pinned test trust policy")
    args = parser.parse_args()
    try:
        replay_case = None
        if args.replay:
            from functools import partial

            from replay import native_checks, replay

            replay_case = partial(replay, native_checks())
        if args.case_dir:
            cases = [build_case(args.case_dir, "input", replay_case)]
        else:
            folder = args.interop_out or HERE.parent / "out"
            bundled = args.interop_out is None
            cases = [
                build_case(folder / "positive", "match", replay_case, bundled=bundled),
                build_case(folder / "stated-negative", "difference", replay_case, bundled=bundled),
                build_case(folder / "positive", "missing", replay_case, bundled=bundled, omit_approval=True),
            ]
            for dossier in cases[:2]:
                approval = dossier["decision"]["magnitude"]
                attempt = dossier["attempted"]
                dossier["label"] = f"{approval['value']} {approval['unit']} / {attempt['value']} {attempt['unit']}"
            if bundled:
                goshi = build_case(
                    folder / "positive", "goshi-02", None, bundled=True,
                    packet_variant=HERE.parent / "goshi-02-letter" / "out",
                )
                goshi["label"] = "Goshi -02 · settlement signature coverage"
                cases.append(goshi)
        def embed(value):
            return json.dumps(value, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")

        data = embed({"corpus": CORPUS, "cases": cases})
        plan = (HERE / "plan.html.in").read_text(encoding="utf-8").replace("<!--PLAN_DATA-->", embed(build_plan_cases()))
        template = (HERE / "reader.html.in").read_text(encoding="utf-8")
        logo = base64.b64encode((HERE / "isoluce-logo.png").read_bytes()).decode("ascii")
        page = (
            template.replace("<!--CASE_DATA-->", data)
            .replace("<!--PLAN_READER-->", plan)
            .replace("<!--ISOLUCE_LOGO-->", logo)
        )
        args.output.write_text(page, encoding="utf-8")
    except (ImportError, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, StopIteration) as error:
        parser.exit(2, f"Could not open one-chain output: {error}\n")


if __name__ == "__main__":
    main()
