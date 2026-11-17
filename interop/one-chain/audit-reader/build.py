#!/usr/bin/env python3
"""Build an offline HTML reader from the public one-chain fixtures."""
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

PIECES = {
    "decision-record.json": "Decision record",
    "action-binding-attachment-a1.json": "Approval attachment A1",
    "action-binding-attachment-a2.json": "Execution attachment A2",
    "signatures-attachment.json": "Person signature attachment",
    "action-specification.json": "Approved specification",
    "action-specification-executed.json": "Attempted specification",
    "receipts.diag.json": "Receipt diagnostic representation",
    "aee-bundle.cbor": "Native execution receipt bundle",
    "tool-response.json": "Tool response",
    "verdict-record.json": "Verdict record",
    "verdict-record.container.json": "Verdict container",
    "dispute-packet.json": "Payment dispute packet",
    "summary.json": "Published verification report",
}


def read(path):
    return json.loads(path.read_bytes())


def money(parameters):
    return {
        "value": str(Decimal(parameters["amount_minor"]) / Decimal(100)),
        "unit": parameters["currency"],
    }


def build_case(key, directory, label, missing=()):
    folder = HERE.parent / "out" / directory
    pieces = {}
    for name, title in PIECES.items():
        content = (folder / name).read_bytes()
        pieces[name] = {
            "title": title,
            "sha256": hashlib.sha256(content).hexdigest(),
            "source": f"{SOURCE}/out/{directory}/{name}",
            "bytes": None if name in missing else base64.b64encode(content).decode("ascii"),
        }

    approved = money(read(folder / "action-specification.json")["parameters"])
    attempted = money(read(folder / "action-specification-executed.json")["parameters"])
    approval = read(folder / "action-binding-attachment-a1.json")
    outcome = next(stage for stage in approval["stages"] if stage["kind"] == "outcome")
    record = read(folder / "decision-record.json")
    classification = {
        "@context": CONTEXT,
        "id": f"urn:example:one-chain:{key}:decision",
        "type": "Decision",
        "label": record["decision_statement"],
        "magnitude": approved,
        "outcome": {"approved": "Approved"}[outcome["outcome"]],
        "recordedIn": [pieces["decision-record.json"]["source"]],
    }

    verdict = read(folder / "verdict-record.json")
    report = read(folder / "summary.json")
    verdict_check = report["link3_verdict"]
    if verdict_check["record_sha256"] != pieces["verdict-record.json"]["sha256"]:
        raise ValueError("Published report does not match the verdict bytes")
    held_by_digest = {
        item["sha256"]: name for name, item in pieces.items() if item["bytes"] is not None
    }
    inputs = [
        {"sha256": item["sha256"], "file": held_by_digest.get(item["sha256"])}
        for item in verdict["evidence"]
    ]
    if sum(item["file"] is None for item in inputs) != len(missing):
        raise ValueError("Unexpected verdict evidence missing")
    stated = verdict["check"]["result"]
    recomputed = verdict_check["steps"]["3"]["re_run_result"]
    if stated != recomputed or verdict_check["state"] != "released":
        raise ValueError("Unexpected verdict in the published fixture")

    execution = report["link1_2_thaha_dps"]
    packet = read(folder / "dispute-packet.json")
    settlement = packet["manifest"]["settlement_anchor"]["anchor"]
    return {
        "key": key,
        "label": label,
        "decision": classification,
        "pieces": pieces,
        "missing": list(missing),
        "attempted": attempted,
        "settlement": money(settlement),
        "rule": verdict["check"]["rule"],
        "verdict": stated,
        "verdictState": verdict_check["state"],
        "verdictInputs": inputs,
        "signatureStatus": execution["dps_a1"]["person_approval"]["status"],
        "bindingStatus": execution["dps_a2"]["dimensions"]["action_binding"],
        "receiptStatus": execution["aee"]["result"],
        "receiptLimitations": execution["aee"]["not_performed"],
        "packetStatus": report["link4_packet"]["result"],
        "scope": report["link4_packet"]["re_derived"]["scope_conformance"],
        "dpsCommit": report["standard_commit"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination HTML file")
    args = parser.parse_args()
    data = {
        "corpus": CORPUS,
        "cases": [
            build_case("match", "positive", "120 / 120 EUR"),
            build_case("difference", "stated-negative", "120 / 150 EUR"),
            build_case(
                "missing", "positive", "Approval piece missing",
                missing=("action-binding-attachment-a1.json",),
            ),
        ],
    }
    packed = json.dumps(data, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    template = (HERE / "reader.html.in").read_text(encoding="utf-8")
    args.output.write_text(template.replace("<!--CASE_DATA-->", packed), encoding="utf-8")


if __name__ == "__main__":
    main()
