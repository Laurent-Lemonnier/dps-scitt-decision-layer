"""Replay the native one-chain checks on the supplied bytes with fixture trust."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
STANDARD_PIN = (HERE.parents[1] / "aqta/approval-record/DPS_STANDARD_COMMIT").read_text().strip()
A1 = "action-binding-attachment-a1.json"
A2 = "action-binding-attachment-a2.json"
RECORD = "decision-record.json"
SIGNATURE = "signatures-attachment.json"
VERDICT = "verdict-record.json"


def native_checks():
    """Load the original tools against a clean checkout of their expected DPS version."""
    location = os.environ.get("DPS_STANDARD")
    if not location:
        raise ValueError("Set DPS_STANDARD to a Git checkout at " + STANDARD_PIN)
    standard = Path(location).resolve()
    try:
        head = subprocess.check_output(
            ["git", "-C", str(standard), "rev-parse", "HEAD"], text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(standard), "status", "--porcelain"],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError as e:
        raise ValueError("DPS_STANDARD must be a Git checkout") from e
    if head != STANDARD_PIN or dirty:
        raise ValueError("Expected a clean DPS Standard checkout at " + STANDARD_PIN)
    spec = importlib.util.spec_from_file_location("one_chain_native", HERE.parent / "build.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    return native


def replay(native, held):
    """Call the fixture verifiers directly. No dossier-supplied report or key is used."""
    c17, aee, sha256 = native.C17, native.AEE, native.sha256
    raw = held[VERDICT]
    report, _ = native.checker({sha256(raw): native.T["intake"]})
    verdict = report.check(
        raw,
        {sha256(held[name]): (held[name], None) for name in (A1, A2, RECORD) if name in held},
        json.loads(held["verdict-record.container.json"]),
    )
    execution = aee.verify_bundle(
        held["aee-bundle.cbor"],
        issuer_public_key=c17.harness_key.public_key(),
        agent_public_key=c17.agent_key.public_key(),
    )
    anchors = {
        native.TYPE_A: {sha256(held[name]) for name in (A1, A2) if name in held},
        native.TYPE_S: {sha256(held[SIGNATURE])},
        native.TYPE_V: {sha256(raw)},
        native.TYPE_R: set(execution.get("record_hashes", {}).values()),
    }
    packet = json.loads(held["dispute-packet.json"])
    dispute = native.G.verify_packet(
        packet, public_key_hex=c17.raw_public(native.packet_key).hex(), held=anchors,
    )
    approved_spec = held["action-specification.json"]
    attempted_spec = held["action-specification-executed.json"]
    approved = json.loads(approved_spec)["parameters"]
    art = {
        "record_bytes": held[RECORD],
        "a2": json.loads(held[A2]),
        "a2_bytes": held[A2],
        "sig": json.loads(held[SIGNATURE]),
        "sig_bytes": held[SIGNATURE],
        "spec_bytes": approved_spec,
        "xspec_bytes": attempted_spec,
        "approved": approved,
    }
    link12 = {
        "aee": execution,
        "dps_a2": c17.dps_checks(art, "a2"),
        "route1": c17.read_binding(held["binding-statement.cose"], anchors),
    }
    result = {
        "standard_commit": STANDARD_PIN,
        "link1_2_thaha_dps": link12,
        "link3_verdict": verdict,
        "link4_packet": dispute,
    }
    if A1 not in held:
        result["join_note"] = "Cross-format checks left open: approval attachment A1 is missing."
        return result
    link12["dps_a1"] = c17.dps_checks({**art, "a1": json.loads(held[A1])}, "a1")
    if execution["result"] != "CHECKS_PERFORMED":
        result["join_note"] = "Cross-format checks left open: execution bundle check failed."
        return result

    bundle = aee.decode_canonical(held["aee-bundle.cbor"], "bundle")
    receipts = [
        aee.decode_canonical(item, f"receipt {index}") if isinstance(item, bytes) else item
        for index, item in enumerate(bundle[2])
    ]
    art.update(
        a1=json.loads(held[A1]), a1_bytes=held[A1], receipts=receipts,
        pepper=c17.PEPPER, canonical_id=c17.APPROVER_CANONICAL_ID,
    )
    link12["joins"] = c17.joins(art, execution)
    expected = "executed_as_approved" if approved_spec == attempted_spec else "not_as_approved"
    result["joins"] = native.joins({
        "chain": art,
        "packet": packet,
        "verdict_raw": raw,
        "verdict_stated": json.loads(raw)["check"]["result"],
        "verdict_native": expected,
    }, result)
    return result
