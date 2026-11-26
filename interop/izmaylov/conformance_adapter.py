#!/usr/bin/env python3
"""Run the independent -02 verifier behind Provared's JSONL conformance kit."""
import json
from pathlib import Path
import sys

from run_vectors import FAMILIES, NOT_ATTEMPTED, Skip, V, reported_slip_signature, trap


# These runners already return their computed answer, independently of scoring.
RAW_FAMILIES = {
    "base64url", "canonical-json", "times", "keys", "ed25519-signatures",
    "seal-key-sets", "stub-contents", "countersignature-contents",
    "approval-contents", "cancellation-contents", "acknowledgement-contents",
    "pass-contents", "seal-contents", "tree-paths", "tree-inclusion",
    "tree-consistency", "tree-consistency-checks", "stamps", "stamps-openssl",
    "stamps-strict-keys", "stamps-flips-ed25519", "stamps-flips-ecdsa",
    "stamps-flips-rsa",
}


def check_origin(case):
    V.check_origin(case["text"], case["rpId"])
    return True


def read_record(case):
    record = V.read_record(case["record"], case["kind"])
    if record.problems:
        raise V.Refused(record.problems[0], "The record was refused by the draft verifier")
    return {
        "kind": record.kind,
        "fingerprint": record.digest,
        "content": record.content,
        "signatures": len(record.sigs),
    }


def check_slip(case):
    opts = case.get("options") or {}
    if "disclosures" in case or "disclosures" in opts or "issuerOrigins" in opts:
        raise Skip("Disclosure and expected-origin options need a separate FORMAT mapping")
    result, record = V.check_slip(case["record"], opts.get("issuerKeys"),
                                  V.Methods(without=opts.get("withoutMethods")))
    if isinstance(record.content, dict) and {"_sd", "_sd_alg"}.intersection(record.content):
        raise Skip("Covered fields are specified by FORMAT")
    return {
        "kind": result["kind"],
        "fingerprint": result["fingerprint"],
        "problems": [{"code": code, "message": f"Independent draft verifier: {code}"}
                     for code in result["problems"]],
        "notes": [],
        "signature": reported_slip_signature(result),
        "issuerKey": result.get("issuerKey"),
        "content": record.content if record.encoded_ok else None,
        "covered": [],
        "disclosureProblems": [],
    }


def answer_request(request):
    stem = Path(request["file"]).stem
    case = request["case"]
    if "expected" in case:
        raise ValueError("A kit request must not include its expected answer")
    try:
        if stem == "origins":
            answer = trap(lambda: check_origin(case))
        elif stem == "records":
            answer = trap(lambda: read_record(case))
        elif stem == "slips":
            answer = trap(lambda: check_slip(case))
        elif stem in RAW_FAMILIES:
            _, answer = FAMILIES[stem]({**case, "expected": None})
        elif request["function"] == "checkBook":
            raise Skip("Core report was tested separately; this bridge has no complete mapping to the kit report shape")
        else:
            raise Skip(NOT_ATTEMPTED.get(stem, "No public draft-verifier mapping for this kit function"))
    except Skip as skipped:
        return {"id": request["id"], "skip": str(skipped)}
    if "refused" in answer:
        refusal = answer["refused"]
        code = refusal["code"] if isinstance(refusal, dict) else refusal
        answer = {"refused": {"code": code, "message": f"Independent draft verifier: {code}"}}
    return {"id": request["id"], "answer": answer}


def main():
    for line in sys.stdin:
        request = json.loads(line)
        print(json.dumps(answer_request(request), ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
