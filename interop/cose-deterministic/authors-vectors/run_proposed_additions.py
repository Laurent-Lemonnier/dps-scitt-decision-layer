#!/usr/bin/env python3.12
"""Run the checker of this folder on proposed-additions.json, including the cases that need a format extension.

  python3.12 run_proposed_additions.py

Two things the adapter for the authors' file (run_authors_vectors.py) does not do are done here: value_cbor is decoded
as a sequence of items when the content type is a CBOR sequence, and an `unprotected` member, when a case carries
one, becomes the unprotected header of the envelope. The cases under "open" have no expected outcome: this checker's
answer is printed, not compared. Standard library only. Exit status 0 when every case that states an expectation
meets it and the recorded answers are the ones this run gives, 1 otherwise."""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import cbor_det  # noqa: E402
import verify_from_text as V  # noqa: E402


def content_type(case):
    return cbor_det.decode(bytes.fromhex(case["protected"])).get(V.LBL_PREIMAGE_CT)


def held_value(case, ct):
    raw = bytes.fromhex(case["value_cbor"])
    return cbor_det.decode(raw, sequence=True) if V._is_seq(ct) else cbor_det.decode(raw)


def run_verify(case):
    ct = content_type(case)
    kwargs = {}
    if "preimage" in case:
        kwargs["preimage"] = bytes.fromhex(case["preimage"])
    if "value_cbor" in case:
        kwargs["value"] = held_value(case, ct)
        kwargs["value_given"] = True
    unprotected = cbor_det.decode(bytes.fromhex(case["unprotected"])) if "unprotected" in case else {}
    envelope = cbor_det.encode(cbor_det.Tag(V.COSE_SIGN1_TAG, [bytes.fromhex(case["protected"]), unprotected,
                                                               bytes.fromhex(case["payload"]), b""]))
    r = V.verify(envelope, **kwargs)
    return {"draft_outcome": r["draft_outcome"], "verdict": r["verdict"]}


def run_emit(case):
    items = cbor_det.decode(bytes.fromhex(case["value_cbor"]), sequence=True)
    preimage = b"".join(cbor_det.encode(item) for item in items)
    digest = V.HASH_ALGS[case["hash_alg"]][1](preimage)
    return preimage.hex() == case["expected"]["preimage"] and digest.hex() == case["expected"]["payload"]


def main():
    with open(os.path.join(HERE, "proposed-additions.json"), encoding="utf-8") as f:
        data = json.load(f)
    ok = True
    for case in data["emit"]:
        good = run_emit(case)
        ok &= good
        print(f"emit   {case['id']}: preimage and digest {'as expected' if good else 'DIFFER'}")
    for case in data["verify"]:
        got = run_verify(case)
        good = got["draft_outcome"] == case["expected"]["outcome"] and got == case.get("this_checker", got)
        ok &= good
        print(f"verify {case['id']}: expected {case['expected']['outcome']}, obtained {got['draft_outcome']} "
              f"({got['verdict']}){'' if good else '  <-- DIFFERS'}")
    for case in data["open"]:
        got = run_verify(case)
        recorded = {k: case["this_checker"][k] for k in ("draft_outcome", "verdict")}
        good = got == recorded
        ok &= good
        print(f"open   {case['id']}: this checker gives {got['draft_outcome']} ({got['verdict']}); no expected outcome"
              f"{'' if good else '  <-- differs from the recorded answer'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
