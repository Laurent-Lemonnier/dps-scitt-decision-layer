#!/usr/bin/env python3.12
"""Run the checker of this folder (verify_from_text.py, written from the text of -00) on the authors' vectors.

The authors' file is data: vectors/vectors.json of action-state-group/cose-deterministic-encodings, pinned by
commit and SHA-256 below. It is not copied into this repository; fetch it and pass its path:

  curl -sO https://raw.githubusercontent.com/action-state-group/cose-deterministic-encodings/b892e0d23c68422ab58bd0f2edd1a6114158a718/vectors/vectors.json
  python3.12 run_authors_vectors.py vectors.json

None of the authors' code is read or run. Each "verify" vector gives a serialized protected header, a payload and
either the preimage or the structured value; no signature. It is wrapped here as an unsigned COSE_Sign1
[protected, {}, payload, h''] and given to verify() with no key, so the signature is not checked. The comparison is
on the draft's outcome (verified / failed / unverified); this checker's own, stricter verdict is reported beside it.

Each "emit" vector gives a structured value; the checker re-creates the preimage with its own core-deterministic
encoder and hashes it, and both are compared with the expected ones. The protected header is not re-created (this
folder has no emitter of headers); it is decoded and its labels are checked against the vector's inputs.

Writes results.json and results.md beside this script. Exit status 0 when every outcome agrees, 1 otherwise."""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import cbor_det  # noqa: E402
import verify_from_text as V  # noqa: E402

PINNED_COMMIT = "b892e0d23c68422ab58bd0f2edd1a6114158a718"
LAST_CHANGE = "37fa8eee92737107922f19c275766eb24a2e2b77"
PINNED_SHA256 = "ca5044045f4da2f5360eb133cc2db683f644efc0fde3ddad2d655ef523c71006"


def envelope(protected_hex, payload_hex):
    """An unsigned COSE_Sign1 around the vector's protected header and payload."""
    return cbor_det.encode(cbor_det.Tag(V.COSE_SIGN1_TAG, [bytes.fromhex(protected_hex), {}, bytes.fromhex(payload_hex), b""]))


def run_verify(v):
    kwargs = {}
    if "preimage" in v:
        kwargs["preimage"] = bytes.fromhex(v["preimage"])
    if "value_cbor" in v:
        kwargs["value"] = cbor_det.decode(bytes.fromhex(v["value_cbor"]))
        kwargs["value_given"] = True
    r = V.verify(envelope(v["protected"], v["payload"]), **kwargs)
    return {"id": v["id"], "description": v["description"], "expected_outcome": v["expected"]["outcome"],
            "expected_reason": v["expected"]["reason"], "obtained_outcome": r["draft_outcome"], "our_verdict": r["verdict"],
            "our_reason": r["reason"], "agrees": r["draft_outcome"] == v["expected"]["outcome"]}


def run_emit(v):
    e = v["expected"]
    out = {"id": v["id"], "description": v["description"]}
    try:
        value = cbor_det.decode(bytes.fromhex(v["value_cbor"]))
        preimage = cbor_det.encode(value)
    except cbor_det.CborError as err:
        out.update({"agrees": False, "our_reason": f"value not decodable or encodable here: {err}"})
        return out
    if v["hash_alg"] not in V.HASH_ALGS:
        out.update({"agrees": False, "our_reason": f"hash algorithm {v['hash_alg']} not implemented here"})
        return out
    digest = V.HASH_ALGS[v["hash_alg"]][1](preimage)
    header = cbor_det.decode(bytes.fromhex(e["protected"]))
    header_ok = (isinstance(header, dict) and header.get(V.LBL_HASH_ALG) == v["hash_alg"]
                 and header.get(V.LBL_PREIMAGE_CT) == v["content_type"] and header.get(V.DEFAULT_LABEL) == V.CORE_DETERMINISTIC)
    out.update({"preimage_agrees": preimage.hex() == e["preimage"], "payload_agrees": digest.hex() == e["payload"],
                "header_labels_agree": header_ok, "our_preimage": preimage.hex()})
    out["agrees"] = out["preimage_agrees"] and out["payload_agrees"] and header_ok
    out["our_reason"] = "preimage, digest and header labels as expected" if out["agrees"] else "differs: see the three flags"
    return out


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    raw = open(argv[1], "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw)
    emit = [run_emit(v) for v in data["emit"]]
    verify = [run_verify(v) for v in data["verify"]]
    stricter = [r for r in verify if r["agrees"] and r["expected_outcome"] == "verified" and r["our_verdict"] != "pass"]
    result = {"vectors_file": {"repository": "action-state-group/cose-deterministic-encodings", "path": "vectors/vectors.json",
                               "read_at_commit": PINNED_COMMIT, "last_changed_at_commit": LAST_CHANGE, "sha256": sha,
                               "sha256_matches_pin": sha == PINNED_SHA256, "header_label": data.get("header_label")},
              "checker": "interop/cose-deterministic/verify_from_text.py (this repository, see its commit)",
              "emit": {"total": len(emit), "agree": sum(r["agrees"] for r in emit), "cases": emit},
              "verify": {"total": len(verify), "agree": sum(r["agrees"] for r in verify), "cases": verify},
              "stricter_here": [r["id"] for r in stricter]}
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
        f.write("\n")
    lines = ["| Vector | Expected (authors) | Draft outcome obtained here | Agrees | This checker's verdict |", "|---|---|---|---|---|"]
    for r in verify:
        lines.append(f"| {r['id']} | {r['expected_outcome']} ({r['expected_reason']}) | {r['obtained_outcome']} | "
                     f"{'yes' if r['agrees'] else 'NO'} | {r['our_verdict']} |")
    lines += ["", "| Emit vector | Preimage | Digest | Header labels |", "|---|---|---|---|"]
    for r in emit:
        def flag(key):
            return "same" if r.get(key) else "DIFFERS"
        lines.append(f"| {r['id']} | {flag('preimage_agrees')} | {flag('payload_agrees')} | {flag('header_labels_agree')} |")
    with open(os.path.join(HERE, "results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"file sha256 {'matches' if sha == PINNED_SHA256 else 'DOES NOT MATCH'} the pin")
    print(f"emit: {result['emit']['agree']}/{result['emit']['total']} agree; verify: {result['verify']['agree']}/{result['verify']['total']} agree")
    print("stricter here (agrees on the draft outcome, not a pass for this checker):", ", ".join(result["stricter_here"]) or "none")
    for r in verify + emit:
        if not r["agrees"]:
            print("DISAGREES:", r["id"], "|", r.get("expected_outcome"), "vs", r.get("obtained_outcome"), "|", r.get("our_reason"))
    return 0 if result["emit"]["agree"] == len(emit) and result["verify"]["agree"] == len(verify) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
