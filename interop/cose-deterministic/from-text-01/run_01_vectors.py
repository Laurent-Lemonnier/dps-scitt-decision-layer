#!/usr/bin/env python3.12
"""Run the -01 checker of this folder (verify_from_text_01.py, written from the text of -01) on the authors' vectors.

The pass of 14 November 2026 (../authors-vectors-01-proposed/) read -01 from the authors' description, with a shim in
front of the -00 checker, because no -01 text existed. The text now exists in the authors' repository; this pass reads
it, and nothing else (pinned below). The checker handles "dtrm" itself; nothing is translated.

One point of the text allows two behaviours, and both are run. -01 Section 3.1 says "dtrm" excludes non-trivial NaNs
as draft-ietf-cbor-serialization-12 defines; that document's Section 4.1 says an encoder presented with such a NaN
"MUST either reject it or encode it as 0xf97e00". nan_mode "reject" and nan_mode "canonical" are both run; the
authors' vectors expect the first.

The vectors are data, read at the commit below (main, after the authors merged their pull request #9 on 14 November
2026); the file is the one read on 14 November (same SHA-256). Not copied here; fetch and pass its path:

  curl -sO https://raw.githubusercontent.com/action-state-group/cose-deterministic-encodings/0621eca4dd59002a92e3eb4781ad1371aaa53bb5/vectors/vectors.json
  python3.12 run_01_vectors.py vectors.json

None of the authors' code is read or run. Writes results.json and results.md beside this script. Exit status 0 when
the reject mode agrees with every expected outcome and the canonical mode differs exactly where the text allows it,
1 otherwise, 2 (nothing written) when the file is not the pinned one."""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_from_text_01 as V  # noqa: E402
cbor_det = V.cbor_det

PINNED_COMMIT = "0621eca4dd59002a92e3eb4781ad1371aaa53bb5"
PINNED_SHA256 = "799b2b05c0a7ad469dfc049c7003cbe7f963865d4f6f35fa2757bfc1a8fad3c2"
TEXT = {"draft-mih-sokolov-cose-deterministic-encodings-01.txt, authors' repository at the same commit":
        "b7a3d0a6e0e5db08184b4667ff6e3021d09964d7890bb3b8a936c23dc8d9b25e",
        "draft-ietf-cbor-serialization-12.txt, ietf.org archive": "1ebad1e4bf28b60212c851fbe21f270bb8ea9e94f3c8728e10063b8be2bb539c"}
MODES = ("reject", "canonical")


def envelope(v):
    return cbor_det.encode(cbor_det.Tag(V.COSE_SIGN1_TAG, [bytes.fromhex(v["protected"]), {}, bytes.fromhex(v["payload"]), b""]))


def run_verify(v, mode):
    kwargs = {"nan_mode": mode}
    if "preimage" in v:
        kwargs["preimage"] = bytes.fromhex(v["preimage"])
    if "value_cbor" in v:
        kwargs["value"] = cbor_det.decode(bytes.fromhex(v["value_cbor"]))
        kwargs["value_given"] = True
    r = V.verify(envelope(v), **kwargs)
    return {"id": v["id"], "expected_outcome": v["expected"]["outcome"], "expected_reason": v["expected"]["reason"],
            "obtained_outcome": r["draft_outcome"], "our_verdict": r["verdict"], "our_reason": r["reason"],
            "agrees": r["draft_outcome"] == v["expected"]["outcome"]}


def encode_dtrm(value_cbor, mode):
    return cbor_det.encode(V.dtrm_value(cbor_det.decode(bytes.fromhex(value_cbor)), mode))


def run_emit(v, mode):
    e = v["expected"]
    out = {"id": v["id"]}
    try:
        preimage = encode_dtrm(v["value_cbor"], mode)
    except (cbor_det.CborError, V.NonTrivialNaN) as err:
        out.update({"agrees": False, "our_reason": f"not encodable here: {err}"})
        return out
    digest = V.HASH_ALGS[v["hash_alg"]][1](preimage)
    header = cbor_det.decode(bytes.fromhex(e["protected"]))
    header_ok = (isinstance(header, dict) and header.get(V.LBL_HASH_ALG) == v["hash_alg"]
                 and header.get(V.LBL_PREIMAGE_CT) == v["content_type"] and header.get(V.DEFAULT_LABEL) == V.DTRM)
    out.update({"preimage_agrees": preimage.hex() == e["preimage"], "payload_agrees": digest.hex() == e["payload"],
                "header_labels_agree": header_ok})
    out["agrees"] = out["preimage_agrees"] and out["payload_agrees"] and header_ok
    return out


def run_reject(v, mode):
    out = {"id": v["id"], "expected": v["expected"]}
    try:
        out.update({"refused": False, "our_output": encode_dtrm(v["value_cbor"], mode).hex()})
    except (V.NonTrivialNaN, cbor_det.CborError) as err:
        out.update({"refused": True, "our_output": f"refused: {err}"})
    out["agrees"] = out["refused"] and v["expected"] == {"error": "encode"}
    return out


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    raw = open(argv[1], "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != PINNED_SHA256:
        print(f"vectors SHA-256 mismatch: expected {PINNED_SHA256}, got {sha}", file=sys.stderr)
        return 2
    data = json.loads(raw)
    result = {"vectors_file": {"repository": "action-state-group/cose-deterministic-encodings", "path": "vectors/vectors.json",
                               "read_at_commit": PINNED_COMMIT, "sha256": sha, "header_label": data.get("header_label")},
              "texts_read": TEXT, "checker": "from-text-01/verify_from_text_01.py", "modes": {}}
    for mode in MODES:
        groups = {"emit": [run_emit(v, mode) for v in data["emit"]],
                  "verify": [run_verify(v, mode) for v in data["verify"]],
                  "reject": [run_reject(v, mode) for v in data["reject"]]}
        result["modes"][mode] = {name: {"total": len(rows), "agree": sum(r["agrees"] for r in rows), "cases": rows}
                                 for name, rows in groups.items()}
    rej, can = result["modes"]["reject"], result["modes"]["canonical"]
    differ = sorted(r["id"] for g in ("emit", "verify", "reject") for r in can[g]["cases"] if not r["agrees"])
    nan_ids = sorted(v["id"] for g in ("emit", "verify", "reject") for v in data[g]
                     if "nan" in v["id"].lower() and v.get("expected") not in (None,) and
                     (g != "emit"))
    result["canonical_mode_differs_on"] = differ
    result["stricter_here"] = [r["id"] for r in rej["verify"]["cases"]
                               if r["agrees"] and r["expected_outcome"] == "verified" and r["our_verdict"] != "pass"]
    ok_reject = all(rej[g]["agree"] == rej[g]["total"] for g in rej)
    ok_canonical = differ == nan_ids
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
        f.write("\n")
    lines = ["| Vector | Expected (authors) | Encoder rejects non-trivial NaNs | Encoder writes them as 0xf97e00 |",
             "|---|---|---|---|"]
    can_by = {r["id"]: r for g in ("verify", "reject") for r in can[g]["cases"]}
    for r in rej["verify"]["cases"]:
        c = can_by[r["id"]]
        lines.append(f"| {r['id']} | {r['expected_outcome']} | {r['obtained_outcome']}{'' if r['agrees'] else ' (DIFFERS)'} | "
                     f"{c['obtained_outcome']}{'' if c['agrees'] else ' (differs)'} |")
    for r in rej["reject"]["cases"]:
        c = can_by[r["id"]]
        lines.append(f"| {r['id']} | encoder error | {'refused' if r['refused'] else 'ENCODED'} | "
                     f"{'refused' if c['refused'] else 'encoded ' + c['our_output']} |")
    lines += ["", f"Emit: {rej['emit']['agree']}/{rej['emit']['total']} (reject mode), "
                  f"{can['emit']['agree']}/{can['emit']['total']} (canonical mode)."]
    with open(os.path.join(HERE, "results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("file sha256 matches the pin")
    for mode in MODES:
        m = result["modes"][mode]
        print(f"{mode}: " + "; ".join(f"{g} {m[g]['agree']}/{m[g]['total']}" for g in m))
    print("canonical mode differs on:", ", ".join(differ) or "nothing")
    print("stricter here (agrees on the outcome, not a pass for this checker):", ", ".join(result["stricter_here"]) or "none")
    return 0 if ok_reject and ok_canonical else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
