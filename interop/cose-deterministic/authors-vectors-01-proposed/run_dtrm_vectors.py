#!/usr/bin/env python3.12
"""Run the checker of this folder on the vectors the authors propose for -01 ("dtrm"), read as the authors described.

No text of -01 exists yet. The reading applied here comes from a message of one of the authors of 14 November 2026
and from the description inside their vector file, nothing else:

  - label 271 stays; the value is the text string "dtrm"; the registry of -00 is gone;
  - any other value, the integer 1 of -00 included, is a value the verifier does not recognize:
    unverified when it holds only the value, never failed;
  - the only NaN "dtrm" emits is 0xf97e00; an encoder rejects any other NaN (payload, signaling, sign bit).

The -00 checker (../verify_from_text.py, ../cbor_det.py) knows nothing of "dtrm". The reading is applied in front of it:

  - the protected header is rewritten before the check: "dtrm" becomes the value the -00 checker knows (1), and the
    integer 1 becomes one it does not know (UNKNOWN below); any other value is left as it is. The vectors carry no
    signature, so nothing signed is altered; this shim could not be used on a signed envelope.
  - a held value, or a value to emit, is refused before encoding when it holds a NaN other than the one allowed.

The authors' file is data, pinned by commit and SHA-256 below (a pull request of theirs, not merged on 14 November
2026). It is not copied here; fetch it and pass its path:

  curl -sO https://raw.githubusercontent.com/action-state-group/cose-deterministic-encodings/3e3440db01c597701d019a49dc0054c66e7b7010/vectors/vectors.json
  python3.12 run_dtrm_vectors.py vectors.json

None of the authors' code is read or run. Writes results.json and results.md beside this script. Exit status 0 when
every expected outcome is obtained, 1 otherwise, 2 (nothing written) when the file is not the pinned one."""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import cbor_det  # noqa: E402
import verify_from_text as V  # noqa: E402

PINNED_COMMIT = "3e3440db01c597701d019a49dc0054c66e7b7010"
PINNED_SHA256 = "799b2b05c0a7ad469dfc049c7003cbe7f963865d4f6f35fa2757bfc1a8fad3c2"
DTRM = "dtrm"
UNKNOWN = 2 ** 31 - 1          # an integer the -00 checker does not recognize
THE_NAN = 0x7FF8000000000000   # binary64 bits of the NaN that 0xf97e00 denotes


class NanRefused(Exception):
    pass


def refuse_other_nans(v):
    """Raise when v holds a NaN other than the one "dtrm" emits. Decided from the bits, as the authors do."""
    if isinstance(v, float):
        if v != v and int.from_bytes(struct.pack(">d", v), "big") != THE_NAN:
            raise NanRefused("a NaN other than 0xf97e00")
    elif isinstance(v, (list, tuple)):
        for item in v:
            refuse_other_nans(item)
    elif isinstance(v, dict):
        for k, item in v.items():
            refuse_other_nans(k)
            refuse_other_nans(item)
    elif isinstance(v, cbor_det.CborMap):
        for k, item in v.pairs:
            refuse_other_nans(k)
            refuse_other_nans(item)
    elif isinstance(v, cbor_det.Tag):
        refuse_other_nans(v.value)


def translate_header(protected_hex):
    """The -01 reading, given to the -00 checker: "dtrm" -> the value it knows (1); the integer 1 -> UNKNOWN.
    Any other value is left as it is: the checker already treats it as one it does not recognize."""
    header = cbor_det.decode(bytes.fromhex(protected_hex))
    if isinstance(header, dict) and V.DEFAULT_LABEL in header:
        header = dict(header)
        value = header[V.DEFAULT_LABEL]
        if value == DTRM:
            header[V.DEFAULT_LABEL] = V.CORE_DETERMINISTIC
        elif type(value) is int and value == V.CORE_DETERMINISTIC:
            header[V.DEFAULT_LABEL] = UNKNOWN
    return cbor_det.encode(header)


def run_verify_untranslated(v):
    """Control: the -00 checker alone on the same case, header as given, no NaN rule."""
    kwargs = {}
    if "preimage" in v:
        kwargs["preimage"] = bytes.fromhex(v["preimage"])
    if "value_cbor" in v:
        kwargs["value"] = cbor_det.decode(bytes.fromhex(v["value_cbor"]))
        kwargs["value_given"] = True
    envelope = cbor_det.encode(cbor_det.Tag(V.COSE_SIGN1_TAG, [bytes.fromhex(v["protected"]), {},
                                                              bytes.fromhex(v["payload"]), b""]))
    r = V.verify(envelope, **kwargs)
    return {"id": v["id"], "expected_outcome": v["expected"]["outcome"], "obtained_outcome": r["draft_outcome"],
            "agrees": r["draft_outcome"] == v["expected"]["outcome"]}


def run_verify(v):
    out = {"id": v["id"], "description": v["description"], "expected_outcome": v["expected"]["outcome"],
           "expected_reason": v["expected"]["reason"]}
    kwargs = {}
    if "preimage" in v:
        kwargs["preimage"] = bytes.fromhex(v["preimage"])
    if "value_cbor" in v:
        value = cbor_det.decode(bytes.fromhex(v["value_cbor"]))
        try:
            refuse_other_nans(value)
        except NanRefused as e:
            out.update({"obtained_outcome": "unverified", "our_verdict": "cannot-encode-value",
                        "our_reason": f"value not encodable under the reading applied: {e}"})
            out["agrees"] = out["obtained_outcome"] == out["expected_outcome"]
            return out
        kwargs["value"] = value
        kwargs["value_given"] = True
    envelope = cbor_det.encode(cbor_det.Tag(V.COSE_SIGN1_TAG, [translate_header(v["protected"]), {},
                                                              bytes.fromhex(v["payload"]), b""]))
    r = V.verify(envelope, **kwargs)
    out.update({"obtained_outcome": r["draft_outcome"], "our_verdict": r["verdict"], "our_reason": r["reason"]})
    out["agrees"] = out["obtained_outcome"] == out["expected_outcome"]
    return out


def run_emit(v):
    e = v["expected"]
    out = {"id": v["id"], "description": v["description"]}
    try:
        value = cbor_det.decode(bytes.fromhex(v["value_cbor"]))
        refuse_other_nans(value)
        preimage = cbor_det.encode(value)
    except (cbor_det.CborError, NanRefused) as err:
        out.update({"agrees": False, "our_reason": f"value not decodable or encodable here: {err}"})
        return out
    if v["hash_alg"] not in V.HASH_ALGS:
        out.update({"agrees": False, "our_reason": f"hash algorithm {v['hash_alg']} not implemented here"})
        return out
    digest = V.HASH_ALGS[v["hash_alg"]][1](preimage)
    header = cbor_det.decode(bytes.fromhex(e["protected"]))
    header_ok = (isinstance(header, dict) and header.get(V.LBL_HASH_ALG) == v["hash_alg"]
                 and header.get(V.LBL_PREIMAGE_CT) == v["content_type"] and header.get(V.DEFAULT_LABEL) == DTRM)
    out.update({"preimage_agrees": preimage.hex() == e["preimage"], "payload_agrees": digest.hex() == e["payload"],
                "header_labels_agree": header_ok, "our_preimage": preimage.hex()})
    out["agrees"] = out["preimage_agrees"] and out["payload_agrees"] and header_ok
    out["our_reason"] = "preimage, digest and header labels as expected" if out["agrees"] else "differs: see the three flags"
    return out


def run_reject(v):
    """The authors expect an encoder error and no preimage."""
    out = {"id": v["id"], "description": v["description"], "expected": v["expected"]}
    try:
        value = cbor_det.decode(bytes.fromhex(v["value_cbor"]))
        refuse_other_nans(value)
        out.update({"refused": False, "our_reason": "encoded: " + cbor_det.encode(value).hex()})
    except NanRefused as err:
        out.update({"refused": True, "our_reason": f"refused before encoding: {err}"})
    except cbor_det.CborError as err:
        out.update({"refused": True, "our_reason": f"refused by the encoder or decoder of this folder: {err}"})
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
    emit = [run_emit(v) for v in data["emit"]]
    verify = [run_verify(v) for v in data["verify"]]
    reject = [run_reject(v) for v in data["reject"]]
    stricter = [r for r in verify if r["agrees"] and r["expected_outcome"] == "verified" and r["our_verdict"] != "pass"]
    groups = {"emit": emit, "verify": verify, "reject": reject}
    result = {"vectors_file": {"repository": "action-state-group/cose-deterministic-encodings", "path": "vectors/vectors.json",
                               "read_at_commit": PINNED_COMMIT, "sha256": sha, "header_label": data.get("header_label"),
                               "status": "proposed for -01 in a pull request of the authors, not merged on 14 November 2026"},
              "reading": "from the authors' message of 14 November 2026 and the description in their file; no -01 text exists",
              "checker": "interop/cose-deterministic/verify_from_text.py, unchanged, behind the translation of this script",
              "stricter_here": [r["id"] for r in stricter]}
    for name, rows in groups.items():
        result[name] = {"total": len(rows), "agree": sum(r["agrees"] for r in rows), "cases": rows}
    plain = [run_verify_untranslated(v) for v in data["verify"]]
    result["control_minus_00_checker_alone"] = {
        "what": "the -00 checker on the 27 verify cases with the header as given and no NaN rule",
        "total": len(plain), "agree": sum(r["agrees"] for r in plain),
        "differ": [r for r in plain if not r["agrees"]],
        "failed_obtained_where_not_expected": [r["id"] for r in plain
                                               if r["obtained_outcome"] == "failed" and r["expected_outcome"] != "failed"]}
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
        f.write("\n")
    lines = ["| Vector | Expected (authors) | Outcome obtained here | Agrees | This checker's verdict |", "|---|---|---|---|---|"]
    for r in verify:
        lines.append(f"| {r['id']} | {r['expected_outcome']} ({r['expected_reason']}) | {r['obtained_outcome']} | "
                     f"{'yes' if r['agrees'] else 'NO'} | {r['our_verdict']} |")
    lines += ["", "| Emit vector | Preimage | Digest | Header labels |", "|---|---|---|---|"]
    for r in emit:
        def flag(key):
            return "same" if r.get(key) else "DIFFERS"
        lines.append(f"| {r['id']} | {flag('preimage_agrees')} | {flag('payload_agrees')} | {flag('header_labels_agree')} |")
    lines += ["", "| Reject vector | Expected (authors) | Here |", "|---|---|---|"]
    for r in reject:
        lines.append(f"| {r['id']} | encoder error, no preimage | {'refused' if r['refused'] else 'ENCODED'} |")
    with open(os.path.join(HERE, "results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("file sha256 matches the pin")
    print("; ".join(f"{name}: {result[name]['agree']}/{result[name]['total']} agree" for name in groups))
    print("stricter here (agrees on the outcome, not a pass for this checker):", ", ".join(result["stricter_here"]) or "none")
    for r in verify + emit + reject:
        if not r["agrees"]:
            print("DISAGREES:", r["id"], "|", r.get("expected_outcome", r.get("expected")), "vs",
                  r.get("obtained_outcome", r.get("refused")), "|", r.get("our_reason"))
    return 0 if all(result[name]["agree"] == result[name]["total"] for name in groups) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
