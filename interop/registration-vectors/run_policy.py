#!/usr/bin/env python3
"""Run the fifteen vectors through the registration policy of ts.isoluce.net, in memory.

  python3 run_policy.py        # writes results-ts-isoluce-net.json and results-ts-isoluce-net.md

The policy is the code of service/scitt/ (policy.py and cose.py, as deployed at ts.isoluce.net since 14 November
2026). It is called as a function: no HTTP request, no log, no receipt, and no trust anchor added to any service.
Four settings:

  strict               test key 1 in an in-memory trust-anchor set, unknown issuers rejected
  open_with_test_key   test key 1 in an in-memory trust-anchor set, unknown issuers accepted
  open_without_key     no anchor, unknown issuers accepted
  reject_without_key   no anchor, unknown issuers rejected: what the deployed service does with these vectors,
                       since neither test key is one of its anchors

Needs cbor2 and cryptography. Deterministic: the same two files every time."""
import hashlib
import json
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "service"))
from scitt import policy  # noqa: E402

VECTORS = HERE / "vectors"
SETTINGS = (("strict", True, "reject", "Test key 1 injected, unknown issuers rejected"),
            ("open_with_test_key", True, "accept", "Test key 1 injected, unknown issuers accepted"),
            ("open_without_key", False, "accept", "No anchor, unknown issuers accepted"),
            ("reject_without_key", False, "reject", "No anchor, unknown issuers rejected (as deployed)"))


def evaluate_all():
    meta = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        anchors_file = pathlib.Path(tmp) / "anchors.json"
        anchors_file.write_text(json.dumps([{"kid": meta["kid"], "holder": "registration vectors, test key 1",
                                             "public_key_pem": (VECTORS / "test-key-1.pub.pem").read_text()}]))
        anchors = {True: policy.TrustAnchors(str(anchors_file)), False: policy.TrustAnchors(None)}
    rows = []
    for item in meta["vectors"]:
        raw = (VECTORS / item["file"]).read_bytes()
        row = {"id": item["id"], "file": item["file"]}
        for name, with_key, mode, _label in SETTINGS:
            try:
                registered, m = policy.evaluate(raw, anchors[with_key], mode)
                row[name] = {"registered": True, "issuer_verified": m["issuer_verified"],
                             "registered_bytes_equal_submitted": registered == raw,
                             "leaf": hashlib.sha256(b"\x00" + registered).hexdigest()}
            except policy.Rejected as r:
                row[name] = {"registered": False, "title": r.title, "detail": r.detail}
        rows.append(row)
    return meta, rows


def cell(result, baseline_leaf, is_baseline):
    if not result["registered"]:
        return f'refused: "{result["title"]}"'
    text = "admitted, issuer verified" if result["issuer_verified"] else "admitted, issuer NOT verified"
    if not result["registered_bytes_equal_submitted"]:
        text += ", re-framed"
        if not is_baseline and result["leaf"] == baseline_leaf:
            text += ", same entry as R01"
    return text


def main():
    meta, rows = evaluate_all()
    (HERE / "results-ts-isoluce-net.json").write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
    change = {item["id"]: item["change"] for item in meta["vectors"]}
    baseline_leaf = hashlib.sha256(b"\x00" + (VECTORS / meta["vectors"][0]["file"]).read_bytes()).hexdigest()
    lines = ["Offline evaluation by the policy code of `service/scitt/` (the Registration Policy of ts.isoluce.net since "
             "14 November 2026), written by `run_policy.py`. The four columns run the same code. In the first two, test "
             "key 1 is supplied only to an in-memory trust-anchor set, with unknown issuers rejected or accepted; the "
             "last two have no anchor, with unknown issuers accepted or rejected. The last column is the deployed "
             "setting: neither test key is an anchor of that service. No HTTP registration is performed. \"Admitted\" "
             "means the policy function returned registered bytes; it does not mean that a vector was appended to the "
             "live log.", "",
             "| Vector | Tested condition | " + " | ".join(label for _n, _k, _m, label in SETTINGS) + " |",
             "|---|---|---|---|---|---|"]
    for row in rows:
        cells = [cell(row[name], baseline_leaf, row["id"] == "R01") for name, _k, _m, _label in SETTINGS]
        lines.append(f"| {row['id']} | {change[row['id']]} | " + " | ".join(cells) + " |")
    lines += ["", "\"re-framed\": the entry the policy returns is not the submitted bytes. \"same entry as R01\": after "
              "re-framing, the bytes are those of R01."]
    (HERE / "results-ts-isoluce-net.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(len(rows), "vectors,", len(SETTINGS), "settings: results-ts-isoluce-net.json and .md written")


if __name__ == "__main__":
    main()
