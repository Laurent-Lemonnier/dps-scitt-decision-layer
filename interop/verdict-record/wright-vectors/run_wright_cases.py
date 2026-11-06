#!/usr/bin/env python3
"""Thin adapter: runs this directory's checker (../verdict.py, as it stands) on Darren Wright's test vectors and proposal cases.

WRIGHT_VECTORS=/path/to/diggertydog/verdict-record-test-vectors (at 97b63b2) python3 run_wright_cases.py

Written from his case files and the two READMEs only (no code of his repository was read: vrcheck.py,
blind-checker.py, gen.py and proposals/run.py were not opened).

What the adapter supplies, and why (every item is a checker input or presenter input in -02 terms):
- policy: his cases name the citation depth `max_depth`; our checker names it `citation_depth`. -02 Section 4.5
  names the three things a policy lists but no member names. The adapter renames that one member. The policy digest
  our report states is therefore over our member names, not his (see REPORT.md).
- container (Section 3): his vectors carry none ("Section 3 leaves those to the container, so each vector supplies
  the record's upper time bound directly as a checker input"). Our checker needs a container that shows the record.
  The adapter builds a stand-in: a detached Ed25519 signature over the exact bytes under a test key the adapter
  generates from a fixed seed, registered in the trust anchors as the key of writer `issuer.example`; the intake
  time (our upper time bound) is the case's `upper_time_bound`. The same is done for every evidence item of format
  `verdict-record/1` whose entry gives an `upper_time_bound`. Mode "raw" runs without any of this, to show what
  our checker says on the case files as they are.
- format rules (Section 4.3 step 2, Section 7): the test-only formats as the READMEs define them: opaque,
  provider-attestation and inference-proof always verify; never-verifies never does; an item's `upper_time_bound`,
  where the case gives one, is what its verification gives. salted-commitment: this checker holds no salt, so no
  item verifies (the policy of p06 does not list it anyway). IronTrellis formats (p08): no rules held here.
- rule urn:example:verdict-record:rule:at-least as the top-level README defines it.
"""
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import verdict  # noqa: E402  (the checker written from the text, ../verdict.py)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

VECTORS = os.environ.get("WRIGHT_VECTORS") or sys.exit("WRIGHT_VECTORS=/path/to/verdict-record-test-vectors (97b63b2) is required")
CASES_DIR = os.path.join(VECTORS, "proposals")
P08_EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "p08-evidence")
OUT = os.path.join(HERE, "results.json")
OUT_FULL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports-full.json")

SEED = hashlib.sha256(b"wright-proposals-adapter-20261106 test key, not a secret").digest()
PRIV = Ed25519PrivateKey.from_private_bytes(SEED)
PUB_HEX = PRIV.public_key().public_bytes_raw().hex()
KEY_REF = "adapter-test-key-1"
WRITER = "issuer.example"  # the writer every case names


def sign_container(raw, writer):
    return {"record_sha256": verdict.sha256(raw), "writer": writer, "key_ref": KEY_REF,
            "signature_b64": base64.b64encode(PRIV.sign(raw)).decode()}


# ---- test-only formats (READMEs) ----
def make_formats(item_bounds):
    def always(raw, items, anchors):
        return True, None, item_bounds.get(verdict.sha256(raw))

    def never(raw, items, anchors):
        return False, "format never-verifies: no item verifies", item_bounds.get(verdict.sha256(raw))

    def salted(raw, items, anchors):
        return False, "salted-commitment: this checker holds no salt (and no committed data) to recompute it", None

    def not_held(name):
        def f(raw, items, anchors):
            return False, f"this checker holds no rules of format {name!r}", None
        return f

    fm = {
        "urn:example:verdict-record:format:opaque": always,
        "urn:example:verdict-record:format:provider-attestation": always,
        "urn:example:verdict-record:format:inference-proof": always,
        "urn:example:verdict-record:format:never-verifies": never,
        "urn:example:verdict-record:format:salted-commitment": salted,
    }
    return fm, not_held


# ---- test-only rule (top-level README) ----
RULES = {
    "urn:example:verdict-record:rule:at-least": {
        "inputs": {"value": "integer", "min": "integer"},
        "run": lambda inp: "pass" if inp["value"] >= inp["min"] else "fail",
    },
}


def load_case(path):
    with open(path, "rb") as f:
        case = json.loads(f.read().decode("utf-8"))
    raw = base64.b64decode(case["record_b64"])
    assert verdict.sha256(raw) == case["record_sha256"], "record_sha256 does not match record_b64"
    return case, raw


def build(case, raw, mode, policy_override=None, extra_items=None):
    """mode 'raw': the case files as they are. mode 'adapter': stand-in container, renamed depth member."""
    # The checker's trust anchors are its own input (Section 4.2): the adapter binds its test key to the party the
    # record names in writer (Section 3: the key must be shown to belong to that party), read leniently from the
    # bytes for that one member only; a record that does not parse gets the name every other case uses.
    writer = WRITER
    try:
        w = json.loads(raw.decode("utf-8")).get("writer")
        if isinstance(w, str) and w:
            w.encode("utf-8")   # a lone surrogate (a10) is no party name; the record is refused anyway
            writer = w
    except Exception:
        pass
    policy = dict(policy_override if policy_override is not None else case["policy"])
    if mode in ("adapter", "policy-only") and "max_depth" in policy:
        policy["citation_depth"] = policy.pop("max_depth")
    anchors = {"writers": {}, "intake": {}}
    items = {}
    item_bounds = {}
    for it in case.get("evidence_items", []):
        b = base64.b64decode(it["b64"])
        d = verdict.sha256(b)
        bound = it.get("upper_time_bound")
        if bound is not None:
            item_bounds[d] = bound
        cont = None
        if mode == "adapter" and bound is not None:
            cont = sign_container(b, WRITER)
            anchors["intake"][d] = bound
        items[d] = (b, cont)
    for d, b in (extra_items or {}).items():
        items[d] = (b, None)
    container = None
    if mode == "adapter" and writer:
        anchors["writers"] = {writer: {KEY_REF: PUB_HEX}}
        anchors["intake"][verdict.sha256(raw)] = case["upper_time_bound"]
        container = sign_container(raw, writer)
    formats, not_held = make_formats(item_bounds)
    for name in policy.get("formats", []):
        if name not in formats and name != verdict.VERSION:
            formats[name] = not_held(name)
    return verdict.Checker(policy, anchors, RULES, formats), container, items


def brief(rep):
    out = {"state": rep.get("state")}
    if "steps" in rep and rep["steps"]:
        out["steps"] = {k: rep["steps"][k]["result"] for k in ("1", "2", "3")}
        reasons = {k: rep["steps"][k].get("why") for k in ("1", "2", "3") if rep["steps"][k].get("why")}
        if reasons:
            out["reasons"] = reasons
    for k in ("before_steps", "reason"):
        if rep.get(k):
            out[k] = rep[k]
    if rep.get("container") and not rep["container"].get("shows_the_record"):
        out["container"] = rep["container"]["reason"]
    out["policy_sha256"] = rep.get("policy_sha256")
    out["upper_time_bound"] = rep.get("upper_time_bound")
    return out


def compare(ours, expected):
    if expected is None:
        return None
    same_state = ours.get("state") == expected.get("state")
    same_steps = ours.get("steps") == expected.get("steps")
    return {"state": same_state, "steps": same_steps}


def main():
    names = sorted(f for f in os.listdir(CASES_DIR) if f.startswith("p0") and f.endswith(".json"))
    results, full = {}, {}
    for fn in names:
        case, raw = load_case(os.path.join(CASES_DIR, fn))
        name = case["name"]
        exp = case["expected_under_02"]
        entry = {"expected_under_02": {"state": exp["state"], "steps": exp["steps"]}, "runs": {}}
        full[name] = {}
        # run A: the case files as they are (no container, his policy member names)
        chk, cont, items = build(case, raw, "raw")
        rep = chk.check(raw, items, cont)
        full[name]["raw"] = rep
        entry["runs"]["raw"] = brief(rep)
        # run A2: depth member renamed, still no container (what Section 3 alone does to the case)
        chk, cont, items = build(case, raw, "policy-only")
        rep = chk.check(raw, items, cont)
        full[name]["policy-only"] = rep
        entry["runs"]["policy-only"] = brief(rep)
        # run B: adapter (stand-in container, depth member renamed, test formats and rule)
        chk, cont, items = build(case, raw, "adapter")
        rep = chk.check(raw, items, cont)
        full[name]["adapter"] = rep
        entry["runs"]["adapter"] = brief(rep)
        entry["agrees_with_expected_under_02"] = compare(entry["runs"]["adapter"], exp)
        # extras
        if name == "p05-evidence-age":
            pol = dict(case["policy"])
            pol["max_evidence_age"] = "P365D"
            chk, cont, items = build(case, raw, "adapter", policy_override=pol)
            rep = chk.check(raw, items, cont)
            full[name]["adapter+max_evidence_age"] = rep
            entry["runs"]["adapter+max_evidence_age"] = brief(rep)
        if name == "p08-irontrellis-refusal":
            extra = {}
            for fe in case.get("evidence_fetch", []):
                p = os.path.join(P08_EVIDENCE_DIR, os.path.basename(fe["url"]))
                if os.path.exists(p):
                    b = open(p, "rb").read()
                    if verdict.sha256(b) == fe["sha256"]:
                        extra[fe["sha256"]] = b
            entry["p08_evidence_fetched_and_digest_matched"] = sorted(extra)
            chk, cont, items = build(case, raw, "adapter", extra_items=extra)
            rep = chk.check(raw, items, cont)
            full[name]["adapter+fetched-items"] = rep
            entry["runs"]["adapter+fetched-items"] = brief(rep)
            entry["agrees_with_expected_under_02"] = compare(entry["runs"]["adapter+fetched-items"], exp)
        for r in full[name].values():
            assert verdict.report_wording_ok(r), "Section 4.4 wording"
        results[name] = entry
        print(f"{name}: raw={entry['runs']['raw']['state']}; adapter={entry['runs']['adapter']['state']} "
              f"{entry['runs']['adapter'].get('steps')} expected={exp['state']} {exp['steps']} "
              f"agree={entry['agrees_with_expected_under_02']}")
    # beyond the ask: his 37 main vectors (-01), same adapter, states only, not analysed
    main_dir = os.path.dirname(CASES_DIR)
    mains = {}
    for fn in sorted(f for f in os.listdir(main_dir) if re.match(r"^[a-f]\d\d-.*\.json$", f)):
        try:
            case, raw = load_case(os.path.join(main_dir, fn))
        except Exception as e:  # noqa: BLE001
            mains[fn] = {"load_error": str(e)}
            continue
        exp = case.get("expected", {})
        chk, cont, items = build(case, raw, "adapter")
        rep = chk.check(raw, items, cont)
        b = brief(rep)
        mains[fn] = {"ours": {"state": b["state"], "steps": b.get("steps"), "reasons": b.get("reasons"), "before_steps": b.get("before_steps")},
                     "expected": {"state": exp.get("state"), "steps": exp.get("steps")},
                     "same_state": b["state"] == exp.get("state"),
                     "same_steps": (b.get("steps") == exp.get("steps")) if exp.get("steps") is not None else None,
                     "depends_on_interpretation": case.get("depends_on_interpretation")}
    with open(os.path.join(os.path.dirname(OUT), "main-vectors-run.json"), "w") as f:
        json.dump(mains, f, indent=1, ensure_ascii=False)
    n = len(mains); same = sum(1 for v in mains.values() if v.get("same_state"))
    print(f"main vectors (beyond the ask): {same}/{n} same state; differing: "
          + ", ".join(k for k, v in mains.items() if not v.get("same_state")))
    meta = {
        "checker": "interop/verdict-record/verdict.py (Laurent-Lemonnier/dps-scitt-decision-layer)",
        "checker_sha256": verdict.sha256(open(verdict.__file__, "rb").read()),
        "cases_repo": "https://github.com/diggertydog/verdict-record-test-vectors",
        "adapter_test_key_pub_hex": PUB_HEX,
    }
    with open(OUT, "w") as f:
        json.dump({"meta": meta, "cases": results}, f, indent=1, ensure_ascii=False)
    with open(OUT_FULL, "w") as f:
        json.dump({"meta": meta, "cases": full}, f, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
