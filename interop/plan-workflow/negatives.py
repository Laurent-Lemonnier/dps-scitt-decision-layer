#!/usr/bin/env python3
"""The failing cases of case 13: the composed plan and AER-1 workflow, changed in one place on the workflow side, each
caught where expected. Each case is published as a directory out/negatives/<case>/ with the documents the checks ran
on, what.txt and, apart from them, result.json."""
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("plan_workflow_build", HERE / "build.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)

JOIN_LIST, JOIN_RECEIPTS, JOIN_ROOT = 10, 11, 12      # positions of the case's own joins after the plan's ten
N = {
    "N1-a-step-missing": ("join:list", "the workflow lists two steps; the approved plan has three", {"drop_step": 1}),
    "N2-steps-reordered": ("join:list", "the workflow lists the second and third steps in the other order", {"swap_steps": True}),
    "N3-output-substituted": ("join:root", "one step's output_hash is not its receipt's; the workflow's root is recomputed over the substitute", {"substitute_output": 1}),
    "N4-root-of-another-list": ("aer1:merkle_root_recomputed", "the merkle_root is computed over other output hashes than the steps listed", {"root_of_other_list": True}),
    "N5-an-extra-step": ("join:list", "the workflow lists a fourth step the plan never approved", {"extra_step": True}),
    "N6-construction-misdeclared": ("aer1:merkle_root_recomputed", "the root is computed in seq-output-v1 and the workflow declares receipt-id-v0", {"declare_v0_compute_v1": True}),
}


def failures(r):
    f = {f"aer1:{k}" for k, v in r["aer1"]["workflow"].items() if not v}
    f |= {"aer1:step_receipt" for x in r["aer1"]["step_receipts"] if x != "pass"}
    keys = list(r["joins"])
    for i, k in enumerate(keys):
        if r["joins"][k] is not True:
            f.add({JOIN_LIST: "join:list", JOIN_RECEIPTS: "join:receipts", JOIN_ROOT: "join:root"}.get(i, f"join:{i}"))
    return f


def publish(d, art, what, entry):
    d.mkdir(parents=True, exist_ok=True)
    B.write(d, art)
    (d / "what.txt").write_text(what + "\n")
    (d / "result.json").write_text(json.dumps(entry, ensure_ascii=False, indent=1) + "\n")


def main():
    out = HERE / "out" / "negatives"
    out.mkdir(parents=True, exist_ok=True)
    summary, ok = {}, True
    for name, (where, what, change) in N.items():
        b = B.build()
        b.update(change)
        art = B.assemble(b)
        r = B.verify(art, b)
        f = failures(r)
        expected = where in f
        ok = ok and expected
        summary[name] = {"what": what, "caught_by": sorted(f), "expected_place": where, "as_expected": expected}
        publish(out / name, art, what, summary[name])
        print(("ok   " if expected else "FAIL ") + f"{name}: caught by {', '.join(sorted(f)) or 'nothing'}")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
