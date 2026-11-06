#!/usr/bin/env python3
"""Build cases 15 and 16 from case 01: the two mutations Ivan Nestorov tested in his outside review of 6 November
2026. Each copies 01-valid, drops references from the capsule, recomputes capsule_id with the library's own
compute_capsule_id (so the capsule still verifies as a document) and writes expected.json: the capsule verifies,
the missing reference is named as a failure, the Standard is not consulted and the join is not checked.

Before the gate of 6 November, check_case.py resolved whatever references were present and consulted the Standard,
and reported the join verified over the documents beside the capsule, for both mutations. Run after build_cases.py
(which clears cases/), with the capsule library on the path: python3 build_mutations.py
"""
import json
import pathlib
import shutil
import sys

from agent_action_capsule import canonical

HERE = pathlib.Path(__file__).resolve().parent
CASES = HERE / "cases"
NS = "org.decisionprovenancestandard"
RECORD, ATTACHMENT = f"{NS}.decision_record", f"{NS}.action_binding_attachment"


def mutate(name, keep, about, kept):
    folder = CASES / name
    if folder.exists():
        shutil.rmtree(folder)
    shutil.copytree(CASES / "01-valid", folder)
    (folder / "result.json").unlink(missing_ok=True)
    capsule = json.loads((folder / "capsule.json").read_bytes())
    capsule["references"] = [r for r in capsule["references"] if r["type"] in keep]
    capsule["capsule_id"] = canonical.compute_capsule_id(capsule)
    (folder / "capsule.json").write_bytes(json.dumps(capsule, ensure_ascii=False, indent=1).encode("utf-8") + b"\n")
    missing = [t for t in (RECORD, ATTACHMENT) if t not in keep]
    (folder / "expected.json").write_bytes(json.dumps({
        "about": about,
        "capsule": {"parse_ok": True, "verify_ok": True},
        "references": kept,
        "required_references": {t: ("resolved" if t in keep else "missing") for t in (RECORD, ATTACHMENT)},
        "failures": [f"required_reference_missing:{t}" for t in missing],
        "dps": {"consulted": False},
        "join": {"request_digest": "not_checked"},
    }, ensure_ascii=False, indent=1).encode("utf-8") + b"\n")
    print("built", name)


def main():
    mutate("15-attachment-reference-missing", {RECORD},
           "case 01 with the action-binding attachment's reference removed and capsule_id recomputed by the library: the capsule "
           "verifies as a document and the record's reference resolves, but the capsule does not cite the attachment beside it; "
           "the attachment is not checked and there is nothing to join: required_reference_missing, never verified",
           {RECORD: {"resolved": True}})
    mutate("16-no-references", set(),
           "case 01 with every reference removed and capsule_id recomputed by the library: the capsule verifies as a document and "
           "cites nothing; the documents beside it are not the ones it cites (it cites none), so the Standard is not consulted "
           "and the join is not checked: both required references missing, never verified",
           {})
    return 0


if __name__ == "__main__":
    sys.exit(main())
