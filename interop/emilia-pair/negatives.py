#!/usr/bin/env python3
"""The failing cases of the EMILIA pair: each is the valid pair changed in one place, run through the same checks, and
caught where expected. Each case is published as a directory out/negatives/<case>/ holding the documents the checks ran
on, the description (what.txt) and, apart from them, the verdicts (result.json)."""
import base64
import copy
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("emilia_pair_build", HERE / "build.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)

N = {}


def case(name, where, what):
    def deco(fn):
        N[name] = (where, what, fn)
        return fn
    return deco


@case("N1-binding-names-other-bytes-of-A1", "ep:authorization_binding_unequal",
      "the binding names A1 by the digest of other bytes of the same content (re-serialised with spaces); the byte scope is the attachment as issued")
def n1(b, art=None):
    if art is None:
        return "before"
    return None


@case("N2-binding-absent-on-one-context", "ep:authorization_binding_mixed_or_unequal",
      "the second approver's context carries no authorization_binding: a mixture of bound and unbound contexts (section 6.1)")
def n2(b, art=None):
    if art is None:
        b["binding_on"] = [True, False]


@case("N3-binding-names-another-specification", "ep:authorization_binding_unequal",
      "the binding names the digest of another version of the specification (amount 12551) than the one the person approved")
def n3(b, art=None):
    if art is None:
        other = dict(b["spec"], parameters=dict(b["spec"]["parameters"], amount_minor=12551))
        b["__bind_spec"] = B.sha256(B.compact(other))


@case("N4-mapping-not-lossless", "ep:mapping_not_lossless_to_the_action",
      "the EP Action Object carries a parameter the specification does not (a memo): the contexts are signed over it, the mapping is not lossless")
def n4(b, art=None):
    if art is None:
        a = B.action_from_spec(b["spec"])
        a["parameters"]["memo"] = "urgent"
        b["ep_action_override"] = a


@case("N5-action-hash-not-recomputed", "ep:action_hash_mismatch",
      "the bundle's action_hash is not the SHA-256 of the canonical Action Object it carries")
def n5(b, art=None):
    if art is not None:
        art["bundle"]["action_hash"] = "sha256:" + "0" * 64


@case("N6-receipt-changed-after-its-digest", "join:0",
      "the Trust Receipt is changed after the later attachment took its digest (log_proof leaf_index 0 -> 1)")
def n6(b, art=None):
    if art is not None:
        art["receipt"]["log_proof"]["leaf_index"] = 1


@case("N7-reverse-reference-in-the-named-attachment", "join:3",
      "the receipt reference is carried in A1, the attachment the binding names: circular; A1 is re-sealed after the binding was signed")
def n7(b, art=None):
    if art is None:
        b["receipt_reference_in"] = "A1"


@case("N8-signoff-by-a-key-outside-the-pinned-set", "ep:approver_key_not_trusted",
      "the second signoff is made with a key the relying party did not pin")
def n8(b, art=None):
    if art is None:
        b["signers"] = [B.EP_APPROVERS[0], (B.EP_APPROVERS[1][0], B.OUTSIDER[1], B.OUTSIDER[2])]


@case("N9-dps-approval-signature-broken", "ep:binding_source_does_not_verify",
      "the person's approval signature in the DPS signatures attachment does not verify: the binding names a source that fails native verification")
def n9(b, art=None):
    if art is not None:
        ps = art["sig_attachment"]["person_signatures"][0]
        sig = bytearray(base64.b64decode(ps["signature"]["value_b64"]))
        sig[0] ^= 1
        ps["signature"]["value_b64"] = base64.b64encode(bytes(sig)).decode()


@case("N10-dps-trust-inputs-not-held", "ep:INDETERMINATE",
      "the relying party holds no DPS trust inputs: the binding cannot be derived, the result is INDETERMINATE, never SATISFIED")
def n10(b, art=None):
    if art is not None:
        art["__without_dps"] = True


@case("N11-execution-of-another-specification", "join:2",
      "the later attachment's request and attempt carry another specification's digest than the one approved")
def n11(b, art=None):
    if art is None:
        other = dict(b["spec"], parameters=dict(b["spec"]["parameters"], amount_minor=99999))
        b["a2_spec_override"] = B.sha256(B.compact(other))


def build_case(name, fn):
    b = B.build()
    fn(b)
    if "__bind_spec" in b or name.startswith("N1-"):
        # a binding that differs from the expected one in one member: rebuild the valid pair, then sign contexts over it
        art0 = B.assemble(copy.deepcopy(B.build()))
        bind = copy.deepcopy(art0["bundle"]["contexts"][0]["authorization_binding"])
        if name.startswith("N1-"):
            bind["attachment_digest"] = "sha256:" + B.sha256(json.dumps(art0["a1"], ensure_ascii=False, indent=1).encode())
        else:
            bind["approved_spec_digest"] = "sha256:" + b.pop("__bind_spec")
        b["binding_override"] = bind
    art = B.assemble(b)
    fn(b, art)
    return art


def failures(r):
    f = set()
    if r["ep_bundle"]["result"] == "INDETERMINATE":
        f.add("ep:INDETERMINATE")
    f |= {f"ep:{x}" for x in r["ep_bundle"]["reasons"]} if r["ep_bundle"]["result"] == "REFUSE" else set()
    f |= {f"join:{i}" for i, v in enumerate(r["joins"].values()) if not v}
    if not r["dps_a1"]["verified"]:
        f.add("dps_a1")
    if not r["dps_a2"]["verified"]:
        f.add("dps_a2")
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
    for name, (where, what, fn) in N.items():
        art = build_case(name, fn)
        r = B.verify(art, with_dps=not art.pop("__without_dps", False))
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
