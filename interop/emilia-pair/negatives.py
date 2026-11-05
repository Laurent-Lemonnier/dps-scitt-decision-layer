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
        a = B.action_from_spec(b["spec"], B.POLICY["policy_id"], B.at(40))
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


def dropped(member, n):
    @case(f"N{n}-context-without-{member}", f"ep:context_0_missing:{member}",
          f"every Authorization Context is issued without {member} and signed validly over the rest: refused by the schema "
          f"controls of section 4 before anything is read (Iman Schrock, 4 November 2026), never SATISFIED")
    def fn(b, art=None):
        if art is None:
            b["context_drop"] = [member]
    return fn


for _n, _m in enumerate(("ep_version", "context_type", "policy_id", "initiator", "approver_index"), start=12):
    dropped(_m, _n)


@case("N17-action-without-policy_id-and-requested_at", "ep:action_missing:policy_id",
      "the Action Object carries only action_type, initiator, parameters, ep_version and target, as the pinned vector's does: "
      "section 3's minimum is not met, refused by the schema controls (the author: the minimum applies)")
def n17(b, art=None):
    if art is None:
        a = B.action_from_spec(b["spec"], B.POLICY["policy_id"], B.at(40))
        del a["policy_id"], a["requested_at"]
        b["ep_action_override"] = a


@case("N18-action-policy_id-made-up", "ep:action_policy_id_not_the_pinned_one",
      "the Action Object's policy_id is a value made up to fill the shape, carried consistently into the contexts, not the "
      "relying party's pinned EP policy identifier: caught at step 10 against the pinned policy (and the binding then differs)")
def n18(b, art=None):
    if art is None:
        b["action_policy_id"] = "ep:policy:made-up@v1"


@case("N19-action-requested_at-not-the-proposal-time", "ep:action_requested_at_not_the_proposal_time",
      "the Action Object's requested_at is not the time of A1's proposal stage (the explicit input the profile derives it from)")
def n19(b, art=None):
    if art is None:
        b["action_requested_at"] = B.at(44)


# ---------------------------------------------------------------- the junction: each EP alone would be satisfied

@case("N20-dps-approver-key-revoked-before-the-signoffs", "ep:binding_source_does_not_verify",
      "the relying party's DPS trust policy states the person's key revoked (superseded) at 09:44, before the approval "
      "it signed at 09:45 and the EP signoffs at 09:55: the DPS approval fails natively (key state), so the source the "
      "binding names does not verify at step 10, though every EP signature, context and the binding's bytes are intact")
def n20(b, art=None):
    if art is not None:
        k = next(k for k in art["trust"]["keys"] if k["key_ref"] == B.OWNER_KEY_REF)
        k.update(revoked_at=B.at(44), revocation_reason="superseded")


@case("N21-dps-approver-is-the-ep-initiator", "ep:dps_approver_is_the_ep_initiator",
      "the EP action is initiated as ep:entity:treasury-controller-1, whom the relying party's pinned identity links "
      "attribute to the person who approved the specification under the DPS (treasury-controller-1): separation of "
      "duties across the junction, refused at step 10 by the binding profile's rule, though EP alone (initiator not an "
      "EP approver) and the DPS alone are satisfied")
def n21(b, art=None):
    if art is None:
        b["spec"]["parameters"]["initiator"] = B.IDENTITY_LINKS[B.OWNER][0]


@case("N22-ep-policy-changed-before-execution", "ep:policy_digest_mismatch",
      "the relying party's EP policy (same policy_id) is changed after the DPS approval and the EP signoffs: at the "
      "pre-execution recheck its digest is not the one every context signed, refused at step 11 (policy_hash X does not "
      "satisfy a requirement under policy_hash Y, section 4); A2's recheck stage still reads 'authorised', as its issuer wrote it")
def n22(b, art=None):
    if art is None:
        b["ep_policy_at_execution"] = dict(B.POLICY, rule="three approvers: controller, treasurer and risk officer; the DPS approval of the exact specification first")


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
