#!/usr/bin/env python3.12
"""Run every vector through the CLI, then conformance and mutation tests.
Writes results.json and results.md. Exit status 0 only if all match."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cbor_det  # noqa: E402
import ed25519_pure  # noqa: E402
import verify_from_text as v  # noqa: E402
import make_vectors as mv  # noqa: E402

PY = sys.executable
failures = []
rows = []


def check(name, cond, detail=""):
    if not cond:
        failures.append(f"{name}: {detail}")
    return cond


# ------------------------------------------------------------------ vectors
def run_vectors():
    vdir = os.path.join(HERE, "vectors")
    for name in sorted(os.listdir(vdir)):
        d = os.path.join(vdir, name)
        with open(os.path.join(d, "expected.json")) as fh:
            exp = json.load(fh)
        args = []
        for a in exp["args"]:
            if a == "demo-key.json":
                args.append(a)
            elif a.startswith("--"):
                args.append(a)
            else:
                args.append(os.path.join("vectors", name, a))
        cmd = [PY, "verify_from_text.py", os.path.join("vectors", name, "envelope.cbor")] + args
        p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
        got = json.loads(p.stdout)
        ok = got["verdict"] == exp["expected_verdict"] and ((p.returncode == 0) == (got["verdict"] == "pass"))
        check(f"vector {name}", ok, f"expected {exp['expected_verdict']}, got {got['verdict']}: {got['reason']}")
        rows.append({"vector": name, "expected": exp["expected_verdict"], "got": got["verdict"],
                     "draft_outcome": got["draft_outcome"], "signature": got["signature"],
                     "reason": got["reason"], "ok": ok,
                     "command": "python3.12 " + " ".join(cmd[1:])})


# ------------------------------------------------------------- conformance
def conformance():
    enc = cbor_det.encode
    hx = lambda b: b.hex()  # noqa: E731
    cases = {
        # RFC 8949 Section 4.2.1 / 4.1 float examples
        "1.5 -> f93e00": hx(enc(1.5)) == "f93e00",
        "1000000.5 -> fa49742408": hx(enc(1000000.5)) == "fa49742408",
        "5.5 -> f94580": hx(enc(5.5)) == "f94580",
        "5555.5 -> fa45ad9c00": hx(enc(5555.5)) == "fa45ad9c00",
        "Infinity -> f97c00": hx(enc(float("inf"))) == "f97c00",
        "-Infinity -> f9fc00": hx(enc(float("-inf"))) == "f9fc00",
        "-0.0 -> f98000": hx(enc(-0.0)) == "f98000",
        "1.1 -> fb3ff199999999999a": hx(enc(1.1)) == "fb3ff199999999999a",
        # integer argument boundaries (4.2.1)
        "23 -> 17": hx(enc(23)) == "17",
        "24 -> 1818": hx(enc(24)) == "1818",
        "-24 -> 37": hx(enc(-24)) == "37",
        "-25 -> 3818": hx(enc(-25)) == "3818",
        "256 -> 190100": hx(enc(256)) == "190100",
        "-257 -> 390100": hx(enc(-257)) == "390100",
        "65536 -> 1a00010000": hx(enc(65536)) == "1a00010000",
        "4294967296 -> 1b0000000100000000": hx(enc(4294967296)) == "1b0000000100000000",
        "-18446744073709551616 -> 3bffffffffffffffff": hx(enc(-18446744073709551616)) == "3bffffffffffffffff",
        # RFC 8949 Section 4.2.1 key-order list
        "4.2.1 key order example": hx(enc(cbor_det.CborMap([(k, 0) for k in
                                         [False, [-1], [100], "aa", "z", -1, 100, 10]])))
        == "a8" + "".join(x + "00" for x in ["0a", "1864", "20", "617a", "626161", "811864", "8120", "f4"]),
        # draft Section 1 example
        "draft {1000:1,'a':2} bytewise": hx(enc({1000: 1, "a": 2})) == "a21903e801616102",
        "draft {1000:1,'a':2} length-first": hx(enc({1000: 1, "a": 2}, key_order="length-first")) == "a26161021903e801",
        # draft Section 5 example
        "draft {'b':2,'a':1} preimage": hx(enc({"b": 2, "a": 1})) == "a2616101616202",
        "draft {'b':2,'a':1} SHA-256": hashlib.sha256(enc({"b": 2, "a": 1})).hexdigest()
        == "a0d3af9e86e5517f729bad0657e2c6f3b7d03899894c8d6b33759074c893b5e3",
        "duplicate keys refused by encoder": _raises(lambda: enc(cbor_det.CborMap([("a", 1), ("a", 2)]))),
    }
    reject = {  # validator must refuse these (hex -> expected error kind)
        "1817": "not-canonical",           # 23 on uint8
        "190017": "not-canonical",         # 23 on uint16
        "5f41614162ff": "not-canonical",   # indefinite bstr
        "9f01ff": "not-canonical",         # indefinite array
        "a2616201616101": "not-canonical", # {"b":1,"a":1} unsorted
        "a2616101616102": "malformed",     # duplicate "a"
        "fb3ff8000000000000": "not-canonical",  # 1.5 on binary64
        "fa3fc00000": "not-canonical",     # 1.5 on binary32
        "fb7ff8000000000000": "not-canonical",  # NaN on binary64, f97e00 suffices
        "f818": "malformed",               # two-byte simple < 32
        "1c": "malformed",                 # reserved AI
        "62c328": "malformed",             # invalid UTF-8
        "0102": "malformed",               # trailing bytes
        "a1": "malformed",                 # truncated
    }
    accept = ["f97e00", "a2616101616202", "a21903e801616102", "fb3ff199999999999a", "c11a514b67b0",
              "f90001", "f98000"]
    for h, kind in reject.items():
        err = cbor_det.check_core_deterministic(bytes.fromhex(h))
        cases[f"validator rejects {h} ({kind})"] = err is not None and err.kind == kind
    for h in accept:
        cases[f"validator accepts {h}"] = cbor_det.check_core_deterministic(bytes.fromhex(h)) is None
    # round trip of every positive preimage through decode/encode
    c2 = cbor_det.encode(mv.CAPSULE_2)
    cases["capsule-2 decode/encode round trip"] = cbor_det.encode(cbor_det.decode(c2, strict=True)) == c2
    # NaN with payload: shortest form keeps the payload
    nan_payload = cbor_det.decode(bytes.fromhex("f97e01"))
    cases["NaN payload kept (f97e01)"] = cbor_det.encode(nan_payload).hex() == "f97e01"
    nan32 = cbor_det.decode(bytes.fromhex("fa7fc00001"))
    cases["NaN payload kept (fa7fc00001)"] = cbor_det.encode(nan32).hex() == "fa7fc00001"
    # Ed25519: RFC 8032 Section 7.1 TEST 1 and TEST 2
    t1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    cases["Ed25519 RFC 8032 TEST 1"] = ed25519_pure.sign(t1, b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    t2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    cases["Ed25519 RFC 8032 TEST 2 pub"] = ed25519_pure.public_key(t2).hex() == \
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    cases["Ed25519 RFC 8032 TEST 2 sig"] = ed25519_pure.sign(t2, b"\x72").hex() == (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    cases["Ed25519 openssl cross-check of P1 signature"] = _openssl_crosscheck()
    for k, ok in cases.items():
        check(f"conformance: {k}", ok is True or ok == "skipped", str(ok))
    return cases


def _raises(fn):
    try:
        fn()
        return False
    except cbor_det.CborError:
        return True


def _openssl_crosscheck():
    """Independent check of our Ed25519 signatures with another implementation:
    the OS-packaged python3-cryptography (EL8 platform-python) if present,
    else OpenSSL >= 3 (pkeyutl -rawin). Skipped if neither is available."""
    env_b = open(os.path.join(HERE, "vectors", "P1-capsule-bytes", "envelope.cbor"), "rb").read()
    prot_b, _, payload, sig = cbor_det.decode(env_b).value
    msg = v.sig_structure(prot_b, payload)
    der = bytes.fromhex("302a300506032b6570032100") + mv.PUB
    with tempfile.TemporaryDirectory(dir="/tmp") as td:
        for n, data in (("pub.der", der), ("msg", msg), ("sig", sig)):
            open(os.path.join(td, n), "wb").write(data)
        plat = "/usr/libexec/platform-python"
        if os.path.exists(plat):
            code = ("from cryptography.hazmat.primitives.serialization import load_der_public_key as l;"
                    "k=l(open('pub.der','rb').read());k.verify(open('sig','rb').read(),open('msg','rb').read());"
                    "print('OK')")
            p = subprocess.run([plat, "-c", code], cwd=td, capture_output=True, text=True)
            if p.returncode == 0 or "InvalidSignature" in p.stderr:
                return p.stdout.strip() == "OK"
        if shutil.which("openssl"):
            p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                                "-inkey", "pub.der", "-rawin", "-in", "msg", "-sigfile", "sig"],
                               cwd=td, capture_output=True, text=True)
            if "unknown option" not in p.stderr:
                return "Signature Verified Successfully" in p.stdout
        return "skipped"


# ---------------------------------------------------------------- mutation
def mutation():
    d = os.path.join(HERE, "vectors", "P1-capsule-bytes")
    env = open(os.path.join(d, "envelope.cbor"), "rb").read()
    pre = open(os.path.join(d, "capsule-1.cbor"), "rb").read()
    stats = {}

    def tally(group, res):
        stats.setdefault(group, {}).setdefault(res["verdict"], 0)
        stats[group][res["verdict"]] += 1
        return res["verdict"]

    # 1. every byte of the envelope, two flips each, with key
    for i in range(len(env)):
        for x in (0x01, 0x80):
            m = bytearray(env)
            m[i] ^= x
            got = tally("envelope byte flips (key given)", v.verify(bytes(m), preimage=pre, pubkey=mv.PUB))
            check(f"mutation env[{i}]^{x:#x}", got != "pass", "mutated envelope passed")
    # 1b. same flips without a key: nothing authenticates the header, so a
    #     pass is acceptable only if the flip left the payload, 258 and the
    #     deterministic-encodings value unchanged (e.g. a flip in the
    #     signature or in the payload-location text).
    for i in range(len(env)):
        for x in (0x01, 0x80):
            m = bytearray(env)
            m[i] ^= x
            got = tally("envelope byte flips (no key)", v.verify(bytes(m), preimage=pre))
            if got == "pass":
                body = cbor_det.decode(bytes(m)).value
                ph = cbor_det.decode(body[0])
                same = body[2] == hashlib.sha256(pre).digest() and ph.get(258) == -16 and ph.get(v.DEFAULT_LABEL) == 1
                check(f"mutation nokey env[{i}]^{x:#x}", same, "pass with altered payload/258/encoding")
    # 2. every byte of the preimage
    for i in range(len(pre)):
        for x in (0x01, 0x80):
            m = bytearray(pre)
            m[i] ^= x
            got = tally("preimage byte flips", v.verify(env, preimage=bytes(m), pubkey=mv.PUB))
            check(f"mutation pre[{i}]^{x:#x}", got != "pass", "mutated preimage passed")
    # 3. truncation / extension of the preimage
    for m in (pre[:-1], pre + b"\x00", pre[1:]):
        got = tally("preimage truncated/extended", v.verify(env, preimage=m, pubkey=mv.PUB))
        check("mutation pre length", got != "pass", "length-mutated preimage passed")
    # 4. structured-value mutations on P2 (value mode)
    d2 = os.path.join(HERE, "vectors", "P2-capsule-value")
    env2 = open(os.path.join(d2, "envelope.cbor"), "rb").read()
    base = mv.CAPSULE_2
    muts = {
        "int 1000 -> float 1000.0": lambda c: c["limits"].__setitem__("max", 1000.0),
        "float 0.5 -> int 0 ": lambda c: c.__setitem__("score", 0),
        "string changed": lambda c: c.__setitem__("capsule", "dps-demo-X"),
        "key dropped": lambda c: c.pop("note"),
        "key added": lambda c: c.__setitem__("extra", 1),
        "null -> false": lambda c: c.__setitem__("note", False),
        "array order": lambda c: c["steps"].reverse(),
        "nested int": lambda c: c["steps"][1].__setitem__("n", -24),
        "true -> 1": lambda c: c.__setitem__("ok", 1),
        "text -> bytes": lambda c: c.__setitem__("capsule", b"dps-demo-2"),
        "value tagged": lambda c: c.__setitem__("capsule", cbor_det.Tag(32, "dps-demo-2")),
    }
    got_ok = v.verify(env2, value=json.loads(json.dumps(base)), value_given=True, pubkey=mv.PUB)["verdict"]
    check("mutation P2 baseline", got_ok == "pass", got_ok)
    for name, fn in muts.items():
        c = json.loads(json.dumps(base))
        fn(c)
        got = tally("structured-value mutations", v.verify(env2, value=c, value_given=True, pubkey=mv.PUB))
        check(f"mutation value {name}", got == "hash-mismatch", got)
    # 5. header-label sweep: re-sign P1 with deterministic-encodings values 0, 2..5, -1
    c1 = cbor_det.encode(mv.CAPSULE_1)
    for val in (0, 2, 3, 5, -1, 65536):
        e = mv.sign1(mv.header(enc=val), hashlib.sha256(c1).digest())
        got = tally("deterministic-encodings value sweep (value mode)",
                    v.verify(e, value=mv.CAPSULE_1, value_given=True, pubkey=mv.PUB))
        check(f"mutation enc={val}", got == "unsupported-encoding", got)
    return stats


def main():
    os.chdir(HERE)
    subprocess.run([PY, "make_vectors.py"], check=True, cwd=HERE)
    run_vectors()
    conf = conformance()
    stats = mutation()
    total_checks = len(rows) + len(conf) + sum(sum(g.values()) for g in stats.values())
    res = {"vectors": rows, "conformance": {k: (v_ if isinstance(v_, str) else bool(v_)) for k, v_ in conf.items()},
           "mutation_verdicts": stats, "failures": failures}
    with open("results.json", "w") as fh:
        json.dump(res, fh, indent=2)
        fh.write("\n")
    lines = ["| Vector | Expected | Obtained | Draft outcome | Signature | Reason |", "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['vector']} | {r['expected']} | {r['got']} | {r['draft_outcome']} | {r['signature']} | "
                     f"{r['reason'].replace('|', '/')} |")
    lines += ["", "Mutation verdict counts:", ""]
    for g, c in stats.items():
        lines.append(f"- {g}: " + ", ".join(f"{k} {n}" for k, n in sorted(c.items())))
    lines += ["", f"Conformance checks: {sum(1 for x in conf.values() if x is True)}/{len(conf)} true"
              f" ({sum(1 for x in conf.values() if x == 'skipped')} skipped)",
              f"Failures: {len(failures)}"]
    with open("results.md", "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\n{total_checks} checks, {len(failures)} failure(s)")
    for f in failures[:30]:
        print("FAIL", f)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
