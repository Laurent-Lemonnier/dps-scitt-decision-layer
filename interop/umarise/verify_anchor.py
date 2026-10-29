#!/usr/bin/env python3
"""VERIFY-ANCHOR, written from draft-fassbender-scitt-time-anchor-08 (Section 4.1,
Section 5) and the OpenTimestamps serialisation as the draft describes it in
Appendix D.4, without OpenTimestamps software. Route 2 of Appendix D.7.

Inputs: artifact bytes, a .ots proof, and the verifier's validated chain: a JSON
file of 80-byte headers by height ({"957289": {"header": "<160 hex>"}, ...}),
which the verifier has itself checked for proof-of-work and linkage from a
checkpoint it holds (see validate_chain). Output: valid | invalid | unverifiable,
with the block-height binding and the Reference Wall-Clock Projection.

Usage: verify_anchor.py --artifact FILE --proof FILE.ots [--chain headers.json]
                        [--checkpoint HEIGHT:BLOCKHASH] [--min-confirmations 6]
"""
import argparse
import hashlib
import json
import struct
import sys

SHA256_OP = 0x08
APPEND, PREPEND, FORK, ATTEST = 0xF0, 0xF1, 0xFF, 0x00
MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
MIN_CONFIRMATIONS = 6  # Assumption A2


def sha256(b):
    return hashlib.sha256(b).digest()


class Reader:
    def __init__(self, data):
        self.d, self.i = data, 0

    def byte(self):
        if self.i >= len(self.d):
            raise ValueError("truncated")
        b = self.d[self.i]
        self.i += 1
        return b

    def take(self, n):
        if self.i + n > len(self.d):
            raise ValueError("truncated")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def varint(self):
        v, shift = 0, 0
        while True:
            b = self.byte()
            v |= (b & 0x7F) << shift
            if not b & 0x80:
                return v
            shift += 7

    def varbytes(self):
        return self.take(self.varint())


def ots_deserialize(data):
    """OTS-DESERIALIZE: header (magic, version, file hash op, msg) then the
    operation tree. Returns (file_hash_op, msg, branches) where each branch is a
    list of operations ending in an attestation; None if parsing fails."""
    try:
        r = Reader(data)
        if r.take(len(MAGIC)) != MAGIC:
            return None
        r.varint()                       # version
        file_hash_op = r.byte()
        msg = r.take(32)                 # 32 bytes for SHA-256 (op 0x08)
        branches = []

        def walk(ops):
            while True:
                tag = r.byte()
                if tag == ATTEST:
                    att_tag = r.take(8)
                    payload = r.varbytes()
                    branches.append((ops, att_tag, payload))
                    return
                if tag == FORK:
                    walk(list(ops))      # one branch, then continue with the next
                    continue
                if tag == APPEND:
                    ops.append(("append", r.varbytes()))
                elif tag == PREPEND:
                    ops.append(("prepend", r.varbytes()))
                elif tag == SHA256_OP:
                    ops.append(("sha256", None))
                else:
                    ops.append(("unsupported", tag))
        walk([])
        return file_hash_op, msg, branches
    except Exception:
        return None


def ots_replay(ops, digest):
    """OTS-REPLAY over append, prepend and SHA-256 only; None otherwise."""
    for op, arg in ops:
        if op == "append":
            digest = digest + arg
        elif op == "prepend":
            digest = arg + digest
        elif op == "sha256":
            digest = sha256(digest)
        else:
            return None
    return digest


def bits_to_target(bits):
    exp, mant = bits >> 24, bits & 0xFFFFFF
    return mant << (8 * (exp - 3)) if exp > 3 else mant >> (8 * (3 - exp))


def block_hash(header):
    return sha256(sha256(header))[::-1].hex()


def validate_chain(headers, checkpoint):
    """The verifier's own check of a header set: every header 80 bytes, proof-of-work
    below its own target, each linked to the previous by hash, and the set anchored
    at a checkpoint (height, block hash) the verifier holds. Returns {height: header}
    for the validated run, or {} if any check fails."""
    hs = {int(k): bytes.fromhex(v["header"]) for k, v in headers.items()}
    if not hs:
        return {}
    heights = sorted(hs)
    cp_h, cp_hash = checkpoint
    if cp_h not in hs or block_hash(hs[cp_h]) != cp_hash:
        return {}
    for i, h in enumerate(heights):
        hdr = hs[h]
        if len(hdr) != 80:
            return {}
        bits = struct.unpack("<I", hdr[72:76])[0]
        if int.from_bytes(sha256(sha256(hdr)), "little") > bits_to_target(bits):
            return {}
        if i > 0:
            if heights[i - 1] != h - 1 or hdr[4:36][::-1].hex() != block_hash(hs[h - 1]):
                return {}
    return hs


def verify_anchor(artifact_bytes, proof_bytes, claimed_hash, validated_chain, min_conf=MIN_CONFIRMATIONS):
    out = {"result": None, "steps": []}
    computed = sha256(artifact_bytes)                                   # 1
    if claimed_hash and computed.hex() != claimed_hash.removeprefix("sha256:"):
        out["result"] = "invalid"; out["steps"].append("2: hash mismatch"); return out
    parsed = ots_deserialize(proof_bytes)                               # 3
    if parsed is None or parsed[0] != SHA256_OP or parsed[1] != computed:
        out["result"] = "invalid"; out["steps"].append("3: proof does not commit to this hash"); return out
    _, _, branches = parsed
    btc = [(ops, payload) for ops, tag, payload in branches if tag == BITCOIN_TAG]
    if not btc:                                                         # 4
        out["result"] = "unverifiable"; out["steps"].append("4: no Bitcoin attestation (calendar commitment only)"); return out
    states = []
    for ops, payload in btc:
        digest = ots_replay(ops, computed)                              # 5
        height = Reader(payload).varint()                               # 6
        header = validated_chain.get(height)                            # 7a + 7b
        if digest is None:
            state = "unsupported"
        elif header is None:
            state = "unavailable"
        elif digest == header[36:68]:
            state = "verified"
        else:
            state = "mismatched"
        states.append((state, height, header, digest))
        out["steps"].append(f"branch height {height}: {state}")
    verified = [s for s in states if s[0] == "verified"]                # 8
    if not verified:
        out["result"] = "unverifiable" if any(s[0] in ("unavailable", "unsupported") for s in states) else "invalid"
        return out
    _, H, header, _ = min(verified, key=lambda s: s[1])
    k = sum(1 for h in validated_chain if h >= H)                        # 9
    if k < min_conf:
        out["result"] = "unverifiable"; out["steps"].append(f"9: {k} confirmations established, {min_conf} required"); return out
    out["block_height_H"] = H                                            # 10
    out["block_time_RWCP"] = struct.unpack("<I", header[68:72])[0]
    out["confirmations_established"] = k
    out["result"] = "valid"                                              # 11
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--proof", required=True)
    ap.add_argument("--claimed-hash")
    ap.add_argument("--chain", help="JSON of validated headers by height; omit to hold no validated view")
    ap.add_argument("--checkpoint", help="HEIGHT:BLOCKHASH the verifier holds; required with --chain")
    ap.add_argument("--min-confirmations", type=int, default=MIN_CONFIRMATIONS)
    a = ap.parse_args()
    chain = {}
    if a.chain:
        h, bh = a.checkpoint.split(":")
        chain = validate_chain(json.load(open(a.chain)), (int(h), bh))
        if not chain:
            print("validated_chain: header set failed the verifier's own checks; holding no validated view", file=sys.stderr)
    res = verify_anchor(open(a.artifact, "rb").read(), open(a.proof, "rb").read(), a.claimed_hash, chain, a.min_confirmations)
    print(json.dumps(res))
    sys.exit(0 if res["result"] == "valid" else 1)


if __name__ == "__main__":
    main()
