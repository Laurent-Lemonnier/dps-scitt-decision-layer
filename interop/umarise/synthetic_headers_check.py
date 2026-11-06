#!/usr/bin/env python3
"""Yohay Etsion's finding on the Standard's issue #96 (5 November 2026), as a failing case: after the real checkpoint
at 957289, linked headers forged with nBits 0x207fffff (a target far above Bitcoin mainnet's limit, so that any hash
meets it) were accepted by validate_chain, which checked each header only against its own target. They must not be:
the target may not exceed mainnet's powLimit, and the difficulty may not change between two retarget boundaries.
Exit 0 when every forged set is refused and the real set still validates; 1 otherwise."""
import json
import pathlib
import struct
import sys

import verify_anchor as V

HERE = pathlib.Path(__file__).resolve().parent
REAL = json.loads((HERE / "headers-957289-957300.json").read_text())
CP = (957289, "000000000000000000018e5b8c68a63c45b3eeac3a05ecf621a3b3f7890e3534")


def forged_after(real, start_height, count, bits, keep_real_bits_mismatch=False):
    """count headers linked by hash above the real header at start_height, each with the given nBits and a nonce
    that meets that (easy) target."""
    hs = {str(h): dict(real[str(h)]) for h in range(CP[0], start_height + 1)}
    prev = bytes.fromhex(real[str(start_height)]["header"])
    for k in range(1, count + 1):
        prev_hash = V.sha256(V.sha256(prev))
        for nonce in range(1 << 32):
            hdr = struct.pack("<I", 0x20000000) + prev_hash + b"\x00" * 32 + struct.pack("<I", 1761700000 + k) \
                + struct.pack("<I", bits) + struct.pack("<I", nonce)
            if int.from_bytes(V.sha256(V.sha256(hdr)), "little") <= V.bits_to_target(bits):
                break
        hs[str(start_height + k)] = {"header": hdr.hex()}
        prev = hdr
    return hs


def main():
    ok = True
    real = V.validate_chain(REAL, CP)
    print("real set:", "validated" if len(real) == len(REAL) else "FAILED", len(real), "headers")
    ok &= len(real) == len(REAL)
    last = max(int(k) for k in REAL)
    forged = forged_after(REAL, last, 5, 0x207FFFFF)
    out = V.validate_chain(forged, CP)
    accepted = [h for h in out if h > last]
    print("five linked headers with nBits 0x207fffff after", last, ":", "accepted" if accepted else "refused")
    ok &= not accepted and not out
    # the difficulty rule alone: the real last header, its nBits rewritten to powLimit (its real hash still meets that
    # easier target, so proof-of-work passes and the target is within the limit), differs from the epoch's nBits at a
    # height that is not a retarget boundary: refused
    assert last % V.RETARGET_INTERVAL != 0
    hdr = bytearray(bytes.fromhex(REAL[str(last)]["header"]))
    hdr[72:76] = struct.pack("<I", V.POW_LIMIT_BITS)
    mutated = {k: dict(v) for k, v in REAL.items()}
    mutated[str(last)] = {"header": bytes(hdr).hex()}
    out2 = V.validate_chain(mutated, CP)
    print("real last header with nBits rewritten to powLimit (another nBits than the epoch's):",
          "accepted" if last in out2 else "refused")
    ok &= last not in out2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
