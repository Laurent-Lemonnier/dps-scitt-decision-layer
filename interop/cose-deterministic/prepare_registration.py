#!/usr/bin/env python3.12
"""Build (locally, nothing is sent) the Signed Statement we would register
through SCRAPI: the P1 Hash Envelope plus the SCITT headers RFC 9943
Section 6 requires (CWT Claims 15 with iss and sub; kid 4, since no x5t /
x5chain). Writes registration/signed-statement.cose and checks it with
verify_from_text.py. See REGISTRATION-PLAN.md."""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cbor_det  # noqa: E402
import make_vectors as mv  # noqa: E402
import verify_from_text as v  # noqa: E402

ISS = "https://ts.isoluce.net/demo-issuer"   # placeholder, to agree with Steven
SUB = "urn:dps-demo:capsule:dps-demo-1"       # placeholder


def main():
    out = os.path.join(HERE, "registration")
    os.makedirs(out, exist_ok=True)
    c1 = cbor_det.encode(mv.CAPSULE_1)
    kid = hashlib.sha256(mv.PUB).digest()[:16]
    hdr = mv.header(loc="capsule-1.cbor", extra={4: kid, 15: {1: ISS, 2: SUB}})
    stmt = mv.sign1(hdr, hashlib.sha256(c1).digest())
    with open(os.path.join(out, "signed-statement.cose"), "wb") as fh:
        fh.write(stmt)
    with open(os.path.join(out, "capsule-1.cbor"), "wb") as fh:
        fh.write(c1)
    res = v.verify(stmt, preimage=c1, pubkey=mv.PUB)
    info = {"file": "registration/signed-statement.cose", "bytes": len(stmt),
            "sha256": hashlib.sha256(stmt).hexdigest(), "kid_hex": kid.hex(),
            "iss": ISS, "sub": SUB, "local_check": res["verdict"], "sent": False}
    with open(os.path.join(out, "signed-statement.json"), "w") as fh:
        json.dump(info, fh, indent=2)
        fh.write("\n")
    print(json.dumps(info, indent=2))
    return 0 if res["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
