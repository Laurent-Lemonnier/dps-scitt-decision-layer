#!/usr/bin/env python3
"""Case 18b: the five OpenTimestamps proofs over this chain's subjects (the real passkey signature value, A1, A2, the
verdict record, the dispute packet), re-checked offline from the pinned files by the two verifiers case 18 uses
(../../one-chain/anchoring/verify.py: the Standard's anchoring 0.2.0 reference check at DPS_STANDARD, and
interop/umarise/verify_anchor.py, route 2 against the header set in headers/). Same inputs by name, this directory's
files. Exit 0 when every proof verifies on both routes; result.json rewritten, deterministic."""
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("one_chain_anchoring_verify", HERE.parent.parent / "one-chain" / "anchoring" / "verify.py")
C18 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C18)

if __name__ == "__main__":
    sys.exit(C18.run(HERE, HERE.parent))
