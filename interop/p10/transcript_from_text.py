"""The transcript tB of prereg section 15, encoded from the grammar the frozen S2b prereg transcribes (section 15.2)
and the field sources of section 15.4; the S2a codec itself was not read. Second pass of the P10 S2b outside reading.

nat(n) is unary in base 255 (0xFF repeated n div 255 times, then n mod 255), so a large value is a long encoding:
`size_*` computes the length first, and the encoder declines a transcript above LIMIT instead of allocating it."""
import hashlib

MAGIC = b"P10S2-Transcript-v0:"
KIND_CODE = {"profileCommit": 0, "instanceCommit": 1, "admission": 2, "closure": 3, "adjudication": 4}
SIG_CODE = {"verified": 0, "badSignature": 1, "keyUnavailable": 2}
LIMIT = 1 << 30          # this reading's own memory guard; the frozen text sets none

READINGS = [
    ("prereg section 15.2, item (fixture)", "`first b -> 00 ++ nat(b)`: the boolean b is written nat(0) for false "
     "and nat(1) for true, as `bool(b)` is defined two lines above"),
    ("prereg section 15.4, keyResolutionDigest", "SHA-256 of the JCS bytes of {\"key_resolution\": K}, K mapping each "
     "iss of frozen.key_resolution to the lowercase hex of its 32-byte fingerprint (the pB form, which the JCS "
     "amendment section 9.10 quotes); this reproduces the expected bytes"),
    ("prereg section 13.1 with 15.2, rows and entries", "a non-subject row is available(sub) with the UTF-8 bytes of "
     "its sub; a subject row that passes stage 1 is available(sub) and has one detailed entry; a row unreadable at "
     "L-B or failing stage 0 or 1 is unavailable"),
]


def nat(n):
    if n < 0:
        raise ValueError("negative nat")
    return b"\xff" * (n // 255) + bytes([n % 255])


def size_nat(n):
    return n // 255 + 1


def enc_bytes(b):
    return nat(len(b)) + b"".join(nat(x) for x in b)


def size_bytes(b):
    return size_nat(len(b)) + len(b) + b.count(0xFF)


def enc_payload(pl):
    kind, v = pl
    if kind == "profileCommit":
        return nat(0) + enc_bytes(v)
    if kind == "instanceCommit":
        ic = v
        return (nat(1) + nat(0) + enc_bytes(ic["requestId"]) + enc_bytes(ic["issuerId"]) + enc_bytes(ic["instanceSubject"])
                + enc_bytes(ic["instanceOwnerIss"])
                + b"".join(enc_bytes(ic[k]) for k in ("log_identity_digest", "leaf_encoding_profile_digest",
                                                      "claim_digest", "profile_digest", "evidence_scope_digest",
                                                      "admission_rule_digest", "coverage_rule_digest",
                                                      "authorized_admitter_set_digest", "subject_derivation_digest")))
    if kind == "admission":
        which, b = v
        return nat(1) + nat(1) + nat(0) + nat(0 if which == "first" else 1) + nat(1 if b else 0)
    if kind == "closure":
        cl = v
        return (nat(1) + nat(1) + nat(1) + nat(0) + enc_bytes(cl["instanceSubject"]) + nat(1 if cl["terminal"] else 0)
                + nat(len(cl["orderedAdmissionRefs"])) + b"".join(nat(r) for r in cl["orderedAdmissionRefs"])
                + enc_bytes(cl["closedEvidenceSetDigest"]) + enc_bytes(cl["checkpointPreclosureTranscriptDigest"]))
    if kind == "adjudication":
        a, b, c = v
        return nat(1) + nat(1) + nat(1) + nat(1) + nat(a) + nat(b) + nat(c)
    raise ValueError(kind)


def size_payload(pl):
    kind, v = pl
    if kind == "closure":
        return (4 + size_bytes(v["instanceSubject"]) + 1 + size_nat(len(v["orderedAdmissionRefs"]))
                + sum(size_nat(r) for r in v["orderedAdmissionRefs"]) + size_bytes(v["closedEvidenceSetDigest"])
                + size_bytes(v["checkpointPreclosureTranscriptDigest"]))
    if kind == "adjudication":
        return 4 + sum(size_nat(x) for x in v)
    return len(enc_payload(pl))      # bounded by the statement's own size


def key_resolution_digest(key_resolution, jcs):
    return hashlib.sha256(jcs({"key_resolution": {i: fp.hex() for i, fp in key_resolution.items()}})).digest()


class TooLarge(Exception):
    def __init__(self, size):
        super().__init__(f"the transcript would be {size} bytes")
        self.size = size


def encode_tb(log_identity_digest, key_resolution_digest_, size, root, rows, detailed):
    """rows: list of (idx, sub_bytes or None); detailed: list of (idx, iss_bytes, kind, sig, payload or None)."""
    total = (len(MAGIC) + size_bytes(log_identity_digest) + size_bytes(key_resolution_digest_) + size_nat(size)
             + size_bytes(root) + size_nat(len(rows))
             + sum(size_nat(i) + 1 + (size_bytes(s) if s is not None else 0) for i, s in rows)
             + size_nat(len(detailed))
             + sum(size_nat(i) + size_bytes(iss) + 2 + (1 + size_payload(p) if p is not None else 1)
                   for i, iss, _, _, p in detailed))
    if total > LIMIT:
        raise TooLarge(total)
    out = [MAGIC, enc_bytes(log_identity_digest), enc_bytes(key_resolution_digest_), nat(size), enc_bytes(root),
           nat(len(rows))]
    for i, s in rows:
        out.append(nat(i) + (nat(0) + enc_bytes(s) if s is not None else nat(1)))
    out.append(nat(len(detailed)))
    for i, iss, kind, sig, p in detailed:
        out.append(nat(i) + enc_bytes(iss) + nat(KIND_CODE[kind]) + nat(SIG_CODE[sig])
                   + (nat(1) + enc_payload(p) if p is not None else nat(0)))
    tb = b"".join(out)
    assert len(tb) == total, (len(tb), total)
    return tb
