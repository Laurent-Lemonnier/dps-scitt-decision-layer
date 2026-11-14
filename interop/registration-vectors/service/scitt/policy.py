"""The Registration Policy (RFC 9943 sections 5.1.1, 6 and 6.3), preconfigured (section 5.1.2, first bootstrapping
mechanism): what a Signed Statement must carry to be registered here, and how its issuer signature is checked.

Mandatory header checks (RFC 9943 section 6):
  - a protected header with alg (1), an integer this service names (-19, -8, -7, -35, -36);
  - kid (4), or x5t (34) / x5chain (33), in the protected header ("The kid header parameter MUST be present when
    neither x5t nor x5chain is present in the protected header"); a kid, when present, is a byte string (RFC 9052
    section 3.1, and the CDDL of RFC 9943 section 6.1): a text string is refused (since 2026-11-14);
  - the CWT Claims header (15, RFC 9597) with iss (1) and sub (2), each a text string (RFC 8392: StringOrURI);
  - an attached payload (SCRAPI section 2.3: a detached payload needs an implementation-specific channel this
    service does not have; its 400 "Payload Missing" applies).

Issuer signature (RFC 9943 section 6.3 step 2, a MUST for the TS): verified when the kid names a trust anchor in
/etc/scitt/trust-anchors.json. When it does not, the statement is refused (SCITT_UNKNOWN_ISSUERS=reject, the setting
since 2026-11-14 and the default). SCITT_UNKNOWN_ISSUERS=accept registers it with issuer_verified = 0 instead: a
deviation from the MUST, under which a wrong signature cannot be told from a right one (README, ambiguity log A4).
"""
import json

from . import cose


class Rejected(Exception):
    """A 400 with a Concise Problem Details title and detail (SCRAPI section 2.3.3)."""

    def __init__(self, title, detail):
        super().__init__(f"{title}: {detail}")
        self.title, self.detail = title, detail


KNOWN_ALGS = {cose.ALG_ED25519, cose.ALG_EDDSA, cose.ALG_ES256, cose.ALG_ES384, cose.ALG_ES512}
VERIFIABLE_ALGS = {cose.ALG_ED25519, cose.ALG_EDDSA, cose.ALG_ES256}


class TrustAnchors:
    """/etc/scitt/trust-anchors.json: a list of {"kid": "...", "holder": "...", "public_key_pem": "..."}. The file
    holds public keys only."""

    def __init__(self, path):
        self.by_kid = {}
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except FileNotFoundError:
                data = []
            for item in data:
                self.by_kid[item["kid"]] = {"holder": item.get("holder"),
                                            "key": cose.load_public_key_pem(item["public_key_pem"].encode("utf-8"))}

    def get(self, kid):
        return self.by_kid.get(kid)


def _text(value):
    return value if isinstance(value, str) else None


def evaluate(raw: bytes, anchors: TrustAnchors, unknown_issuers: str):
    """Applies the policy to the submitted bytes. Returns (registered_bytes, meta) or raises Rejected.
    registered_bytes: the statement with its unprotected header set to {} (RFC 9943 section 6.3), the protected
    header, payload and signature byte-for-byte as submitted; when the submitted unprotected header was already
    empty and the encoding canonical, these are the submitted bytes themselves (A1)."""
    try:
        protected, pmap, unprotected, payload, signature = cose.parse_sign1(raw)
    except cose.NotCose as exc:
        raise Rejected("Malformed request", f"The request could not be parsed as a tagged COSE_Sign1: {exc}")

    alg = pmap.get(cose.HDR_ALG)
    if not isinstance(alg, int) or alg not in KNOWN_ALGS:
        raise Rejected("Bad Signature Algorithm",
                       f"Signed Statement contained a non-supported algorithm ({alg!r}); this service registers "
                       f"{sorted(KNOWN_ALGS)}")
    if payload is None:
        raise Rejected("Payload Missing", "Signed Statement payload must be present (detached payloads are not "
                                          "accepted by this service)")
    kid = pmap.get(cose.HDR_KID)
    if kid is None and cose.HDR_X5T not in pmap and cose.HDR_X5CHAIN not in pmap:
        raise Rejected("Rejected", "Signed Statement names no kid (4), x5t (34) or x5chain (33) in its protected header "
                                   "(RFC 9943 section 6)")
    if kid is not None and not isinstance(kid, bytes):
        raise Rejected("Rejected", "kid (4) is not a byte string (RFC 9052 section 3.1; RFC 9943 section 6.1)")
    claims = pmap.get(cose.HDR_CWT_CLAIMS)
    if not isinstance(claims, dict):
        raise Rejected("Rejected", "Signed Statement carries no CWT Claims header (15) in its protected header "
                                   "(RFC 9943 section 6, RFC 9597)")
    iss, sub = _text(claims.get(cose.CWT_ISS)), _text(claims.get(cose.CWT_SUB))
    if iss is None or sub is None:
        raise Rejected("Rejected", "The CWT Claims must include iss (1) and sub (2) as text strings (RFC 9943 "
                                   "section 6)")
    if not 1 <= len(iss) <= 8192:
        raise Rejected("Rejected", "iss must be between 1 and 8192 characters (RFC 9943 section 6)")
    crit = pmap.get(cose.HDR_CRIT)
    if crit is not None:
        raise Rejected("Rejected", f"Signed Statement carries a crit (2) header this service does not understand: "
                                   f"{crit!r} (RFC 9052 section 3.1)")
    content_type = pmap.get(cose.HDR_CONTENT_TYPE)
    if content_type is not None and not isinstance(content_type, (str, int)):
        raise Rejected("Rejected", "content type (3) is neither text nor an integer")

    kid_text = kid.decode("utf-8", "replace") if kid is not None else None
    anchor = anchors.get(kid_text) if kid_text is not None else None
    verified = False
    if anchor is not None:
        if alg not in VERIFIABLE_ALGS:
            raise Rejected("Bad Signature Algorithm", f"the trust anchor {kid_text} cannot be used with alg {alg}")
        if not cose.verify_issuer_signature(anchor["key"], alg, protected, payload, signature):
            raise Rejected("Rejected", "Signed Statement signature does not verify under the trust anchor its kid names")
        verified = True
    elif unknown_issuers != "accept":
        raise Rejected("Rejected", "Signed Statement not accepted by the current Registration Policy: its kid names no "
                                   "configured trust anchor")

    registered = raw if not unprotected else None
    if registered is None or cose.encode_sign1(protected, {}, payload, signature) != raw:
        # the unprotected header is emptied (RFC 9943 section 6.3) and the four items re-framed canonically (A1)
        registered = cose.encode_sign1(protected, {}, payload, signature)
    meta = {"alg": alg, "issuer_kid": kid_text, "iss": iss, "sub": sub,
            "content_type": str(content_type) if content_type is not None else None, "issuer_verified": verified}
    return registered, meta
