Offline evaluation by the policy code of `service/scitt/` (the Registration Policy of ts.isoluce.net since 14 November 2026), written by `run_policy.py`. The four columns run the same code. In the first two, test key 1 is supplied only to an in-memory trust-anchor set, with unknown issuers rejected or accepted; the last two have no anchor, with unknown issuers accepted or rejected. The last column is the deployed setting: neither test key is an anchor of that service. No HTTP registration is performed. "Admitted" means the policy function returned registered bytes; it does not mean that a vector was appended to the live log.

| Vector | Tested condition | Test key 1 injected, unknown issuers rejected | Test key 1 injected, unknown issuers accepted | No anchor, unknown issuers accepted | No anchor, unknown issuers rejected (as deployed) |
|---|---|---|---|---|---|
| R01 | none: tagged COSE_Sign1, alg -19, kid, CWT Claims with iss and sub, content type, attached payload, empty unprotected header | admitted, issuer verified | admitted, issuer verified | admitted, issuer NOT verified | refused: "Rejected" |
| R02 | alg is -8 (EdDSA) instead of -19 | admitted, issuer verified | admitted, issuer verified | admitted, issuer NOT verified | refused: "Rejected" |
| R03 | the unprotected header carries one member | admitted, issuer verified, re-framed, same entry as R01 | admitted, issuer verified, re-framed, same entry as R01 | admitted, issuer NOT verified, re-framed, same entry as R01 | refused: "Rejected" |
| R04 | no tag 18 in front of the COSE_Sign1 | refused: "Malformed request" | refused: "Malformed request" | refused: "Malformed request" | refused: "Malformed request" |
| R05 | the CWT Claims carry iss and no sub | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" |
| R06 | no CWT Claims header (label 15) at all | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" |
| R07 | no kid, and no x5t or x5chain | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" |
| R08 | the payload is nil (detached); the signature is over the payload of R01 | refused: "Payload Missing" | refused: "Payload Missing" | refused: "Payload Missing" | refused: "Payload Missing" |
| R09 | two additions that go together: a private label (-65537) in the protected header, and crit listing it | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" |
| R10 | the last bit of the signature is flipped | refused: "Rejected" | refused: "Rejected" | admitted, issuer NOT verified | refused: "Rejected" |
| R11 | valid, signed with a second test key the service must never be given | refused: "Rejected" | admitted, issuer NOT verified | admitted, issuer NOT verified | refused: "Rejected" |
| R12 | kid is a text string instead of a byte string | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" |
| R13 | no alg in the protected header | refused: "Bad Signature Algorithm" | refused: "Bad Signature Algorithm" | refused: "Bad Signature Algorithm" | refused: "Bad Signature Algorithm" |
| R14 | iss is the integer 1 instead of a text string | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" | refused: "Rejected" |
| R15 | the array of four items has its head on two bytes (0x98 0x04) | admitted, issuer verified, re-framed, same entry as R01 | admitted, issuer verified, re-framed, same entry as R01 | admitted, issuer NOT verified, re-framed, same entry as R01 | refused: "Rejected" |

"re-framed": the entry the policy returns is not the submitted bytes. "same entry as R01": after re-framing, the bytes are those of R01.
