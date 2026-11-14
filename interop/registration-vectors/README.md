# Registration vectors: a baseline Signed Statement and fourteen variations

Made for the IETF 127 Hackathon (14 and 15 November 2026), for the item "one record, two logs". When the same Signed
Statement goes to two Transparency Services, the first thing that differs is what each one admits, and which bytes
each one puts in its log. These statements make that difference visible.

One baseline and fourteen variations, each testing one registration condition. The subject stays fixed unless the
tested condition removes it; signatures change when signed inputs or the signing key change. R09 adds a critical
parameter together with its crit reference, and R11 changes the key and its kid.

They are not a conformance suite. Many outcomes are left to a service's Registration Policy by RFC 9943 itself; the
table says where a text decides and where it does not.

## The vectors

| Vector | Tested condition | What the texts say | So |
|---|---|---|---|
| `R01-baseline.cose` | none: tagged COSE_Sign1, alg -19, kid, CWT Claims with iss and sub, content type, attached payload, empty unprotected header | RFC 9943 Section 6: every MUST on a Signed Statement is met | eligible for registration if authentication succeeds and the service's additional policy requirements are met |
| `R02-alg-eddsa.cose` | alg is -8 (EdDSA) instead of -19 | RFC 9864 deprecates -8 in favour of the fully specified -19, and does not prohibit it; RFC 9943 does not mandate a particular signature algorithm | left to the registration policy |
| `R03-unprotected-not-empty.cose` | the unprotected header carries one member | RFC 9943 Section 6.3: a TS MAY accept it, and the unprotected header MUST be an empty map in what is included in the Statement Sequence | if registered, the registered bytes differ from the submitted ones, and the leaf does not cover the member |
| `R04-untagged.cose` | no tag 18 in front of the COSE_Sign1 | RFC 9943 Section 6.1 defines Signed_Statement = #6.18(COSE_Sign1) | outside that tagged form; record the service's observed handling without treating normalization as a cited requirement |
| `R05-no-sub.cose` | the CWT Claims carry iss and no sub | RFC 9943 Section 6: the CWT Claims value MUST include iss and sub; Section 6.3 step 2: the TS MUST check the required protected headers | refused |
| `R06-no-cwt-claims.cose` | no CWT Claims header (label 15) at all | RFC 9943 Section 6: the protected header MUST include the CWT Claims header parameter | refused |
| `R07-no-kid.cose` | no kid, and no x5t or x5chain | RFC 9943 Section 6: kid MUST be present when neither x5t nor x5chain is present in the protected header | refused |
| `R08-detached-payload.cose` | the payload is nil (detached); the signature is over the payload of R01 | draft-ietf-scitt-scrapi-11 Section 2.3: a detached payload needs an implementation-specific channel; Section 2.3.3 lists the error "Payload Missing" | refused unless the service has such a channel |
| `R09-crit-unknown-label.cose` | two additions that go together: a private label (-65537) in the protected header, and crit listing it | RFC 9052 Section 3.1: a label listed in crit that the recipient does not understand is an error | refused by a service that does not know the label |
| `R10-bad-signature.cose` | the last bit of the signature is flipped | RFC 9943 Section 6.3 step 2: the TS MUST verify the signature of the Signed Statement | refused when the service knows the issuer's key (it cannot tell otherwise) |
| `R11-issuer-never-configured.cose` | valid, signed with a second test key the service must never be given | RFC 9943 Section 5.1.1.1: a TS MUST authenticate Signed Statements as part of a Registration Policy; Section 6.3 step 2: it MUST verify the signature; Section 6: key discovery is out of scope | refused when no authenticated binding to the signing key can be established; keep test key 2 untrusted in this test |
| `R12-kid-as-text.cose` | kid is a text string instead of a byte string | RFC 9052 Section 3.1 (Table 3) and the CDDL of RFC 9943 Section 6.1: kid is a bstr | not a conforming kid; a service that finds the key anyway is lenient |
| `R13-no-alg.cose` | no alg in the protected header | RFC 9943 Section 6.1 makes alg optional; RFC 9052 Sections 3.1 and 10 allow algorithm selection to depend on the application profile or authenticated context. Signature verification remains mandatory under RFC 9943 Section 6.3 | policy-dependent: ts.isoluce.net's policy requires an explicit supported alg and refuses this vector |
| `R14-iss-not-text.cose` | iss is the integer 1 instead of a text string | RFC 8392 Section 3.1.1: iss is a StringOrURI | refused |
| `R15-array-head-not-shortest.cose` | the array of four items has its head on two bytes (0x98 0x04) | The cited sections (RFC 9943 Section 6.3, RFC 9942 Section 5.2.1) do not specify whether a service preserves an otherwise valid non-shortest outer array encoding. RFC 9052 Section 9's minimum-length encoding rule applies to Sig_structure, Enc_structure and MAC_structure | if registered, say whether the leaf covers the submitted bytes or a re-framed statement |

The baseline uses iss `https://example.org/registration-vectors`, sub `urn:example:registration-vector:R01`, content type `application/json`
and a 33-byte payload. The vectors keep those values except where the tested condition removes or changes one: R05
omits sub, R06 omits the claims header, R08 detaches the payload, and R14 replaces iss with an integer. All signatures
except R11 use test key 1; R11 uses test key 2, which must remain untrusted for this test.

Because the subject is fixed, a service that re-frames a statement before registering it can end with the bytes of
R01: emptying the unprotected header of R03, or shortening the array head of R15, gives R01 exactly. Whether such a
vector then comes back as the entry of R01 is itself a result worth recording.

Both keypairs in this directory are deliberately public test fixtures: anyone can sign with them (the seeds are in
`make_vectors.py`). Neither public key is the receipt verification key of ts.isoluce.net, and neither is the issuer key
used in `../one-chain/registration/`. Never configure them as trust anchors for ts.isoluce.net. Use test key 1 only on
an isolated disposable test instance; keep test key 2 untrusted. Accepted test entries cannot be removed from an
append-only log.

## What the policy function of ts.isoluce.net does with them

[results-ts-isoluce-net.md](results-ts-isoluce-net.md): an offline policy evaluation on 14 November 2026, in three
settings. Test key 1 was supplied only to an in-memory trust-anchor set in the first two; the third has no anchor.
No HTTP registration was performed, and nothing was appended to the live log. The table does not test client
authentication, transport errors, receipt issuance or log persistence, and it does not establish which anchors and
which setting the deployed service uses.

The source of that service is not in this repository, so a third party cannot rerun this table from the files here.
For the record, the two modules evaluated had these SHA-256: `policy.py`
`637611b28d58caeddd6fd1b1055a32ee19d37dd6a6c198dcb3385c51f7e11e45`, `cose.py`
`d300adaaac4d73acc9e84c1b06283ffe417823b0254e6952d384cfec7133308c` (Python 3.12, cbor2 6.2.1, cryptography 50.0.2).

What the table shows about that policy, in order of weight:

- **With no anchor for the issuer and unknown issuers accepted, R10 is admitted**: its signature is corrupted, and the
  policy does not verify a signature it has no key for. The entry is marked as not verified. Admission in that mode is
  not issuer authentication, and it departs from RFC 9943 Section 6.3 step 2. R11 is admitted in the same way.
- **R12, kid as a text string, is admitted and the key found.** RFC 9052 Section 3.1 and the CDDL of RFC 9943 Section
  6.1 make kid a byte string. This is a defect of the policy.
- R02: the policy accepts a valid -8 signature. RFC 9864 deprecates that identifier; it does not prohibit verification
  of existing signatures using it.
- R13: the policy requires an explicit supported alg. This is a local policy restriction, not a general rejection
  mandated by RFC 9943.
- R03 is admitted after its unprotected header is emptied: that is the rule of RFC 9943 Section 6.3, not a deviation.
  R15 is admitted after its array head is shortened: a choice the cited sections do not settle. In both cases the entry
  is not the bytes the client sent; here it is the entry of R01. A receipt has to be checked on the registered bytes.

## Trying another service

```sh
python3 run_against.py https://your-test-instance.example        # needs nothing outside the standard library
```

It posts each statement to `<url>/entries` (draft-ietf-scitt-scrapi-11 Section 2.3) and prints the status, the
Location and the first bytes of the answer. **Use an isolated test instance.**

This script records the initial HTTP response only. A 202 is pending, not a completed registration. It does not
verify a receipt or compare the registered statement bytes; those checks must be performed separately using the
service's returned Location and documented retrieval interface. Exit status 0 does not mean that every statement was
registered or that the service passed a conformance test.

A result is worth writing down in three columns per vector: admitted or refused; if refused, the error title; if
admitted, whether the entry is the submitted bytes. An issue on this repository with that table is enough to add a
service to this folder.

## Regenerate

```sh
pip install cbor2 cryptography
python3 make_vectors.py      # the same bytes every time: fixed seeds, deterministic signatures
```

The SHA-256 of each file is in `vectors/vectors.json`.
