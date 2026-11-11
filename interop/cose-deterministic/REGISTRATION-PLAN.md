# Registration plan: one Hash Envelope through SCITT + SCRAPI, receipt verified offline

Status: **prepared, nothing sent.** No request has been made to any
Transparency Service. This file lists what is known from public texts and
what has to be confirmed with Steven Mih before Saturday 14 November.

## 1. Which implementation

The brief says "the SCITT + SCRAPI reference implementation John Andersen
brings". Public search on 2026-11-10:

- `scitt-community/scitt-api-emulator` (GitHub): the SCITT emulator John
  Andersen worked on in earlier hackathons. GitHub reports it **archived**,
  last push 2024-11-22. It predates the current SCRAPI text (-11, June 2026),
  so its endpoints and receipt format may differ from SCRAPI -11 and
  RFC 9942. One IETF 127 project (WEXP) uses "a pinned, archived
  scitt-api-emulator revision".
- The IETF 127 hackathon wiki page (read 2026-11-10) has no project naming
  John Andersen or a SCRAPI reference service.
- Other public SCRAPI services exist (e.g. `vcon-dev/scittles`,
  `forestrie/canopy`); none is named as "the reference".
- `ietf-wg-scitt/examples` holds receipt vectors (Hash Envelope Signed
  Statements with Microsoft and DataTrails receipts; a `scitt-cose` vector
  set copied from `action-state-group/scitt-cose`). They are data and could
  test an offline receipt verifier without running anyone's code.

**To confirm with Steven:** the exact implementation, its repository and
commit, whether John runs it (hosted URL or a local instance in the room),
and which SCRAPI revision it follows.

None of these codebases has been opened or run for this work.

## 2. What we would register

`registration/signed-statement.cose` (245 bytes, SHA-256
`5c66bf38…b9ad19`, built by `prepare_registration.py`, checked locally with
`verify_from_text.py`: `pass`). It is the P1 Hash Envelope plus the headers
RFC 9943 Section 6 requires of a Signed Statement:

```
18([
  <<{
    1: -8,                          / alg: EdDSA /
    4: h'60612f2d06cb171f37437ce7536decd2',   / kid: first 16 bytes of SHA-256(public key) /
    15: { 1: "https://ts.isoluce.net/demo-issuer",   / CWT iss (placeholder) /
          2: "urn:dps-demo:capsule:dps-demo-1" },    / CWT sub (placeholder) /
    258: -16,                       / payload-hash-alg: SHA-256 /
    259: "application/cbor",
    260: "capsule-1.cbor",
    271: 1                          / deterministic-encodings: core-deterministic (TBD_1 = 271 assumed) /
  }>>,
  {},
  h'<SHA-256 of capsule-1.cbor>',
  h'<Ed25519 signature, demo key>'
])
```

Signing key: `demo-key.json` (demonstration key, seed published).

## 3. The SCRAPI request (draft-ietf-scitt-scrapi-11, Section 2.3)

```
POST /entries HTTP/1.1
Host: <TS host, to confirm>
Accept: application/cose
Content-Type: application/cose

<registration/signed-statement.cose, 245 bytes>
```

Expected answers:

- `201 Created`, `Location: …/entries/<id>`, body = Receipt
  (`application/cose`), or
- `202 Accepted`, `Location: …/entries/<id>`, optional `Retry-After`; then
  `GET /entries/<id>` with `Accept: application/cose` until `200 OK`
  (receipt) — `204` while running, `404` with Concise Problem Details if
  registration failed;
- `400` with Concise Problem Details (`application/concise-problem-details+cbor`,
  RFC 9290) if the Registration Policy refuses the statement.

Before or after: `GET /.well-known/scitt-keys` with
`Accept: application/cbor` returns the TS COSE Key Set (Section 2.1), needed
to verify the receipt offline. Save the key set with its retrieval time.

Every request and response would be saved byte for byte in
`registration/` (request body, status, headers, body), with the time and the
TS URL.

## 4. Offline receipt verification (RFC 9942)

Using only the saved files, no network:

1. Decode the receipt: tagged COSE_Sign1 (`18`). Protected header: `alg`
   (1), `vds` (395) = 1 (RFC9162_SHA256), any other VDS → reject
   ("unsupported VDS"). Unprotected header: `vdp` (396) map with
   `inclusion-proof` (-1) = array of bstr, each `.cbor [tree_size,
   leaf_index, [+ bstr]]`. Payload nil (detached root).
2. Check `leaf_index < tree_size`, else fail (RFC 9942 Section 5.2).
3. Compute the leaf hash: `SHA-256(0x00 || leaf_entry)` (RFC 9162
   Section 2.1.1), where `leaf_entry` is the bytes the TS put in the log for
   our Signed Statement — **to confirm** (see 6).
4. Fold the inclusion path (RFC 9162 Section 2.1.3.2): `fn = leaf_index`,
   `sn = tree_size - 1`, `r = leaf hash`; for each `p`: if `sn == 0` fail;
   if `fn` odd or `fn == sn`: `r = SHA-256(0x01 || p || r)` and, if `fn` was
   even, shift `fn` and `sn` right until `fn` is odd or zero; else
   `r = SHA-256(0x01 || r || p)`; then shift both right once. At the end
   `sn` must be 0. `r` is the Merkle root.
5. Put `r` as the detached payload and verify the receipt signature
   (RFC 9052 Section 4.4, `Sig_structure = ["Signature1", protected, h'', r]`)
   with the TS key from the saved key set (selected by `kid` (4) if
   present). RFC 9942 Section 5.2.1: inclusion first, then signature.
6. Independently, re-run `verify_from_text.py` on the registered Signed
   Statement with `capsule-1.cbor`: the content binding and the
   `deterministic-encodings` claim do not depend on the log.

Output: one line per step, verdict `receipt-valid` / `receipt-invalid
(<step>)`, plus the content-binding verdict, in the same table format as
`results.md`.

This verifier is not written yet. It needs ES256 (P-256) verification,
which the examples in SCRAPI and RFC 9942 use; we would write it in pure
Python from FIPS 186-5 / RFC 6979 texts, as we did for Ed25519.

## 5. What is known

- Endpoints, media types and status codes: SCRAPI -11, Sections 2.1-2.4.
- Signed Statement minimum headers: RFC 9943 Section 6 (CWT Claims 15 with
  iss and sub; kid when no x5t/x5chain).
- Receipt structure and inclusion proof: RFC 9942 Sections 4.3, 5.2, 5.2.1;
  RFC 9162 for the Merkle algorithms.
- Our statement is a valid Hash Envelope and passes our checker.

## 6. To confirm with Steven (and John) before Saturday

1. The implementation, its commit, and where it runs (URL, or local in the
   room). Whether it follows SCRAPI -11 (`POST /entries`, 201/202) or the
   older emulator flow.
2. Registration Policy: does it accept EdDSA (-8)? a `kid` it does not
   know (or must the demo key be pre-registered / given as `x5chain` or
   another key-discovery route)? a placeholder `iss`? an unregistered label
   271 in the protected header?
3. The label for TBD_1: 271, as suggested in the draft, for all
   implementations at the hackathon?
4. Exactly which bytes form the log leaf (the whole Signed Statement as
   submitted, a TS-normalized form, or a hash of parts of it). Without this,
   step 3 of section 4 cannot be done from the text.
5. Receipt signature algorithm and how its key is published
   (`/.well-known/scitt-keys`, `kid` format).
6. Whether the TS embeds the receipt into a Transparent Statement
   (unprotected label 394) or only returns the receipt.
7. Folder layout and whether results go to his repository or ours (link).

## 7. Commands we would run (not run)

```
# 1. keys
curl -sS -H 'Accept: application/cbor' https://<TS>/.well-known/scitt-keys \
     -o registration/ts-keys.cbor -D registration/ts-keys.headers
# 2. register
curl -sS -X POST -H 'Content-Type: application/cose' -H 'Accept: application/cose' \
     --data-binary @registration/signed-statement.cose https://<TS>/entries \
     -o registration/response.body -D registration/response.headers
# 3. if 202: poll the Location URL until 200
curl -sS -H 'Accept: application/cose' <Location> -o registration/receipt.cose -D registration/receipt.headers
# 4. offline
python3.12 verify_receipt.py registration/receipt.cose registration/signed-statement.cose registration/ts-keys.cbor   # to be written
```

These need Laurent's explicit go before anything is sent.
