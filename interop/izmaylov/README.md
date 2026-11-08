# Independent verifier for draft-izmaylov-agent-permission-receipts-02 (Provared, Pavel Izmaylov, 31 October 2026) — 2026-11-08

`verify_from_text.py` is a verifier written from the draft's text alone. `run_vectors.py` replays every published
test vector of the author's repository through it and compares answers; `mutation_tests.py` adds eleven mutations of
published logs for codes no attempted vector reaches. Nothing here imports, reads or runs the author's code. This is a
third party's check that the text is enough to reach the published answers, and a list of where it is not.

| File | What it is |
|---|---|
| `verify_from_text.py` | the verifier (records, permission rules, chains, log, heads, time-stamps, the three answers, a command line) |
| `run_vectors.py` | the replay of every vector; per family: agree / disagree / not attempted; each disagreement carries its cause |
| `mutation_tests.py` | 11 mutations of published logs that need no re-signing |
| `draft/` | the draft text read (`draft-izmaylov-agent-permission-receipts-02.txt`) and its SHA-256 |
| `vectors/` | `PINNED_COMMIT.*` and `SHA256SUMS.*` of the vectors; the files themselves (54 MB) are fetched by `../run.sh` at the pinned commit and checked against the digests |
| `judge-v0.6.0.json`, `judge-main.json` | the reports: one record per family, every disagreement with our answer, the vector's, and its cause |
| `run-20261108-*.txt`, `mutation-20261108.txt` | the printed runs of 8 November 2026 |

## What was read, and what was not

- **The draft**, in full: Sections 1 to 18 and Appendices A to D (2,744 lines, `draft/`, SHA-256 `2f0e9348…f22d`). Where the
  text says "specified only in [FORMAT]" (Section 15) the verifier stops there: the format description
  (`spec/provared-format.md`) was not opened.
- **The vectors**: `github.com/provared/provared`, directory `test-vectors/`, each file a set of cases `{input, expected}`.
  Two pins, both run: **tag v0.6.0** (`e4dd2f0381c1…`, 25 October 2026), the release Section 17 of the draft names as its
  implementation, 96 files, 14,742 cases; and **main at `24cac844…`** (7 November 2026, after tag v0.8.0), 98 files,
  14,776 cases. The difference between the two is in eight files (`slips`, `stub-contents`, `issuer-origins`,
  `issuer-origin-shows`, `denial-contents`, `denial-constants`, `http-fingerprints`, `recorder-details-after`).
  The vector files themselves, `test-vectors/README.md` and `conformance/README.md` (the rule for comparing an answer:
  codes and shape, findings in any order, wording free) were opened. Nothing else: not `src/`, `python/`, `test/`,
  `tools/`, `gateway/`, the conformance kit's code, nor the other packages. None of the author's code was run.
  The repository was cloned to read the vectors, so the other files were on disk; they were not opened.
- **Comparison used here**: codes and shape as the vectors' README says for another implementation. A vector agrees when
  our problems of an entry are exactly the expected set (the kit's README lets an entry's problems be a subset; this is
  stricter), our findings are the same multiset, our three answers and the digests are equal. The `time` of a stamp is
  compared after rounding down to the second, as 9.3 says ("Times are taken to the second, rounded down"; the vectors
  keep milliseconds, A17). Messages are not compared.
- **Libraries** used for signature mathematics only: `cryptography` (ECDSA P-256 and P-384, RSA PKCS#1 v1.5, P-256 point
  validation) and `pqcrypto` 1.0 (ML-DSA-87 and SLH-DSA-SHA2-256s, pure mode, empty context). Ed25519 is implemented in
  the file (Section 4.6 sets rules that "libraries differ on"); it agrees on all 22 vectors of `ed25519-signatures`
  (the cases of the paper "Taming the many EdDSAs" and cases made by the author). A method can be declared missing (`--without`), which is how the vectors'
  "device without SLH-DSA" runs are reproduced.

## Results

`python3 run_vectors.py --vectors <test-vectors dir>`; `../run.sh` runs both pins and fails if any family differs from the
committed reports.

| Pin | Cases | Agree | Disagree | Not attempted |
|---|---|---|---|---|
| tag v0.6.0 (the draft's release) | 14,742 | 11,314 | 119 | 3,309 |
| main `24cac84` | 14,776 | 11,319 | 125 | 3,332 |

Of the 11,433 attempted at v0.6.0, 11,314 agree (99.0 %). 51 of the 119 disagreements are cases the draft itself announces
(Section 17 for the time-stamp refusals, Sections 5, 8 and 15 for [FORMAT]); 48 are one open reading (A5); 20 are the
other readings of the log below. The six more at main are one reading (A22). A second pass over the 25 "other readings" and
the 8 [FORMAT] cases (9 November 2026, entries A28 and A29 of the log) changed two readings and closed 5 disagreements;
the others were re-read against the text and kept.

Per family, at v0.6.0 (families with at least one attempted case; the others are below):

| Family (file) | Function it tests | Cases | Agree | Disagree | Not attempted |
|---|---|---|---|---|---|
| `base64url` | strict base64url (11.1) | 11 | 11 | 0 | 0 |
| `canonical-json` | canonical form and value domain (11.2) | 37 | 37 | 0 | 0 |
| `characters` | length in code points (4.3) | 7 | 5 | 0 | 2 |
| `times` | times that exist (4.3) | 18 | 18 | 0 | 0 |
| `keys` | key shapes and thumbprints (4.4, 11.2, 11.3) | 62 | 62 | 0 | 0 |
| `ed25519-signatures` | the rules of 4.6, with the cases of the paper | 22 | 22 | 0 | 0 |
| `ecdsa-der` | ES256 signature in strict DER (4.7) | 11 | 10 | 1 | 0 |
| `origins` | the form of `origin` and its relation to `rpId` (5) | 3,710 | 3,710 | 0 | 0 |
| `seal-key-sets` | key-set digest (11.3) | 16 | 16 | 0 | 0 |
| `stub-contents`, `countersignature-contents`, `approval-contents`, `cancellation-contents`, `acknowledgement-contents`, `pass-contents`, `seal-contents` | members of the records (4.2, 5.1, 6, 7, 8, 9.2) | 42 + 4 + 137 + 60 + 84 + 260 + 63 = 650 | 41 + 4 + 128 + 51 + 69 + 246 + 60 = 599 | 49 | 2 |
| `records` | envelope read as a kind (11.1) | 3 | 3 | 0 | 0 |
| `slips` | one permission: envelope, members, passkey (4.7, 5) | 170 | 154 | 8 | 8 |
| `tree-leaves`, `tree-roots`, `tree-paths`, `tree-inclusion`, `tree-consistency`, `tree-consistency-checks` | Merkle tree (9.1, RFC 9162) | 2,638 | 2,609 | 0 | 29 |
| `seal-stamps` | `stamps` of a head or cancellation (9.3, 11.4) | 42 | 34 | 4 | 4 |
| `stamps`, `stamps-openssl`, `stamps-strict-keys`, `stamps-flips-ecdsa`, `stamps-flips-ed25519`, `stamps-flips-rsa` | one RFC 3161 token, made up or made by OpenSSL, and with every byte changed in turn (9.3) | 347 + 574 + 37 + 866 + 1,275 + 582 = 3,681 | 3,651 | 23 | 7 |
| `der-strict` | the DER rules of 9.3 item 2 | 368 | 340 | 28 | 0 |
| `books`, `denial-books`, `held-seals` | whole logs: the three answers, problems and findings per entry (6 to 10) | 53 + 12 + 26 = 91 | 31 + 1 + 1 = 33 | 6 | 52 |

The disagreements sum to 119 (49 + 8 + 1 + 4 + 23 + 28 + 6). The full per-file table, with the 60 families that are not
attempted at all, is in `run-20261108-v0.6.0.txt`.

**Whole logs.** The `checkBook` families hold 91 cases. 39 need nothing from [FORMAT] and were attempted; 33 of them agree on
everything: the three answers, the entry count and root, every entry's kind, digest, problem set, finding multiset and
whether it was compared (the 6 that do not are in groups 3 and 4 below). 17 of the other 52 hold records of the four further
kinds (`refusal`, `terms`, `vouching`, `withdrawal`) or of one the draft does not know (`denial`): for these the draft says
what a core verifier does ("A core verifier reports the four further kinds ... in the same way [unknown-entry], and so never
calls such a log intact", 9.1), and that was checked: 17 of 17 logs give `unknown-entry` on those entries and are not
intact. The remaining 35 need the principal's own copy of a cancellation, witness statements, seals held elsewhere,
disclosures, vouching records or block headers, all [FORMAT].

**Findings and problem codes exercised.** The attempted logs reach these findings: `action-not-allowed`, `prohibited`,
`party-not-allowed`, `outside-valid-time`, `over-limit`, `over-each-limit`, `over-count-limit`, `over-period-limit`,
`countersignature-missing`, `approval-missing`, `after-cancellation`, `pass-not-allowed`, `pass-wider`. Not reached by any
vector: `amount-missing`. Problem codes reached: `not-json`, `line-not-canonical`, `unknown-entry`, `too-large`,
`root-mismatch`, `issuer-not-expected`, `signature-invalid`, `slip-missing`, `slip-unusable`, `duplicate-id`,
`duplicate-slip`, `chain-broken`, `time-went-backwards`, `countersignature-wrong-stub`, `approval-mismatch`,
`approval-invalid`, `approval-reused`, `approval-dated-after-stub`, and, in the single-record and stamp families, the `bad-*`,
`passkey-*` and `stamp-*` codes. **Not reached by any attempted vector**: `approval-not-found`, `cancellation-invalid`,
`cancellation-not-found`, `check-failed`, `countersignature-invalid`, `countersignature-not-possible`, `dated-after-stamp`,
`pass-mismatch`, `pass-missing`, `pass-too-deep`, `seal-chain-broken`, `seal-mismatch`, `sealer-not-expected`,
`terms-not-found`, and `amount-missing`. Seven of them are reached by `mutation_tests.py` (`approval-not-found`,
`countersignature-invalid`, `pass-missing`, `cancellation-not-found`, `cancellation-invalid`, `sealer-not-expected`,
`seal-mismatch`), by editing published logs without re-signing; the rest are written from the text and checked by nothing.

**Signature methods.** All five are implemented; none is reported "not implemented". ML-DSA-87 signatures verify in all 33
attempted logs that agree (every receipt carries one) and a changed byte makes one invalid (`mutation_tests.py`);
SLH-DSA-SHA2-256s verifies, all three signatures valid, on the head of `the sample record` (two cases of `books`), and a cut-short
third signature is `signature-invalid` as 4.5 says. The vectors are answered "on a
device without SLH-DSA" (`withoutMethods` in every case), so every comparison above is run that way, and the "not verified
because the method is lacking" path (answer 2 no, methods named, answer 3 resting on the signatures verified) is the one
compared; with SLH-DSA present the heads verify (`mutation_tests.py`, last line) but no vector states what the answers
should then be.

## Where the text and the vectors differ

Each group: the draft's sentence, our reading, the vector's expectation, the cases. Case names are those of the files.

**1. Non-strict base64url inside the content of a record: 48 cases (A5).** `acknowledgement-contents` 15, `pass-contents`
11, `approval-contents` 9, `cancellation-contents` 9, `seal-contents` 3, `stub-contents` 1 (`id: padding`, `slip: a slash`,
`id: stray bits`, `a faulty cancellation, pass and time: the cancellation is reported`, …).
Draft 11.1: "Every value written in base64url, in a record's envelope or content or in a log entry, ... is read strictly: a
verifier MUST refuse padding, a character outside the alphabet, a length that leaves 1 when divided by 4, and unused bits
that are not zero (bad-base64url; in a key, bad-key; in "authenticatorData" and "clientDataJSON", passkey-bad-data)."
Our reading: an `id` or a digest in a record's content that is not strict base64url is `bad-base64url`. Vector: `bad-field`
(message: "id: must be a unique number of 16 bytes in base64url"). Appendix A glosses `bad-field` as "member missing,
unknown, or malformed", which supports the vectors; 11.1 supports us. One sentence in 11.1 or Appendix A would settle it.

**2. What Section 17 announces: 43 cases.** "It refuses some time-stamps that Section 9.3 accepts: a string written in parts;
elements of a SET OF out of DER order in the signed attributes, in the TSTInfo, or in a certificate; a BIT STRING whose
unused bits are not zero; a second signing-time attribute; and an Ed25519 time-stamp whose digest algorithm is not SHA-512
or carries parameters, as [RFC8419] requires." 9.3 item 2: "every BIT STRING with at most 7 unused bits", "The order of SET OF
elements and the omission of DEFAULT values are not checked". Cases: BIT STRING unused bits 13 (`der-strict` 11, and byte
352 and byte 442 of two flip files), string written in parts 8 (`der-strict`), SET OF order 18 (`der-strict` 9; `stamps` 5;
`stamps-openssl` 3; `stamps-flips-rsa` 1), Ed25519 with a digest algorithm other than SHA-512 or with parameters 4
(`stamps`). We follow 9.3; the vectors follow 0.6.0. Open issue 4 of the draft is the same point.

**3. [FORMAT] parts, which a core verifier does not read: 8 cases.** `slips` 7 ("covered fields, none revealed", …):
Section 5, "Any other member is a problem for a core verifier (bad-field); this includes the members by which [FORMAT] covers
fields (Section 15)". `books` 1, `a cancellation, time-stamped, and stubs after it`: Section 8, "Section 22 of [FORMAT] adds a
stricter rule for a time-stamped cancellation. A receipt before it in the log is also reported ... Without that rule, a core
verifier can miss receipts made after a cancellation." The vector reports `after-cancellation` on the receipt before the
cancellation; we do not.

**4. The three answers, 5 cases (A16).** Draft 10.1: "Was everything verified? Yes only if every entry was read as far as its
signatures, and no signature or time-stamp in the log was left unverified because the verifier does not implement its
method." Two situations: (a) three cases of `books` where an expected top fingerprint or number of entries is given and is
wrong ("another top fingerprint expected", "another number of entries expected", "a number of entries given as true"): we
report `root-mismatch` (9.2) and answer 2 yes; the vectors say `fullyChecked: false`. (b) two cases where a receipt was
altered after signing or carries the countersignature of another receipt (`a stub changed after signing`, `the
countersignature of another stub`): we verify the countersignature's own signatures although `countersignature-wrong-stub`
is reported (6 lists three confirmations, "A verifier MUST confirm "stub" (countersignature-wrong-stub), that such keys
exist (...), and both signatures (countersignature-invalid)"), so the entry was read as far as its signatures; the vectors
say not.

**5. Passkey confirmations (A8, A28): no disagreement left.** Draft 4.7: the verifier "MUST confirm that" seven things, each with
a code. The first replay read them as independent and reported every failing one; the vectors stop at the first (`client data
whose type is not text`, `client data nested deeply`: 2 cases). Changed after the second pass, as A28 below: a passkey signature
reports the first confirmation of the list that fails. Both readings agree on every single-fault passkey case of `slips`.

**6. One-offs.** `slips` `a payload that is a list` (A3, 11.2 says the content "MUST be a JSON object ... (payload-not-canonical)";
vector `bad-field`); `ecdsa-der` `a number of 33 bytes` (A25: 4.7 allows INTEGERs "of 1 to 33 bytes in their shortest form", a 33-byte
value above 2^256 is accepted by the DER rule and cannot verify; vector `passkey-bad-data`); `pass-contents` `a faulty helper name and
keys` (A23: which of two faulty members is reported first is not specified: we report `keys` before `name`, as the canonical
order has them); `stamps` `a time in the year 50` (A26), `a broken ECDSA signature, ECDSA said to be missing` (A11); `stamps` 5 and
`stamps-flips-ecdsa` 1 where a layout defect in the TSTInfo's `accuracy` or in an extension is `stamp-bad-data` for us and
`stamp-invalid` for the vectors, or the reverse (A13: `accuracy given twice in seconds` and `..., the second within`, where the
vectors keep the last value although RFC 3161 allows `seconds` once; `accuracy of five bytes`, an INTEGER of 2^31 that item 6
refuses as above 300, `stamp-invalid`, where the vectors say it cannot be read; `accuracy that is negative`, which item 6's "at
most 300" does not refuse; `an extension with a truth value in an odd place` and `byte 159` of the ECDSA flips, where the layout
of an extension is a defect of item 1, reported before item 6's critical flag or item 5's signature); `seal-stamps` 4 (A27: size limit of a token
against strict base64url, and an empty token); at main, 6 cases of `stub-contents` where `provared.tool-name`, `provared.tool-call-id`
and `provared.tool-result` are accepted as reserved document names: Section 6 says a reserved name "MUST be one of the seven
names of Section 27 of [FORMAT]" (A22); they are not in the seven, and are not in the vectors of v0.6.0.

## Not attempted, with reasons (v0.6.0: 3,309 cases)

| Cases | Reason |
|---|---|
| 1,034 | records of the kinds refusal, terms, vouching, withdrawal, denial, witness: [FORMAT] (Section 15) |
| 971 | time-stamps from a public blockchain (block headers, proofs): [FORMAT]; "a core verifier does not count it" (9.3) |
| 682 | internal functions of the author's DER reader (`readElement`, `children`, `timeOf`, `ecdsaToRaw`): not rules of the draft; the DER rules are exercised through `der-strict` and the token files |
| 207 | the author's recorder and stub writer and its scenarios: the draft does not specify how a recorder keeps its log (Section 1) |
| 104 | writing and signing records, preparing a challenge: the draft specifies the verifier and the records |
| 94 | one-page proofs (Show, 39), the check before acting (FORMAT 20, 37), the book number of a seal (FORMAT 21.6, 18): [FORMAT] |
| 49 | the exact texts behind the reserved document names (FORMAT 27) |
| 111 | other [FORMAT] parts inside families that were otherwise attempted: witness statements (58), seals held elsewhere (30), disclosures and covered fields (10), vouching records (2), block headers (2) and block sizes (4), a copy of a cancellation (5) |
| 17 | logs holding the four further kinds: not compared with the vectors, checked against 9.1 instead (17 of 17 as the draft says) |
| 36 | a JavaScript value where a size, an index, a list, hex text or a token is expected (boolean, fraction, text, null): no counterpart in a verifier of bytes |
| 4 | an unpaired surrogate is not a Unicode scalar value (4.3): the draft gives no count (2) or refuses it earlier, at 11.2 (2) |

## What the verifier does, by the draft's own words

- **Records** (4.1): eight kinds, each a JWS in the general JSON serialisation over RFC 8785 canonical content; the
  protected header is compared as the exact bytes `{"typ":"vnd.provared.X.v0+json","alg":"<alg>"}` (11.1); the digest is the
  SHA-256 of the decoded `payload`; the content domain is objects, arrays, text and integers 0 to 2^53−1, eight levels, no
  unpaired surrogate (11.2). Order of checks as 10.1: encoding, members, records relied on; "At the first problem in those
  steps, it reports that problem's code and checks nothing further in that entry"; id comparison before the lookup;
  everything else is reported.
- **Signatures** (4.5, 4.6): Ed25519 then ML-DSA-87 (and SLH-DSA-SHA2-256s on a head), each with the key at the same position;
  a wrong length is `signature-invalid` whether or not the method exists; Ed25519 as 4.6: S < L, A and R decode, no small
  order, cofactorless equation; keys: y < p and not the y of the eight small-order points, "whatever the sign bit". Missing
  method: "not verified", never invalid.
- **Passkeys** (4.7): client data UTF-8, no BOM, JSON object, last repeated member wins; `webauthn.get`; challenge = base64url
  of SHA-256 of the JWS signing input; origin string equal and `crossOrigin` not true; authenticator data ≥ 37 bytes,
  `rpId` hash, flags UP and UV set, AT clear, ED clear means exactly 37 bytes; ES256 as a strict DER ECDSA-Sig-Value; RS256;
  Ed25519. For an approval or a cancellation every failure is `approval-invalid` / `cancellation-invalid`.
- **The permission and receipts** (5 to 7): limits `max`, `each`, `count`, with and without `per`; conditions with `above`;
  `never`; `passes` and depth; half-open validity; chain by `seq`/`previous`; `time-went-backwards`; countersignature by the
  service's keys; approval ≤ 300 s after the receipt and not reused.
- **Findings** (10.2), named as the text names them, `over-period-limit` once per period limit exceeded, the others once:
  `action-not-allowed`, `prohibited`, `party-not-allowed`, `outside-valid-time`, `amount-missing`, `over-limit`,
  `over-each-limit`, `over-count-limit`, `over-period-limit`, `countersignature-missing`, `approval-missing`,
  `after-cancellation`, `pass-not-allowed`, `pass-wider`. "Only compared receipts count toward totals." A receipt is compared
  "only if it is sound, at least one of its signatures was verified and none failed, and its permission's passkey signature was
  verified".
- **Cancellation** (8): the effective cancellation is "the first cancellation of it in the log that is sound when read and
  whose passkey signature, and that of its permission, were verified"; later receipts and delegations are `after-cancellation`;
  an acknowledgement names a cancellation "judged again once the whole log has been read".
- **The log** (9.1, 9.2, 11.4): one entry to a line, the leaves are the lines' bytes, root by RFC 9162 2.1.1; heads: three
  signatures, `size` is the head's own place, `root` of the entries before it, `previous` the nearest earlier head, `when` not
  before it, recorder key set among the trusted digests, otherwise said not compared.
- **Time-stamps** (9.3): the RFC 3161 token under the DER rules of the list, imprint, signed attributes, ESSCertID(v2), the
  signature by RSA (2,048 to 8,192 bits, odd exponent 3 to 2^32 − 1), ECDSA P-256 or P-384, or Ed25519 (4.4 applied),
  `genTime` within the certificate, accuracy ≤ 300 s, no critical extension; the TSA is trusted by the digest of its
  certificate; a stamp counts "from a trusted TSA, on a record whose signatures were all verified"; "existed by", never "existed
  at"; `dated-after-stamp` beyond 300 s. Output: for each stamp its state (valid, untrusted with the certificate's digest,
  unavailable), the entries the last counted time-stamp reaches, and `existed_by` for each entry.
- **The three answers** (10.1), kept apart: problem found; everything verified; within permission ("Yes only if no problem was
  found, every receipt and delegation was compared, and none gave a finding"); and "A verifier MUST call a log intact only if no
  problem was found and everything was verified". When answer 2 is no, the third is reported as resting only on the
  signatures verified, with the methods lacked named.

## Ambiguity log

Readings the text leaves open. Section numbers are the draft's. "Changed" marks a reading changed after the first replay
against the vectors (disclosed in the next section); the text is silent in those cases, and the vectors, not the text,
settled our choice.

1. **A1, 4.4 / 4.6: is a key that is not a point refused as a key?** 4.4 states two tests (y < p, not the y of a small-order
   point); 4.6 rule 2 says A "decodes to a point on the curve". We read the second as a rule of verification (the signature is
   `invalid`), not of the key's shape (`bad-key`). Vectors: `pass-contents` keys are placeholders that are not points and are accepted.
2. **A2, 4.4: ES256 coordinates.** "A P-256 public key, two coordinates of 32 bytes". We refuse a coordinate that is not
   below p (a point has one encoding). Changed after the replay (`keys`: "x written as 5 plus the prime"); the text does not
   say it.
3. **A3, 11.2 / 4.2: a payload that is JSON but not an object.** `payload-not-canonical` (11.2: "It MUST be a JSON object") or
   `bad-field` (4.2: "A map MUST hold exactly the members listed")? We say the first; the vector the second.
4. **A4, 11.1 / 4.7: where the base64url of `authenticatorData` and `clientDataJSON` is read.** 11.1 names `passkey-bad-data`
   for them, 4.7 is where the passkey is checked. Changed: first read at the envelope stage (record has no digest, nothing else
   reported), now at the passkey stage (record read, then `passkey-bad-data`), which the vector shows.
5. **A5, 11.1 / Appendix A: base64url in content: `bad-base64url` or `bad-field`.** See the first difference. 48 cases.
6. **A6, 11.1: order of the envelope checks.** The text lists, in this order, exact members (`bad-envelope`), strict base64url,
   the protected header (`unknown-type`, `payload-type-mismatch`), number and order of signatures (`bad-signatures-layout`),
   and, in 11.2, size (`too-large`). We check shape, then size, then base64url, then headers, then layout, then content.
7. **A7, 11.1 / 4.1: the shape of a signature entry.** "Each element of signatures MUST hold exactly protected and signature and,
   for a passkey signature, also header". We read each entry at the position 4.1 gives the signer: an entry beyond the
   expected number is a layout problem, not a shape problem. Changed (`a slip read as a stub` and `two signatures` would
   otherwise differ).
8. **A8, 4.7: are the seven confirmations independent?** See group 5. First read as independent, all failing codes reported;
    changed after the vectors (A28): the first failing confirmation of the list is the signature's problem.
9. **A9, 9.1 / RFC 9162: consistency with a tree of size 0, and sizes out of range.** The draft defines no consistency proof
   (open issue 6). For the empty earlier tree we accept an empty proof against the empty-tree root; for m or n out of range,
   `check-failed`. Changed for m = 0 (first: any root; the vectors accept it only against the empty-tree root).
10. **A10, 9.3 item 3: parameters of the hash algorithm in the message imprint.** "has the hashAlgorithm SHA-256": parameters are
    not examined. Changed (first: absent or NULL only).
11. **A11, 4.5 / 9.3: a TSA signature that cannot be checked because the method is missing, and is also malformed.** We say
    `unavailable` (not verified); the vector `stamp-invalid`. The draft names no switch for time-stamp methods; we use the
    names of the signature methods (RS256, ES256, Ed25519).
12. **A12, 9.3 items 1, 2, 6: how deeply the certificates are read.** The text asks for DER over everything, for each
    certificate's validity times and the signing certificate's key "written exactly as its own specification sets out", and says
    "The certificate's extensions are not examined". We read every certificate that is a SEQUENCE down to its validity and
    public key info (version, serial, algorithm, issuer and subject as SEQUENCEs, validity, key info, optional tags), the
    signing certificate's key in full, and nothing of extensions or names; elements of `certificates` that are not SEQUENCEs
    are not read. Changed: a deeper reading (names, algorithm identifiers, extensions) disagreed on several dozen byte flips
    and was reduced; the seven flip disagreements that remain are SET OF order and unused-bits cases (group 2) and one layout case (A13).
13. **A13, 9.3 items 1 and 4: layout defect or invalid content?** Item 1 puts layout "as RFC 3161 and RFC 5652 require" under
    `stamp-bad-data`; item 4 puts attribute content, multiplicity ("at most once and holds exactly one value") and the like
    under `stamp-invalid`. We use `stamp-bad-data` for ASN.1 syntax (including the structure of ESSCertID and accuracy) and
    `stamp-invalid` for semantic and multiplicity defects. Six cases differ (nine before the second pass: three cases of
    an elliptic-curve key's parameters are now `stamp-invalid`, see A29).
14. **A14, 11.4: a log line that is JSON but not an object; the size check.** `unknown-entry` (we) for a line such as `[]`; the
    length limit is checked before the line is read.
15. **A15, 9.3 item 2: counting.** "at most 4,000 elements, none more than 24 levels deep": a level is a constructed element inside
    another; "length field of at most four bytes" is the bytes after the first length octet; nothing may follow the token.
    Changed for the level count (a primitive leaf does not make a level).
16. **A16, 10.1: what "read as far as its signatures" covers.** See group 4. A mismatched root does not change answer 2 for us.
17. **A17, 9.3: "Times are taken to the second, rounded down."** The vectors carry milliseconds; compared after rounding.
18. **A18, 10.2: windows of a `per` limit.** "every receipt for the action, in any chain and anywhere in the log"; we count compared
    receipts only, as "Only compared receipts count toward totals" says for totals.
19. **A19, 6: "MUST NOT be dated more than 300 seconds after the receipt"**: approval time minus receipt time > 300 s.
20. **A20, 8: "sound when read".** A later `dated-after-stamp` does not stop a cancellation from being effective; a cancellation
    whose passkey or whose permission's passkey signature is only "unavailable" is not effective.
21. **A21, 4.3: unpaired surrogates and the length of text.** Not Unicode scalar values; 11.2 refuses them in content; the
    four vectors that count them are not attempted.
22. **A22, 6: details names.** "a name that begins so MUST be one of the seven names"; non-reserved names may repeat; the
    three identifier names may repeat. At main the vectors accept three more reserved names.
23. **A23, 10.1: which of several faulty members is reported.** Unspecified; we follow the canonical member order of the content.
24. **A24, 9.2: "size is its own place in the log".** A head at index i has `size` i and `root` over entries 0 to i − 1.
25. **A25, 4.7 item 7: INTEGERs "of 1 to 33 bytes".** A 33-byte positive value above 2^256 is well formed; verification fails.
26. **A26, 9.3: genTime written with a year below 100.** A moment that exists, so outside the certificate's validity
    (`stamp-invalid`); the vector `stamp-bad-data`.
27. **A27, 9.3 / 11.4: the token size limit against strict base64url, and an empty token.** Base64url first (`bad-base64url`),
    then the size (`bad-field`); an empty token is read as far as the DER rules, which refuse it (`stamp-bad-data`).
28. **A28, 4.7: which confirmation is reported when several fail.** *Changed after seeing the vectors* (2 cases of `slips`:
    `client data whose type is not text`, `client data nested deeply`). Text: "follows Section 7.2 of [WebAuthn] as far as it
    applies to a later check with no state, and MUST confirm that: 1. ... 7." Each of the seven carries one code. First reading:
    seven independent checks, every failing code reported. Now: the passkey signature is one signature, the confirmations are
    a numbered list that follows the sequence of WebAuthn 7.2, and the first one that fails gives the problem. The text does not
    say it (10.1 says "at the first problem" only of encoding, members and records relied on), so this is a reading the vectors
    settled; it changes nothing for a single fault. Cases: 2 of 14,742 at v0.6.0 (same at main).
29. **A29, 9.3 items 2 and 5: parameters of an elliptic-curve key in the signing certificate.** *Changed after seeing the
    vectors* (3 cases of `stamps`: `certificate: a key with no curve`, `a key with a curve given as null`, `a P-256 key with its
    curve written out`). Text, item 2: the key is "written exactly as its own specification sets out": for RSA "with the
    parameters present and NULL", for Ed25519 "with no parameters and 32 bytes", for ECDSA only "as Section 2.2 of [RFC5480], as
    an uncompressed point" (the point, not the parameters). Item 5: "a key of any other kind or on any other curve is refused
    (stamp-invalid)". First reading: parameters that are not a named curve are a layout defect (`stamp-bad-data`). Now: they
    are a key on no accepted curve (`stamp-invalid`), since item 2 states the layout of the ECDSA point only. Cases: 3 of 14,742
    at v0.6.0 (same at main).

**Disclosed changes after the first replay.** The first replay ran with these readings: on-curve test in the key's shape
(A1), P-256 coordinates not bounded (A2), passkey header values read at the envelope stage (A4), signature entries shaped
irrespective of position (A7), the message imprint's algorithm parameters required to be absent or NULL (A10), consistency
with an empty tree accepted whatever the root (A9), levels counting primitive leaves (A15), and a deeper reading of
certificates (A12). Each was changed after seeing the vectors disagree; for A1, A2, A4, A7, A9 and A12 the text does not
decide, and the choice is the vectors'. A second pass (9 November 2026) went back over the 20 remaining "other readings" and
the 8 [FORMAT] cases, text in hand, and changed two more after seeing the vectors: the first failing passkey confirmation only
(A28, 2 cases) and the parameters of an elliptic-curve key in a time-stamp certificate (A29, 3 cases). That makes **ten**
readings changed after the vectors. Kept after re-reading, because the text supports our answer and the vectors are the
exception: A3 (11.2 puts "MUST be a JSON object" under `payload-not-canonical`; 4.2's `bad-field` is about the members of a
map); A11 (4.5 says the wrong-length rule "does not reach a TSA's signature inside a time-stamp"; a signature that cannot be
checked is not verified); A13 for `accuracy` (RFC 3161 gives `seconds` once; an INTEGER above 300 is item 6's `stamp-invalid`;
a negative one is not above 300), for an extension out of layout (item 1 before items 5 and 6); A16 (10.1's two conditions for
answer 2 say nothing of a mismatched root, and "Every other problem ... is reported" covers the countersignature of another
stub); A23 (no order is given for two faulty members); A25 (a 33-byte INTEGER is in 4.7's range, the failure comes at the
verification); A26 (year 0050 is a moment that exists; "denoting a moment that exists" is the only test of item 2); A27 (the
limit is stated in bytes of a token, which a string that is not base64url does not have; an empty string is a token of 0
bytes). The 8 [FORMAT] cases stay as they are: Section 5 says in terms that the members by which [FORMAT] covers fields are
`bad-field` for a core verifier (7 cases), and Section 8 that the stricter rule of Section 22 of [FORMAT] is not specified
here (1 case). Two plain errors were also corrected: regular expressions that accepted a trailing
line feed (`$` for `\Z`), and a name collision in the certificate reader.

## Limits

- **Anchors and trust.** TSA certificates are trusted by digest, as 9.3 says: no chain, no revocation, no network. The
  time-stamp path that counts (a trusted TSA on a head whose three signatures verified) was exercised only on
  cancellations: no attempted vector has a head that counts, because all are answered without SLH-DSA, where "a seal's
  time-stamp never counts". `dated-after-stamp` is written from the text and reached by no vector or mutation. Block
  time-stamps are reported as not counted (9.3), nothing more.
- **Libraries.** ML-DSA-87 and SLH-DSA-SHA2-256s are checked by `pqcrypto`; their correctness here rests on that library and on
  agreement with the author's signatures (valid on every attempted log that carries them; a changed byte is invalid).
- **Not written from the text**: nothing of [FORMAT]: no Show, no check before acting, no refusal, terms, vouching or
  withdrawal, no blockchain time-stamp, no covered fields, no principal's copy of a cancellation, no witness; no executor.
- **Test inputs the vectors lack**: a log with a head that counts, `amount-missing`, a chain of delegations deeper than one,
  `pass-too-deep`, `terms-not-found` and the codes listed above. Eleven mutations cover seven of them; there is no
  generator of signed logs here.
- **Speed.** Ed25519 is pure Python (about 10 ms a verification); a log of 100,000 entries would take hours.
- **No claim beyond the three questions.** This is a reading of a draft by a third party; it says nothing about the draft's
  security properties, and "agree" means the same answer on the author's inputs, not that the text is complete.

## The draft against the Decision Provenance Standard's standing approval and action binding

Read: action binding 0.3.0 (rules 9 to 12, with 5 and 13) and signatures 0.2.0, as vendored in `../aqta/approval-record/dps-standard`.
The two documents answer different first questions: the draft is about **what a principal allowed an agent to do and whether
each recorded act stayed within it, checked offline from signed records**; the DPS action binding is about **whether the
action carried out is the action that was approved, with a report of what a check found**. Neither is a substitute for the
other. Items that are the same kind of thing are placed side by side; "no counterpart" means none in the text read.

| Subject | draft-izmaylov-…-02 | DPS action binding 0.3.0 / signatures 0.2.0 |
|---|---|---|
| What a person signs | a **permission**: actions, services, limits, conditions, `never`, validity, `passes`, purpose; one passkey signature (ES256, RS256 or Ed25519) over the JWS signing input via the WebAuthn challenge (4.7) | a **standing approval** of **bounds** (rule 9): `operation`, `target`, `policy_version` exact; `input_version_refs`; one constraint for every parameter; `max_requests`; `valid_from`, `valid_until`; the reviewer was shown the bounds' digest (`shown_bounds_digest`); the person's signature is signatures 0.2.0's `person_standing_approval` (record, stage, `bounds_digest`, `shown_view_digest` when stated); for an approval of one specification, `person_approval` carries `shown_spec_digest`, `shown_view_digest` and `approved_spec_digest` |
| Bounds on one act | `each` (no single amount above), `max` (sum of amounts), `count`, and any of the last two inside a rolling window `per` (1 s to 366 days) | `exact`, `one_of`, `max_length`, `min`, `max` per parameter (rule 10): closed, nothing else; `max_requests`; one period |
| Count of acts | `count` (and `per`): counted by the verifier over the agent's receipts | `max_requests`, and for a one-off approval `request_limit` (rule 5): one request unless the approval states a `request_limit`; a standing approval "never a `request_limit`"; the count is "of requests recorded, not requests run" |
| Sum over acts | `max` (total of amounts, one unit per action), over all receipts of the permission and its delegations | no counterpart in the Standard's text read (the cumulative limit of draft-gilda is a separate document) |
| Rolling window | `per` | no counterpart: one period `valid_from`–`valid_until` |
| Conditions | `requires`: `countersignature` by the service, or `approval` (the principal's passkey over one exact action, ≤ 300 s before the receipt, once), optionally above an amount | the review and outcome of a specification (rules 3, 4): the approval is bound to the digest shown; a change needs a named person; no counterpart for a counterparty's countersignature |
| Cancellation / revocation | a passkey-signed **cancellation**; the first sound one is effective; later receipts and delegations are `after-cancellation`; an agent's **acknowledgement** states it was told; a time-stamped cancellation rule is only in [FORMAT] | `standing_revocation` (rule 12): "A request after it is not authorised. Its absence shows nothing"; the executor rechecks the authorisation before each attempt |
| "Within permission" | the third answer: yes only if no problem, every receipt and delegation compared, no finding; findings by receipt (10.2) | each request is reported inside, outside, or **not checked** (rules 11, 13); a verification report per attachment |
| Delegation | `passes` 1 to 10, narrowing only (`pass-wider`, `pass-not-allowed`), shared totals | no counterpart for delegation; "A change never starts from a standing approval" (rule 6) |
| Who signs the act | the **agent** signs each receipt (Ed25519 and ML-DSA-87); the service may countersign it | "no one signs a request" (signatures 0.2.0, on `person_standing_approval`): the attachment records the requests, attempts and observed results as the issuer's stages, sealed as a whole by the issuer |
| Exact bytes | content digest = SHA-256 of the decoded payload (11.2); records name each other by digest | specifications and bounds carried as exact bytes under their digest; the attachment's seal is an Ed25519 organisation seal over the attachment's bytes |
| Evidence of time | RFC 3161 time-stamps of heads and cancellations; "existed by", never "existed at" | anchoring 0.2.0 (independent timestamp and checkpoint) |
| Log | Merkle tree RFC 9162, signed heads with Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s | a signed attachment per decision record; no tree; Ed25519 |

**Gaps in the draft, seen from the Standard**: no decision record (no object for proposal, review, outcome and rationale,
as stages with their own ids); no digest of what the person was shown (`shown_view_digest`): 6 says "An approval shows that the
passkey approved the action, not that the principal read it"; no comparison of the specification shown, approved, requested
and attempted (the receipt is the agent's own statement of the action, matched to the approval's `action`, `amount`, `with`,
`details`; the service's countersignature "does not say whether the service accepted the action, completed it, or only let
it through", open issue 8; no observed result); no live recheck of the authority before an act (offline by design; the
executor is a named role and "does not specify how an executor decides", 1).

**Gaps in the Standard's standing approval, seen from the draft**: no post-quantum signature, no append-only tree or signed
tree head, no per-window counters or sums of amounts, no counterparty countersignature, no delegation, no passkey-signed
cancellation acknowledged by the agent. Each side's absence is the other's scope, not a defect of either.

## Running

```
python3 verify_from_text.py LOG.jsonl [--passkey THUMBPRINT] [--recorder KEYSET_DIGEST] [--tsa CERT_DIGEST] [--root R --size N] [--without ML-DSA-87]
python3 run_vectors.py --vectors <dir of test-vectors>   [--report out.json] [--check judge-v0.6.0.json] [--verbose]
python3 mutation_tests.py --vectors <dir of test-vectors>
../run.sh      # fetches both pins, checks their digests, replays, compares with the committed reports
```

Requirements: Python 3.11 or later, `cryptography >= 42`, `pqcrypto >= 1.0`.
