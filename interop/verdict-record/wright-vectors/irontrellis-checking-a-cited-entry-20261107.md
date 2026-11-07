<!-- Source: https://github.com/zerohourzulu/irontrellis/issues/13#issuecomment-6701158070
     author: zerohourzulu ; created_at: 2026-11-07T02:41:10Z ; updated_at: 2026-11-07T02:41:10Z
     fetched: 2026-11-07T08:34:47Z via the GitHub API (repos/zerohourzulu/irontrellis/issues/13/comments, cc-web); body saved verbatim below -->

Proposed text for draft -01, new section in "Export, verification and freshness": what a checker does with one cited decision. Review welcome: run it against your checker, and log anything the text leaves open (one issue per ambiguity, using the Spec ambiguity form, is easiest).

For the v2-g3 suite, the suite index is [conformance/v2-g3/INDEX.sha256](https://github.com/zerohourzulu/irontrellis/blob/983a508c499735e4e47034a9795c167181eeb86d/conformance/v2-g3/INDEX.sha256), SHA-256 `4c745f10e00564eb7e48af35e4e592ae6ebed003c6b16affa5556b42f338a68b`; its session challenge profile is `g3` (named as `challengeProfile` in that suite's MANIFEST.json).

---
### Checking a cited entry

A relying party is often handed one decision rather than a full export: a verdict record, a receipt or an audit finding that cites a position in a history and states a result. This section says what a checker does with such a citation, so that two independent checkers given the same citation reach the same outcome.

#### The citation

A citation MUST bind, by value or by SHA-256 digest of canonical bytes:

- **the cited head**: hash, position and timestamp ("The chain and the head");
- **the domain and policy identifiers** the decision was made under;
- **the evaluation time** ("Replay and determinism");
- **the replay identifier** ("The replay identifier", below);
- **the request**, by the digest of its canonical encoding;
- **the cited result**: every field of the decision the replay produces, in versioned canonical bytes.

A citation missing any of these, or with one malformed, is an invalid citation. A checker MUST NOT fill a gap from defaults or from the presented history.

The chain hashes canonical record encodings, not the bytes of a file. A digest of a history file pins one serialization and MAY be added so a checker can fetch the bytes; it never replaces the cited head.

#### Where the head comes from

Where an encoding takes owner keys from the history's own genesis, as the example encoding does (appendix "Example encoding"), the cited head is the checker's only cryptographic anchor, and its source decides what a check means.

A head is **anchored** when the checker obtained it, or verified it, from a source its own policy accepts: an owner head attestation under a key the checker trusts independently of the presented history, a witness it accepts, or a public chain anchor it accepts ("Rollback and freshness"). An owner key read from the presented genesis does not anchor anything: a presenter can fabricate a self-consistent genesis, history, head and result.

Any other head is **unanchored**. Every outcome below MUST be reported together with its anchoring (ANCHORED or UNANCHORED), the head and its source; the two MUST NOT be separable in the report. An UNANCHORED outcome shows internal consistency only.

An anchored head can still be old. The checker MUST report the head's as-of time and the freshness evidence it holds. An outcome describes the cited prefix; it MUST NOT be used to authorize current or continuing activity unless the relying party's policy accepts that freshness, or the checker also performs the later-records check ("Later records", below).

#### Procedure

1. **Validate the citation.** Every binding in "The citation", above is present and well formed, and the replay identifier is one the checker's policy accepts. Otherwise the outcome is INVALID CITATION.
2. **Check the context.** The domain and policy identifiers in the citation MUST equal those in the presented genesis. A mismatch is INVALID CITATION, not a replayed DENY.
3. **Fix the prefix.** Replay exactly the records at positions 0 through p, the cited position, and no record after p. If the presented records do not reach p, or the record at p does not match the cited head in hash, position and timestamp, the outcome is INDETERMINATE with a code naming the presenter's evidence as the cause. Missing or malformed presented evidence is never read as a DENY.
4. **Replay.** Rebuild state from the genesis under the replay identifier, and re-derive the decision for the cited request at the cited evaluation time ("The decision procedure").
5. **Compare** every field of the re-derived decision with the cited result, as canonical bytes: at least decision, code, ordered failure list, scope assurance, controlling authorities and budget fields.
6. **Report** one outcome, with its anchoring, head, source and as-of time:

| Outcome | Meaning |
|---|---|
| REPRODUCED | The replay gives the cited result, field for field. |
| NOT REPRODUCED | The replay gives a different result. The checker reports both. |
| INDETERMINATE | The presented records cannot support the replay; the code says why. |
| NOT RUN | The citation is valid and its replay identifier is accepted, but this checker does not implement it. It names the identifier. |
| INVALID CITATION | A binding is missing, malformed, not accepted, or contradicts the presented genesis. |

#### The replay identifier

An interface version alone does not pin behavior. Its meaning can change between releases while the string stays the same, for example in the order of failures or the budget procedure. And an encoding setting outside the request can change the verdict: in the example encoding, which fields a session signature covers.

A replay identifier MUST name:

- the operation version;
- every encoding setting that changes verdicts (in the example encoding, the session challenge profile);
- a **behavior pin**: the SHA-256 digest of a published conformance suite's index.

The **suite index** is a UTF-8 text file, one line per file of the suite, each line the file's lowercase hexadecimal SHA-256 digest, two spaces and its path, ending in a line feed. Paths are relative to the suite's root directory, use "/" as separator, and contain no "." or ".." segments; entries are unique and sorted by the bytes of the path. The index lists every file in the suite's directory, excludes itself, and lists no symbolic links; that directory MUST hold everything needed to interpret the suite: the cases, their expected outputs, the histories they use and any generator or notes they rely on. A test harness used to run the suite is not part of it. An index MUST be published before any citation names its digest.

A checker MUST use exactly the named identifier: no negotiation, no fallback to a nearby version. A suite digest pins what was tested; it does not show that a checker passed it. A checker claiming an identifier MUST pass the suite it pins.

A second implementation can claim a suite digest; it cannot claim another implementation's source commit. A citation MAY add a source commit for retrieval.

#### Later records

A checker MAY also replay the full current history to report what later records say about the cited decision, for example that authority it relied on was later shown to have ended (see the record that a root grantor's standing ended, also proposed for -01). That is a separate report with its own result, and it MUST NOT change the outcome above. Where an outcome is used to authorize current or continuing activity, this check, or freshness evidence the relying party's policy accepts, is REQUIRED, and the current head it uses MUST itself be anchored ("Where the head comes from", above) and fresh under that same policy. A presenter's claim that a history is complete or current is not such evidence, and neither is a head's own timestamp unless the anchor vouches for the time.

