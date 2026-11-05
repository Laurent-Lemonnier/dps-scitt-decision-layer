# Supplied-source aggregation correspondence (local candidate)

This 2026-10-30 addition is separate from Laurent Lemonnier's saved 2026-10-29
replay. `judge-20261029.json`, `run-20261029.txt` and the historical README are
unchanged. This is a proposed addition; maintainer acceptance is not implied.

The rule is Section 5.4, pinned in `REVISION-01-PIN.json` of
`probityai/agent-evidence-vectors` v0.28.0, commit
`3a3c5b0007bbd870d775aee1c41098112b001df6`, passage `5.4-aggregation`, SHA-256
`223972b640f9aa204fe9e588580950f6ef9b219e8784c18c82cda9df7c9cf473`.
The selector is independently implemented here; it does not import the
reference package or its `aggregate_values` function.

- If any source value was never held, select `none` and the smallest `maxAge`
  among never-held values.
- Otherwise select the whole pair with the earliest `lastResult + maxAge`,
  breaking an expiry tie by earlier `lastResult`.
- Compare that pair to the named `evaluation.inputs` entry of a valid signed
  record. Also require the supplied `reportedAt` to denote the signed
  `decision.reportedAt`. Equivalent RFC 3339 offset spellings compare as instants.

The existing record outputs (`got`, `codes`, `agree`) retain their meaning.
The new per-row `aggregation.status` is `match`, `mismatch`, `invalid-input`,
`not-checked` (record not valid or unsupported container), or `not-applicable`
(no aggregation member). Summary fields `aggregationMembers` and
`aggregationMatched` count supplied cases and matches. Exit 0 requires both
the existing record checks and every supplied aggregation case to pass.
No supplied sources means no aggregation claim, not a successful check.

FR14 already supplies the two values; no new corpus member is needed. The
tests reverse their order, change only B's bound from 7200 to 3601 (both
values remain fresh, but B must win), and replace the local selector with
the historical independent minima as a negative control. The latter two
leave the signed FR14 bytes and its `valid` verdict unchanged, but fail the
separate correspondence check. Additional tests cover expiry ties, never-held
values, malformed source inputs, exact fractional seconds, and field binding.

Run from the repository root, using Python 3.12 and `cryptography>=42`:

```sh
python3 interop/gilda/gilda_verify_independent.py \
  --corpus /path/to/vectors-agent-audit-record --report /tmp/judge-new-local.json
GILDA_CORPUS=/path/to/vectors-agent-audit-record \
  python3 -m unittest discover -s interop/gilda -p 'test_gilda_aggregation.py' -v
```

The supplied source values are not authenticated by the record signature.
This check does not establish which values a producer actually used, their
completeness or authenticity, or full producer conformance. It does not add
anchor validation or replay the WEXP x AAR experiment. Local preparation and
tests were AI-assisted; no acceptance or maintainer endorsement is implied.
