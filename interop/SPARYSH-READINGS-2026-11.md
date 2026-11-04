# Our reading of the findings of dps-reading-1 and dps-reading-1b — 5 November 2026

Andrii Sparysh's two outside readings of action binding 0.3.0 and signatures 0.2.0 (Assault-Consulting/Palimpsests,
`docs/interop/dps-reading-1` and `dps-reading-1b`, at the Standard's `c904372`, whose text for both extensions is the
same as at `007f8c9`) drafted findings for the Standard's repository and asked whether to file them. For each, how this
repository reads the same text: the same way, differently, or as silent. Nothing here answers for the Steward; the
issues, if filed, carry the reader's own reading.

| Finding | The text | Our reading |
|---|---|---|
| 1/F01, the seal's `subject` and `embedded_copy` (O06, O46) | signatures README: the verifier "does the reverse and compares; it also reports whether the copy agrees with the seal (`embedded_copy`)"; the seal is verified when `signature`, `subject` and `key_state` are | the same as dps-reading-1: read literally, a disagreeing copy fails `embedded_copy` and leaves `subject` verified; the cases fold the copy into `subject`; the text could say which |
| 1b/F-01, `authorisation_recheck` not checked (L02, L07) | action binding: "that each attempt follows an authorising recheck"; nothing on the dimension when there is no attempt | silent; our cases read it as the cases do: not checked when nothing was rechecked or attempted (our `emilia-pair` A1 relies on it), verified when a recorded recheck needs nothing more |
| 1b/F-02, the dimension of each binding check (L23, L42, L43) | one sentence lists every binding check | silent; we follow the reference report's dimensions and never assign a check ourselves |
| 1b/F-03, which media types a verifier reads (L40) | "Where it cannot read them, it reports them as not checked" | silent; our cases only write `application/json` |
| 1b/F-04, `embedded_copy` with no copy (O03, O05); `identity_reason` values | the report schema constrains `embedded_copy`'s values but not its absence; `identity_reason` appears in neither the README nor the report schema at `007f8c9` | the same: silent on the first; the values `not_held`, `not_read`, `none_read` are used by the cases and defined nowhere in the text |
| 1b/F-05, W07 not reproducible with `findings` | `cases.json` W07: "the reference report of A0 and A1 … is base_report"; the README asks for findings, not their wording | the same: a report written from the text can match statuses and values, not the findings' bytes |
| 1b/F-06, a referenced policy, a specification's own expiry, an approval's age (our N4 to N6) | no dimension reads them | the same; our approval-record reports them outside the extensions (`policy_checks_verified`), and issue #94 already asks the Steward whether a declared `valid_until` should be checked |

## The ambiguities both readings logged, as our cases meet them

- **"Each stage comes after the stages it names"** (list order, time, equal times): in every attachment our cases
  publish, each stage comes after each stage it names both in the list and in time, never at an equal time (in
  `agent-pass`, standing approvals interleave the list without breaking this), so our cases verify under each of the
  readings logged.
- **`later_supplemented` and `recorded_at`**: no case uses `later_supplemented`; every rationale is `contemporaneous`,
  recorded at its outcome's own time.
- **Requests under a standing approval and `request_limit`**: only `agent-pass` has them; it states no
  `request_limit` on its two standing approvals and requests each of its 35 specifications once, so whether those
  requests count toward a limit changes no verdict there.
