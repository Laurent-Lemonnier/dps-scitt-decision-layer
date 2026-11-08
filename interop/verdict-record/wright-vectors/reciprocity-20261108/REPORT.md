# Darren Wright's checker run on our verdict records — 8 November 2026

Reciprocity of the run of 6 November (our `verdict.py` on his 37 vectors and 8 proposals). Here his own checker,
`vrcheck.py` at `diggertydog/verdict-record-test-vectors` 97b63b2, is run unchanged on four verdict records of
`dps-scitt-decision-layer` (main 896cc8e), each wrapped in his vector format (`record_b64`, the three evidence items by
their exact bytes, a policy in his member names: `judgement_kinds: ["check-run"]`, `formats` = the two format names the
record lists, `max_depth: 2`, an upper time bound).

| Vector | Record | His checker says |
|---|---|---|
| c18-verdict-positive | case 18, the auditor's verdict `executed_as_approved` over A1, A2 and the decision record | held; step 1 PASS; step 2 NOT RUN ("evidence[0]: checker cannot verify this format"); step 3 NOT RUN ("rule specification not held") |
| c18-verdict-stated-negative | case 18, the verdict stating `not_as_approved` over the 150/120 chain | same |
| c16-A-verdict-v1 | case 16, version 1 | same |
| c16-C-verdict-v2 | case 16, version 2 (supersedes version 1) | same |

What it shows: the four records pass his Section 2.1 parsing and Section 2.2 member checks (nothing refused: canonical
form, members, `supersedes` at version 2) and his step 1; his checker holds neither our two formats (the Standard's
action-binding attachment and record file) nor our rule `executed-as-approved:v1`, so it holds the records, as the text
says a checker must when it cannot verify a listed format or does not hold the rule. That is the mirror of what ours
does on his p08. What it does not show: agreement on steps 2 and 3, which would need his checker to hold our format
rules and our rule — the registration question his Appendix B raises.

One reading difference seen: on step 2 his checker stops at the first item it cannot verify (`evidence[0]`); ours reports
every item. Same state, same step result.

Files: the four vectors, `vrcheck-results.txt` (his output verbatim). His code was run, not read for any rule of ours.
