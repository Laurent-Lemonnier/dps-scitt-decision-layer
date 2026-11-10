# WEXP Core-02: an outside reproduction

Mikhail Sergeev entered "WEXP appraisal Core-02: two appraisers, specification-derived tests, and a SCITT boundary
experiment" in the IETF 127 Hackathon and asked, on 9 November 2026, for an outside reproduction of its two
comparisons. This folder holds no code: the workflow `.github/workflows/wexp-reproduce.yml` follows his REPRODUCE.md
files literally, on a fresh GitHub runner, at the commits he pinned:

- wexp-check a2fd1ffd (second appraiser), wexp-ref 56289024 (reference appraiser), wexp-vectors edd67056 (sets 001
  and 002): unit tests, then the corpus comparison with `--baseline comparison.json`.
- wexp-interop a45c88e9, experiment scitt-receipt-boundary-001, package pkg-001: the read-only collection checks, then a
  repeated appraisal with wexp-ref 56289024 and wexp-check 25ec856e. The optional SCITT registration is not repeated.

The run log of the workflow is the record: revisions, commands, Python version and observed output. It is reported
to the author as it is, whether it agrees or differs. Nothing here was changed in his code or data.
