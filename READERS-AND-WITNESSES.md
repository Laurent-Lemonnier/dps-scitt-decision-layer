# Readers and witnesses

Who, other than the author, has checked the records of this repository, and who holds or watches the log they are
registered on. Started on 14 November 2026, during the IETF 127 Hackathon. It lists what is published and can be
rerun; what has only been said in a mail is not listed.

Two roles, and they are not judged the same way.

- A **reader** runs a verifier on the records. A reader's result is worth what its rerun is worth: it is listed with
  the implementation and the commit that produced it, so that anyone can run it again. Who the reader is matters less.
- A **witness** holds the records on a log of its own, or watches this repository's log and says what it saw. A
  witness is worth what its independence is worth: it is listed with who operates it.

The other direction, this repository's verifiers run on other authors' drafts and vectors, is in
[interop/README.md](interop/README.md).

## Readers

| Reader | Implementation and commit | Records read | Published result and limits |
|---|---|---|---|
| Andrii Sparysh | [Palimpsests, dps-reading-1 and dps-reading-1b](https://github.com/Assault-Consulting/Palimpsests/tree/02537ba8ad2f8b2236423d36e4c527a1fb252750/docs/interop) | Standard extensions at c9043722384f784ae578ae0a64400be8a3864259; this repository's examples and approval-record inputs at fdc5f6352795fc713309cd25ac2669d22840e0cc | Published per-case readings of action binding and signatures. The first reading saw the negative expectations before reconstruction; the second documents a separate reading boundary. Core-schema validation and reconstructed inputs have stated limits. These are not complete validations of draft-lemonnier-scitt-decision-provenance-01. |
| Andrii Sparysh, anchoring and OTS | [Palimpsests, dps-reading-2 and dps-reading-2b](https://github.com/Assault-Consulting/Palimpsests/tree/02537ba8ad2f8b2236423d36e4c527a1fb252750/docs/interop) | The anchoring extension and four umarise proof/artifact pairs from this repository at 549b50afb146c172d92177063b4e3d3d3e17beab | Published replay and negative-vector results, with explicit limits on independent chain validation. These are not timestamps of ts.isoluce.net checkpoints. |
| Darren Wright | [verdict-record-test-vectors, a867a23bbaf88df942f6c09f7e002b7ddda5814d](https://github.com/diggertydog/verdict-record-test-vectors/tree/a867a23bbaf88df942f6c09f7e002b7ddda5814d/interop/one-chain) | one-chain at f0d766a1ca8422c64ad792fad7876db2737a7f72 | Published report: 48 verdict records agree on state, steps and re-run result. The DPS checks use the Standard's reference implementation; this is an outside run of the composed case, not an independent implementation of all DPS checks. |

These entries describe published results with their implementation and input commits. A new verifier written directly
from draft-lemonnier-scitt-decision-provenance-01 and its pinned references would complement these partial readings.

## Witnesses of ts.isoluce.net

| Witness | Operated by | What it does | Since | Independent of the log's operator? |
|---|---|---|---|---|
| [temoin/](temoin/README.md), GitHub Actions, scheduled hourly | the author | samples the current signed head, verifies its signature and consistency with previously recorded heads, and records newly observed heads on branch `temoin`; Sigstore bundles are published when cosigning succeeds | first published observation: 13 November 2026 | No. Different infrastructure and signing identity, same operator |
| OpenTimestamps proofs of checkpoints | submitted by the log's operator to public calendars | the checkpoints submitted and their proofs are listed at https://registre.isoluce.net/ancres/ ; a proof is complete only once it carries a Bitcoin attestation | see the dates of the files listed | For time only, and only for a completed proof that the reader verifies; nothing about what the head holds |

A timestamp entry requires the exact checkpoint bytes, a completed proof and the verification inputs. No hourly
coverage is claimed here. No independent watcher is listed on this page yet.

## Other logs holding the same records

| Log | Operated by | Statements | Receipts checked with |
|---|---|---|---|
| none yet | | | |

The four records of the one-chain case are ready to register, as Signed Statements with the issuer's public key:
[interop/one-chain/registration/](interop/one-chain/registration/README.md).

Before registering anything real, a test instance of a service can be tried with a baseline statement and fourteen
variations, each testing one registration condition: [interop/registration-vectors/](interop/registration-vectors/README.md). They show what a service
admits and which bytes it puts in its log.

## To be listed as a reader

1. Pick what to read: the decision record of draft-lemonnier-scitt-decision-provenance-01 and the references it
   pins, or any case under `interop/`. The draft's worked examples are in `examples/release-decision/` and `demo/`;
   the signed approval of its Section 8 is in `interop/aer1-decision/`; the larger composed case is in
   `interop/one-chain/`.
2. Write your verifier from the text, or bring one you have. Do not start from this repository's code if the point
   is a second reading: where two readings differ, the text is at fault until shown otherwise.
3. Run it on the records at a commit of this repository, and say which.
4. Publish the implementation and its commit, and open an issue here with: the name to show, the repository and
   commit of the implementation, the commit of the records, and the result case by case, differences first.

A result that disagrees is listed like one that agrees.

## To be listed as a witness or as a second log

- Second log: register the statements of `interop/one-chain/registration/`, then open an issue with the entry
  identifiers, where the receipts can be fetched, which bytes your leaf covers and which algorithm your receipts carry.
  A refusal by your registration policy is a result too; say what was refused and why.
- Witness: read the signed head at `https://ts.isoluce.net/checkpoint.cose`, check it under the key in
  `temoin/service-public.pem`, and publish what you saw (size, root, time) somewhere you control. `temoin/temoin.py`
  shows one way; a witness of your own writing is worth more.

In both cases: say who operates it, and whether you have any tie to the author or to the log's operator.
