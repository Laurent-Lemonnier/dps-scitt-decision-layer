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

| Reader | Implementation and commit | Records read | Result | Reported |
|---|---|---|---|---|
| none published yet | | | | |

As of 14 November 2026 every check of the decision record in this repository is the author's or the Decision
Provenance Standard's own reference check. Readers have been offered for this weekend and after; each will be listed
here when its result is published.

## Witnesses of ts.isoluce.net

| Witness | Operated by | What it does | Since | Independent of the log's operator? |
|---|---|---|---|---|
| [temoin/](temoin/README.md), GitHub Actions, hourly | the author | reads each signed log head, checks its signature under a pinned key and its consistency with the last head it saw, records it on the branch `temoin`, cosigned by Sigstore under the workflow's identity | 13 November 2026 | No. Other infrastructure and another signing identity, same operator |
| OpenTimestamps | public calendars, the Bitcoin chain | each log head is timestamped within the hour | 10 November 2026 | Yes, for time only: it shows the head existed before a block, nothing about what it holds |

No other party watches the log yet.

## Other logs holding the same records

| Log | Operated by | Statements | Receipts checked with |
|---|---|---|---|
| none yet | | | |

The four records of the one-chain case are ready to register, as Signed Statements with the issuer's public key:
[interop/one-chain/registration/](interop/one-chain/registration/README.md).

## To be listed as a reader

1. Pick what to read: the decision record of draft-lemonnier-scitt-decision-provenance-01 and the references it
   pins, or any case under `interop/` (the one-chain case is the shortest path; `examples/` has the two worked
   examples of the draft).
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
