# One-chain evidence reader

Download [one-chain-reader.html](one-chain-reader.html) using GitHub's **Download raw file** button and open it locally. Choose a dossier and start from Decision, Execution, Verdict or Payment dispute.

| Dossier | What the reader shows |
| --- | --- |
| 120 / 120 EUR | Wright's rule derives `executed_as_approved`. The native composition checks pass. |
| 120 / 150 EUR | Wright's rule derives `not_as_approved` and releases the verdict stating that result. The dispute packet verifies and reports a breach of the approved amount. |
| Approval piece missing | Wright leaves the verdict `held`, with the rule `NOT RUN`. The dispute packet checker identifies the unresolved approval anchor. |

The source panels offer pinned paths for the public fixtures, SHA-256 digests and downloads of the original bytes. The decision description is available as JSON-LD using the existing [decision context](https://w3id.org/decision/context.jsonld).

## Open existing one-chain output

The reader takes the files produced by [one-chain](../README.md#running). From the repository root:

```sh
python3 interop/one-chain/audit-reader/build.py --interop-out interop/one-chain/out /tmp/one-chain-reader.html
```

Use `--case-dir interop/one-chain/out/stated-negative` instead of `--interop-out` to open one dossier. This mode reads the supplied `summary.json` and labels it as a supplied report. It checks that the report names the same verdict bytes and locates the cited files by digest. The Python build accepts the one-chain fixture layout. The resulting HTML works offline.

## Replay the native checks

Use Python 3.12. Set `DPS_STANDARD` to a clean Git checkout of the [DPS Standard](https://github.com/decision-provenance-standard/standard) at the existing [one-chain pin](../../aqta/approval-record/DPS_STANDARD_COMMIT), `007f8c99ec910564bac1c508b76c8ce8391fa11e`. Install its dependencies in an isolated environment:

```sh
python -m pip install -r "$DPS_STANDARD/tools/requirements.txt" \
  -r "$DPS_STANDARD/extensions/action-binding/tests/requirements.txt" cbor2
PYTHONDONTWRITEBYTECODE=1 python interop/one-chain/audit-reader/build.py \
  --replay --interop-out interop/one-chain/out /tmp/one-chain-reader.html
```

The checked-in HTML was generated with `--replay` against the bundled examples. Omitting the source option uses those bundled fixtures. The build invokes the existing execution, DPS, verdict and dispute checkers on the held bytes, plus the native K1–K12 checks where the relevant pieces are held. It embeds a new report and leaves the input directory untouched. A supplied `summary.json` is not an input to replay. The third case intentionally leaves A1 out of the bytes held by the replay.

## What the prototype covers

The replay uses the fixture trust policy, public test keys and the example's time assumptions. Those inputs are for the synthetic one-chain scenarios only. The Wright check is the implementation from the hackathon written against Wright's text. The reader presents its result alongside the other three formats. A production integration supplies its own authorised dossiers and reports under its own trust policy. The browser never calls a service to send the dossier.

The decision panel projects the recorded decision label, amount and outcome into [`dec:`](https://github.com/Laurent-Lemonnier/decision). The rest of the evidence uses the source formats. Code follows the repository's Apache-2.0 licence. The `dec:` context and vocabulary are by Laurent Lemonnier under CC BY 4.0.
