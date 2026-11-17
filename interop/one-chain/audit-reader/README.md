# One-chain evidence reader

Download [one-chain-reader.html](one-chain-reader.html) from GitHub using **Download raw file**, then open the saved file in a browser. It shows three synthetic dossiers:

| Dossier | What the reader shows |
| --- | --- |
| 120 / 120 EUR | The approved specification and the execution agree in the fixture. |
| 120 / 150 EUR | The published verdict rerun derives `not_as_approved`. The payment dispute packet verifies and reports a breach of the approved amount. |
| Approval piece missing | The original verdict is still visible. A1 is absent from the local dossier, so a local rerun remains open. |

Choose Decision, Execution, Verdict or Payment dispute to start at that contribution. The source panels contain pinned paths, SHA-256 digests, and downloads of the original bytes. The dossier's decision description can also be downloaded as JSON-LD.

## Build

From the cloned repository root, use Python 3.10 or later:

```sh
python3 interop/one-chain/audit-reader/build.py /tmp/one-chain-reader.html
```

Open the resulting file. The browser needs no server or network connection. The embedded examples are in English so the contributors can review the same interface. Downloaded JSON-LD names the existing public [decision context](https://w3id.org/decision/context.jsonld). A JSON-LD processor can use a local copy of that context when offline.

## Sources and scope

- The build reuses the two [published fixtures](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/e444fffb5a6488e9898061bc02c3c52ebdbf97b8/interop/one-chain/out) at e444fffb5a6488e9898061bc02c3c52ebdbf97b8. The incomplete dossier is a deliberately incomplete view of the first fixture.
- The decision panel uses existing terms from [`dec:`](https://github.com/Laurent-Lemonnier/decision) for the decision label, amount, outcome and record link. Values such as the oversight required by policy are outside this initial projection. The four original formats still supply their own rules and evidence.
- The Python build hashes the native files, matches the Wright evidence digests and checks that the published rerun report belongs to the displayed verdict. The page presents the published reports, including the receipt checks left out. It does not rerun the native cryptographic checks. To rerun those checks, follow the [one-chain instructions](../README.md).
- The HTML is a demonstration for the supplied public fixtures. It reads a compact JSON-LD decision description in the known context. General RDF graph import and arbitrary private case ingestion are outside this version.

Code follows the repository's Apache-2.0 licence. The `dec:` context and vocabulary are by Laurent Lemonnier under CC BY 4.0.
