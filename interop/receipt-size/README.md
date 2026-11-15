# receipt-size: a receipt that signs its tree size and leaf index, and one that does not

An RFC 9942 receipt of inclusion (RFC9162_SHA256) signs the Merkle root; the tree size and the leaf index it states sit
in the unprotected header (scitt@ietf.org, "RFC 9942 inclusion receipts: tree-size is not authenticated by the signed
root", 15 November 2026). Since 15 November 2026 the receipts of ts.isoluce.net repeat both values in the protected
header (labels -65537 and -65538, private use), so that the signature covers them. This folder holds one receipt of
each kind for the same statement, and a check that can be replayed offline.

Written with an AI assistant (Claude), reviewed and run by Laurent Lemonnier.

| File | What it is | SHA-256 |
|---|---|---|
| `vectors/receipt-signed-size.cose` | receipt of leaf 0 at tree size 38, with the two labels (`GET /entries/{id}`) | `a14c5f9ce5b664e948e2593eddfb42176076a0c1323c77ce0c51e1ff8036e1cf` |
| `vectors/receipt-plain.cose` | the same receipt without them (`?signed-size=0`) | `1d25f8209452e60b77a6908b3f23328e00368b048c48a70ff67abaee4e59e13d` |
| `vectors/checkpoint.cose` | the service's signed tree head at size 38 (`/checkpoint.cose`) | `f99e7491d0d58d43382e27e1a1749ceab5a860c080f64d4f66e626ed18ccb582` |
| `vectors/scitt-keys.cbor` | the service's public keys (`/.well-known/scitt-keys`) | `c9de0b5cc39eeb865bf3b50d6d6b9634d9bd1edfafdabb32f45985fbbcfe7ad9` |
| statement | `../one-chain/registration/action-binding-attachment-a1.signed-statement.cose` | as committed |
| `verify_receipt.py` | the service's receipt reader (RFC 9942 section 5.2.1, RFC 9162 section 2.1.3.2, RFC 9052 section 4.4), as deployed on 15 November 2026 | |

## The check (`check.py`, `results.json`)

For each receipt, every pair (tree size, leaf index) with a tree size from 1 to 128 replaces the pair of the unprotected
proof, 8,255 edited copies; path, protected header and signature stay as issued.

| Receipt | Read alone | Read with the signed tree head |
|---|---|---|
| plain (RFC 9942 as is) | the issued pair and **31 other pairs** are accepted (leaf 0 at every size from 33 to 64) | the issued pair only |
| with signed size and index | **the issued pair only** | the issued pair only |

```
python3 check.py        # Python 3, cbor2, cryptography; no network
python3 verify_receipt.py --statement ../one-chain/registration/action-binding-attachment-a1.signed-statement.cose \
    --receipt vectors/receipt-signed-size.cose --scitt-keys vectors/scitt-keys.cbor
```

## What it does not show

Nothing about append-only behaviour, equivocation or registration time. The labels are this service's own; a verifier
that does not know them ignores them and verifies as before (`../../READERS-AND-WITNESSES.md`).
