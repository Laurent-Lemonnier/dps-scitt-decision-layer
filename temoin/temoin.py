#!/usr/bin/env python3
"""temoin.py: an external witness of the transparency log https://ts.isoluce.net, written from the text of RFC 9162
section 2.1 (Merkle tree hash, consistency proofs), RFC 9052 section 4.4 (COSE_Sign1 signature) and RFC 9679 (COSE
Key Thumbprint). It shares no code with the service and pins the service's public key.

  temoin.py [--tetes tetes.jsonl] [--base-url URL] [--cle service-public.pem] [--preuves DIR] [--rejouer]

One run:
  1. reads GET /checkpoint.cose and GET /checkpoint.json; verifies the signed tree head (a tagged COSE_Sign1 whose
     attached payload is bstr .cbor [tree_size, root]) with the PINNED key, and that the JSON says the same thing;
  2. reads the last head seen in tetes.jsonl (one JSON object per line), then
       - no head yet: recomputes the root from every leaf_hash of GET /entries and compares it with the signed root;
       - the log grew: verifies GET /consistency?old=&new= as RFC 9162 section 2.1.4.2 says, between the root kept in
         the file (never the one the service returns) and the newly signed root;
       - same size: the roots must be identical (otherwise FORK);
       - smaller size: the log shrank (failure);
  3. appends one line (size, root, issued_at, sha256 of the checkpoint COSE, size the proof started from, witnessed_at,
     GITHUB_RUN_ID when present) only when the head is new and every check held. Nothing is written on failure.

--rejouer checks every head recorded in the file against the head the service signs now (consistency proof, or root
equality at the same size) and writes nothing: anyone can replay the witness's history this way.

Exit codes: 0 verified; 1 service unreachable, malformed answer or unusable file; 2 signed head invalid (signature,
key, header, or JSON that disagrees with the COSE); 3 consistency proof invalid; 4 root divergence (FORK, or a full
recomputation that does not give the signed root); 5 the log shrank.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
SERVICE = "https://ts.isoluce.net"
PINNED_KID = "g3JYRtHgACp0biv12cMhoDDEGxDjRRDIv9UoWb0kjDA"   # RFC 9679 thumbprint of service-public.pem
USER_AGENT = "temoin-ts/0.1 (external witness)"

# COSE header labels (IANA "COSE Header Parameters") and values this witness accepts
ALG, KID, CWT, VDS = 1, 4, 15, 395
ED25519, EDDSA = -19, -8                       # RFC 9864 section 3.1; RFC 9053 section 2.2 (deprecated)
RFC9162_SHA256 = 1                             # RFC 9942 section 5.1
CWT_ISS, CWT_SUB, CWT_IAT = 1, 2, 6            # RFC 8392 section 3.1

OK, E_NET, E_SIG, E_CONSIST, E_FORK, E_SHRINK = 0, 1, 2, 3, 4, 5


class Echec(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------ RFC 9162 section 2.1, SHA-256

def sha256(b):
    return hashlib.sha256(b).digest()


def mth(leaves):
    """RFC 9162 section 2.1.1 over leaf hashes: MTH({}) = HASH(''), MTH({d0}) = leaf, else
    HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])) with k the largest power of two smaller than n."""
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def verify_consistency(first, second, first_hash, second_hash, path):
    """RFC 9162 section 2.1.4.2, step by step. Returns None when the proof holds, else the reason."""
    if not 0 < first < second:
        return f"tailles {first} -> {second} : il faut 0 < ancienne < nouvelle"
    if not path:                                                          # step 1
        return "preuve vide (etape 1)"
    if first & (first - 1) == 0:                                          # step 2: first is an exact power of 2
        path = [first_hash] + list(path)
    fn, sn = first - 1, second - 1                                        # step 3
    while fn & 1:                                                         # step 4
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]                                                     # step 5
    for c in path[1:]:                                                    # step 6
        if sn == 0:                                                       # 6.a
            return "preuve plus longue que l'arbre (etape 6.a)"
        if fn & 1 or fn == sn:                                            # 6.b
            fr = sha256(b"\x01" + c + fr)                                 # 6.b.i
            sr = sha256(b"\x01" + c + sr)
            if not fn & 1:                                                # 6.b.ii
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = sha256(b"\x01" + sr + c)
        fn >>= 1                                                          # 6.c
        sn >>= 1
    if sn != 0:                                                           # step 7
        return "preuve plus courte que l'arbre (etape 7, sn != 0)"
    if fr != first_hash:
        return "la preuve ne redonne pas l'ancienne racine (celle du fichier)"
    if sr != second_hash:
        return "la preuve ne redonne pas la nouvelle racine signee"
    return None


# ------------------------------------------------------------------ the pinned key and the signed tree head

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def load_pinned_key(path, expect_kid):
    pub = serialization.load_pem_public_key(open(path, "rb").read())
    if not isinstance(pub, Ed25519PublicKey):
        raise Echec(E_SIG, f"{path} n'est pas une cle Ed25519")
    x = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # RFC 9679 sections 3 and 4.1: SHA-256 of the deterministic CBOR of {kty: OKP, crv: Ed25519, x}
    kid = b64url(sha256(cbor2.dumps({1: 1, -1: 6, -2: x}, canonical=True)))
    if expect_kid and kid != expect_kid:
        raise Echec(E_SIG, f"la cle {path} a le kid {kid}, l'epingle attendue est {expect_kid}")
    return pub, kid


def rfc3339(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_checkpoint(raw, pub, kid, issuer):
    """The service's signed tree head: tag 18 over [protected, unprotected, payload, signature] (RFC 9052 section
    4.2); protected header alg -19 (or -8), kid = the pinned kid, vds 395 = 1, CWT claims iss = sub = the service,
    iat; payload attached = bstr .cbor [tree_size, root]; signature over Sig_structure (RFC 9052 section 4.4)."""
    try:
        item = cbor2.loads(raw)
    except Exception as exc:
        raise Echec(E_SIG, f"checkpoint.cose n'est pas du CBOR : {exc}")
    if not isinstance(item, cbor2.CBORTag) or item.tag != 18:
        raise Echec(E_SIG, "checkpoint.cose n'est pas un COSE_Sign1 etiquete 18")
    arr = list(item.value) if isinstance(item.value, (list, tuple)) else None
    if not arr or len(arr) != 4:
        raise Echec(E_SIG, "COSE_Sign1 : un tableau de quatre elements est attendu")
    protected, _unprotected, payload, signature = arr
    if not (isinstance(protected, bytes) and isinstance(payload, bytes) and isinstance(signature, bytes)):
        raise Echec(E_SIG, "COSE_Sign1 : en-tete protege, charge utile attachee et signature doivent etre des bstr")
    try:
        pmap = cbor2.loads(protected)
    except Exception as exc:
        raise Echec(E_SIG, f"en-tete protege illisible : {exc}")
    if not hasattr(pmap, "get"):
        raise Echec(E_SIG, "en-tete protege : une table est attendue")
    if pmap.get(ALG) not in (ED25519, EDDSA):
        raise Echec(E_SIG, f"alg {pmap.get(ALG)!r} : -19 (Ed25519) attendu")
    hkid = pmap.get(KID)
    hkid = hkid.decode("utf-8", "replace") if isinstance(hkid, bytes) else hkid
    if hkid != kid:
        raise Echec(E_SIG, f"kid {hkid!r} dans la tete signee, la cle epinglee est {kid}")
    if pmap.get(VDS) != RFC9162_SHA256:
        raise Echec(E_SIG, f"vds {pmap.get(VDS)!r} : RFC9162_SHA256 (1) attendu")
    claims = pmap.get(CWT)
    if not hasattr(claims, "get") or not isinstance(claims.get(CWT_IAT), int):
        raise Echec(E_SIG, "revendications CWT (15) absentes ou sans iat")
    if claims.get(CWT_ISS) != issuer or claims.get(CWT_SUB) != issuer:
        raise Echec(E_SIG, f"iss/sub {claims.get(CWT_ISS)!r}/{claims.get(CWT_SUB)!r} : {issuer} attendu")
    tbs = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    try:
        pub.verify(signature, tbs)
    except InvalidSignature:
        raise Echec(E_SIG, "SIGNATURE INVALIDE : la tete n'est pas signee par la cle epinglee")
    try:
        body = cbor2.loads(payload)
        size, root = body
    except Exception:
        raise Echec(E_SIG, "charge utile signee : [tree_size, root] attendu")
    if not (isinstance(size, int) and size >= 0 and isinstance(root, bytes) and len(root) == 32):
        raise Echec(E_SIG, "charge utile signee : [tree_size >= 0, racine de 32 octets] attendu")
    return {"tree_size": size, "root": root, "issued_at": rfc3339(claims[CWT_IAT])}


# ------------------------------------------------------------------ HTTP (GET only)

def get(base, path, tries=4):
    url = base.rstrip("/") + path
    last = None
    for i in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code < 500 and exc.code != 429:
                break
        except (urllib.error.URLError, OSError) as exc:
            last = str(exc)
        time.sleep(2 * (i + 1))
    raise Echec(E_NET, f"service injoignable ou en erreur : GET {url} : {last}")


def get_json(base, path):
    try:
        return json.loads(get(base, path))
    except ValueError as exc:
        raise Echec(E_NET, f"GET {path} : JSON illisible ({exc})")


def unhex32(h, what):
    try:
        b = bytes.fromhex(h)
    except (TypeError, ValueError):
        b = b""
    if len(b) != 32:
        raise Echec(E_NET, f"{what} : 32 octets en hexadecimal attendus")
    return b


# ------------------------------------------------------------------ the witness

def signed_head(args, pub, kid, evidence):
    """The signed head, read twice (COSE, then JSON); both must describe the same checkpoint. If a new checkpoint
    was issued between the two reads, read again."""
    for _ in range(3):
        raw = get(args.base_url, "/checkpoint.cose")
        js = get_json(args.base_url, "/checkpoint.json")
        evidence["checkpoint.cose"] = raw
        evidence["checkpoint.json"] = json.dumps(js, indent=1).encode()
        head = verify_checkpoint(raw, pub, kid, args.emetteur)
        if js.get("checkpoint_cose_b64") and base64.b64decode(js["checkpoint_cose_b64"]) != raw:
            continue                                     # a newer checkpoint in between: read both again
        if (js.get("tree_size"), js.get("root_hash_hex"), js.get("issued_at"), js.get("kid")) != \
                (head["tree_size"], head["root"].hex(), head["issued_at"], kid):
            raise Echec(E_SIG, "checkpoint.json ne dit pas la meme chose que la tete COSE signee")
        head["cose_sha256"] = hashlib.sha256(raw).hexdigest()
        return head
    raise Echec(E_SIG, "checkpoint.json et checkpoint.cose divergent apres trois lectures")


def all_leaves(args, size, evidence):
    leaves, start = [], 0
    while start < size:
        page = get_json(args.base_url, f"/entries?start={start}&count={min(1000, size - start)}")
        rows = page.get("entries") or []
        if not rows:
            raise Echec(E_NET, f"/entries?start={start} : aucune entree alors que la tete signee en compte {size}")
        for r in rows:
            if len(leaves) == size:
                break
            if r.get("leaf_index") != len(leaves):
                raise Echec(E_NET, f"/entries : leaf_index {r.get('leaf_index')} a la place {len(leaves)}")
            leaves.append(unhex32(r.get("leaf_hash_hex"), f"leaf_hash de la feuille {len(leaves)}"))
        start = len(leaves)
    evidence["entries.json"] = json.dumps([h.hex() for h in leaves], indent=1).encode()
    return leaves


def consistency(args, old_size, old_root, new_size, new_root, evidence, tag=""):
    js = get_json(args.base_url, f"/consistency?old={old_size}&new={new_size}")
    evidence[f"consistency{tag}.json"] = json.dumps(js, indent=1).encode()
    if js.get("tree_size_1") != old_size or js.get("tree_size_2") != new_size:
        raise Echec(E_CONSIST, f"/consistency repond pour {js.get('tree_size_1')} -> {js.get('tree_size_2')}, "
                               f"{old_size} -> {new_size} demande")
    path = [unhex32(h, "consistency_path") for h in js.get("consistency_path") or []]
    why = verify_consistency(old_size, new_size, old_root, new_root, path)
    if why:
        raise Echec(E_CONSIST, f"COHERENCE INVALIDE {old_size} -> {new_size} : {why}")
    return len(path)


def read_heads(path):
    heads = []
    if not os.path.exists(path):
        return heads
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                h = json.loads(line)
                h["root"] = unhex32(h["root_hash_hex"], "root_hash_hex")
                if not isinstance(h["tree_size"], int) or h["tree_size"] < 0:
                    raise ValueError
            except (ValueError, KeyError, TypeError, Echec):
                raise Echec(E_NET, f"{path} ligne {n} illisible")
            heads.append(h)
    return heads


def compare(args, seen, head, evidence, tag=""):
    """Checks the signed head against one head seen before. Returns the size the proof started from."""
    old, new = seen["tree_size"], head["tree_size"]
    if new < old:
        raise Echec(E_SHRINK, f"LE JOURNAL A RETRECI : {old} entrees vues, la tete signee n'en annonce que {new}")
    if new == old:
        if head["root"] != seen["root"]:
            raise Echec(E_FORK, f"FORK : meme taille {new}, racine signee {head['root'].hex()} "
                                f"au lieu de {seen['root'].hex()}")
        return old
    if old == 0:                                         # every tree extends the empty one; recompute instead
        return None
    consistency(args, old, seen["root"], new, head["root"], evidence, tag)
    return old


def full_recompute(args, head, evidence):
    leaves = all_leaves(args, head["tree_size"], evidence)
    root = mth(leaves)
    if root != head["root"]:
        raise Echec(E_FORK, f"RACINE DIVERGENTE : {len(leaves)} feuilles donnent {root.hex()}, "
                            f"la tete signee dit {head['root'].hex()}")
    return len(leaves)


def run(args):
    evidence = {}
    try:
        pub, kid = load_pinned_key(args.cle, args.kid)
        head = signed_head(args, pub, kid, evidence)
        heads = read_heads(args.tetes)
        print(f"tete signee : taille {head['tree_size']}, racine {head['root'].hex()}, emise {head['issued_at']}, "
              f"signature verifiee (kid {kid})")
        if args.rejouer:
            if not heads:
                raise Echec(E_NET, f"{args.tetes} : aucune tete a rejouer")
            for i, seen in enumerate(heads):
                frm = compare(args, seen, head, evidence, tag=f"-{i}")
                if frm is None:
                    full_recompute(args, head, evidence)
                print(f"  ligne {i + 1} : taille {seen['tree_size']} ({seen.get('witnessed_at', '?')}) "
                      f"coherente avec la tete actuelle")
            print(f"REJEU OK : {len(heads)} tete(s) du fichier sont des prefixes du journal actuel")
            return OK
        if not heads:
            n = full_recompute(args, head, evidence)
            proof_from, method = 0, "full_recompute"
            print(f"premiere execution : racine recalculee depuis {n} feuilles, identique a la racine signee")
        else:
            seen = heads[-1]
            frm = compare(args, seen, head, evidence)
            if frm is None:
                n = full_recompute(args, head, evidence)
                proof_from, method = 0, "full_recompute"
                print(f"racine recalculee depuis {n} feuilles, identique a la racine signee")
            elif head["tree_size"] == seen["tree_size"]:
                print(f"taille inchangee ({head['tree_size']}), racine identique : aucune ligne ajoutee")
                return OK
            else:
                proof_from, method = frm, "consistency"
                print(f"preuve de coherence RFC 9162 {frm} -> {head['tree_size']} verifiee "
                      f"(ancienne racine prise dans {os.path.basename(args.tetes)})")
        line = {"tree_size": head["tree_size"], "root_hash_hex": head["root"].hex(), "issued_at": head["issued_at"],
                "checkpoint_cose_sha256": head["cose_sha256"], "proof_from_size": proof_from, "method": method,
                "witnessed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if os.environ.get("GITHUB_RUN_ID"):
            line["github_run_id"] = os.environ["GITHUB_RUN_ID"]
        os.makedirs(os.path.dirname(os.path.abspath(args.tetes)), exist_ok=True)
        with open(args.tetes, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, separators=(",", ":")) + "\n")
        print(f"ligne ajoutee a {args.tetes}")
        return OK
    except Echec as exc:
        print(f"ECHEC (code {exc.code}) : {exc}", file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=temoin ts.isoluce.net::{exc}")
        if args.preuves:
            os.makedirs(args.preuves, exist_ok=True)
            for name, data in evidence.items():
                with open(os.path.join(args.preuves, name), "wb") as f:
                    f.write(data)
            with open(os.path.join(args.preuves, "verdict.json"), "w") as f:
                json.dump({"code": exc.code, "message": str(exc), "service": args.base_url}, f, indent=1)
        return exc.code


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tetes", default=os.path.join(HERE, "tetes.jsonl"), help="registre des tetes vues (JSON lines)")
    ap.add_argument("--base-url", default=SERVICE)
    ap.add_argument("--emetteur", default=SERVICE, help="iss/sub attendus dans la tete signee")
    ap.add_argument("--cle", default=os.path.join(HERE, "service-public.pem"), help="cle publique epinglee (PEM)")
    ap.add_argument("--kid", default=PINNED_KID, help="kid attendu de la cle epinglee ('' pour ne pas le verifier)")
    ap.add_argument("--preuves", help="en cas d'echec, y ecrire les reponses du service et le verdict")
    ap.add_argument("--rejouer", action="store_true", help="verifier chaque tete du fichier contre la tete actuelle")
    sys.exit(run(ap.parse_args()))


if __name__ == "__main__":
    main()
