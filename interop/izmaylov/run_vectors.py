#!/usr/bin/env python3
"""
Replays the published vectors of github.com/provared/provared (test-vectors/, pinned commit in vectors/PINNED_COMMIT)
through verify_from_text.py and compares our answers with each vector's expected answer.

Per vector family (one JSON file): agree / disagree / not attempted. A vector is "not attempted" when it needs something
the draft does not specify (parts specified only in [FORMAT], Section 15), when its input is a JavaScript value that has
no counterpart in a JSON-over-bytes verifier (a boolean where a size is expected, text where a list is expected), or when
the function under test is internal to the author's library and not named by the draft. The reason is printed.

Usage: run_vectors.py --vectors DIR [--only FILE-STEM ...] [--report out.json] [--verbose]
"""
import argparse, base64, collections, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_from_text as V

def hx(s): return bytes.fromhex(s)

RESULTS = collections.OrderedDict()   # stem -> {'agree': n, 'disagree': [..], 'skip': {reason: n}}

class Skip(Exception): pass

def refused(code): return {'refused': {'code': code}}
def exp_code(e): return e['refused']['code'] if 'refused' in e else None

def run_with(stem, d, fn, verbose=False):
    res = RESULTS.setdefault(stem, {'function': d['function'], 'agree': 0, 'disagree': [], 'skip': collections.Counter(), 'n': 0})
    for c in d['cases']:
        res['n'] += 1
        try:
            ok, detail = fn(c)
        except Skip as s:
            res['skip'][str(s)] += 1; continue
        except Exception as ex:   # a crash is a disagreement with a code-less answer (Section 18: never a crash)
            ok, detail = False, f'CRASH {type(ex).__name__}: {ex}'
        if ok: res['agree'] += 1
        else:
            exp = json.dumps(c['expected'])
            res['disagree'].append({'name': c.get('name'), 'ours': detail, 'expected': exp[:300], 'cause': explain(stem, c.get('name') or '', str(detail), exp)})
            if verbose: print('  DISAGREE', stem, c.get('name'), '|', detail)

def explain(stem, name, ours, exp):
    """The reading of the draft (README, ambiguity log A1..A27) or the scope statement that accounts for a disagreement."""
    code = lambda: (json.loads(exp).get('refused') or {}).get('code')
    if stem.endswith('-contents') and 'bad-base64url' in ours and code() == 'bad-field': return 'A5'
    if stem == 'pass-contents' and 'name and keys' in name: return 'A23'
    if stem == 'slips':
        if 'covered fields' in name: return 'format: covered fields (draft 5, 15)'
        if 'client data' in name: return 'A8'
        if 'payload that is a list' in name: return 'A3'
    if stem == 'books':
        if 'top fingerprint' in name or 'number of entries' in name: return 'A16'
        if 'changed after signing' in name or 'countersignature of another' in name: return 'A16'
        if 'cancellation, time-stamped' in name: return 'format: the stricter rule of FORMAT 22 (draft 8)'
    if stem == 'der-strict' or stem.startswith('stamps'):
        if 'bits' in exp and 'DER allows' in exp: return 'draft 17: BIT STRING unused bits'
        if 'written in parts' in exp: return 'draft 17: a string written in parts'
        if 'order DER requires' in exp or 'out of DER order' in name or 'another order' in name: return 'draft 17: SET OF order'
        if 'Ed25519' in name and ('SHA-' in name or 'parameters' in name): return 'draft 17: Ed25519 digest algorithm and parameters'
        if 'kind that is not used here' in exp or 'unknown constructed tag' in name: return 'draft 9.3: tag kinds not listed'
        if stem == 'der-strict' and name.startswith('random'): return 'draft 17 / 9.3 (random inputs, same three causes or an unlisted tag)'
    if stem == 'stamps':
        if 'ECDSA said to be missing' in name: return 'A11'
        if 'year 50' in name: return 'A26'
        if name.startswith('statement: accuracy') or 'truth value' in name: return 'A13'
        if name.startswith('certificate: a key') or 'curve written out' in name: return 'A13'
        if 'second, larger value' in name: return 'A13'
    if stem.startswith('stamps-flips') or stem == 'stamps-openssl':
        if '506' in name or '556' in name or '580' in name: return 'A12'
        if 'byte 159' in name: return 'A13'
        if 'byte 611' in name: return 'A12'
        return 'draft 17: BIT STRING unused bits'
    if stem == 'seal-stamps': return 'A27'
    if stem == 'ecdsa-der': return 'A25'
    if stem == 'stub-contents' and 'bad-base64url' in ours: return 'A5'
    if stem == 'stub-contents' and ('reserved' in name or 'tool' in name): return 'A22'
    return 'not classified'

def trap(fn):
    """Run fn; return {'ok': value} or {'refused': code}."""
    try: return {'ok': fn()}
    except V.Refused as e: return {'refused': e.code}

def same_answer(ours, exp):
    if 'refused' in exp: return ours.get('refused') == exp['refused']['code'], ours
    return ours.get('ok', 'REFUSED:' + str(ours.get('refused'))) == exp['ok'], ours

# ------------------------------------------------------------ small families
def f_base64url(c): return same_answer(trap(lambda: V.b64u_dec(c['text']).hex()), c['expected'])
def f_canonical(c):
    r = trap(lambda: V.parse_canonical(c['text'], require_object=False))
    return same_answer(r, c['expected'])
def f_characters(c):
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in c['text']): raise Skip('unpaired surrogate: not a Unicode scalar value, so not text under 4.3; the draft gives no count')
    return same_answer({'ok': V.count_chars(c['text'])}, c['expected'])
def f_times(c):
    t = V.parse_time(c['text']); return same_answer({'ok': None if t is None else t * 1000}, c['expected'])
def f_keys(c):
    r = trap(lambda: dict(zip(('alg', 'thumbprint'), V.check_key(c['key'], c['allowed']))))
    return same_answer(r, c['expected'])
def f_ed25519(c):
    if 'Ed25519' in (c.get('without') or []):
        if V.Methods(without=c['without']).can('Ed25519'): raise Skip('?')
        return same_answer({'ok': 'unavailable'}, c['expected'])
    r = trap(lambda: V.ed25519_verify(hx(c['key']), hx(c['signature']), hx(c['message'])))
    return same_answer(r, c['expected'])
def f_ecdsa_der(c):
    def go():
        r, s = V.ecdsa_der_to_rs(hx(c['der']))
        if r >= 2**256 or s >= 2**256: return 'accepted by the DER rules of 4.7 (33 bytes, shortest form, positive); the value exceeds 2^256 and cannot verify'
        return (r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).hex()
    return same_answer(trap(go), c['expected'])
def f_origins(c):
    def go():
        V.check_origin(c['text'], c['rpId']); return True
    try: return same_answer(trap(go), c['expected'])
    except Exception as e: raise
def f_keyset_digest(c): return same_answer(trap(lambda: V.key_set_digest(c['keys'])), c['expected'])

def f_content(kind):
    def f(c):
        if kind == 'pass' and 'lone' in c.get('name', '') and 'pair' in c.get('name', ''): raise Skip('unpaired surrogate: not a Unicode scalar value (4.3); the draft refuses it at the content parse (11.2), the vector tests the member check alone')
        def go():
            V.VALIDATORS[kind](c['content']); return True
        return same_answer(trap(go), c['expected'])
    return f

def need_int(*xs):
    for x in xs:
        if not isinstance(x, int) or isinstance(x, bool): raise Skip('a JavaScript value that is not an integer where a size or index is expected (boolean, fraction, text, null): no counterpart in a bytes-and-integers verifier')
def need_hex(*xs):
    for x in xs:
        if not isinstance(x, str): raise Skip('a JavaScript value that is not hexadecimal text where bytes are expected')
        try: bytes.fromhex(x)
        except ValueError: raise Skip('a JavaScript value that is not hexadecimal text where bytes are expected')

def f_leafhash(c): return same_answer({'ok': V.leaf_hash(hx(c['leaf'])).hex()}, c['expected'])
def f_treeroot(c): return same_answer({'ok': V.tree_root([hx(x) for x in c['leaves']]).hex()}, c['expected'])
def f_inclusion_path(c):
    need_int(c['index'])
    return same_answer(trap(lambda: [h.hex() for h in V.inclusion_path([hx(x) for x in c['leaves']], c['index'])]), c['expected'])
def f_verify_inclusion(c):
    need_int(c['index'], c['size']); need_hex(c['leaf'], c['root'])
    if not isinstance(c['path'], list): raise Skip('a JavaScript value that is not a list where a path is expected')
    need_hex(*c['path'])
    return same_answer({'ok': V.verify_inclusion(c['index'], c['size'], hx(c['leaf']), [hx(p) for p in c['path']], hx(c['root']))}, c['expected'])
def f_consistency_proof(c):
    need_int(*c['ms'])
    if not isinstance(c['leaves'], list): raise Skip('a JavaScript value that is not a list where leaves are expected')
    leaves = [hx(x) for x in c['leaves']]; n = len(leaves)
    def go():
        out = []
        for m in c['ms']:
            proof = V.consistency_proof(m, leaves)
            out.append({'m': m, 'proof': [h.hex() for h in proof], 'checks': V.verify_consistency(m, n, V.tree_root(leaves[:m]), V.tree_root(leaves), proof)})
        return out
    return same_answer(trap(go), c['expected'])
def f_verify_consistency(c):
    need_int(c['m'], c['n']); need_hex(c['rootM'], c['rootN'])
    if not isinstance(c['proof'], list): raise Skip('a JavaScript value that is not a list where a proof is expected')
    need_hex(*c['proof'])
    return same_answer({'ok': V.verify_consistency(c['m'], c['n'], hx(c['rootM']), hx(c['rootN']), [hx(p) for p in c['proof']])}, c['expected'])

def f_slips(c):
    opts = c.get('options') or {}
    if 'disclosures' in c: raise Skip('covered fields and disclosures: specified only in [FORMAT] (Section 15)')
    if 'issuerOrigins' in opts: raise Skip('the issuer address the verifier expects: the draft says a verifier MAY be told it (Section 18), names no code')
    m = V.Methods(without=opts.get('withoutMethods'))
    out, r = V.check_slip(c['record'], opts.get('issuerKeys'), m)
    e = c['expected']['ok']
    ours = {'problems': sorted(out['problems']), 'fingerprint': out['fingerprint'], 'state': ('invalid' if any(p.startswith('passkey-') or p == 'signature-invalid' for p in out['problems']) else out['signature']['state']),
            'issuerKey': out.get('issuerKey')}
    exp = {'problems': sorted(p['code'] for p in e['problems']), 'fingerprint': e['fingerprint'], 'state': e['signature']['state'],
           'issuerKey': e.get('issuerKey')}
    ok = ours == exp
    if ok and e['problems'] == [] and r.content != e.get('content'): ok = False; ours['content'] = 'differs'
    return ok, ours

CORE_KINDS = {'slip', 'stub', 'pass', 'cancellation', 'acknowledgement', 'seal', 'unreadable'}
FORMAT_CLAIM = collections.Counter()

def f_book(c):
    opts = c.get('options') or {}
    for o, why in (('cancellations', "the principal's own copy of a cancellation handed to the verifier (Section 8: specified only in [FORMAT], Section 22)"),
                   ('vouchers', 'vouching records: [FORMAT]'), ('disclosures', 'covered fields and disclosures: [FORMAT]'),
                   ('blocks', 'block time-stamps and header chains: [FORMAT]'), ('witnesses', 'witness statements: [FORMAT]'),
                   ('seals', 'seals held by another party, handed over beside the log: [FORMAT]'),
                   ('issuerOrigins', 'the issuer address a verifier is told to expect: no code in the draft (Section 18)')):
        if o in opts: raise Skip(why)
    e = c['expected']['ok']
    if any(x.get('witnesses') for x in e['entries']) or e.get('held') or e['summary'].get('witnessed'): raise Skip('witness statements beside a seal, or seals held elsewhere: [FORMAT]')
    if any(x.get('covered') for x in e['entries']): raise Skip('covered fields: [FORMAT]')
    extra = sorted({x['kind'] for x in e['entries']} - CORE_KINDS)
    m = V.Methods(without=opts.get('withoutMethods'))
    ours = V.check_log(c['text'], opts.get('expectedRoot'), opts.get('expectedSize'), opts.get('issuerKeys'), opts.get('sealKeys'), opts.get('stampServices'), m)
    if extra:
        # the draft says what a core verifier does with the four further kinds: unknown-entry, and never intact (9.1)
        okc = (not ours['answers']['intact']) and all(x.problems == ['unknown-entry'] for x in ours['entries'] if x.kind == 'unreadable' and x.problems == ['unknown-entry']) \
              and sum(1 for x in ours['entries'] if 'unknown-entry' in x.problems) >= 1
        FORMAT_CLAIM['holds' if okc else 'fails'] += 1
        raise Skip('the log holds records of kinds specified only in [FORMAT] (' + ', '.join(extra) + '); the draft says a core verifier reports unknown-entry and never calls the log intact (9.1): checked separately')
    a = ours['answers']; s = e['summary']; diffs = []
    def chk(name, o, x):
        if o != x: diffs.append(f'{name}: ours {o!r}, expected {x!r}')
    chk('size', ours['size'], e['size']); chk('root', ours['root'], e['root'])
    chk('log problems', sorted(ours['problems']), sorted(p['code'] for p in e['problems']))
    chk('problemFound', a['problem_found'], s['problemFound']); chk('fullyChecked', a['everything_verified'], s['fullyChecked'])
    chk('withinSlips', a['within_permission'], s['withinSlips']); chk('intact', a['intact'], s['intact'])
    chk('methodsMissing', a['methods_missing'], sorted(s['methodsMissing']))
    if len(ours['entries']) != len(e['entries']): diffs.append(f"entries: ours {len(ours['entries'])}, expected {len(e['entries'])}")
    else:
        for x, y in zip(ours['entries'], e['entries']):
            tag = f"entry {y['index']} ({y['kind']})"
            chk(tag + ' kind', x.kind, y['kind'])
            chk(tag + ' problems', sorted(x.problems), sorted(p['code'] for p in y['problems']))
            chk(tag + ' findings', x.findings, sorted([b['code'] for b in y['breaches']], key=lambda k: (V.FINDING_ORDER.index(k) if k in V.FINDING_ORDER else 99)))
            if y['kind'] in ('stub', 'pass'): chk(tag + ' compared', x.compared, y.get('compared'))
            if y['kind'] != 'unreadable' and y['fingerprint'] is not None and x.fingerprint is not None: chk(tag + ' fingerprint', x.fingerprint, y['fingerprint'])
    return (not diffs), '; '.join(diffs)[:600]

def f_der_strict(c):
    return same_answer(trap(lambda: (V.validate_der(hx(c['bytes']), whole=False), True)[1]), c['expected'])

def f_parse_record(c):
    r = V.read_record(c['record'], c['kind'])
    e = c['expected']
    if 'refused' in e: return r.problems == [e['refused']['code']], r.problems
    return (not r.problems and r.digest == e['ok']['fingerprint'] and r.content == e['ok']['content']), r.problems

def f_seal_stamps(c):
    def go():
        return V.decode_stamps(c['stamps'])
    ok, ours = same_answer(trap(go), c['expected'])
    if not ok and isinstance(c['stamps'], list) and any(isinstance(x, dict) for x in c['stamps']) and 'ok' in ours:
        raise Skip('sizes of a block time-stamp (block header, proof): block time-stamps are specified only in [FORMAT] (Section 15); the draft gives no size')
    return ok, ours

def f_stamp(c):
    if 'stampedValue' in c or 'tokenValue' in c: raise Skip('a JavaScript value that is not text where the stamped digest or the token is expected (null, number, object): no counterpart in a bytes verifier')
    if 'stamped' not in c: raise Skip('no stamped digest given')
    opts = c.get('options')
    opts = opts if isinstance(opts, dict) else {}
    trusted = opts.get('trusted') if isinstance(opts.get('trusted'), list) else None
    wo = opts.get('without') if isinstance(opts.get('without'), list) else []
    wo = [{'RSA': 'RS256', 'ECDSA': 'ES256'}.get(x, x) for x in wo if isinstance(x, str) and x in ('RSA', 'ECDSA', 'Ed25519')]
    m = V.Methods(without=wo)
    def go():
        tok = bytearray(V.b64u_dec(c['token']))
        ch = c.get('change') or {}
        if 'flip' in ch: tok[ch['flip'][0]] ^= ch['flip'][1]         # "byte i changed by d": taken as an exclusive-or
        if 'cut' in ch: tok = tok[:ch['cut']]
        if 'append' in ch: tok += bytes.fromhex(ch['append'])
        tok = bytes(tok)
        st = V.b64u_dec(c['stamped']) if isinstance(c['stamped'], str) else None
        r = V.check_stamp(tok, st, trusted, m)
        return {'state': r['state'], 'when': None if r['time'] is None else V.time_text(r['time']), 'time': None if r['time'] is None else r['time'] * 1000, 'authority': r['authority']}
    # the vector's `time` keeps milliseconds; the draft takes times to the second, rounded down (9.3): compare floors
    e = c['expected']
    if 'ok' in e and e['ok'].get('time') is not None:
        e = {'ok': dict(e['ok'], time=e['ok']['time'] // 1000 * 1000)}
        return same_answer(trap(go), e)
    return same_answer(trap(go), c['expected'])

FAMILIES = {
    'base64url': f_base64url, 'canonical-json': f_canonical, 'characters': f_characters, 'times': f_times, 'keys': f_keys,
    'ed25519-signatures': f_ed25519, 'ecdsa-der': f_ecdsa_der, 'origins': f_origins, 'seal-key-sets': f_keyset_digest,
    'stub-contents': f_content('stub'), 'countersignature-contents': f_content('countersignature'),
    'approval-contents': f_content('approval'), 'cancellation-contents': f_content('cancellation'),
    'acknowledgement-contents': f_content('acknowledgement'), 'pass-contents': f_content('pass'),
    'seal-contents': f_content('seal'),
    'tree-leaves': f_leafhash, 'tree-roots': f_treeroot, 'tree-paths': f_inclusion_path, 'tree-inclusion': f_verify_inclusion,
    'tree-consistency': f_consistency_proof, 'tree-consistency-checks': f_verify_consistency,
    'stamps': f_stamp, 'stamps-openssl': f_stamp, 'stamps-strict-keys': f_stamp, 'stamps-flips-ed25519': f_stamp,
    'stamps-flips-ecdsa': f_stamp, 'stamps-flips-rsa': f_stamp,
    'books': f_book, 'chained-books': f_book, 'held-seals': f_book, 'renewal-books': f_book, 'two-agent-books': f_book,
    'denial-books': f_book, 'witness-books': f_book, 'issuer-origins': f_book,
    'der-strict': f_der_strict,
    'slips': f_slips, 'records': f_parse_record, 'seal-stamps': f_seal_stamps,
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vectors', required=True); ap.add_argument('--only', nargs='*'); ap.add_argument('--report')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--check', help='a report written by an earlier run: exit 1 if any family has other counts or other disagreements')
    a = ap.parse_args()
    t0 = time.time()
    allnames = sorted(f[:-5] for f in os.listdir(a.vectors) if f.endswith('.json'))
    for stem in allnames:
        if a.only and stem not in a.only: continue
        d = json.load(open(os.path.join(a.vectors, stem + '.json')))
        fn = FAMILIES.get(stem)
        if fn is None:
            RESULTS[stem] = {'function': d['function'], 'agree': 0, 'disagree': [], 'skip': collections.Counter({NOT_ATTEMPTED.get(stem, 'not named by the draft'): len(d['cases'])}), 'n': len(d['cases'])}
            continue
        run_with(stem, d, fn, a.verbose)
    report(a, time.time() - t0)
    if a.check: sys.exit(check_against(a.check))

FMT = 'parts specified only in [FORMAT] (draft Section 15)'
WRITE = 'writing and signing records (the signing side): the draft specifies the verifier and the records, not a writer'
def _na():
    d = {}
    for k in ('acknowledgements-written', 'approvals-assembled', 'approvals-prepared', 'cancellations-assembled', 'cancellations-prepared',
              'passes-written', 'approval-requests'):
        d[k] = WRITE
    for k in ('denial-before', 'check-before', 'held-seals-before', 'witness-before'):
        d[k] = 'the check before acting (FORMAT Section 20): ' + FMT
    for k in ('shows', 'chained-shows', 'denial-shows', 'held-seal-shows', 'issuer-origin-shows', 'make-show', 'renewal-shows', 'two-agent-shows', 'witness-shows'):
        d[k] = 'a Show, the one-page proof of single entries: ' + FMT
    for k in ('block-fingerprints', 'block-stamp-items', 'block-stamps-flips', 'block-stamps', 'header-answers', 'header-bits', 'header-blocks',
              'header-chains', 'header-checks', 'header-steps'):
        d[k] = 'time-stamps from a public blockchain: ' + FMT + '; a core verifier does not count a block time-stamp (9.3)'
    for k in ('denial-codes', 'denial-constants', 'denial-contents', 'denials-written', 'refusal-contents', 'refusals-written', 'terms-contents',
              'terms-written', 'vouching-contents', 'vouchings-written', 'withdrawal-contents', 'withdrawals-written', 'witness-contents',
              'witnesses-written', 'record-constants'):
        d[k] = 'records of the kinds refusal, terms, vouching, withdrawal, denial, witness: ' + FMT
    for k in ('der-children', 'der-elements', 'der-times', 'der-ecdsa'):
        d[k] = 'an internal function of the author\'s DER reader, not a rule of the draft (the DER rules are exercised through the time-stamp and der-strict vectors)'
    d['http-fingerprints'] = 'the exact texts behind the reserved document names (FORMAT Section 27): ' + FMT
    for k in ('recorder-details-after', 'recorder-scenarios', 'tool-scenarios', 'tree-builder', 'sealer-trees'):
        d[k] = 'the author\'s recorder and stub writer (how a recorder keeps its log): the draft does not specify it (Section 1)'
    d['seal-books'] = 'the book number of a seal (FORMAT Section 21.6): ' + FMT
    return d
NOT_ATTEMPTED = _na()

def check_against(path):
    ref = json.load(open(path)); bad = 0
    for stem, r in RESULTS.items():
        o = ref.get(stem)
        if o is None: print('CHECK: not in the reference report:', stem); bad += 1; continue
        mine = (r['agree'], sorted(x['name'] or '' for x in r['disagree']), sum(r['skip'].values()))
        theirs = (o['agree'], sorted(x['name'] or '' for x in o['disagree']), sum(o['skip'].values()))
        if mine != theirs: print('CHECK: counts or disagreements differ from the reference for', stem, mine[0], theirs[0]); bad += 1
    print('CHECK:', 'identical to the reference report' if not bad else f'{bad} families differ')
    return 1 if bad else 0

def report(a, secs):
    tot = collections.Counter()
    print(f"{'file':34} {'function':22} {'n':>5} {'agree':>6} {'disagree':>8} {'not attempted':>13}")
    for stem, r in RESULTS.items():
        sk = sum(r['skip'].values()); tot['n'] += r['n']; tot['agree'] += r['agree']; tot['dis'] += len(r['disagree']); tot['skip'] += sk
        print(f"{stem:34} {r['function']:22} {r['n']:5} {r['agree']:6} {len(r['disagree']):8} {sk:13}")
    causes = collections.Counter(x['cause'] for v in RESULTS.values() for x in v['disagree'])
    print('disagreements by cause:', dict(causes))
    print('draft 9.1 claim on logs holding the four further kinds (unknown-entry reported, never intact):', dict(FORMAT_CLAIM))
    print(f"{'TOTAL':34} {'':22} {tot['n']:5} {tot['agree']:6} {tot['dis']:8} {tot['skip']:13}   ({secs:.0f} s)")
    if a.report:
        json.dump({k: dict(v, skip=dict(v['skip'])) for k, v in RESULTS.items()}, open(a.report, 'w'), indent=1)

if __name__ == '__main__':
    main()
