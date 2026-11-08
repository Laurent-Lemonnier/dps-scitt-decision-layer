#!/usr/bin/env python3
"""
Mutations of the published logs that need no re-signing, for codes that no attempted vector exercises.
An entry line of a log is not itself signed: its records are, and a record's digest covers its content only (Section 4.3),
so these edits change what the verifier reads and leave every signature as it was made.

Usage: mutation_tests.py --vectors DIR
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_from_text as V

def load_case(vdir, f, name):
    d = json.load(open(os.path.join(vdir, f + '.json')))
    return next(c for c in d['cases'] if c['name'] == name)

def lines_of(c): return [json.loads(l) for l in c['text'].split('\n') if l]
def text_of(objs): return ''.join(V.jcs(o) + '\n' for o in objs)

def flip_b64(s, pos=10):
    """Change one character of a base64url string (stays strict base64url)."""
    b = bytearray(V.b64u_dec(s)); b[pos] ^= 1; return V.b64u_enc(bytes(b))

def run(vdir):
    results = []
    def check(name, got, want):
        ok = got == want; results.append(ok); print(('ok   ' if ok else 'FAIL ') + name + ('' if ok else f'  got {got}, wanted {want}'))
    m = V.Methods(without=['SLH-DSA-SHA2-256s'])
    def log(c, objs, **kw):
        o = c['options']
        return V.check_log(text_of(objs), None, None, o.get('issuerKeys'), o.get('sealKeys'), o.get('stampServices'), kw.get('methods', m))
    c = load_case(vdir, 'books', 'two stubs within the slip'); base = lines_of(c)
    r = log(c, base); check('unchanged log: intact, within', (r['answers']['intact'], r['answers']['within_permission']), (True, True))
    # a receipt with an approval whose approval record is left out of the entry: Section 6, approval-not-found
    objs = lines_of(c); i = next(k for k, o in enumerate(objs) if 'approval' in o)
    del objs[i]['approval']; r = log(c, objs)
    check('approval record left out of its entry -> approval-not-found', r['entries'][i].problems, ['approval-not-found'])
    # a countersignature whose ML-DSA-87 signature is changed: countersignature-invalid
    objs = lines_of(c); i = next(k for k, o in enumerate(objs) if 'countersignature' in o)
    objs[i]['countersignature']['signatures'][1]['signature'] = flip_b64(objs[i]['countersignature']['signatures'][1]['signature'], 100)
    r = log(c, objs); check('countersignature signature changed -> countersignature-invalid', r['entries'][i].problems, ['countersignature-invalid'])
    # the same, on a device without ML-DSA-87: not verified, not invalid (Section 4.5, 10.1)
    r = log(c, objs, methods=V.Methods(without=['ML-DSA-87'])); e = r['entries'][i]
    check('same change, ML-DSA-87 missing -> no problem, answer 2 is no, method named', (e.problems, r['answers']['everything_verified'], r['answers']['methods_missing']), ([], False, ['ML-DSA-87']))
    # ES256 missing: the permission's passkey signature is not verified, so nothing is compared (Section 10.1)
    r = log(c, base, methods=V.Methods(without=['ES256'])); check('ES256 missing -> slip not verified, nothing compared, answer 3 no', (r['answers']['everything_verified'], r['answers']['within_permission'], r['answers']['methods_missing']), (False, False, ['ES256']))
    # a delegation left out: receipts under it have pass-missing
    c = load_case(vdir, 'books', 'passes: totals, periods, wider, one too many'); objs = lines_of(c)
    j = next(k for k, o in enumerate(objs) if 'pass' in o); del objs[j]; r = log(c, objs)
    under = [e for e in r['entries'] if 'pass-missing' in e.problems]
    check('a delegation left out -> pass-missing on what relies on it', len(under) >= 1, True)
    # a cancellation left out: the acknowledgement names a cancellation that is not there
    c = load_case(vdir, 'books', 'a cancellation, time-stamped, and stubs after it'); objs = lines_of(c)
    j = next(k for k, o in enumerate(objs) if 'cancellation' in o); del objs[j]; r = log(c, objs)
    ack = next(e for e in r['entries'] if e.kind == 'acknowledgement')
    check('cancellation left out -> cancellation-not-found on its acknowledgement, no after-cancellation', (ack.problems, [e.findings for e in r['entries'] if e.kind == 'stub']), (['cancellation-not-found'], [[], []]))
    # a cancellation whose passkey signature is changed: cancellation-invalid, and then it is not the effective one
    objs = lines_of(c); j = next(k for k, o in enumerate(objs) if 'cancellation' in o)
    sig = objs[j]['cancellation']['signatures'][0]; sig['signature'] = flip_b64(sig['signature'], 20)
    r = log(c, objs); e = r['entries'][j]
    check('cancellation signature changed -> cancellation-invalid; the receipts after it are no longer after-cancellation',
          (e.problems, [x.findings for x in r['entries'] if x.kind == 'stub']), (['cancellation-invalid'], [[], []]))
    # a head: an entry inserted before it makes size and root wrong (Section 9.2), and a recorder not trusted (item 5)
    c = load_case(vdir, 'books', 'the sample record'); objs = lines_of(c)
    seal_i = next(k for k, o in enumerate(objs) if 'seal' in o)
    r = V.check_log(c['text'], None, None, None, ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'], None, V.Methods())
    check('recorder key set not among the trusted ones -> sealer-not-expected', 'sealer-not-expected' in r['entries'][seal_i].problems, True)
    objs2 = objs[:seal_i - 1] + [objs[seal_i - 1], objs[seal_i - 1]] + objs[seal_i:]     # one entry repeated before the head
    r = log(c, objs2, methods=V.Methods()); check('an entry added before the head -> seal-mismatch', 'seal-mismatch' in r['entries'][seal_i + 1].problems, True)
    # the full set of methods verifies the head's three signatures (Section 4.1, 4.5)
    r = V.check_log(c['text'], None, None, None, None, None, V.Methods())
    check('head signed with Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s: all three verify', r['entries'][seal_i].states, ['valid', 'valid', 'valid'])
    print(f'{sum(results)}/{len(results)} mutation tests as expected')
    return 0 if all(results) else 1

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--vectors', required=True); a = ap.parse_args()
    sys.exit(run(a.vectors))
