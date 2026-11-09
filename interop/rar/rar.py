"""Case 19: the approved plan of case 13b, expressed as OAuth 2.0 Rich Authorization Requests (RFC 9396)
`authorization_details`, referenced from the decision record by digest, and checked against what was signed and what ran.

Standard library only. Nothing here signs anything: the one real signature is case 13b's (`../plan-run-real/signed/`)."""
import hashlib, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.join(HERE, '..', 'plan-run-real')
PROJECTION = 'rar-projection-0.1'
RAR_RUN = 'urn:example:rar:workflow-run'
RAR_STEP = 'urn:example:rar:plan-step'


def jcs(o):
    """RFC 8785 for the values used here (strings, integers, arrays, objects; no floats)."""
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def typed(b):
    return 'sha256:' + sha(b)


def project(spec):
    """The authorization_details a plan specification implies. Pure function of the specification's content.

    RFC 9396 Section 2.2: `locations` are typically the URIs of the resource server and `identifier` names a specific resource at the
    API. The specification names the resource each step touches (its `target`) and no resource server, so the target goes in
    `identifier` and `locations` is not set (it would be invented). Members other than `type`, `actions` and `identifier` are
    type-specific (Section 2.2: "An API MAY define its own extensions"); the types are ours (Section 2.1)."""
    p = spec['parameters']
    out = [{
        'type': RAR_RUN,
        'actions': [spec['operation']],
        'identifier': spec['target'],
        'plan_hash': p['plan_hash'],
        'usecase_ref': p['usecase_ref'],
        'policy_version': spec['policy_version'],
        'valid_until': spec['valid_until'],
    }]
    for s in p['steps']:
        out.append({
            'type': RAR_STEP,
            'actions': [s['operation']],
            'identifier': s['target'],
            'step_index': s['index'],
            'parameters_digest': typed(jcs(s['parameters'])),
        })
    return out


def is_filtered_view(view, full):
    """RFC 9396 Sections 7, 9.1, 9.2, 13: the AS may filter or omit details for an audience. A view is acceptable when every
    element is one of the full set's (it may say less, never more or different)."""
    return [i for i, e in enumerate(view) if e not in full]


def reference(decision_id, stage_id, rar, spec_bytes):
    """What the decision record carries instead of the details themselves (typed digest reference)."""
    return {
        'decision_id': decision_id, 'stage_id': stage_id,
        'authorization_details_digest': typed(jcs(rar)),
        'derived_from_spec_digest': sha(spec_bytes),
        'projection': PROJECTION,
    }


def well_formed(rar):
    """RFC 9396 Section 2: an array of objects, each with a string `type`; the common fields keep their types."""
    p = []
    if not isinstance(rar, list) or not rar:
        return ['authorization_details is not a non-empty array']
    for i, e in enumerate(rar):
        if not isinstance(e, dict):
            p.append('element %d is not an object' % i); continue
        if not isinstance(e.get('type'), str) or not e['type']:
            p.append('element %d has no type' % i)
        for k in ('locations', 'actions', 'datatypes', 'privileges'):
            if k in e and not (isinstance(e[k], list) and all(isinstance(x, str) for x in e[k])):
                p.append('element %d: %s is not an array of strings' % (i, k))
        if 'identifier' in e and not isinstance(e['identifier'], str):
            p.append('element %d: identifier is not a string' % i)
    return p


def covers(rar, manifest, only_described=False):
    """Is every executed step inside the details, and nothing run beyond them? Needs only the details and the run.
    Section 2.2: with several common fields the permission is their product; each step here has one action and one resource,
    so membership is the whole test. `only_described` = a filtered view: steps the view does not describe are not its business
    (the manifest is then the part of the run for that audience)."""
    p = []
    steps = {e.get('step_index'): e for e in rar if isinstance(e, dict) and e.get('type') == RAR_STEP}
    ran = manifest['steps']
    if len(ran) != len(steps) and not only_described:
        p.append('%d steps ran, %d are described' % (len(ran), len(steps)))
    for s in ran:
        e = steps.get(s['index'])
        if e is None:
            p.append('step %d ran and is not described' % s['index']); continue
        if s['operation'] not in e.get('actions', []):
            p.append('step %d: operation %s is not among its actions' % (s['index'], s['operation']))
        if s['target'] != e.get('identifier'):
            p.append('step %d: target %s is not the identifier described' % (s['index'], s['target']))
    return p


def check(rar, ref, spec_bytes, approval, manifest):
    """Every layer. Returns {layer: [problems]}; an empty list is a pass."""
    spec = json.loads(spec_bytes)
    r = {}
    r['V1_signed_spec'] = [] if len({sha(spec_bytes), approval['approved_spec_digest'], approval['shown_spec_digest'],
                                    manifest['spec_digest']}) == 1 else ['the specification bytes, the approval and the run name different digests']
    r['V2_derived_from_spec'] = [] if rar == project(spec) else ['the details are not what the specification implies']
    r['V3_reference'] = []
    if ref['authorization_details_digest'] != typed(jcs(rar)):
        r['V3_reference'].append('the reference digest is not the digest of the details')
    if ref['derived_from_spec_digest'] != sha(spec_bytes):
        r['V3_reference'].append('the reference names another specification')
    r['V4_execution_covered'] = covers(rar, manifest)
    r['V5_rfc9396_shape'] = well_formed(rar)
    return r


def rar_only(rar, manifest):
    """What a resource server holding only the details and the run can say (no specification, no approval)."""
    return {'V4_execution_covered': covers(rar, manifest), 'V5_rfc9396_shape': well_formed(rar)}


def load():
    sb = open(os.path.join(CASE, 'signed', 'action-specification.json'), 'rb').read()
    ap = json.load(open(os.path.join(CASE, 'signed', 'person-approval.json')))
    mf = json.load(open(os.path.join(CASE, 'out', 'plan-run-manifest.json')))
    return sb, ap, mf
