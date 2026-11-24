"""Explicit Codex work/review evidence; preserves the default local Prime flow.

Agent identities are recorded attestations, not cryptographic identity. The
checker binds separate authors, exact card/report/artifact hashes and criteria.
"""


def check(root, task, receipt, binding):
    file, read_json, sha, artifacts = binding
    paths = [task['work_record'], task['review_record']]
    if paths[0] == paths[1]:
        raise ValueError('Codex work and review records must differ')
    for field, name in [('work_record', paths[0]), ('review_record', paths[1])]:
        if receipt[field] != name or receipt[field + '_sha256'] != sha(file(root, name)):
            raise ValueError('Codex record binding changed: ' + field)
    work, review = [read_json(file(root, name)) for name in paths]
    report = 'Plan/local-ai/' + task.get('acceptance_result', task['result'])
    card = 'Plan/local-ai/' + task['card']
    if (work.get('schema') != 1 or work.get('record_type') != 'codex-work-snapshot' or
            work.get('task_id') != task['id'] or work.get('card_path') != card or
            work.get('card_sha256') != sha(file(root, card)) or
            work.get('result_path') != report or work.get('result_sha256') != sha(file(root, report))):
        raise ValueError('Codex work snapshot does not match current card/report')
    authors = work.get('authors')
    if not isinstance(authors, list) or not authors or any(not isinstance(a, str) or not a.strip() for a in authors):
        raise ValueError('Codex work authors missing')
    if (review.get('schema') != 1 or review.get('task_id') != task['id'] or
            review.get('decision') != 'accepted' or review.get('findings')):
        raise ValueError('Codex independent review did not accept')
    reviewer = review.get('reviewer_agent')
    if not isinstance(reviewer, str) or not reviewer.strip() or reviewer in authors:
        raise ValueError('Codex reviewer must differ from work authors')
    if receipt.get('reviewer_agent') != reviewer or receipt.get('review_backend') != 'codex-v1':
        raise ValueError('Codex reviewer/backend binding missing')
    work_files = artifacts(root, work['artifacts'])
    reviewed = artifacts(root, review['reviewed_artifacts'])
    bound = artifacts(root, receipt['artifacts'])
    required = [card, report, *task.get('required_artifacts', [])]
    for name in required:
        digest = sha(file(root, name))
        if work_files.get(name) != digest or reviewed.get(name) != digest:
            raise ValueError('Codex mandatory card/report/artifact not independently reviewed: ' + name)
    for name, digest in {**work_files, **reviewed,
                         **{p: sha(file(root, p)) for p in paths}}.items():
        if bound.get(name) != digest:
            raise ValueError('Codex receipt does not bind all work/review evidence: ' + name)
    checks = review['checks']
    if len({c['id'] for c in checks}) != len(checks):
        raise ValueError('Duplicate Codex review criteria')
    by_id = {c['id']: c for c in checks}
    receipt_checks = {c['id']: c for c in receipt['checks']}
    for criterion in task['criteria']:
        c = by_id.get(criterion, {})
        if c.get('outcome') != 'pass' or not str(c.get('evidence', '')).strip():
            raise ValueError('Codex criterion not passed: ' + criterion)
        if receipt_checks.get(criterion) != c:
            raise ValueError('Codex criterion differs from independent review: ' + criterion)


def template(root, task, binding):
    file, sha = binding
    fields = {'review_backend': 'codex-v1', 'reviewer_agent': 'FEHLT'}
    for field in ['work_record', 'review_record']:
        name = task.get(field, 'FEHLT')
        fields[field] = name
        try:
            fields[field + '_sha256'] = sha(file(root, name))
        except (OSError, ValueError):
            fields[field + '_sha256'] = 'FEHLT'
    return fields
