#!/usr/bin/env python3
"""Bind independent review receipts to distinct, local Prime runs.

These are workflow/evidence checks, not cryptographic identity or a sandbox.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import importlib.util


def _codex():
    spec = importlib.util.spec_from_file_location('codex_review', Path(__file__).with_name('codex_review.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file(root, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute() or '..' in Path(name).parts:
        raise ValueError('Ungültiger relativer Evidenzpfad')
    root = root.resolve()
    path = root / name
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError('Evidenz fehlt oder liegt außerhalb des Projekts: ' + name)
    return path


def _json(path):
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError('JSON-Objekt erwartet')
    return data


def _run(root, run_id):
    if not isinstance(run_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', run_id):
        raise ValueError('Ungültige Run-ID')
    base = root.resolve() / 'work/prime-local/runs'
    run = base / run_id
    if run.is_symlink() or not run.is_dir() or not run.resolve().is_relative_to(root.resolve()):
        raise ValueError('Prime-Run fehlt oder liegt außerhalb des Projekts')
    return run


def _assignment(root, run, task_id, phase, card_hash):
    a = _json(_file(run, 'assignment.json'))
    if (a.get('task_id') != task_id or a.get('phase') != phase or
            a.get('project', a.get('project_root')) != str(root.resolve()) or a.get('card_sha256') != card_hash):
        raise ValueError('Run-Zuteilung passt nicht zu Projekt, Karte oder Phase')
    return a


def _artifacts(root, items):
    if not isinstance(items, list):
        raise ValueError('Artefaktliste fehlt')
    out = {}
    for item in items:
        path = item['path']
        file = _file(root, path)
        if path in out or item['sha256'] != _sha(file):
            raise ValueError('Doppeltes oder geändertes Artefakt: ' + path)
        out[path] = item['sha256']
    return out


def _submission(root, t, run_id):
    run = _run(root, run_id)
    card_hash = _sha(_file(root, 'Plan/local-ai/' + t['card']))
    assignment = _assignment(root, run, t['id'], 'work', card_hash)
    if _json(_file(run, 'local-session.json')).get('transport_status') != 'closed':
        raise ValueError('Arbeitslauf ist nicht sauber geschlossen')
    s = _json(_file(run, 'submission.json'))
    result_path = 'Plan/local-ai/' + t.get('acceptance_result', t['result'])
    if (s.get('schema') != 1 or s.get('task_id') != t['id'] or s.get('run_id') != run_id or
            s.get('card_sha256') != card_hash or s.get('result_path') != result_path or
            assignment.get('result_path') != result_path or
            s.get('result_sha256') != _sha(_file(root, result_path))):
        raise ValueError('Arbeitsabgabe passt nicht zum aktuellen Bericht')
    artifacts = _artifacts(root, s['artifacts'])
    for name in t.get('required_artifacts', []):
        if name not in artifacts or name not in assignment.get('required_artifacts', []):
            raise ValueError('Pflichtartefakt fehlt in Arbeitsabgabe: ' + name)
    return s, artifacts


def review_errors(root, t, receipt):
    if not t.get('separate_review'):
        return []
    try:
        backend = t.get('review_backend', 'prime-local')
        if backend == 'codex-v1':
            _codex().check(root, t, receipt, (_file, _json, _sha, _artifacts))
            return []
        if backend != 'prime-local':
            raise ValueError('Unknown review backend: ' + str(backend))
        work_id, review_id = receipt['work_run_id'], receipt['review_run_id']
        if work_id == review_id:
            raise ValueError('Arbeitslauf und Prüflauf müssen verschieden sein')
        submission, artifacts = _submission(root, t, work_id)
        assignment = _assignment(root, _run(root, review_id), t['id'], 'review', submission['card_sha256'])
        if assignment.get('work_run_id') != work_id or assignment.get('result_sha256') != submission['result_sha256']:
            raise ValueError('Prüflauf ist nicht an diese Arbeitsabgabe gebunden')
        if receipt.get('result_path') != submission['result_path'] or receipt.get('result_sha256') != submission['result_sha256']:
            raise ValueError('Abnahme und Arbeitsabgabe beziehen sich auf verschiedene Berichte')
        reviewed = _artifacts(root, receipt['artifacts'])
        if any(reviewed.get(name) != digest for name, digest in artifacts.items()):
            raise ValueError('Abnahme bindet nicht alle abgegebenen Artefakte')
        return []
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return [t['id'] + ': getrennte Abnahme: ' + str(exc)]


def template_fields(root, t):
    if not t.get('separate_review'):
        return {}
    if t.get('review_backend') == 'codex-v1':
        return _codex().template(root, t, (_file, _sha))
    result = {'work_run_id': 'FEHLT', 'review_run_id': 'FEHLT'}
    base = root / 'work/prime-local/runs'
    try:
        # Bounded traversal; no recursive search or model-generated provenance.
        runs = []
        with os.scandir(base) as entries:
            for index, entry in enumerate(entries):
                if index >= 2000:
                    return result
                if entry.is_dir(follow_symlinks=False):
                    runs.append(Path(entry.path))
        for run in sorted(runs, key=lambda p: p.stat().st_mtime_ns, reverse=True):
            try:
                _submission(root, t, run.name)
                result['work_run_id'] = run.name
                break
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                continue
        current = os.environ.get('KI_PRIME_RUN_DIR')
        if current:
            run = Path(current)
            if run.resolve() != _run(root, run.name).resolve():
                return result
            a = _assignment(root, run, t['id'], 'review', _sha(_file(root, 'Plan/local-ai/' + t['card'])))
            s, _ = _submission(root, t, a['work_run_id'])
            if a.get('result_sha256') == s['result_sha256']:
                result.update(work_run_id=a['work_run_id'], review_run_id=run.name)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        pass
    return result


def seal_submission(project, run):
    """Seal a complete work result once; missing output means no submission."""
    project, run = Path(project).resolve(), Path(run)
    try:
        if run.resolve() != _run(project, run.name).resolve():
            raise ValueError('Fremder Run')
        a = _json(_file(run, 'assignment.json'))
        if a.get('phase') != 'work':
            return None
        if a.get('project', a.get('project_root')) != str(project):
            raise ValueError('Fremdes Projekt')
        queue = _json(_file(project, 'Plan/local-ai/QUEUE.json'))
        matches = [t for t in queue['tasks'] if t['id'] == a['task_id']]
        if len(matches) != 1:
            raise ValueError('Karte nicht eindeutig in Queue')
        task = matches[0]
        card = _file(project, 'Plan/local-ai/' + task['card'])
        if a['result_path'] != 'Plan/local-ai/' + task.get('acceptance_result', task['result']):
            raise ValueError('Ergebnispfad geändert')
        if a.get('required_artifacts', []) != task.get('required_artifacts', []):
            raise ValueError('Pflichtartefakte geändert')
        if a['card_sha256'] != _sha(card):
            raise ValueError('Karte geändert')
        result = _file(project, a['result_path'])
        artifacts = [{'path': name, 'sha256': _sha(_file(project, name))} for name in a.get('required_artifacts', [])]
        submission = {'schema': 1, 'task_id': a['task_id'], 'run_id': run.name,
                      'card_sha256': a['card_sha256'], 'result_path': a['result_path'],
                      'result_sha256': _sha(result), 'artifacts': artifacts}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    target = run / 'submission.json'
    try:
        with target.open('x') as output:
            json.dump(submission, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        return None
    return submission
