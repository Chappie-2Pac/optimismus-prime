#!/usr/bin/env python3
"""Small JSON/config sidecar; the mother-session supervisor is prime.sh."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
from datetime import datetime, timezone


EXPECTED_W5_READER_SHA256 = '7b9c8e79c3f19c8dc544b6a8d567fd42c66e328aacce7869f37a834c2c48c639'


def reject_symlink_components(path, label):
    absolute = Path(path).absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f'{label} enthält einen Symlink: {current}')


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(path)


def within(path, root):
    p = path.resolve()
    if not p.is_relative_to(root.resolve()):
        raise ValueError(f'Pfad außerhalb des Projekts: {path}')
    return p


def runtime(project):
    p = within(project / 'work/prime-local', project)
    # No redirected lock/state paths, even within the project.
    for item in (project/'work', project/'work/prime-local', p/'mother.lock', p/'runs'):
        if item.is_symlink():
            raise ValueError(f'Kein Symlink als Runtime-Schreibpfad: {item}')
    return p


def task_engine():
    """Only code shipped with this module is trusted, never project scripts."""
    module = Path(__file__).resolve().parent
    installed = module/'task_engine/local_ai_tasks.py'
    if installed.is_file():
        return installed
    # The source checkout keeps the engine next to ki-prime, not in the target.
    staged = module.parent/'local_ai_tasks.py'
    if module.name == 'ki-prime' and module.parent.name == 'scripts' and staged.is_file():
        return staged
    raise ValueError('Vertrauenswürdige Task-Engine fehlt; Prime-Installation aktualisieren.')


def review_engine():
    path = task_engine().with_name('local_ai_review.py')
    spec = importlib.util.spec_from_file_location('prime_review_engine', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_w5_observation(prime, run, module, *, runs_root):
    """Load optional W5 context without giving it task or runtime authority."""
    trusted_module = Path(__file__).resolve().parent
    reject_symlink_components(module, 'W5-Reader-Modulpfad')
    if module.resolve(strict=True) != trusted_module:
        raise ValueError('W5-Reader muss aus der installierten Mother-Modulwurzel kommen')
    reader_path = trusted_module / 'w5_observation.py'
    if reader_path.is_symlink():
        raise ValueError('W5-Reader darf kein Symlink sein')
    if not reader_path.is_file():
        raise ValueError('W5-Reader fehlt')
    if digest(reader_path) != EXPECTED_W5_READER_SHA256:
        raise ValueError('W5-Reader ist nicht die gepinnte Prime-Version')
    spec = importlib.util.spec_from_file_location('prime_local_w5_reader', reader_path)
    if spec is None or spec.loader is None:
        raise ValueError('W5-Reader konnte nicht geladen werden')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    load = getattr(reader, 'load_optional_w5_observation', None)
    if not callable(load):
        raise ValueError('W5-Reader ohne Lesefunktion')
    return load(run, prime, runs_root=runs_root)


def task_query(project, command, *args):
    engine = task_engine()
    try:
        result = subprocess.run([sys.executable, '-I', str(engine), '--root', str(project),
                                 command, *args, '--json'], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Projektprüfung nach 60 Sekunden abgebrochen; kein Modellzeitlimit.') from exc
    try:
        data = json.loads(result.stdout)
    except ValueError as exc:
        raise ValueError('Task-Engine lieferte kein JSON: ' + result.stderr.strip()) from exc
    if result.returncode or data.get('errors'):
        raise ValueError('Projekt-Gate: ' + '; '.join(data.get('errors') or [result.stderr.strip() or 'Prüfung fehlgeschlagen']))
    if data.get('schema') != 1:
        raise ValueError('Unbekanntes Task-Engine-Schema')
    return data


def preflight(project):
    path = project/'Plan/local-ai/QUEUE.json'
    if not path.exists() and not path.is_symlink():
        return None
    within(path, project)
    return task_query(project, 'summary')


def assignment(project, run=None):
    """Only the launcher-selected card grants a bounded work or review phase."""
    phase = os.environ.get('KI_PRIME_PHASE', 'coordinate')
    task_id = os.environ.get('KI_PRIME_TASK_ID') or None
    if phase not in ('coordinate', 'work', 'review') or ((phase == 'coordinate') != (task_id is None)):
        raise ValueError('Ungültige Auftragsbindung')
    value = {'schema': 1, 'project': str(project.resolve()), 'task_id': task_id,
             'phase': phase, 'card_sha256': None, 'run_id': run.name if run else None,
             'writable_paths': [], 'created_at': now()}
    if task_id is None:
        return value
    summary = preflight(project)
    if summary is None:
        raise ValueError('work/review benötigt eine Kartenqueue')
    packet = task_query(project, 'packet', task_id)
    q = read_json(project/'Plan/local-ai/QUEUE.json')
    if digest(project/'Plan/local-ai/QUEUE.json') != packet['queue_sha256']:
        raise ValueError('Queue während Auftragsbindung geändert')
    by = {t['id']: t for t in q['tasks']}
    task = by[task_id]
    if any(by[dep]['status'] != 'DONE' for dep in task['depends_on']):
        raise ValueError('Abhängigkeiten der gewählten Karte sind nicht DONE')
    if task['status'] not in ('READY', 'RUNNING', 'BLOCKED'):
        raise ValueError('Gewählte Karte ist für work/review nicht freigegeben')
    if any(t['status'] == 'RUNNING' and t['id'] != task_id for t in q['tasks']):
        raise ValueError('Eine andere Karte ist bereits aktiv')
    report = project/packet['result_path']
    if phase == 'work':
        if report.exists():
            raise ValueError('Ergebnis vorhanden: review oder ausdrücklich neue Reparaturkarte verwenden')
        paths = list(task.get('work_paths', [])) + [packet['result_path']]
    else:
        if not report.is_file() or not packet.get('review_path'):
            raise ValueError('Review benötigt Ergebnisbericht und Abnahmepfad')
        paths = [packet['review_path']]
        if run:
            paths += [f'work/local-ai-review/{task_id}/review-{run.name}/']
    if run:
        paths += [str((run/'handoff.md').relative_to(project))]
    for path in paths:
        if not isinstance(path, str) or Path(path).is_absolute() or '..' in Path(path).parts:
            raise ValueError('Schreibbereich muss ein relativer Projektpfad sein')
        within(project/path, project)
    if os.environ.get('KI_PRIME_WORKER') == '1':
        value['execution_mode'] = 'worker'
    value.update(result_path=packet['result_path'], required_artifacts=packet['required_artifacts'],
                 result_sha256=digest(report) if phase == 'review' else None,
                 card_sha256=packet['card_sha256'], queue_sha256=packet['queue_sha256'],
                 writable_paths=list(dict.fromkeys(paths)))
    if phase == 'review' and task.get('separate_review'):
        work_id = review_engine().template_fields(project, task).get('work_run_id')
        if not work_id or work_id == 'FEHLT':
            raise ValueError('Review benötigt eine geschlossene, passende Arbeitsabgabe')
        value['work_run_id'] = work_id
    return value


def queue(project):
    summary = preflight(project)
    return read_json(project/'Plan/local-ai/QUEUE.json') if summary is not None else None


def previous(project):
    runs = runtime(project)/'runs'
    link = runs/'latest'
    if not link.exists() and not link.is_symlink():
        return None
    p = link.resolve(strict=True)
    if p.parent != runs.resolve():
        raise ValueError('Ungültiger latest-Verweis')
    state = read_json(p/'session_state.json')
    if state.get('run_id') != p.name or state.get('role') != 'local-mother-session':
        raise ValueError('Kein passender lokaler Mutter-Run')
    if (p/'local-session.json').is_file():
        binding = read_json(p/'local-session.json')
        if binding['project'] != str(project):
            raise ValueError('Run gehört zu anderem Projekt')
    return p


def status(project):
    lines = [f'Projekt: {project}']
    try:
        summary = preflight(project)
        if summary is None:
            lines.append('Keine Projektqueue; Nutzerauftrag und Projektregeln verwenden.')
        else:
            lines.append('Aufgabenquelle: Plan/local-ai/QUEUE.json (geprüft)')
            selected = summary['selected']
            if selected:
                role = 'Plan' if selected['action'] == 'review' else selected['owner']
                lines.append(f"Nächster Schritt: {selected['id']} — {selected['title']} | Rolle {role} | {selected['status']} | Aktion {selected['action']}")
            else:
                lines.append('Keine zulässige Karte ausgewählt; offene Gates prüfen.')
            lines.append('Bereit: ' + (', '.join(summary['ready']) or 'keine'))
            for item in summary['blocked']:
                lines.append(f"Blockiert {item['id']}: {item['reason']}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        lines.append(f'Projekt-Gate UNGÜLTIG; Modellstart gesperrt: {exc}')
    p = previous(project)
    if p:
        binding = read_json(p/'local-session.json') if (p/'local-session.json').is_file() else {'transport_status': 'stale_unbound'}
        live = False
        owner = p/'writer/active.d/owner.json'
        if owner.is_file():
            try:
                meta = read_json(owner)
                stat = Path(f'/proc/{meta["pid"]}/stat').read_text().rsplit(') ', 1)[1].split()
                live = (stat[19] == meta['starttime'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == meta['boot_id'] and datetime.now().timestamp() < meta['expires_at_epoch'])
            except (OSError, KeyError, ValueError):
                pass
        lines += [f'Letzter Run: {p}', f"Sitzung: {binding['transport_status'] if binding['transport_status'] != 'running' else 'aktiv (Lease)' if live else 'stale_unleased'}", f'Übergabe, falls vorhanden: {p}/handoff.md']
    else:
        lines.append('Noch kein lokaler Prime-Run.')
    return '\n'.join(lines)


def config(base, run, module, project):
    binding = read_json(run/'local-session.json')
    if binding['project'] != str(project.resolve()) or run.resolve().parent != (runtime(project)/'runs').resolve():
        raise ValueError('Prime-Konfiguration passt nicht zum Projekt')
    c = copy.deepcopy(base)
    if c.get('model') != 'lokal/qwen3.6-local' or c.get('enabled_providers') != ['lokal']:
        raise ValueError('Lokale Providerbindung unerwartet; bitte Konfiguration prüfen')
    agent = copy.deepcopy(c['agent']['lokal'])
    agent.update(description='Lokale Prime-Muttersession: Plan, Build und Lokal sequenziell', mode='primary', prompt=(module/'MOTHER.md').read_text())
    # Only the successfully loaded guard enables tools; a missing plugin stays read-only.
    agent['permission'] = {'*': 'deny'}
    c['permission'] = {'*': 'deny'}
    c['plugin'] = [(module/'guard-plugin.mjs').as_uri()]
    c['mcp'] = {}
    c['agent'] = {'prime': agent}
    c['default_agent'] = 'prime'
    c['instructions'] = list(dict.fromkeys([*c.get('instructions', []), str(run/'cockpit.md')]))
    status_template = 'Lies Plan/local-ai/QUEUE.json und Plan/local-ai/NEXT.md, falls vorhanden. Nenne vorhandene Berichte zur Abnahme und genau den nächsten zulässigen Schritt. Keine Dateien ändern.'
    if (project/'Plan/local-ai/QUEUE.json').exists():
        status_template = (f'Rufe die vertrauenswürdige Task-Engine {task_engine()} mit --root {project} summary --json auf. '
                           'Nenne den ausgewählten Originaltitel, Aktion und offene Gates. Bei Fehlern stoppen. Keine Dateien ändern.')
    c['command'] = {
        'prime-status': {'description': 'Projektstatus gezielt prüfen', 'agent': 'prime', 'template': status_template},
        'prime-handoff': {'description': 'Geprüften Stand und nächsten Schritt sichern', 'agent': 'prime', 'template': f'Schreibe eine kurze, belegte Übergabe nach {run}/handoff.md: Auftrag, tatsächlich geprüft, offene Punkte, nächster Schritt. Projektstatus nur bei belegter Abnahme aktualisieren. Keine Folgekarte beginnen.'},
    }
    return c


def main():
    action = sys.argv[1]
    project = Path(sys.argv[2]).resolve(strict=True)
    if action == 'task':
        os.execv(sys.executable, [sys.executable, '-I', str(task_engine()), '--root', str(project), *sys.argv[3:]])
    elif action == 'check':
        prime = Path(sys.argv[3]).resolve(strict=True)
        for name in ('lib/prime_core.sh', 'lib/prime_runtime_guard.sh', 'scripts/prime_mother_bootstrap.sh', 'scripts/prime_append_event.sh', 'scripts/prime_set_resume_gate.sh'):
            if not (prime/name).is_file():
                raise ValueError(f'Prime-Baustein fehlt: {name}')
        runtime(project); queue(project); previous(project); assignment(project)
        probe=subprocess.run(['bwrap','--ro-bind','/','/','--dev','/dev','--proc','/proc','--unshare-all','/usr/bin/true'],capture_output=True,text=True,timeout=10)
        if probe.returncode:raise ValueError('Shell-Sandbox nicht verfügbar: '+probe.stderr.strip())
        for name in ('guard.py','guard-plugin.mjs'):
            if not Path(__file__).with_name(name).is_file():raise ValueError('Prime-Schutz fehlt: '+name)
        print('Prime-Voraussetzungen und Projektpfade geprüft.')
    elif action == 'runtime':
        p = runtime(project); (p/'runs').mkdir(parents=True, exist_ok=True); print(p)
    elif action == 'previous':
        print(previous(project) or '')
    elif action == 'status':
        print(status(project))
    elif action == 'prepare':
        prime, run = Path(sys.argv[3]), Path(sys.argv[4])
        prev, module = sys.argv[5], Path(sys.argv[6])
        trusted_module = Path(__file__).resolve().parent
        if module.resolve(strict=True) != trusted_module:
            raise ValueError('Mother-Modulwurzel ist nicht vertrauenswürdig')
        module = trusted_module
        bound = assignment(project, run)
        write_json(run/'assignment.json', bound)
        write_json(run/'local-session.json', {'schema': 1, 'project': str(project), 'controller': 'local-opencode', 'model': 'lokal/qwen3.6-local', 'prime_root': str(prime), 'previous_run': prev or None, 'started_at': now(), 'transport_status': 'running', 'objective_verified': False})
        paths = [prime/'lib/prime_core.sh', prime/'lib/prime_runtime_guard.sh', prime/'lib/prime_current_index.sh', prime/'lib/prime_transaction_store.sh', prime/'scripts/prime_mother_bootstrap.sh', prime/'scripts/prime_append_event.sh', prime/'scripts/prime_set_resume_gate.sh', *module.glob('*.py'), *module.glob('*.sh'), *module.glob('*.mjs'), module/'MOTHER.md']
        for name in ('modules/w5_dispatch_bridge_s0/mother_observation.py', 'modules/w5_dispatch_bridge_s0/source_attestation.py'):
            path = prime/name
            if path.is_symlink() or not path.is_file():
                raise ValueError(f'W5-Primequelle fehlt oder ist ein Symlink: {path}')
            paths.append(path)
        if (project/'Plan/local-ai/QUEUE.json').exists():
            engine = task_engine()
            paths.extend([engine, engine.with_name("local_ai_state.py"), engine.with_name("local_ai_review.py"), engine.with_name("local_ai_validators.py")])
        for name in ('AGENTS.md', 'Plan/local-ai/QUEUE.json', 'Plan/local-ai/NEXT.md'):
            if (project/name).is_file(): paths.append(project/name)
        observation_path = run/'w5-observation.json'
        result_path = run/'w5-result.json'
        for path in (observation_path, result_path):
            if path.is_file() and not path.is_symlink():
                paths.append(path)
        write_json(run/'sources.json', [{'path': str(p), 'sha256': digest(p)} for p in paths])
        summary = preflight(project)
        packet = None
        if summary is not None:
            q = read_json(project/'Plan/local-ai/QUEUE.json')
            if digest(project/'Plan/local-ai/QUEUE.json') != summary['queue_sha256']:
                raise ValueError('Queue während Vorbereitung geändert; erneut starten.')
            write_json(run/'queue-at-start.json', q)
            write_json(run/'task-summary.json', summary)
            selected_id = bound['task_id'] or (summary['selected']['id'] if summary['selected'] else None)
            if selected_id:
                packet = task_query(project, 'packet', selected_id)
                if (packet['queue_sha256'] != summary['queue_sha256'] or
                        (bound['task_id'] and packet['card_sha256'] != bound['card_sha256'])):
                    raise ValueError('Karte/Queue während Vorbereitung geändert; erneut starten.')
                write_json(run/'task-packet.json', packet)
        text = f'# Prime-Cockpit\n\nAktueller Run: {run}\nSteuerung: lokale KI; kein Codex.\n'
        text += f'Auftragsbindung: {bound["phase"]}; Karte: {bound["task_id"] or "keine"}.\n'
        text += 'Nur die gebundene Phase/Karte bearbeiten. Andere Karte benötigt einen neuen Nutzerstart.\n'
        text += 'Projektqueue ist maßgeblich; Prime tasks.json bleibt absichtlich leer.\n\n'
        # Avoid resolving the just-created latest through missing metadata (now present).
        text += status(project) + '\n'
        if summary is not None:
            engine = task_engine()
            text += f'\nTask-Engine (vertrauenswürdiger Installationspfad): {engine}\n'
            text += f'Queue SHA256: {summary["queue_sha256"]}\n'
            text += 'Vor Entscheidungen summary --json mit --root auf diesem Projekt erneut prüfen.\n'
        try:
            w5_observation = load_w5_observation(
                prime,
                run,
                module,
                runs_root=runtime(project) / 'runs',
            )
            w5_observation_error = None
        except (OSError, ValueError, KeyError, TypeError, ImportError, SyntaxError, RuntimeError, AttributeError) as exc:
            w5_observation = None
            w5_observation_error = str(exc)
        if w5_observation is not None:
            text += '\n## W5-Observation (nur lesender Hintergrundbeleg)\n\n'
            text += json.dumps(w5_observation, ensure_ascii=False, indent=2, sort_keys=True) + '\n'
            text += ('Diese Projektion ist Evidence-only: Sie ändert keine Queue, keinen Status, '
                     'keine Resume-Entscheidung und startet nichts.\n')
        elif w5_observation_error:
            text += '\n## W5-Observation nicht verwendbar\n\n'
            text += f'Lesefehler: {w5_observation_error}\n'
            text += 'Nicht als Ausführungs- oder Resume-Freigabe interpretieren.\n'
        if packet:
            text += f'\n## Genau eine vorbereitete Karte: {packet["task_id"]}\n\n'
            role = 'Plan' if packet['action'] == 'review' else packet['owner']
            text += f'Aktion: {packet["action"]}; Arbeitsrolle jetzt: {role}; Kartenrolle: {packet["owner"]}; Status: {packet["status"]}\n'
            text += f'Karten-SHA256: {packet["card_sha256"]}\n'
            text += 'Das Paket ist ein Startsnapshot, keine Ausführungsfreigabe. Nutzerauftrag abwarten.\n'
            text += 'Bei review nur Abnahme bearbeiten, bei resume vorhandene Arbeit prüfen.\n'
            text += 'Nach einer Karte stoppen und übergeben; keine automatische Folgekette.\n\n'
            text += packet['card_text'] + '\n'
            text += f'\nErgebnis: {packet["result_path"]}\nAbnahme: {packet["review_path"]}\n'
            text += 'Geforderte Artefaktpfade (Inhalte nur bei Bedarf lesen):\n'
            text += '\n'.join('- ' + p for p in packet['required_artifacts']) + '\n'
        if prev:
            text += f'\nVorheriger Run (nur bei Bedarf): {prev}\nÜbergabe: {prev}/handoff.md\n'
        # Retrieval is optional context, never task authority or a status transition.
        spec=importlib.util.spec_from_file_location('prime_knowledge',module/'knowledge.py')
        knowledge=importlib.util.module_from_spec(spec);spec.loader.exec_module(knowledge)
        query=packet['card_text'] if packet else 'Abnahme Wiederaufnahme Wissensdatenbank'
        try:
            found=knowledge.search(project,prime,query)
            write_json(run/'knowledge.json',found)
            (run/'knowledge.md').write_text(knowledge.render(found))
        except (OSError,ValueError,KeyError,TypeError) as exc:
            write_json(run/'knowledge.json',{'schema':1,'hits':[],'warnings':[str(exc)]})
            (run/'knowledge.md').write_text('# Wissen nicht verfügbar\n'+str(exc)+'\nOriginalkarte und Projektquellen prüfen.\n')
        text += '\n'+(run/'knowledge.md').read_text()
        (run/'cockpit.md').write_text(text)
    elif action == 'finish':
        run, rc = Path(sys.argv[3]), int(sys.argv[4])
        binding = read_json(run/'local-session.json') if (run/'local-session.json').is_file() else {'schema': 1, 'project': str(project), 'objective_verified': False}
        tool_blocked=(run/'tool-circuit.json').is_file()
        binding.update(transport_status='tool_blocked' if tool_blocked else 'closed' if rc == 0 else 'interrupted_or_failed', exit_code=rc, ended_at=now())
        write_json(run/'local-session.json', binding)
        if rc == 0 and not tool_blocked and (run/'assignment.json').is_file():
            assignment_data = read_json(run/'assignment.json')
            if assignment_data.get('execution_mode') == 'worker':
                worker = read_json(run/'worker-state.json')
                expected = 'ready_for_review' if assignment_data['phase'] == 'work' else 'reviewed'
                if worker.get('status') != expected:
                    binding.update(transport_status='worker_incomplete', exit_code=111)
                    write_json(run/'local-session.json', binding)
                    raise ValueError('Workerphase unvollständig; keine Versiegelung')
                if assignment_data['phase'] == 'work' and not review_engine().seal_submission(project, run):
                    binding.update(transport_status='seal_failed', exit_code=111)
                    write_json(run/'local-session.json', binding)
                    raise ValueError('Workerabgabe konnte nicht versiegelt werden')
            else:
                review_engine().seal_submission(project, run)
        (run/'closeout.md').write_text(f'# Transportende\n\nExitcode: {rc}. Kein fachlicher Abschluss behauptet.\nProjektstatus:\n\n{status(project)}\n')
    else:
        raise ValueError('Unbekannte Aktion')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'ki prime: {exc}', file=sys.stderr)
        sys.exit(111)
