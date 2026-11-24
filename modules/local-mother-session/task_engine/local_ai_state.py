#!/usr/bin/env python3
"""Single-writer queue transitions with CAS and recoverable, immutable records.

This protects cooperating tools against crashes/stale snapshots, not against
an actor with unrestricted filesystem access or concurrent artifact rewriting.
"""
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import uuid


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def durable_new(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())
    sync_dir(path.parent)


def safe_tree(root,relative,create=False):
    path=root
    for part in Path(relative).parts:
        path=path/part
        if path.is_symlink():raise ValueError(f'Symlink als Steuerpfad nicht erlaubt: {path}')
        if create and not path.exists():path.mkdir(mode=0o700)
        if not path.is_dir():raise ValueError(f'Steuerverzeichnis fehlt: {path}')
    return path


def paths(root,create=True):
    base=safe_tree(root,'Plan/local-ai')
    queue=base/'QUEUE.json'
    if queue.is_symlink() or not queue.is_file():raise ValueError('Queue muss eine reguläre Datei sein')
    journal=base/'control'
    if create or journal.exists() or journal.is_symlink():
        journal=safe_tree(root,'Plan/local-ai/control',create=create)
    return queue,journal


def lock(journal):
    fd=os.open(journal/'queue.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd);raise ValueError('Queue-Schreiber ist aktiv; später mit frischem Hash wiederholen')
    return fd


def validate_transaction(tx):
    before=(tx/'before.json').read_bytes();after=(tx/'after.json').read_bytes()
    manifest=json.loads((tx/'transaction.json').read_text())
    if hash_bytes(before)!=manifest['before_sha256'] or hash_bytes(after)!=manifest['after_sha256']:
        raise ValueError(f'Transaktionsdateien verändert: {tx}')
    return manifest


def recover_locked(queue,journal):
    pending=[]
    for tx in sorted(journal.glob('tx-*')):
        if tx.is_symlink() or not tx.is_dir():raise ValueError('Ungültiger Transaktionspfad')
        committed=tx/'COMMITTED';aborted=tx/'ABORTED'
        if committed.is_symlink() or aborted.is_symlink():raise ValueError('Terminalmarker darf kein Symlink sein')
        if committed.exists() and aborted.exists():raise ValueError('Widersprüchliche Terminalmarker')
        if committed.exists() and not committed.is_file():raise ValueError('Ungültiger COMMITTED-Marker')
        if aborted.exists() and not aborted.is_file():raise ValueError('Ungültiger ABORTED-Marker')
        if committed.is_file() or aborted.is_file():continue
        if not (tx/'PREPARED').exists():
            # No queue write happens before the durable PREPARED marker.
            durable_new(tx/'ABORTED',b'incomplete preparation; no queue write\n')
            continue
        for name in ('before.json','after.json','transaction.json','PREPARED'):
            if (tx/name).is_symlink():raise ValueError('Symlink in Transaktion')
        manifest=validate_transaction(tx)
        live=hash_bytes(queue.read_bytes())
        if live==manifest['after_sha256']:
            durable_new(tx/'COMMITTED',b'recovered committed queue\n')
        elif live==manifest['before_sha256']:
            durable_new(tx/'ABORTED',b'recovered before replacement; no automatic replay\n')
        else:
            raise ValueError(f'Queue driftet gegenüber offener Transaktion {tx.name}; manuell prüfen')
        pending.append(tx.name)
    return pending


def unfinished(root):
    journal=root/'Plan/local-ai/control'
    if not journal.exists():return []
    if journal.is_symlink():return ['Steuerjournal ist ein Symlink']
    problems=[]
    for p in sorted(journal.glob('tx-*')):
        if p.is_symlink() or not p.is_dir():
            problems.append(f'Ungültiger Transaktionspfad {p.name}')
            continue
        committed=p/'COMMITTED';aborted=p/'ABORTED'
        if committed.is_symlink() or aborted.is_symlink():
            problems.append(f'Ungültiger Terminalmarker {p.name}')
            continue
        if committed.exists() and aborted.exists():
            problems.append(f'Widersprüchliche Terminalmarker {p.name}')
            continue
        if committed.exists() and not committed.is_file():
            problems.append(f'Ungültiger COMMITTED-Marker {p.name}')
            continue
        if aborted.exists() and not aborted.is_file():
            problems.append(f'Ungültiger ABORTED-Marker {p.name}')
            continue
        manifest=p/'transaction.json';before=p/'before.json';after=p/'after.json';prepared=p/'PREPARED'
        if not all(path.is_file() for path in (manifest,before,after,prepared)):
            problems.append(f'Unvollständige Transaktion {p.name}')
            continue
        try:
            record=json.loads(manifest.read_text())
            if not isinstance(record,dict) or prepared.read_bytes()!=b'prepared\n':
                raise ValueError('ungültiger Prepare-Nachweis')
            if hash_bytes(before.read_bytes())!=record.get('before_sha256') or hash_bytes(after.read_bytes())!=record.get('after_sha256'):
                raise ValueError('Before-/After-Digest driftet')
            if committed.is_file() and committed.read_bytes() not in (b'committed\n',b'recovered committed queue\n'):
                raise ValueError('ungültiger COMMITTED-Nachweis')
            if aborted.is_file() and aborted.read_bytes() not in (b'evidence changed before commit\n',b'recovered before replacement; no queue write\n',b'recovered before replacement; no automatic replay\n'):
                raise ValueError('ungültiger ABORTED-Nachweis')
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            problems.append(f'Beschädigte Transaktion {p.name}')
            continue
        if not committed.is_file() and not aborted.is_file():
            problems.append(f'Offene Transaktion {p.name}; zuerst recover ausführen')
    return problems


def evidence_fingerprint(root,t,engine):
    result=engine.report_path(root,t)
    wanted=[engine.contained(root/'Plan/local-ai',t['card']),result]
    if t.get('review_required'):
        receipt=engine.contained(root/'Plan/local-ai',t['review']);wanted.append(receipt)
        review=json.loads(receipt.read_text())
        wanted += [engine.contained(root,a['path']) for a in review['artifacts']]
    return {str(p):engine.sha(p) for p in wanted}


def transition(root,engine,command,id,expected,reason='',result=None,cascade=False,actor='Plan',dry_run=False,hook=None,updated_at=None,writer_metadata=None,recover=True,commit_hook=None):
    if actor!='Plan':raise ValueError('Statuswechsel sind der Projektrolle Plan vorbehalten')
    if not re.fullmatch('[0-9a-f]{64}',expected or ''):raise ValueError('--expect erfordert den SHA256 der zuletzt gelesenen Queue')
    queue,journal=paths(root,create=not dry_run);fd=None if dry_run else lock(journal);temp=None
    try:
        if dry_run:
            pending=unfinished(root)
            if pending:raise ValueError('Dry-run benötigt abgeschlossene Transaktionen; recover separat ausführen')
        else:
            if recover:
                recover_locked(queue,journal)
            else:
                pending=unfinished(root)
                if pending:raise ValueError('Queue-Journal benötigt explizite Recovery: '+'; '.join(pending))
        before=queue.read_bytes()
        if hash_bytes(before)!=expected:raise ValueError('Veralteter Queuestand (CAS); summary erneut lesen, nicht blind wiederholen')
        q,by=engine.load(root)
        if queue.read_bytes()!=before:raise ValueError('Queue wurde während des Lesens verändert')
        if id not in by:raise ValueError(f'Unbekannte Karte: {id}')
        candidate=copy.deepcopy(q); cb={t['id']:t for t in candidate['tasks']};t=cb[id]
        old=t['status'];deps=all(d in cb and cb[d]['status']=='DONE' for d in t['depends_on'])
        changed=[id]; proof={}
        if command!='block' and engine.errors(root,q,by):
            raise ValueError('Queueprüfung fehlgeschlagen: '+'; '.join(engine.errors(root,q,by)))
        if command=='start':
            if old!='READY' or not deps:raise ValueError('start benötigt READY und erfüllte Abhängigkeiten')
            if any(x['status']=='RUNNING' for x in cb.values()):raise ValueError('Auf dem Laptop darf nur eine Karte aktiv sein')
            if (t.get('result') or t.get('acceptance_result')) and engine.report_path(root,t).exists():
                raise ValueError('Bericht vorhanden: Abnahme statt erneutem Start')
            t['status']='RUNNING'
        elif command=='ready':
            if old not in ('WAITING','BLOCKED') or not deps:raise ValueError('ready benötigt WAITING/BLOCKED und erfüllte Abhängigkeiten')
            if old=='BLOCKED' and not reason.strip():raise ValueError('Freigabe benötigt Erklärung, wie der Blocker behoben wurde')
            t['status']='READY'
        elif command=='release':
            if old!='RUNNING':raise ValueError('release benötigt eine RUNNING-Karte')
            if not reason.strip():raise ValueError('release benötigt einen Grund')
            if (t.get('result') or t.get('acceptance_result')) and engine.report_path(root,t).exists():
                raise ValueError('Bericht vorhanden: Karte prüfen/abnehmen statt Lease freizugeben')
            t['status']='READY'
        elif command=='block':
            if not reason.strip():raise ValueError('block benötigt --reason')
            t.update(status='BLOCKED',reason=reason)
            affected={id}
            while True:
                new={x['id'] for x in cb.values() if any(d in affected for d in x['depends_on'])}
                if new<=affected:break
                affected|=new
            descendants=[x for x in cb.values() if x['id'] in affected-{id} and x['status'] in ('READY','RUNNING','DONE')]
            if descendants and not cascade:raise ValueError('Aktive/abgenommene Nachfolger betroffen; explizites --cascade nötig')
            for child in descendants:
                child.update(status='BLOCKED',reason=f'Abhängigkeit {id} gesperrt: {reason}')
                changed.append(child['id'])
        elif command=='accept':
            if old not in ('RUNNING','READY','BLOCKED') or not deps:raise ValueError('accept benötigt offene Karte mit erfüllten Abhängigkeiten')
            if old=='BLOCKED' and not reason.strip():raise ValueError('Abnahme eines Blockers benötigt --reason')
            if result:
                engine.contained(root/'Plan/local-ai',result)
                t['acceptance_result']=result
            if not t.get('review_required'):raise ValueError('Kontrollierte Abnahme benötigt review_required und Kriterien; keine Legacy-Selbstabnahme')
            failures=engine.review_errors(root,t)
            if failures:raise ValueError('; '.join(failures))
            proof=evidence_fingerprint(root,t,engine)
            t['status']='DONE'
        else:raise ValueError('Unbekannter Statusbefehl')
        if reason.strip():t['last_transition_reason']=reason
        if command!='block':t.pop('reason',None)
        # A caller that must compare a durable preflight with the real commit
        # may provide one timestamp for both passes.  Legacy callers retain the
        # historical wall-clock behavior when it is omitted.
        candidate['updated']=updated_at if updated_at is not None else datetime.now(timezone.utc).isoformat()
        failures=engine.errors(root,candidate,cb)
        if failures:raise ValueError('Zielzustand ungültig: '+'; '.join(failures))
        after=encoded(candidate)
        info={'schema':1,'operation':command,'actor':actor,'task_id':id,'from':old,'to':t['status'],
              'changed_tasks':changed,'reason':reason,'before_sha256':expected,'after_sha256':hash_bytes(after),
              'evidence_sha256':proof,'created_at':candidate['updated']}
        if writer_metadata is not None:
            info['writer_metadata']=copy.deepcopy(writer_metadata)
        if dry_run:return dict(info,dry_run=True)
        tx=journal/('tx-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex)
        tx.mkdir(mode=0o700);sync_dir(journal)
        durable_new(tx/'before.json',before);durable_new(tx/'after.json',after)
        durable_new(tx/'transaction.json',encoded(info));durable_new(tx/'PREPARED',b'prepared\n')
        if hook:hook('prepared')
        if queue.read_bytes()!=before:raise ValueError('Queue driftet vor Commit; offene Transaktion bleibt zur Prüfung erhalten')
        if command=='accept' and (engine.review_errors(root,t) or evidence_fingerprint(root,t,engine)!=proof):
            durable_new(tx/'ABORTED',b'evidence changed before commit\n');raise ValueError('Abnahmenachweise vor Commit verändert')
        temp=queue.parent/('.QUEUE.'+uuid.uuid4().hex+'.tmp')
        durable_new(temp,after)
        if hook:hook('before_replace')
        os.replace(temp,queue);sync_dir(queue.parent)
        if hook:hook('replaced')
        durable_new(tx/'COMMITTED',b'committed\n')
        committed_info=dict(info,transaction=str(tx.relative_to(root)),dry_run=False)
        if commit_hook:commit_hook(committed_info)
        return committed_info
    finally:
        if temp is not None and temp.exists():
            try:temp.unlink()
            except OSError:pass
        if fd is not None:os.close(fd)


def recover(root):
    queue,journal=paths(root);fd=lock(journal)
    try:return recover_locked(queue,journal)
    finally:os.close(fd)
