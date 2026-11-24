#!/usr/bin/env python3
"""Task packets, evidence checks and controlled, journaled Plan transitions."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import importlib.util
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
STATES = {'READY','WAITING','RUNNING','DONE','BLOCKED'}
# Legacy local roles plus the explicit Prime MCP ownership labels.  The MCP
# still maps mutations through the Plan transition engine; these labels only
# make the imported, read-only-discovered card queues schema-compatible.
ROLES = {'Plan','Build','Lokal','codex','local-ai','shared'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contained(root, value):
    if not isinstance(value,str) or not value or Path(value).is_absolute():
        raise ValueError(f'Erwartet relativen Projektpfad: {value!r}')
    p=(root/value).resolve()
    if not p.is_relative_to(root.resolve()):
        raise ValueError(f'Pfad verlässt erlaubten Bereich: {value}')
    return p


def load(root):
    base=root/'Plan/local-ai'
    contained(root,'Plan/local-ai')
    q=json.loads((base/'QUEUE.json').read_text())
    updated = q['updated']
    if isinstance(updated, str) and updated.endswith('Z'):
        updated = updated[:-1] + '+00:00'
    datetime.fromisoformat(updated)
    if len(q['updated']) < 10 or ('T' in q['updated'] and len(q['updated']) < 19):
        raise ValueError('updated muss Datum oder vollständiger ISO-Zeitstempel sein')
    if q.get('schema',1)!=1 or not isinstance(q.get('tasks'),list):
        raise ValueError('Ungültiges Queue-Schema')
    tasks=q['tasks']
    if any(not isinstance(t,dict) or not isinstance(t.get('id'),str) or not t['id'] for t in tasks):
        raise ValueError('Ungültige Karten-ID')
    by={t['id']:t for t in tasks}
    if len(by)!=len(tasks): raise ValueError('Doppelte Karten-ID')
    preferred=q.get('preferred_order',[])
    if not isinstance(preferred,list) or any(i not in by for i in preferred) or len(set(preferred))!=len(preferred):
        raise ValueError('Ungültige bevorzugte Reihenfolge')
    for t in tasks:
        if not isinstance(t.get('depends_on'),list) or any(not isinstance(x,str) for x in t['depends_on']):
            raise ValueError('Ungültige Abhängigkeiten')
        if not isinstance(t.get('review_required',False),bool):raise ValueError('review_required muss boolesch sein')
        if t.get('review_required'):
            if not t.get('review') or not isinstance(t.get('criteria'),list) or not t['criteria'] or any(not isinstance(c,str) or not c for c in t['criteria']):
                raise ValueError('Review benötigt Pfad und benannte Kriterien')
        artifacts=t.get('required_artifacts',[])
        if not isinstance(artifacts,list):raise ValueError('Pflichtartefakte müssen Liste sein')
        for name in artifacts:contained(root,name)
        if t['owner'] not in ROLES or t['status'] not in STATES:
            raise ValueError(f"Ungültige Rolle/Status: {t['id']}")
        card=contained(base,t['card'])
        if not card.is_file(): raise ValueError(f'Karte fehlt: {card}')
        lines=card.read_text().splitlines()
        if not lines:raise ValueError(f'Leere Karte: {card}')
        title=lines[0]
        if not title.startswith(f"# {t['id']} — "):
            raise ValueError(f'Karten-ID/Titel widersprüchlich: {card}')
        for field in ('result','acceptance_result','review'):
            if t.get(field): contained(base,t[field])
        if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', d) for d in t['depends_on']):
            raise ValueError(f"Ungültige Abhängigkeit: {t['id']}")
    active=set();visited=set()
    def visit(id):
        if id in active: raise ValueError(f'Zyklische Abhängigkeit: {id}')
        if id in visited:return
        active.add(id)
        for dep in by[id]['depends_on']:
            if dep in by:visit(dep)
        active.remove(id);visited.add(id)
    for id in by:visit(id)
    return q,by


def report_path(root,t):
    relative = t.get('acceptance_result') or t.get('result')
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{t.get('id','Karte')}: Ergebnisbericht fehlt")
    return contained(root/'Plan/local-ai',relative)


def extension(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def validate(root,t):
    return extension('local_ai_validators').validate(root,t)


def review_errors(root,t):
    prefix=t['id']+': '
    try:
        base=root/'Plan/local-ai'
        r=json.loads(contained(base,t['review']).read_text())
        if r['task_id']!=t['id'] or r['decision']!='accepted' or r['reviewer'] not in ('Plan','Lokal'):
            raise ValueError('keine passende Abnahme durch Plan/Lokal')
        if r['card_sha256']!=sha(contained(base,t['card'])):
            raise ValueError('Karte seit Abnahme geändert')
        report=report_path(root,t)
        if contained(root,r['result_path'])!=report or r['result_sha256']!=sha(report):
            raise ValueError('Berichtspfad oder Berichthash stimmt nicht')
        checks=r['checks']
        if len({c['id'] for c in checks})!=len(checks):raise ValueError('Doppelte Prüfkriterien')
        checked={c['id']:c for c in checks}
        for criterion in t['criteria']:
            c=checked.get(criterion,{})
            if c.get('outcome')!='pass' or not str(c.get('evidence','')).strip():
                raise ValueError(f'Kriterium ohne belegte Abnahme: {criterion}')
        artifacts={}
        for a in r['artifacts']:
            p=contained(root,a['path'])
            if not p.is_file() or sha(p)!=a['sha256']:raise ValueError(f'Artefakt fehlt/geändert: {a["path"]}')
            artifacts[p]=a['sha256']
        for name in t.get('required_artifacts',[]):
            if contained(root,name) not in artifacts:raise ValueError(f'Pflichtartefakt nicht gebunden: {name}')
        return validate(root,t) + extension('local_ai_review').review_errors(root,t,r)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        return [prefix+str(exc)]


def errors(root,q,by):
    problems=state_module().unfinished(root); running={}
    for t in q['tasks']:
        id=t['id'];status=t['status']
        # READY cards may legitimately wait for dependencies; start() enforces
        # that the selected card itself has all dependencies completed.
        if status in ('RUNNING','DONE'):
            missing=[d for d in t['depends_on'] if d not in by or by[d]['status']!='DONE']
            if missing:problems.append(f'{id}: {status} trotz offener Abhängigkeiten {missing}')
        if status=='RUNNING':
            if t['owner'] in running:problems.append(f"Mehrere aktive Karten für {t['owner']}")
            running[t['owner']]=id
        if status=='BLOCKED' and not t.get('reason'):problems.append(f'{id}: BLOCKED ohne Ursache')
        if status=='DONE':
            if not report_path(root,t).is_file():problems.append(f'{id}: DONE ohne Ergebnisbericht')
            if t.get('review_required'):problems+=review_errors(root,t)
    if sum(t['status']=='RUNNING' for t in q['tasks'])>1:
        problems.append('Auf dem Laptop darf insgesamt nur eine Karte RUNNING sein')
    return problems


def template(root,t):
    report=report_path(root,t)
    def hash_or_missing(p):return sha(p) if p.is_file() else 'FEHLT'
    return {**extension('local_ai_review').template_fields(root,t), 'task_id':t['id'],'reviewer':'Plan','decision':'pending',
            'card_sha256':sha(contained(root/'Plan/local-ai',t['card'])),
            'result_path':str(report.relative_to(root)), 'result_sha256':hash_or_missing(report),
            'checks':[{'id':c,'outcome':'not_checked','evidence':''} for c in t.get('criteria',[])],
            'artifacts':[{'path':name,'sha256':hash_or_missing(contained(root,name))} for name in t.get('required_artifacts',[])]}


def state_module():
    spec=importlib.util.spec_from_file_location('local_ai_state',Path(__file__).with_name('local_ai_state.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def engine():
    return SimpleNamespace(load=load,errors=errors,review_errors=review_errors,report_path=report_path,contained=contained,sha=sha)


def describe(root,t):
    card=contained(root/'Plan/local-ai',t['card'])
    exists=report_path(root,t).is_file()
    action=('review' if exists else 'resume' if t['status']=='RUNNING' else 'execute') if t['status'] in ('READY','RUNNING') else 'none'
    return {'id':t['id'],'owner':t['owner'],'title':card.read_text().splitlines()[0].split(' — ',1)[1],
            'status':t['status'],'action':action,'card_sha256':sha(card),'result_exists':exists}


def summary(root):
    path=root/'Plan/local-ai/QUEUE.json';before=path.read_bytes()
    q,by=load(root);issues=errors(root,q,by)
    order=q.get('preferred_order',[])
    ordered=sorted(q['tasks'],key=lambda t:order.index(t['id']) if t['id'] in order else len(order))
    candidates=[t for t in ordered if t['status']=='RUNNING'] or [t for t in ordered if t['status']=='READY']
    selected=describe(root,candidates[0]) if candidates and not issues else None
    if path.read_bytes()!=before:raise ValueError('Queue während Snapshot verändert')
    return {'schema':1,'queue_sha256':hashlib.sha256(before).hexdigest(),'selected':selected,
            'ready':[t['id'] for t in ordered if t['status']=='READY'],
            'blocked':[{'id':t['id'],'reason':t.get('reason','')} for t in ordered if t['status']=='BLOCKED'],
            'errors':issues}


def packet(root,id):
    snap=summary(root)
    if snap['errors']:raise ValueError('; '.join(snap['errors']))
    q,by=load(root)
    if id not in by:raise ValueError('Unbekannte Karte')
    t=by[id];description=describe(root,t);card=contained(root/'Plan/local-ai',t['card'])
    text=card.read_text()
    if len(text.encode())>24000:raise ValueError('Karte überschreitet 24000 Bytes; in kleinere Aufgaben schneiden')
    if sha(root/'Plan/local-ai/QUEUE.json')!=snap['queue_sha256'] or sha(card)!=description['card_sha256']:
        raise ValueError('Eingaben während Paketerstellung verändert')
    return {'schema':1,'task_id':id,'owner':t['owner'],'title':description['title'],'status':t['status'],
            'action':description['action'],'queue_sha256':snap['queue_sha256'],'card_sha256':description['card_sha256'],
            'card_text':text,'result_path':str(report_path(root,t).relative_to(root)),
            'review_path':'Plan/local-ai/'+t['review'] if t.get('review') else None,
            'required_artifacts':t.get('required_artifacts',[]),
            'dependencies':[{'id':d,'status':by[d]['status']} for d in t['depends_on']],
            'limits':{'one_card':True,'max_card_bytes':24000},
            'transition_hint':f"start {id} --expect {snap['queue_sha256']}" if description['action']=='execute' else 'Bericht prüfen; keine automatische Freigabe'}


def main():
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('command',choices=['check','next','show','receipt-template','review-check','summary','packet','start','ready','block','accept','recover','validate'])
    parser.add_argument('id',nargs='?')
    parser.add_argument('--json',action='store_true')
    parser.add_argument('--expect',help='SHA256 der zuletzt gelesenen Queue; für Statuswechsel Pflicht')
    parser.add_argument('--reason',default='')
    parser.add_argument('--result',help='Expliziter Ersatzbericht relativ zu Plan/local-ai')
    parser.add_argument('--actor',default='Plan')
    parser.add_argument('--cascade',action='store_true',help='Beim Sperren betroffene aktive/abgenommene Nachfolger mit sperren')
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args();root=args.root.resolve()
    if args.command=='recover':
        print(json.dumps({'recovered':state_module().recover(root)},ensure_ascii=False));return 0
    if args.command in ('start','ready','block','accept'):
        outcome=state_module().transition(root,engine(),args.command,args.id,args.expect,args.reason,args.result,args.cascade,args.actor,args.dry_run)
        print(json.dumps(outcome,ensure_ascii=False,indent=2));return 0
    if args.command=='summary':
        snap=summary(root);print(json.dumps(snap,ensure_ascii=False,indent=2));return bool(snap['errors'])
    if args.command=='packet':
        print(json.dumps(packet(root,args.id),ensure_ascii=False,indent=2));return 0
    q,by=load(root)
    if args.command=='check':
        found=errors(root,q,by)
        for e in found:print('FEHLER:',e)
        if not found:print('OK: Queue/Abhängigkeiten und erforderliche Abnahmebelege konsistent. Keine fachliche Testgarantie.')
        return bool(found)
    if args.command=='next':
        snap=summary(root)
        if snap['errors']:print('\n'.join(snap['errors']));return 1
        if not snap['selected']:
            print('Keine freigegebene Karte. Plan muss Abhängigkeiten/Abnahmen prüfen.');return 0
        selected=snap['selected'];t=by[selected['id']]
        if selected['action']=='review':print(f"Plan: vorhandenen Bericht von {t['id']} zuerst abnehmen, nicht überschreiben.")
        print(f"Nächste Karte: {t['id']} ({t['owner']}) — Plan/local-ai/{t['card']}")
        print('Queue SHA256: '+snap['queue_sha256'])
        print('Weitere freigegebene Karten: '+', '.join(i for i in snap['ready'] if i!=t['id']))
    else:
        if args.id not in by:parser.error('Bekannte Karten-ID erforderlich')
        t=by[args.id]
    if args.command=='receipt-template':
        if args.result:
            t=dict(t,acceptance_result=args.result)
        print(json.dumps(template(root,t),ensure_ascii=False,indent=2));return 0
    if args.command=='validate':
        found=validate(root,t)
        print(json.dumps({'task_id':t['id'],'errors':found,'passed':not found},ensure_ascii=False,indent=2));return bool(found)
    if args.command=='review-check':
        if args.result:t=dict(t,acceptance_result=args.result)
        found=review_errors(root,t)
        print('\n'.join(found) if found else 'Abnahmebeleg formal und kryptografisch konsistent; fachliche Verantwortung bleibt beim Prüfer.')
        return bool(found)
    if args.command=='show':
        found=errors(root,q,by)
        if found:print('Keine Ausführungsfreigabe: '+ '; '.join(found));return 1
    card=contained(root/'Plan/local-ai',t['card'])
    if t.get('required_artifacts'):print('Pflichtartefakte für die Abnahme: '+', '.join(t['required_artifacts']))
    allowed=t['status'] in ('READY','RUNNING') and all(by[d]['status']=='DONE' for d in t['depends_on'])
    print(f"Status: {t['status']}; Ausführung {'freigegeben' if allowed else 'NICHT freigegeben'}; Karte SHA256 {sha(card)}")
    print(card.read_text());return 0


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError,IndexError,AttributeError) as exc:
        print(f'FEHLER: {exc}',file=sys.stderr);sys.exit(1)
