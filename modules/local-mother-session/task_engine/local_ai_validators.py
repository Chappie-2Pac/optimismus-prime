"""Read-only, bounded evidence checks; these do not prove prose or compiler behavior.

Opt in with task.validator = toolchain-v1 or sources-v1. Exactly one required
artifact ending in .json is the manifest. The report is acceptance_result or
result, relative to Plan/local-ai, and must be a nonempty UTF-8 regular file.

toolchain-v1 manifest: compiler (absolute path), compiler_sha256; assembler,
linker, host_loader, target_loader each {path: absolute, sha256}; sysroot
(absolute existing directory); nonempty cflags/ldflags string arrays, cflags
containing --sysroot=<sysroot>; env nonempty string mapping without variable
placeholders; provenance nonempty array of {path: absolute, sha256, kind}, with
at least header, crt, libc. Optional helpers is an array of absolute project
work paths; each needs a matching helper provenance entry. Helper provenance
must remain in project work. Flags -EL and generic+aarch64 are rejected.

sources-v1 manifest: sources array (1..5) of {path,sha256}; search object with
root (existing absolute directory), scope (nonempty string), limits (nonempty
string describing time/scope limits); conclusions nonempty array of {claim,
status: observed|not_evidenced, source_indices: zero-based integer array}.
Observed claims require a source; not_evidenced expresses a search limitation,
not global absence. Optional global_absence must be false. Free prose remains
subject to independent review; the validator cannot establish its truth.

JSON/report size <=1 MiB; each hashed regular file <=256 MiB. No commands run.
Paths may resolve symlinks (Yocto uses them); devices/FIFOs are never read.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_FILE = 256 * 1024 * 1024
MAX_TEXT = 1024 * 1024


def _read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(f'{path}: requires regular file <= {limit} bytes')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f'{path}: size limit exceeded')
        return data
    finally:
        os.close(fd)


def _string(value, label):
    if not isinstance(value, str) or not value.strip() or '\x00' in value:
        raise ValueError(f'{label}: nonempty string required')
    return value


def _path(root, value, absolute=False):
    path = Path(_string(value, 'path'))
    if absolute and not path.is_absolute():
        raise ValueError(f'{path}: absolute path required')
    if not path.is_absolute():
        if '..' in path.parts:
            raise ValueError('relative path must not escape project')
        path = root / path
    return path


def _bound(root, entry, absolute=False):
    if not isinstance(entry, dict):
        raise ValueError('file binding requires path and sha256')
    path = _path(root, entry.get('path'), absolute)
    digest = entry.get('sha256')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError(f'{path}: lowercase SHA256 required')
    if hashlib.sha256(_read(path, MAX_FILE)).hexdigest() != digest:
        raise ValueError(f'{path}: SHA256 mismatch')
    return path.resolve()


def _toolchain(root, data):
    _bound(root, {'path': data.get('compiler'), 'sha256': data.get('compiler_sha256')}, True)
    for field in ('assembler', 'linker', 'host_loader', 'target_loader'):
        _bound(root, data.get(field), True)
    sysroot = _path(root, data.get('sysroot'), True)
    if not sysroot.is_dir():
        raise ValueError('sysroot: existing directory required')
    for field in ('cflags', 'ldflags'):
        flags = data.get(field)
        if not isinstance(flags, list) or not flags or any(not isinstance(x, str) or not x.strip() for x in flags):
            raise ValueError(f'{field}: nonempty string array required')
        if any(x == '-EL' or 'generic+aarch64' in x for x in flags):
            raise ValueError(f'{field}: invalid inherited GCC flag')
    if f'--sysroot={sysroot}' not in data['cflags']:
        raise ValueError('cflags: explicit --sysroot=<sysroot> required')
    env = data.get('env')
    if not isinstance(env, dict) or not env or any(not isinstance(k, str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', k) or not isinstance(v, str) or '$' in v or '\x00' in v for k, v in env.items()):
        raise ValueError('env: explicit string values without variable placeholders required')
    provenance = data.get('provenance')
    if not isinstance(provenance, list) or not 1 <= len(provenance) <= 256:
        raise ValueError('provenance: 1..256 bindings required')
    kinds, helper_paths = set(), set()
    for item in provenance:
        path = _bound(root, item, True)
        kind = _string(item.get('kind'), 'provenance.kind')
        kinds.add(kind)
        if kind == 'helper':
            if not path.is_relative_to((root / 'work').resolve()):
                raise ValueError('helper must be within project work directory')
            helper_paths.add(path)
    if not {'header', 'crt', 'libc'} <= kinds:
        raise ValueError('provenance: header, crt and libc bindings required')
    helpers = data.get('helpers', [])
    if not isinstance(helpers, list) or len(helpers) > 256:
        raise ValueError('helpers: bounded path array required')
    for helper in helpers:
        if _path(root, helper, True).resolve() not in helper_paths:
            raise ValueError('helpers: matching helper provenance required')


def _sources(root, data):
    sources = data.get('sources')
    if not isinstance(sources, list) or not 1 <= len(sources) <= 5:
        raise ValueError('sources: 1..5 bindings required')
    for source in sources:
        _bound(root, source)
    search = data.get('search')
    if not isinstance(search, dict):
        raise ValueError('search: root, scope and limits required')
    if not _path(root, search.get('root'), True).is_dir():
        raise ValueError('search.root: existing directory required')
    _string(search.get('scope'), 'search.scope')
    _string(search.get('limits'), 'search.limits')
    conclusions = data.get('conclusions')
    if not isinstance(conclusions, list) or not 1 <= len(conclusions) <= 64:
        raise ValueError('conclusions: 1..64 entries required')
    for conclusion in conclusions:
        if not isinstance(conclusion, dict):
            raise ValueError('conclusion: object required')
        _string(conclusion.get('claim'), 'conclusion.claim')
        status = conclusion.get('status')
        indices = conclusion.get('source_indices')
        if status not in ('observed', 'not_evidenced') or conclusion.get('global_absence', False) is not False:
            raise ValueError('conclusion: observed/not_evidenced only; global absence is not supported')
        if not isinstance(indices, list) or any(type(x) is not int or not 0 <= x < len(sources) for x in indices):
            raise ValueError('conclusion.source_indices: valid source indices required')
        if status == 'observed' and not indices:
            raise ValueError('observed conclusion requires source indices')
    if data.get('global_absence', False) is not False:
        raise ValueError('global absence is not supported')


def validate(root, task):
    """Return errors; unconfigured cards are left to their existing review gates."""
    validator = task.get('validator')
    if validator is None:
        return []
    try:
        if validator not in ('toolchain-v1', 'sources-v1'):
            raise ValueError(f'unknown validator: {validator}')
        root = Path(root).resolve()
        report = task.get('acceptance_result') or task.get('result')
        report_path = _path(root / 'Plan/local-ai', report)
        if not _read(report_path, MAX_TEXT).decode('utf-8').strip():
            raise ValueError('nonempty report required')
        artifacts = task.get('required_artifacts', [])
        manifests = [x for x in artifacts if isinstance(x, str) and x.endswith('.json')]
        if len(manifests) != 1:
            raise ValueError('exactly one required JSON manifest required')
        data = json.loads(_read(_path(root, manifests[0]), MAX_TEXT))
        if not isinstance(data, dict):
            raise ValueError('manifest must be a JSON object')
        (_toolchain if validator == 'toolchain-v1' else _sources)(root, data)
        return []
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return [f"{task.get('id', '?')}: {validator}: {exc}"]
