"""Crash-safe restore of an archive package from static read-only replicas.

A restore plan (JSON) names the trusted manifest, an ordered list of static
replica directories (each replica is itself a payload root), the final target
directory and a private state directory. Every relative plan path is resolved
against the plan file's directory.

The package is assembled entirely inside the state directory. Payload bytes
are copied in bounded chunks from the first replica, in order, that offers an
ordinary file whose size and SHA256 match the manifest entry; missing files,
corrupt files, links and other non-regular entries simply fall through to the
next replica. A per-entry receipt records which replica supplied the bytes.
A journal inside the state directory tracks completed entries; a resume always
re-verifies journaled bytes from the disk instead of trusting the log. Only
after the whole staged package is re-verified is it renamed, within one file
system, onto a target path that does not yet exist. An unjournaled but intact
package already present at the target is recognized as this run's product and
reported as idempotent success; any other existing target is refused.

Single operator, standard library only. Replicas are assumed static and
read-only; there is no defence against a concurrent malicious file swap.
"""
from pathlib import Path
import hashlib, json, os, shutil, stat, tempfile
from .common import require, ident, read
from .files import relative
from .model import validate_entries

MAX_FILE=8_000_000
MAX_TOTAL=32_000_000
CHUNK=65_536
MAX_REPLICAS=64
STATE_DIRNAME='.restore-state'
JOURNAL_NAME='journal.json'
RECEIPTS_NAME='receipts.json'
PACKAGE_NAME='package'
PAYLOAD_NAME='payload'
PART_SUFFIX='.part'


class RestoreError(ValueError):
    """A restore contract violation, topology failure or unfixable source gap."""


def _no_symlink_chain(path):
    """No existing segment of an absolute path may be a symlink."""
    current=Path(path.anchor)
    for part in path.parts[1:]:
        current=current/part
        if current.is_symlink():
            raise RestoreError('path traverses a symlink: '+str(current))
    return path


def _ensure_plain_dir(path):
    """Create a directory, refusing any symlinked segment on the way."""
    _no_symlink_chain(path)
    path.mkdir(parents=True,exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise RestoreError('state path is not a plain directory: '+str(path))


def _inside(child,parent):
    try:path=Path(child).resolve()
    except OSError:return False
    return path==parent or parent in path.parents


def _plan_path(value,base,label,must_exist_kind=None):
    if not isinstance(value,str) or not value:
        raise RestoreError('plan field must be a non-empty path: '+label)
    candidate=Path(value)
    if candidate.is_absolute():
        resolved=candidate
    else:
        ident(value);relative(value);resolved=base/candidate
    _no_symlink_chain(resolved)
    resolved=resolved.resolve()
    if must_exist_kind=='file':
        if not resolved.exists() or resolved.is_symlink() or not resolved.is_file():
            raise RestoreError(label+' must be an existing regular file')
    elif must_exist_kind=='dir':
        if not resolved.exists() or resolved.is_symlink() or not resolved.is_dir():
            raise RestoreError(label+' must be an existing directory without symlinks')
    return resolved


def _load_plan(plan_path):
    plan_path=Path(plan_path).resolve()
    if plan_path.is_symlink() or not plan_path.is_file():
        raise RestoreError('restore plan must be an existing regular file')
    try:
        data,digest=read(plan_path)
        require(data,'manifest replicas target state')
        base=plan_path.parent
        manifest=_plan_path(data['manifest'],base,'manifest','file')
        if not isinstance(data['replicas'],list) or not data['replicas'] or len(data['replicas'])>MAX_REPLICAS:
            raise RestoreError('replicas must be an ordered array of 1..%d directories'%MAX_REPLICAS)
        replicas=[]
        for i,item in enumerate(data['replicas']):
            replica=_plan_path(item,base,'replicas[%d]'%i,'dir')
            if replica in replicas:raise RestoreError('duplicate replica directory')
            replicas.append(replica)
        target=_plan_path(data['target'],base,'target')
        state=_plan_path(data['state'],base,'state')
        # The plan file itself must never be placed where the run would write.
        for written in (target,state):
            if plan_path==written or _inside(plan_path,written):
                raise RestoreError('plan file must stay outside target and state directories')
        # Input tree = manifest directory plus every replica tree. Target and
        # state must be outside all of them, and must not contain one another.
        input_roots=[manifest.parent]+replicas
        for root in input_roots:
            if _inside(target,root):raise RestoreError('target must be outside the input tree')
            if _inside(state,root):raise RestoreError('state must be outside the input tree')
        if target==state or _inside(target,state) or _inside(state,target):
            raise RestoreError('target and state must be separate, neither containing the other')
        manifest_data,manifest_digest=read(manifest)
        expected,total=validate_entries(manifest_data)
    except RestoreError:
        raise
    except ValueError as e:
        raise RestoreError(str(e)) from e
    identity={'manifest_sha256':manifest_digest,'plan_sha256':digest,
              'target':os.path.abspath(str(target)),
              'replicas':[os.path.abspath(str(r)) for r in replicas]}
    return {'plan_path':plan_path,'plan_sha256':digest,'manifest':manifest,
            'manifest_data':manifest_data,'manifest_sha256':manifest_digest,
            'replicas':replicas,'target':target,'state':state,
            'expected':expected,'total':total,'identity':identity}


def _eval_candidate(path,entry):
    """Return (size, digest) for a qualifying ordinary source file, else None.

    Every rejection reason (missing, link, special file, wrong size, digest
    mismatch, I/O failure, capacity breach) simply means this replica does not
    qualify, so the caller may try the next replica in order.
    """
    try:
        st=path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):return None
    if st.st_size!=entry['bytes'] or st.st_size>MAX_FILE:return None
    digest=hashlib.sha256();count=0
    try:
        with path.open('rb') as stream:
            while True:
                chunk=stream.read(CHUNK)
                if not chunk:break
                count+=len(chunk)
                if count>MAX_FILE:return None
                digest.update(chunk)
    except OSError:
        return None
    if count!=entry['bytes'] or digest.hexdigest()!=entry['sha256']:return None
    return count,digest.hexdigest()


def _find_source(plan,name):
    """First ordered replica holding a size/digest-matching ordinary file."""
    entry=plan['expected'][name]
    parts=relative(name)
    for index,replica in enumerate(plan['replicas']):
        path=replica.joinpath(*parts)
        found=_eval_candidate(path,entry)
        if found is not None:
            return {'index':index,'root':str(replica),'path':str(path),
                    'bytes':found[0],'sha256':found[1]}
    raise RestoreError('no qualifying replica source for manifest entry: '+name)


def _fsync_dir(path):
    try:
        fd=os.open(str(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    except OSError:return
    try:os.fsync(fd)
    except OSError:pass
    finally:os.close(fd)


def _atomic_write_json(path,payload):
    dest=Path(path)
    fd,temp=tempfile.mkstemp(dir=str(dest.parent),prefix=dest.name+'.',suffix='.tmp')
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(payload,stream,sort_keys=True,ensure_ascii=False,allow_nan=False,indent=2)
            stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temp,dest);_fsync_dir(dest.parent)
    except BaseException:
        if os.path.exists(temp):
            try:os.unlink(temp)
            except OSError:pass
        raise


def _load_journal(plan):
    journal_path=plan['state']/STATE_DIRNAME/JOURNAL_NAME
    if not journal_path.exists():return None
    try:
        data,_=read(journal_path)
        require(data,'identity published entries')
        if data['identity']!=plan['identity']:
            raise RestoreError('state identity mismatch: manifest, target or ordered replicas changed; refusing to resume')
        if not isinstance(data['published'],bool) or not isinstance(data['entries'],dict):
            raise RestoreError('malformed restore journal')
        for name,record in data['entries'].items():
            require(record,'path bytes sha256 source')
            if record['path']!=name or name not in plan['expected']:
                raise RestoreError('journal entry not bound to the current manifest')
            require(record['source'],'index root path bytes sha256')
        if set(data['entries'])-set(plan['expected']):
            raise RestoreError('journal names entries absent from the manifest')
    except RestoreError:
        raise
    except ValueError as e:
        raise RestoreError('malformed restore journal: '+str(e)) from e
    return data


def _hash_file(path):
    digest=hashlib.sha256();count=0
    with Path(path).open('rb') as stream:
        while True:
            chunk=stream.read(CHUNK)
            if not chunk:break
            count+=len(chunk)
            if count>MAX_FILE:raise RestoreError('staged file exceeds 8 MB')
            digest.update(chunk)
    return count,digest.hexdigest()


def _verify_staged(plan,path,name):
    """Byte-level re-verification of a staged file against the manifest."""
    entry=plan['expected'][name]
    try:count,digest=_hash_file(path)
    except OSError:return False
    return count==entry['bytes'] and digest==entry['sha256']


def _copy_chunked(src_path,dest_path,entry,name,barrier):
    """Bounded chunk copy; the bytes written are counted as they land."""
    fd,temp=tempfile.mkstemp(dir=str(dest_path.parent),prefix=dest_path.name+'.',suffix=PART_SUFFIX)
    written=0
    try:
        with os.fdopen(fd,'wb') as out,Path(src_path).open('rb') as src:
            while written<entry['bytes']:
                chunk=src.read(CHUNK)
                if not chunk:break
                out.write(chunk);written+=len(chunk)
                if barrier is not None:barrier('copy_chunk',name)
            out.flush();os.fsync(out.fileno())
        if written!=entry['bytes']:
            raise RestoreError('source length changed while copying: '+name)
        os.replace(temp,dest_path);_fsync_dir(dest_path.parent)
    except BaseException:
        if os.path.exists(temp):
            try:os.unlink(temp)
            except OSError:pass
        raise
    return written


def _clean_partials(payload):
    """Remove chunk-copy temp files left by an earlier interrupted run."""
    for current,dirs,names in os.walk(payload,followlinks=False):
        base=Path(current)
        for name in names:
            if name.endswith(PART_SUFFIX):
                try:(base/name).unlink()
                except FileNotFoundError:pass


def _walk_payload(root):
    files=[]
    for current,dirs,names in os.walk(root,followlinks=False):
        base=Path(current)
        for d in dirs:
            if (base/d).is_symlink():raise RestoreError('package must not contain symlinks')
        for name in names:
            path=base/name
            if path.is_symlink() or not path.is_file():
                raise RestoreError('package must contain ordinary files only')
            files.append(path)
    return sorted(files)


def _verify_package(plan,package,receipts):
    """Whole-package re-verification before publication."""
    payload=package/PAYLOAD_NAME
    if not payload.is_dir() or payload.is_symlink():
        raise RestoreError('staged payload directory missing or unsafe')
    staged={p.relative_to(payload).as_posix():p for p in _walk_payload(payload)}
    if set(staged)!=set(plan['expected']):
        raise RestoreError('staged payload does not match the manifest entry set')
    by_name={r['path']:r for r in receipts}
    if set(by_name)!=set(plan['expected']):
        raise RestoreError('receipts do not cover exactly the manifest entries')
    for name in sorted(plan['expected']):
        entry=plan['expected'][name];count,digest=_hash_file(staged[name])
        if count!=entry['bytes'] or digest!=entry['sha256']:
            raise RestoreError('staged byte verification failed: '+name)
        receipt=by_name[name]
        if receipt['bytes']!=entry['bytes'] or receipt['sha256']!=entry['sha256']:
            raise RestoreError('receipt does not match the manifest: '+name)
        source=receipt['source']
        if source['root'] not in plan['identity']['replicas']:
            raise RestoreError('receipt names a replica outside the ordered list: '+name)
        if _eval_candidate(Path(source['path']),entry) is None:
            raise RestoreError('receipt source no longer qualifies: '+name)


def _recognize_target(plan):
    """Identify this run's complete product at an existing target, else refuse."""
    target=plan['target']
    if target.is_symlink() or not target.is_dir():
        raise RestoreError('target exists and is not a directory; refusing to overwrite')
    payload=target/PAYLOAD_NAME;receipts_path=target/RECEIPTS_NAME
    if payload.is_symlink() or not payload.is_dir() or receipts_path.is_symlink() or not receipts_path.is_file():
        raise RestoreError('target holds another directory layout; refusing to overwrite')
    try:
        receipts,_=read(receipts_path)
        if not isinstance(receipts,list):raise RestoreError('bad receipts')
        _verify_package(plan,target,receipts)
    except (ValueError,OSError,KeyError) as e:
        raise RestoreError('target holds an unrecognized or incomplete directory; refusing to overwrite') from e
    return receipts


def restore(plan_path,barrier=None):
    """Run (or idempotently resume) one restore; return a JSON-ready summary."""
    plan=_load_plan(plan_path)
    _ensure_plain_dir(plan['state'])
    work=plan['state']/STATE_DIRNAME;package=work/PACKAGE_NAME;payload=package/PAYLOAD_NAME
    journal_path=work/JOURNAL_NAME;receipts_path=package/RECEIPTS_NAME
    journal=_load_journal(plan)
    resumed=journal is not None

    if journal is not None and journal['published'] and plan['target'].exists():
        receipts=_recognize_target(plan)
        return _summary(plan,receipts,resumed=True,recognized=True)

    if journal is None or not package.is_dir() or not payload.is_dir():
        # No usable staging yet (fresh run, or a published product whose
        # target and staging are both gone): rebuild staging inside the same
        # state directory, keeping the bound identity.
        if work.exists():shutil.rmtree(work)
        work.mkdir(parents=True);payload.mkdir(parents=True)
        journal={'identity':plan['identity'],'published':False,'entries':{}}
        _atomic_write_json(journal_path,journal)
    _clean_partials(payload)

    for name in sorted(plan['expected']):
        staged=payload.joinpath(*relative(name))
        if name in journal['entries']:
            # The log never substitutes for byte verification.
            if staged.is_symlink() or not staged.is_file() or not _verify_staged(plan,staged,name):
                if staged.is_symlink() or staged.is_file():staged.unlink()
                del journal['entries'][name]
                _atomic_write_json(journal_path,journal)
            else:
                if barrier is not None:barrier('resume_verified',name)
                continue
        # An unjournaled file at this path is an unaccounted remnant: never
        # trust it, remove it and fetch fresh bytes from an ordered replica.
        if staged.is_symlink() or staged.is_file():staged.unlink()
        source=_find_source(plan,name)
        if barrier is not None:barrier('before_copy',name)
        staged.parent.mkdir(parents=True,exist_ok=True)
        written=_copy_chunked(source['path'],staged,plan['expected'][name],name,barrier)
        if not _verify_staged(plan,staged,name):
            staged.unlink(missing_ok=True)
            raise RestoreError('copied bytes failed verification: '+name)
        if barrier is not None:barrier('file_unjournaled',name)
        receipt={'path':name,'bytes':written,'sha256':plan['expected'][name]['sha256'],
                 'source':{'index':source['index'],'root':source['root'],
                           'path':source['path'],'bytes':source['bytes'],
                           'sha256':source['sha256']}}
        journal['entries'][name]=receipt
        _atomic_write_json(journal_path,journal)  # file complete and now accounted
        if barrier is not None:barrier('after_journal',name)

    receipts=[journal['entries'][n] for n in sorted(journal['entries'])]
    _atomic_write_json(receipts_path,receipts)
    _verify_package(plan,package,receipts)  # whole-package re-verification

    target=plan['target']
    if target.exists():
        # Crash after rename but before the journal was marked published.
        receipts=_recognize_target(plan)
        journal['published']=True;_atomic_write_json(journal_path,journal)
        return _summary(plan,receipts,resumed=resumed,recognized=True)
    if target.is_symlink():
        raise RestoreError('target cannot be a symlink')
    _ensure_plain_dir(target.parent)
    try:
        same=os.stat(target.parent).st_dev==os.stat(package).st_dev
    except OSError as e:
        raise RestoreError('cannot compare target and staging file systems') from e
    if not same:
        raise RestoreError('target and state must reside on the same file system')
    if barrier is not None:barrier('before_publish','')
    try:
        os.rename(package,target)  # same file system, atomic, target does not exist
    except OSError as e:
        # EXDEV or a late-appearing target: staging stays intact in the state
        # directory so the operator can correct the plan and resume.
        raise RestoreError('atomic publication failed: '+str(e)) from e
    _fsync_dir(target.parent)
    if barrier is not None:barrier('publish_unjournaled','')
    journal['published']=True;_atomic_write_json(journal_path,journal)
    if barrier is not None:barrier('after_publish','')
    return _summary(plan,receipts,resumed=resumed,recognized=False)


def _summary(plan,receipts,resumed,recognized):
    return {'schema_version':1,'identity':plan['identity'],
            'target':os.path.abspath(str(plan['target'])),
            'files':len(plan['expected']),'bytes':plan['total'],
            'receipts':receipts,'resumed':resumed,'recognized_existing':recognized}
