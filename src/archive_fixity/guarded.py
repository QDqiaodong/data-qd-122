"""Guarded capture for a payload tree that may be rewritten during verification.

The manifest directory is trusted and immutable; the payload tree is not.
Every path step is taken through an anchored descriptor opened with O_NOFOLLOW,
so symlinks are never followed. Regular files are opened O_NONBLOCK so a FIFO
or other special file can never block the reader. Descriptor fingerprints
(path, type, device, inode, size, nanosecond mtime/ctime) are snapshotted for
the whole tree before and after capture and compared per file around each read.

Only the listed observations are guaranteed: a stable report means no observed
mutation between the snapshots, not that a write could not happen and be
reverted between samples.
"""
from pathlib import Path
import errno, hashlib, os, stat
from .files import relative
from .model import validate

MAX_FILE=8_000_000
MAX_TOTAL=32_000_000
MAX_ENTRIES=5000
READ_CHUNK=65536
_NOFOLLOW=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
# O_NONBLOCK on directory descriptors is harmless on regular directories but
# stops an intermediate segment swapped for a FIFO from blocking the open.
_DIR_FLAGS=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
if hasattr(os,'O_DIRECTORY'):_DIR_FLAGS|=os.O_DIRECTORY


class GuardInstability(ValueError):
    """Observed mutation or I/O failure while guarding the payload tree."""


def _fp(st):
    return (stat.S_IFMT(st.st_mode),st.st_dev,st.st_ino,st.st_size,
            st.st_mtime_ns,st.st_ctime_ns)


class TreeGuard:
    """Anchored, symlink-safe, non-blocking capture of one payload tree."""

    def __init__(self,base,payload_root):
        relative(payload_root)
        self.base=Path(base);self.parts=payload_root.split('/')
        # Anchor the trusted manifest directory itself, then each payload
        # root segment with O_NOFOLLOW so the root chain cannot be swapped
        # to a symlink underneath us.
        self.fds=[]
        try:
            self.fds.append(os.open(self.base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)))
            for part in self.parts:
                self.fds.append(self._open_dir(part,self.fds[-1]))
        except BaseException:
            self.close();raise
        self.root_fd=self.fds[-1]
        st=os.fstat(self.root_fd)
        self.root_identity=(st.st_dev,st.st_ino)
        # Re-stat every root chain segment by name from the previous anchor.
        # If a segment is replaced later its name-based fingerprint changes
        # even though our held descriptor still points at the old inode.
        self.chain_refs=self._root_chain_stats()

    def close(self):
        while self.fds:
            fd=self.fds.pop()
            try:os.close(fd)
            except OSError:pass

    def __enter__(self):return self
    def __exit__(self,*exc):self.close();return False

    def _open_dir(self,name,dir_fd):
        try:return os.open(name,_DIR_FLAGS,dir_fd=dir_fd)
        except OSError as e:
            if e.errno==errno.ENOENT:raise ValueError('payload root must exist') from e
            if e.errno==errno.ELOOP or self._is_link(dir_fd,name):
                raise ValueError('payload root cannot use symlinks') from e
            if e.errno in (errno.ENOTDIR,errno.EISDIR):
                raise ValueError('payload root must exist') from e
            raise

    @staticmethod
    def _is_link(dir_fd,name):
        try:return stat.S_ISLNK(os.stat(name,dir_fd=dir_fd,follow_symlinks=False).st_mode)
        except OSError:return False

    def _root_chain_stats(self):
        refs=[]
        for parent_fd,fd,name in zip(self.fds[:-1],self.fds[1:],self.parts):
            refs.append((parent_fd,name,_fp(os.stat(name,dir_fd=parent_fd,follow_symlinks=False))))
        return refs

    def check_root_chain(self):
        """Detect replacement or mutation of any payload-root path segment."""
        for parent_fd,name,ref in self.chain_refs:
            try:now=_fp(os.stat(name,dir_fd=parent_fd,follow_symlinks=False))
            except OSError as e:
                raise GuardInstability('payload root path changed: '+name) from e
            if now!=ref:raise GuardInstability('payload root path changed: '+name)
        st=os.fstat(self.root_fd)
        if (st.st_dev,st.st_ino)!=self.root_identity:
            raise GuardInstability('payload root descriptor changed')

    def snapshot(self):
        """Fingerprint the root path and every tree entry without following links."""
        self.check_root_chain()
        entries={};stack=[('',self.root_fd)];owned=[]
        try:
            while stack:
                rel,dir_fd=stack.pop()
                with os.scandir(dir_fd) as it:
                    for entry in it:
                        name=rel+'/'+entry.name if rel else entry.name
                        try:st=entry.stat(follow_symlinks=False)
                        except OSError as e:
                            raise GuardInstability('cannot stat payload entry: '+name) from e
                        if name in entries:raise GuardInstability('duplicate payload entry: '+name)
                        entries[name]=_fp(st)
                        if len(entries)>MAX_ENTRIES:
                            raise ValueError('inventory exceeds %d entries'%MAX_ENTRIES)
                        if stat.S_ISDIR(st.st_mode):
                            try:child=os.open(entry.name,_DIR_FLAGS,dir_fd=dir_fd)
                            except OSError as e:
                                if e.errno==errno.ELOOP:continue
                                raise GuardInstability('cannot open payload directory: '+name) from e
                            stack.append((name,child));owned.append(child)
        finally:
            for fd in reversed(owned):
                try:os.close(fd)
                except OSError:pass
        return entries

    @staticmethod
    def require_unchanged(before,after,label):
        if before!=after:
            for name in sorted(set(before)|set(after)):
                if before.get(name)!=after.get(name):
                    raise GuardInstability('payload tree %s: observed change at %s'%(label,name))
            raise GuardInstability('payload tree %s changed'%label)

    def inspect(self,name,barrier=None):
        """Resolve one manifest entry segment by segment, never following links."""
        parts=relative(name);dir_fd=self.root_fd;opened=[]
        try:
            for i,part in enumerate(parts):
                last=i==len(parts)-1
                if not last:
                    try:
                        st=os.stat(part,dir_fd=dir_fd,follow_symlinks=False)
                    except FileNotFoundError:return {'status':'missing'}
                    except OSError as e:
                        if e.errno==errno.ELOOP:return {'status':'unsafe_link'}
                        raise
                    if stat.S_ISLNK(st.st_mode):return {'status':'unsafe_link'}
                    if not stat.S_ISDIR(st.st_mode):return {'status':'non_directory_parent'}
                    try:dir_fd=os.open(part,_DIR_FLAGS,dir_fd=dir_fd)
                    except OSError as e:
                        if e.errno==errno.ELOOP:return {'status':'unsafe_link'}
                        if e.errno==errno.ENOENT:return {'status':'missing'}
                        raise
                    opened.append(dir_fd);continue
                try:
                    st=os.stat(part,dir_fd=dir_fd,follow_symlinks=False)
                except FileNotFoundError:return {'status':'missing'}
                except OSError as e:
                    if e.errno==errno.ELOOP:return {'status':'unsafe_link'}
                    raise
                if stat.S_ISLNK(st.st_mode):return {'status':'unsafe_link'}
                if not stat.S_ISREG(st.st_mode):return {'status':'not_regular_file'}
                if st.st_size>MAX_FILE:raise ValueError('payload file exceeds 8 MB')
                before=_fp(st)
                try:fd=os.open(part,_NOFOLLOW,dir_fd=dir_fd)
                except OSError as e:
                    if e.errno==errno.ELOOP:return {'status':'unsafe_link'}
                    if e.errno==errno.ENOENT:return {'status':'missing'}
                    raise
                opened.append(fd)
                fst=os.fstat(fd)
                if (fst.st_dev,fst.st_ino)!=(st.st_dev,st.st_ino):
                    raise GuardInstability('payload file swapped before read: '+name)
                if not stat.S_ISREG(fst.st_mode):return {'status':'not_regular_file'}
                try:
                    digest,count=self._read(fd,name,barrier)
                    after=_fp(os.fstat(fd))
                    if after!=before:
                        raise GuardInstability('payload file changed during read: '+name)
                    if count!=st.st_size:
                        raise GuardInstability('payload file actual length changed: '+name)
                    return {'status':'read','actual_bytes':count,'actual_sha256':digest.hexdigest()}
                finally:
                    os.close(opened.pop())
        finally:
            for fd in reversed(opened):
                try:os.close(fd)
                except OSError:pass

    def _read(self,fd,name,barrier):
        digest=hashlib.sha256();count=0;chunks=0
        while True:
            try:chunk=os.read(fd,READ_CHUNK)
            except BlockingIOError as e:
                raise GuardInstability('non-blocking read failed: '+name) from e
            if not chunk:break
            count+=len(chunk);chunks+=1
            if count>MAX_FILE:raise ValueError('payload exceeds read bound')
            digest.update(chunk)
            if chunks==1 and barrier is not None:
                barrier('read_chunk',name)
        return digest,count


def audit_guarded(data,base,barrier=None):
    root,expected,_total=validate(data,base)
    payload_root=data['payload_root']
    with TreeGuard(base,payload_root) as guard:
        before=guard.snapshot()
        results=[];captured=0
        for name,e in sorted(expected.items()):
            actual=guard.inspect(name,barrier)
            captured+=actual.get('actual_bytes',0)
            if captured>MAX_TOTAL:raise ValueError('captured payload total exceeds 32 MB')
            if actual['status']=='read':
                failures=[]
                if actual['actual_bytes']!=e['bytes']:failures.append('size_mismatch')
                if actual['actual_sha256']!=e['sha256']:failures.append('digest_mismatch')
                actual['status']='mismatch' if failures else 'verified';actual['differences']=failures
            results.append({'path':name,'expected_bytes':e['bytes'],'expected_sha256':e['sha256'],**actual})
            if barrier is not None:barrier('after_file',name)
        if barrier is not None:barrier('pre_final_snapshot','')
        after=guard.snapshot()
        TreeGuard.require_unchanged(before,after,'capture')
    extras=[]
    for name in sorted(after):
        ftype=after[name][0]
        if stat.S_ISDIR(ftype) or name in expected:continue
        extras.append({'path':name,'is_link':stat.S_ISLNK(ftype),'is_directory':False})
    counts={status:sum(r['status']==status for r in results) for status in sorted({r['status'] for r in results})}
    return {'files':results,'status_counts':counts,'unlisted_entries':extras,
            'manifest_files':len(expected),'captured_bytes':captured,
            'all_manifest_files_verified':all(r['status']=='verified' for r in results),
            'inventory_clean':not extras and all(r['status']=='verified' for r in results),
            'observed_stable':True}
