"""Static local archive paths; no links, external mounts or mutable-file guarantees."""
from pathlib import Path
import hashlib,os,stat
from .common import ident

def relative(name):
    ident(name);parts=name.split('/')
    if name.startswith('/') or any(p in ('','.','..') for p in parts) or '\\' in name:
        raise ValueError('archive path must be canonical relative POSIX path')
    return parts

def inspect(root,name):
    parts=relative(name);path=root
    for i,part in enumerate(parts):
        path=path/part
        try:mode=path.lstat().st_mode
        except FileNotFoundError:return {'status':'missing'}
        if stat.S_ISLNK(mode):return {'status':'unsafe_link'}
        if i<len(parts)-1 and not stat.S_ISDIR(mode):return {'status':'non_directory_parent'}
    if not stat.S_ISREG(mode):return {'status':'not_regular_file'}
    if path.stat().st_size>8_000_000:raise ValueError('payload file exceeds 8 MB')
    digest=hashlib.sha256();count=0
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(65536),b''):
            count+=len(chunk)
            if count>8_000_000:raise ValueError('payload exceeds read bound')
            digest.update(chunk)
    return {'status':'read','actual_bytes':count,'actual_sha256':digest.hexdigest()}

def inventory(root):
    result=[]
    for current,dirs,files in os.walk(root,followlinks=False):
        base=Path(current)
        for name in sorted(dirs+files):
            path=base/name
            result.append({'path':path.relative_to(root).as_posix(),'is_link':path.is_symlink(),'is_directory':path.is_dir() and not path.is_symlink()})
            if len(result)>5000:raise ValueError('inventory exceeds 5000 entries')
        dirs[:]=sorted(d for d in dirs if not (base/d).is_symlink())
    return sorted(result,key=lambda r:r['path'])
