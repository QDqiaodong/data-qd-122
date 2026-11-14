from pathlib import Path
import re
from .common import require,ident,number,rows
from .files import relative,inspect,inventory

def validate(data,base):
    """Shared manifest validation for static and guarded capture modes."""
    require(data,'payload_root entries');relative(data['payload_root']);root=Path(base)
    for part in data['payload_root'].split('/'):
        root=root/part
        if root.is_symlink():raise ValueError('payload root cannot use symlinks')
    if not root.is_dir():raise ValueError('payload root must exist')
    expected={};total=0
    for e in rows(data['entries'],2000):
        require(e,'path bytes sha256');name=e['path'];relative(name);size=number(e['bytes'],0,8_000_000)
        if not isinstance(e['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',e['sha256']):raise ValueError('expected lowercase SHA256')
        if name in expected:raise ValueError('duplicate manifest payload path')
        expected[name]=e;total+=size
    if total>32_000_000:raise ValueError('manifest payload total exceeds 32 MB')
    return root,expected,total

def audit(data,base):
    root,expected,total=validate(data,base)
    captured=0;results=[]
    for name,e in sorted(expected.items()):
        actual=inspect(root,name);captured+=actual.get('actual_bytes',0)
        if captured>32_000_000:raise ValueError('captured payload total exceeds 32 MB')
        if actual['status']=='read':
            failures=[]
            if actual['actual_bytes']!=e['bytes']:failures.append('size_mismatch')
            if actual['actual_sha256']!=e['sha256']:failures.append('digest_mismatch')
            actual['status']='mismatch' if failures else 'verified';actual['differences']=failures
        results.append({'path':name,'expected_bytes':e['bytes'],'expected_sha256':e['sha256'],**actual})
    extras=[e for e in inventory(root) if not e['is_directory'] and e['path'] not in expected]
    counts={status:sum(r['status']==status for r in results) for status in sorted({r['status'] for r in results})}
    return {'files':results,'status_counts':counts,'unlisted_entries':extras,
            'manifest_files':len(expected),'captured_bytes':captured,
            'all_manifest_files_verified':all(r['status']=='verified' for r in results),
            'inventory_clean':not extras and all(r['status']=='verified' for r in results)}

def analyze(data):
    raise ValueError('archive audit requires its manifest directory; use the CLI or audit(data, base)')
