import argparse,json,sys
from pathlib import Path
from .common import read,save,require
from .files import relative
from .model import audit
from .guarded import audit_guarded

def run(source,capture_mode='static'):
    if capture_mode not in ('static','guarded'):raise ValueError('capture mode must be static or guarded')
    source=Path(source);data,digest=read(source)
    result=audit_guarded(data,source.parent) if capture_mode=='guarded' else audit(data,source.parent)
    report={'schema_version':1,'source_sha256':digest,'result':result}
    if capture_mode=='guarded':report['capture_mode']='guarded'
    return report

def main():
    p=argparse.ArgumentParser(description='Read-only fixity audit of a local archive')
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--capture-mode',choices=('static','guarded'),default='static',
                   help='static (default): original contract; guarded: observe a mutable payload tree')
    a=p.parse_args();report=None
    try:
        if a.source.is_symlink() or a.source.resolve()==a.output.resolve():raise ValueError('unsafe source/output')
        data,digest=read(a.source)
        require(data,'payload_root entries');relative(data['payload_root'])
        root=(a.source.parent/data['payload_root']).resolve();target=a.output.resolve()
        if target==root or root in target.parents:raise ValueError('report must stay outside the read-only payload tree')
        if a.capture_mode=='static':
            result=audit(data,a.source.parent)
        else:
            result=audit_guarded(data,a.source.parent)
        report={'schema_version':1,'source_sha256':digest,'result':result}
        if a.capture_mode=='guarded':report['capture_mode']='guarded'
        save(a.output,report)
    except (ValueError,TypeError,KeyError,OSError,OverflowError,RecursionError) as e:
        print(str(e),file=sys.stderr);return 2
    print(json.dumps(report,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
