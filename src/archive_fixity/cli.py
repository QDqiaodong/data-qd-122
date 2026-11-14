import argparse,json,sys
from pathlib import Path
from .common import read,save,require
from .model import audit
from .files import relative

def run(source):
    source=Path(source);data,digest=read(source)
    return {'schema_version':1,'source_sha256':digest,'result':audit(data,source.parent)}

def main():
    p=argparse.ArgumentParser(description='Read-only fixity audit of a static local archive')
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        if a.source.is_symlink() or a.source.resolve()==a.output.resolve():raise ValueError('unsafe source/output')
        data,digest=read(a.source);require(data,'payload_root entries');relative(data['payload_root'])
        root=(a.source.parent/data['payload_root']).resolve();target=a.output.resolve()
        if target==root or root in target.parents:raise ValueError('report must stay outside the read-only payload tree')
        report={'schema_version':1,'source_sha256':digest,'result':audit(data,a.source.parent)};save(a.output,report)
    except (ValueError,TypeError,KeyError,OSError,OverflowError,RecursionError) as e:
        print(str(e),file=sys.stderr);return 2
    print(json.dumps(report,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
