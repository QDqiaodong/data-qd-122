"""Test-only subprocess helper: crash a restore at a deterministic fault point.

Not part of the packaged CLI. The barrier raises inside the restore pipeline
so an interrupted process leaves real on-disk state (staged files, journal and
possibly an unjournaled published package); the test suite then resumes with
the ordinary CLI.
"""
import argparse,hashlib,json,os
from pathlib import Path
from archive_fixity.restore import restore

SCENARIOS=('copy_chunk','file_unjournaled','publish_unjournaled')


class CrashInjected(RuntimeError):pass


def sha(body):return hashlib.sha256(body).hexdigest()


def write_tree(root,files):
    for name,body in files.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--base',required=True);ap.add_argument('--scenario',required=True,choices=SCENARIOS)
    a=ap.parse_args()
    if a.scenario not in SCENARIOS:raise SystemExit(2)
    base=Path(a.base);base.mkdir(parents=True,exist_ok=True)
    files={'a.txt':b'first file contents'*1000,'sub/b.bin':b'\x00\x01\x02'*500,'empty.txt':b''}
    entries=[{'path':n,'bytes':len(b),'sha256':sha(b)} for n,b in sorted(files.items())]
    manifest_dir=base/'meta';manifest_dir.mkdir()
    manifest=manifest_dir/'manifest.json'
    manifest.write_text(json.dumps({'payload_root':'unused','entries':entries}))
    replicas=[]
    for i in range(2):
        replica=base/('replica%d'%i);replica.mkdir()
        # Replica 0 lacks sub/b.bin so replica 1 must supply it.
        write_tree(replica,{n:b for n,b in files.items() if not (i==0 and n=='sub/b.bin')})
        replicas.append(str(replica))
    plan=base/'plan.json'
    plan.write_text(json.dumps({'manifest':'meta/manifest.json','replicas':replicas,
                                'target':'out/package','state':'work'}))
    fired=set()
    def barrier(event,name):
        key=(event,name)
        if key in fired:return
        if (a.scenario=='copy_chunk' and event=='copy_chunk' and name=='a.txt') or \
           (a.scenario=='file_unjournaled' and event=='file_unjournaled' and name=='a.txt') or \
           (a.scenario=='publish_unjournaled' and event=='publish_unjournaled'):
            fired.add(key);raise CrashInjected('injected at '+event)
    try:
        restore(plan,barrier=barrier)
    except CrashInjected as e:
        print('RESTORE_CRASH:'+str(e));return 3
    print('restore completed without hitting the fault point');return 4


if __name__=='__main__':
    raise SystemExit(main())
