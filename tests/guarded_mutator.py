"""Test-only subprocess helper: run a guarded audit with injected mutations.

Not part of the packaged CLI. Scenarios fire at explicit synchronization
barriers inside the capture so the races are deterministic rather than timed.
"""
import argparse,hashlib,json,os
from pathlib import Path
from archive_fixity.guarded import audit_guarded,GuardInstability


def make_manifest(base,payload_root,entries):
    data={'payload_root':payload_root,'entries':entries}
    (Path(base)/'input.json').write_text(json.dumps(data))
    return data


def mutate(scenario,payload,event,name):
    if scenario=='link_swap' and event=='read_chunk' and name=='a.txt':
        target=payload.parent/'outside.txt';target.write_bytes(b'EXTERNAL-SECRET-BYTES')
        victim=payload/'a.txt';victim.unlink();victim.symlink_to(target)
    elif scenario=='link_to_fifo' and event=='read_chunk' and name=='a.txt':
        fifo=payload.parent/'pipe.fifo';os.mkfifo(fifo)
        victim=payload/'a.txt';victim.unlink();victim.symlink_to(fifo)
    elif scenario=='parent_replace' and event=='read_chunk' and name=='sub/a.txt':
        old=payload/'sub';old.rename(payload/'sub_old')
        new=payload/'sub';new.mkdir();(new/'a.txt').write_bytes(b'REPLACED-PARENT-BYTES')
    elif scenario=='root_replace' and event=='pre_final_snapshot':
        old=payload;old.rename(payload.parent/'payload_old')
        new=payload.parent/'payload';new.mkdir();(new/'a.txt').write_bytes(b'NEW-ROOT')
    elif scenario=='append' and event=='read_chunk' and name=='big.bin':
        with (payload/'big.bin').open('ab') as stream:stream.write(b'X'*10)
    elif scenario=='new_file' and event=='pre_final_snapshot':
        (payload/'brand_new.txt').write_bytes(b'late arrival')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--base',required=True);ap.add_argument('--scenario',required=True)
    ap.add_argument('--output')
    a=ap.parse_args();base=Path(a.base);payload=base/'payload';payload.mkdir(parents=True)
    entries=[]
    if a.scenario=='parent_replace':
        (payload/'sub').mkdir()
        body=b'parent anchor bytes';(payload/'sub/a.txt').write_bytes(body)
        entries=[{'path':'sub/a.txt','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}]
    elif a.scenario=='append':
        body=b'Z'*100000;(payload/'big.bin').write_bytes(body)
        entries=[{'path':'big.bin','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}]
    else:
        body=b'stable anchor bytes';(payload/'a.txt').write_bytes(body)
        entries=[{'path':'a.txt','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}]
    data=make_manifest(base,'payload',entries)
    def barrier(event,name):mutate(a.scenario,payload,event,name)
    try:
        report=audit_guarded(data,base,barrier=barrier)
    except GuardInstability as e:
        print('GUARD_INSTABILITY:'+str(e));return 2
    except OSError as e:
        print('IO_FAILURE:'+str(e));return 2
    if a.output:
        from archive_fixity.common import save
        save(Path(a.output),{'schema_version':1,'capture_mode':'guarded','result':report})
    print(json.dumps(report,sort_keys=True));return 0


if __name__=='__main__':
    raise SystemExit(main())
