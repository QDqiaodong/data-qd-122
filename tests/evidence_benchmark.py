"""Opt-in scale check for the evidence store (not part of the unit suite).

Builds one NDJSON batch with the requested number of revisions and file
states, ingests it through the public API, then answers a few queries at
different knowledge cutoffs:

    PYTHONPATH=src:tests python3 tests/evidence_benchmark.py \
        --revisions 100000 --files-per-report 100
"""
import argparse
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parent))

from archive_fixity.evidence import format_timestamp,ingest,query


def build_batch(path,revisions,per_report):
    with open(path,'w',encoding='utf-8') as stream:
        for i in range(revisions):
            files=[{'path':'bucket%02d/file%04d.bin'%(j%16,j),'status':'verified',
                    'expected_bytes':1,'expected_sha256':'0'*64,'actual_bytes':1,
                    'actual_sha256':'0'*64,'differences':[]} for j in range(per_report)]
            report={'schema_version':1,
                    'source_sha256':hashlib.sha256(b'report-%d'%i).hexdigest(),
                    'result':{'files':files,'status_counts':{'verified':len(files)},
                              'unlisted_entries':[],'manifest_files':len(files),
                              'captured_bytes':len(files),
                              'all_manifest_files_verified':True,'inventory_clean':True}}
            stream.write(json.dumps({'archive_id':'bench-archive',
                                     'verification_id':'verify-%06d'%i,'revision':1,
                                     'observed_at':format_timestamp(i*1_000_000),
                                     'report':report},ensure_ascii=False)+'\n')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--revisions',type=int,default=100_000)
    ap.add_argument('--files-per-report',type=int,default=100)
    a=ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        base=Path(td);batch=base/'batch.ndjson';db=base/'evidence.sqlite3'
        t=time.time();build_batch(batch,a.revisions,a.files_per_report)
        print('batch: %.1f MB in %.1fs'%(batch.stat().st_size/1e6,time.time()-t))
        t=time.time();summary=ingest(db,batch)
        elapsed=time.time()-t
        states=a.revisions*a.files_per_report
        print('ingest: %d revisions, %d file states in %.1fs'%(a.revisions,states,elapsed))
        print('size: %.1f MB; head=%d'%(db.stat().st_size/1e6,summary['knowledge_head']))
        target='bucket00/file0000.bin'
        latest=summary['knowledge_head']
        for fraction in (1.0,0.5,0.01):
            cutoff=max(1,int(latest*fraction))
            t=time.time();result=query(db,'bench-archive',target,
                                      format_timestamp(a.revisions*1_000_000),cutoff)
            print('query S=%-7d %-14s %.1f ms'%(cutoff,result['verification_id'],
                                                (time.time()-t)*1000))
    return 0


if __name__=='__main__':raise SystemExit(main())
