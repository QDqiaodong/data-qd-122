"""Opt-in scale check for the evidence store (not part of the unit suite).

Builds one NDJSON batch with the requested number of revisions and file
states, ingests it through the public API, then answers a few queries at
different knowledge cutoffs.  ``--mode v1`` instead constructs the same history
in the legacy v1 layout (one compressed report per revision), queries it
read-only, then measures the explicit v2 migration:

    PYTHONPATH=src:tests python3 tests/evidence_benchmark.py \
        --revisions 100000 --files-per-report 100
    PYTHONPATH=src:tests python3 tests/evidence_benchmark.py \
        --revisions 100000 --files-per-report 100 --mode v1
"""
import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parent))

from archive_fixity.evidence import format_timestamp,ingest,query,migrate
import evidence_v1_fixture as v1


def report_for(i,per_report):
    files=[{'path':'bucket%02d/file%04d.bin'%(j%16,j),'status':'verified',
            'expected_bytes':1,'expected_sha256':'0'*64,'actual_bytes':1,
            'actual_sha256':'0'*64,'differences':[]} for j in range(per_report)]
    return {'schema_version':1,
            'source_sha256':hashlib.sha256(b'report-%d'%i).hexdigest(),
            'result':{'files':files,'status_counts':{'verified':len(files)},
                      'unlisted_entries':[],'manifest_files':len(files),
                      'captured_bytes':len(files),
                      'all_manifest_files_verified':True,'inventory_clean':True}}


def build_batch(path,revisions,per_report,shared=False):
    with open(path,'w',encoding='utf-8') as stream:
        for i in range(revisions):
            report=report_for(0 if shared else i,per_report)
            stream.write(json.dumps({'archive_id':'bench-archive',
                                     'verification_id':'verify-%06d'%i,'revision':1,
                                     'observed_at':format_timestamp(i*1_000_000),
                                     'report':report},ensure_ascii=False)+'\n')


def build_v1(db,revisions,per_report,shared=False):
    store=v1.build(db)
    for i in range(revisions):
        store.add('verify-%06d'%i,1,format_timestamp(i*1_000_000),
                  report_for(0 if shared else i,per_report),compress_level=6,
                  archive='bench-archive')
    store.close()

def timings(db,latest,revisions,target):
    for fraction in (1.0,0.5,0.01):
        cutoff=max(1,int(latest*fraction))
        t=time.time();result=query(db,'bench-archive',target,
                                  format_timestamp(revisions*1_000_000),cutoff)
        print('query S=%-7d %-14s %.1f ms'%(cutoff,result['verification_id'],
                                            (time.time()-t)*1000))


def size_mb(db):
    """On-disk size after folding WAL back into the main database file."""
    con=sqlite3.connect(str(db),isolation_level=None)
    try:con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    finally:con.close()
    return db.stat().st_size/1e6


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--revisions',type=int,default=100_000)
    ap.add_argument('--files-per-report',type=int,default=100)
    ap.add_argument('--mode',choices=('v2','v1'),default='v2')
    ap.add_argument('--shared',action='store_true',
                    help='every revision carries the same report (dedup scale check)')
    a=ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        base=Path(td);db=base/'evidence.sqlite3';target='bucket00/file0000.bin'
        states=a.revisions*a.files_per_report
        t=time.time()
        if a.mode=='v2':
            batch=base/'batch.ndjson';build_batch(batch,a.revisions,a.files_per_report,a.shared)
            print('batch: %.1f MB in %.1fs'%(batch.stat().st_size/1e6,time.time()-t))
            t=time.time();summary=ingest(db,batch)
            print('ingest v2: %d revisions, %d file states in %.1fs'
                  %(a.revisions,states,time.time()-t))
            print('size: %.1f MB; head=%d'%(size_mb(db),summary['knowledge_head']))
            timings(db,summary['knowledge_head'],a.revisions,target)
        else:
            build_v1(db,a.revisions,a.files_per_report,a.shared)
            print('build v1: %d revisions, %d file states in %.1fs'
                  %(a.revisions,states,time.time()-t))
            print('size before: %.1f MB'%size_mb(db))
            timings(db,a.revisions,a.revisions,target)
            t=time.time();summary=migrate(db)
            print('migrate: %s in %.1fs'%(summary,time.time()-t))
            print('size after: %.1f MB'%size_mb(db))
            timings(db,summary['knowledge_head'],a.revisions,target)
    return 0


if __name__=='__main__':raise SystemExit(main())
