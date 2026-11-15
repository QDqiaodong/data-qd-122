"""Test-only helpers: build audit reports and NDJSON evidence lines."""
import hashlib,json
from pathlib import Path
from archive_fixity.evidence import format_timestamp

ROOT=Path(__file__).resolve().parents[1]
EMPTY_SHA=hashlib.sha256(b'').hexdigest()
ZERO_SHA='0'*64


def sha(body):return hashlib.sha256(body).hexdigest()


def report(files=(),unlisted=(),source='0'*64,capture_mode=None,clean=None):
    """A structurally valid v1 audit report.

    ``files`` is a sequence of ``(path, body)`` pairs whose bytes are verified.
    A pair may instead be ``(path, body, status)`` to record a mismatch, or
    ``(path, None, 'missing')`` for an unread finding.
    """
    entries=[];total=0
    for item in files:
        path,body=item[0],item[1]
        status=item[2] if len(item)>2 else 'verified'
        if status=='missing':
            entries.append({'path':path,'expected_bytes':0,'expected_sha256':EMPTY_SHA,
                            'status':'missing'})
            continue
        actual_sha=sha(body)
        expected_sha=actual_sha if status=='verified' else \
            ('0' if actual_sha[0]!='0' else '1')+actual_sha[1:]
        expected_bytes=len(body) if status=='verified' else len(body)+1
        differences=[] if status=='verified' else ['size_mismatch','digest_mismatch']
        entries.append({'path':path,'expected_bytes':expected_bytes,
                        'expected_sha256':expected_sha,'status':status,
                        'actual_bytes':len(body),'actual_sha256':sha(body),
                        'differences':differences})
        total+=len(body)
    extras=[{'path':p,'is_link':False,'is_directory':False} for p in unlisted]
    counts={}
    for e in entries:counts[e['status']]=counts.get(e['status'],0)+1
    result={'files':entries,'status_counts':counts,'unlisted_entries':extras,
            'manifest_files':len(entries),'captured_bytes':total,
            'all_manifest_files_verified':all(e['status']=='verified' for e in entries),
            'inventory_clean':not extras and all(e['status']=='verified' for e in entries)}
    if capture_mode=='guarded':result['observed_stable']=True
    out={'schema_version':1,'source_sha256':source,'result':result}
    if capture_mode=='guarded':out['capture_mode']='guarded'
    return out


def line(verification,revision,observed_at,report_body=None,archive='archive-1',
         retracted=False):
    item={'archive_id':archive,'verification_id':verification,
          'revision':revision,'observed_at':observed_at}
    if retracted:item['retracted']=True
    else:item['report']=report_body
    return json.dumps(item,ensure_ascii=False)


def write_batch(path,lines):
    path=Path(path)
    path.write_text(''.join(item+'\n' for item in lines),encoding='utf-8')
    return path


def iso(seconds,fraction=0):return format_timestamp(seconds*1_000_000+fraction)
