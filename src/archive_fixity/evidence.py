"""Revisioned SQLite evidence store for archived audit reports.

The store is append-only in knowledge order.  One NDJSON batch supplies whole
audit reports (or retractions) for verification events.  Every accepted
revision receives the next knowledge sequence in the same transaction as its
report body and summary; any bad line rolls the entire batch back, so a failed
batch can simply be retried.

A query selects one *whole* report per verification, never a per-path history:

1. at the knowledge cutoff S, take the last revision of every verification;
2. among those, keep only valid (non-retracted) observations no later than T;
3. pick the observation with the greatest observation instant, breaking ties
   by descending verification id;
4. look the requested path up inside that one report only.

Late arrivals, corrections and retractions therefore cannot leak into an older
knowledge cutoff, and a path can never be stitched together from several
revisions.  SQLite performs the revision selection; a reader decompresses only
the single chosen report, never the history.

Standard library only.
"""
from pathlib import Path
import argparse
import datetime as _datetime
import hashlib
import json
import re
import sqlite3
import sys
import time
import zlib
from .common import ident, loads
from .files import relative

SCHEMA_VERSION=1
MAX_LINE=16_000_000
MAX_FILE=8_000_000
MAX_TOTAL=32_000_000
MAX_FILES=2000
MAX_UNLISTED=5000
MAX_REVISION=2**31-1
MAX_SEQUENCE=2**63-1
DEFAULT_RETRY_ATTEMPTS=8
DEFAULT_RETRY_DELAY=0.05
COMPRESS_LEVEL=6

REPORT_STATUSES=frozenset(('verified','mismatch','missing','unsafe_link',
                           'non_directory_parent','not_regular_file'))
READ_STATUSES=frozenset(('verified','mismatch'))
DIFFERENCES=frozenset(('size_mismatch','digest_mismatch'))

STATIC_RESULT_KEYS={'files','status_counts','unlisted_entries','manifest_files',
                    'captured_bytes','all_manifest_files_verified','inventory_clean'}
READ_FILE_KEYS={'path','expected_bytes','expected_sha256','status',
                'actual_bytes','actual_sha256','differences'}
UNREAD_FILE_KEYS={'path','expected_bytes','expected_sha256','status'}
UNLISTED_KEYS={'path','is_link','is_directory'}

_TS=re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})'
               r'(?:\.(\d{1,6}))?(?:Z|\+00:00)$')
_EPOCH=_datetime.datetime(1970,1,1,tzinfo=_datetime.timezone.utc)
_MAX_DELTA=_datetime.datetime(9999,12,31,23,59,59,999999,tzinfo=_datetime.timezone.utc)-_EPOCH
MAX_INSTANT_US=(_MAX_DELTA.days*86_400_000_000+_MAX_DELTA.seconds*1_000_000
                +_MAX_DELTA.microseconds)


class EvidenceError(ValueError):
    """A contract violation, bad batch line or unresolvable query."""


# ---------------------------------------------------------------- timestamps

def parse_timestamp(value):
    """Canonical UTC instant -> integer microseconds since the Unix epoch.

    Accepted forms are ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z`` and the same with an
    explicit ``+00:00`` offset.  Non-UTC offsets, non-canonical calendar dates
    and leap seconds are rejected so equal instants always compare equal.
    """
    if not isinstance(value,str):raise EvidenceError('timestamp must be a string')
    match=_TS.match(value)
    if match is None:
        raise EvidenceError('timestamp must be UTC ISO-8601 with Z or +00:00: '+value)
    year,month,day,hour,minute,second,fraction=match.groups()
    if second=='60':raise EvidenceError('leap seconds are not supported: '+value)
    try:
        moment=_datetime.datetime(int(year),int(month),int(day),int(hour),int(minute),
                                  int(second),int(fraction or '0'),
                                  tzinfo=_datetime.timezone.utc)
    except ValueError as e:raise EvidenceError('invalid timestamp: '+value) from e
    delta=moment-_EPOCH
    return delta.days*86_400_000_000+delta.seconds*1_000_000+delta.microseconds


def format_timestamp(micros):
    """Inverse of parse_timestamp; exact for every accepted value."""
    moment=_EPOCH+_datetime.timedelta(microseconds=micros)
    body=moment.strftime('%Y-%m-%dT%H:%M:%S')
    if moment.microsecond:body+='.%06d'%moment.microsecond
    return body+'Z'


def _knowledge_cutoff(value):
    if type(value) is not int or not 0<=value<=MAX_SEQUENCE:
        raise EvidenceError('knowledge cutoff must be a non-negative sequence integer')
    return value


# ---------------------------------------------------------------- connections

def _plain(path,label):
    path=Path(path)
    if path.is_symlink():raise EvidenceError(label+' cannot be a symlink')
    return path


def _open_writable(path,busy_timeout=5000):
    path=_plain(path,'evidence store')
    try:
        if not path.parent.exists():path.parent.mkdir(parents=True)
        con=sqlite3.connect(str(path),isolation_level=None)
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('PRAGMA synchronous=FULL')
        con.execute('PRAGMA busy_timeout=%d'%busy_timeout)
    except (sqlite3.Error,OSError) as e:
        raise EvidenceError('cannot open evidence store: '+str(e)) from e
    return con


def _open_existing(path):
    path=_plain(path,'evidence store')
    if not path.is_file():raise EvidenceError('evidence store does not exist: '+str(path))
    con=None
    try:
        con=sqlite3.connect(str(path),isolation_level=None)
        con.execute('PRAGMA query_only=ON')
        con.execute('PRAGMA busy_timeout=5000')
        row=con.execute('SELECT schema_version FROM evidence_meta WHERE id=1').fetchone()
    except sqlite3.Error as e:
        if con is not None:con.close()
        raise EvidenceError('not an evidence store (v%d): %s'%(SCHEMA_VERSION,e)) from e
    if row is None or row[0]!=SCHEMA_VERSION:
        con.close();raise EvidenceError('incompatible evidence store schema')
    return con


_SCHEMA=(
 'CREATE TABLE IF NOT EXISTS evidence_meta('
 ' id INTEGER PRIMARY KEY CHECK(id=1),'
 ' schema_version INTEGER NOT NULL,'
 ' created_utc TEXT NOT NULL)',
 'CREATE TABLE IF NOT EXISTS verifications('
 ' verification_id TEXT PRIMARY KEY,'
 ' archive_id TEXT NOT NULL)',
 'CREATE TABLE IF NOT EXISTS revisions('
 ' revision_id INTEGER PRIMARY KEY AUTOINCREMENT,'
 ' verification_id TEXT NOT NULL,'
 ' archive_id TEXT NOT NULL,'
 ' revision INTEGER NOT NULL CHECK(revision>=1),'
 ' observed_at TEXT NOT NULL,'
 ' observed_us INTEGER NOT NULL,'
 ' kind TEXT NOT NULL CHECK(kind IN (\'report\',\'retraction\')),'
 ' line_sha256 TEXT NOT NULL,'
 ' report_sha256 TEXT,'
 ' report_z BLOB,'
 ' report_size INTEGER NOT NULL CHECK(report_size>=0),'
 ' total_bytes INTEGER NOT NULL CHECK(total_bytes>=0),'
 ' statuses_json TEXT NOT NULL,'
 ' status_counts_json TEXT NOT NULL,'
 ' file_count INTEGER NOT NULL CHECK(file_count>=0),'
 ' unlisted_count INTEGER NOT NULL CHECK(unlisted_count>=0),'
 ' all_verified INTEGER NOT NULL CHECK(all_verified IN (0,1)),'
 ' clean INTEGER NOT NULL CHECK(clean IN (0,1)),'
 ' CHECK((kind=\'report\')=(report_z IS NOT NULL)),'
 ' CHECK((kind=\'report\')=(report_sha256 IS NOT NULL)),'
 ' UNIQUE(verification_id,revision))',
 # Knowledge lookup for "last revision of this verification at S".
 'CREATE INDEX IF NOT EXISTS revisions_verification_lookup'
 ' ON revisions(verification_id,revision_id)',
 # Timeline scan for the winning whole report (time desc, id desc).
 'CREATE INDEX IF NOT EXISTS revisions_timeline'
 ' ON revisions(archive_id,observed_us DESC,verification_id DESC)',
)


def _init(con):
    con.execute('BEGIN IMMEDIATE')
    try:
        for statement in _SCHEMA:con.execute(statement)
        row=con.execute('SELECT schema_version FROM evidence_meta WHERE id=1').fetchone()
        if row is None:
            con.execute('INSERT INTO evidence_meta(id,schema_version,created_utc) VALUES(1,?,?)',
                        (SCHEMA_VERSION,_datetime.datetime.now(_datetime.timezone.utc)
                         .strftime('%Y-%m-%dT%H:%M:%S.%fZ')))
        elif row[0]!=SCHEMA_VERSION:
            raise EvidenceError('incompatible evidence store schema')
        con.execute('COMMIT')
    except BaseException:
        try:con.execute('ROLLBACK')
        except sqlite3.Error:pass
        raise


# ---------------------------------------------------------------- validation

def _canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,
                      separators=(',',':'))


def _check_keys(obj,expected,label,line_no):
    if not isinstance(obj,dict):
        raise EvidenceError('line %d: %s must be an object'%(line_no,label))
    if set(obj)!=set(expected):
        missing=sorted(set(expected)-set(obj));extra=sorted(set(obj)-set(expected))
        raise EvidenceError('line %d: %s fields differ (missing %s, unexpected %s)'
                            %(line_no,label,missing,extra))


def _validate_report(report,line_no):
    """Validate a report against the current static/guarded v1 structure."""
    if not isinstance(report,dict):
        raise EvidenceError('line %d: report must be an object'%line_no)
    mode=report.get('capture_mode','static')
    expected={'schema_version','source_sha256','result'}
    if 'capture_mode' in report:
        if report['capture_mode']!='guarded':
            raise EvidenceError('line %d: capture_mode, when present, must be "guarded"'%line_no)
        expected.add('capture_mode')
    _check_keys(report,expected,'report',line_no)
    if type(report['schema_version']) is not int or report['schema_version']!=1:
        raise EvidenceError('line %d: report schema_version must be 1'%line_no)
    if not isinstance(report['source_sha256'],str) or \
       re.fullmatch('[0-9a-f]{64}',report['source_sha256']) is None:
        raise EvidenceError('line %d: report source_sha256 must be lowercase SHA256'%line_no)
    result=report['result'];result_keys=set(STATIC_RESULT_KEYS)
    if mode=='guarded':result_keys.add('observed_stable')
    _check_keys(result,result_keys,'report result',line_no)
    if mode=='guarded' and result['observed_stable'] is not True:
        raise EvidenceError('line %d: guarded report must carry observed_stable:true'%line_no)

    files=result['files']
    if not isinstance(files,list) or len(files)>MAX_FILES:
        raise EvidenceError('line %d: report files must be an array of <=%d'%(line_no,MAX_FILES))
    listed=set();total=0
    for item in files:
        if not isinstance(item,dict):
            raise EvidenceError('line %d: file entry must be an object'%line_no)
        path=item.get('path');relative(path)
        if path in listed:raise EvidenceError('line %d: duplicate report path: %s'%(line_no,path))
        listed.add(path)
        status=item.get('status')
        if status not in REPORT_STATUSES:
            raise EvidenceError('line %d: invalid file status for %s'%(line_no,path))
        _check_keys(item,READ_FILE_KEYS if status in READ_STATUSES else UNREAD_FILE_KEYS,
                    'file entry',line_no)
        size=item['expected_bytes']
        if type(size) is not int or not 0<=size<=MAX_FILE:
            raise EvidenceError('line %d: expected_bytes out of range for %s'%(line_no,path))
        digest=item['expected_sha256']
        if not isinstance(digest,str) or re.fullmatch('[0-9a-f]{64}',digest) is None:
            raise EvidenceError('line %d: expected_sha256 invalid for %s'%(line_no,path))
        if status in READ_STATUSES:
            actual_bytes=item['actual_bytes']
            if type(actual_bytes) is not int or not 0<=actual_bytes<=MAX_FILE:
                raise EvidenceError('line %d: actual_bytes out of range for %s'%(line_no,path))
            actual_sha=item['actual_sha256']
            if not isinstance(actual_sha,str) or re.fullmatch('[0-9a-f]{64}',actual_sha) is None:
                raise EvidenceError('line %d: actual_sha256 invalid for %s'%(line_no,path))
            diffs=item['differences']
            if not isinstance(diffs,list) or len(diffs)>2:
                raise EvidenceError('line %d: differences must be a bounded array'%line_no)
            if any(d not in DIFFERENCES for d in diffs) or len(set(diffs))!=len(diffs):
                raise EvidenceError('line %d: invalid differences for %s'%(line_no,path))
            size_differs=actual_bytes!=size;digest_differs=actual_sha!=digest
            if status=='verified' and (diffs or size_differs or digest_differs):
                raise EvidenceError('line %d: verified entry is inconsistent for %s'%(line_no,path))
            if status=='mismatch':
                if not diffs:
                    raise EvidenceError('line %d: mismatch requires differences for %s'
                                        %(line_no,path))
                if ('size_mismatch' in diffs)!=size_differs or \
                   ('digest_mismatch' in diffs)!=digest_differs:
                    raise EvidenceError('line %d: mismatch differences disagree with bytes for %s'
                                        %(line_no,path))
            total+=actual_bytes
    if total>MAX_TOTAL:
        raise EvidenceError('line %d: report read total exceeds 32 MB'%line_no)

    unlisted=result['unlisted_entries']
    if not isinstance(unlisted,list) or len(unlisted)>MAX_UNLISTED:
        raise EvidenceError('line %d: unlisted_entries must be an array of <=%d'
                            %(line_no,MAX_UNLISTED))
    extras=set()
    for item in unlisted:
        _check_keys(item,UNLISTED_KEYS,'unlisted entry',line_no)
        path=item['path'];relative(path)
        if path in extras or path in listed:
            raise EvidenceError('line %d: duplicate or listed unlisted path: %s'%(line_no,path))
        if type(item['is_link']) is not bool or type(item['is_directory']) is not bool:
            raise EvidenceError('line %d: unlisted flags must be booleans'%line_no)
        extras.add(path)

    counts=result['status_counts']
    if not isinstance(counts,dict):
        raise EvidenceError('line %d: status_counts must be an object'%line_no)
    derived={}
    for item in files:derived[item['status']]=derived.get(item['status'],0)+1
    if counts!=derived:
        raise EvidenceError('line %d: status_counts do not match the file entries'%line_no)
    if type(result['manifest_files']) is not int or result['manifest_files']!=len(files):
        raise EvidenceError('line %d: manifest_files does not match the file entry count'%line_no)
    if type(result['captured_bytes']) is not int or result['captured_bytes']!=total:
        raise EvidenceError('line %d: captured_bytes does not match read bytes'%line_no)
    all_verified=all(item['status']=='verified' for item in files)
    if type(result['all_manifest_files_verified']) is not bool or \
       result['all_manifest_files_verified']!=all_verified:
        raise EvidenceError('line %d: all_manifest_files_verified is inconsistent'%line_no)
    if type(result['inventory_clean']) is not bool:
        raise EvidenceError('line %d: inventory_clean must be boolean'%line_no)
    clean=(not extras) and all_verified
    if result['inventory_clean']!=clean:
        raise EvidenceError('line %d: inventory_clean is inconsistent'%line_no)
    canonical=_canonical(report);encoded=canonical.encode('utf-8')
    return {'report':report,'total':total,'file_count':len(files),
            'unlisted_count':len(extras),
            'report_json':canonical,'report_sha256':hashlib.sha256(encoded).hexdigest(),
            'report_size':len(encoded),
            'statuses_json':_canonical(sorted({item['status'] for item in files})),
            'status_counts_json':_canonical(counts),
            'all_verified':all_verified,'clean':clean}


def _retraction_summary():
    return {'report':None,'total':0,'file_count':0,'unlisted_count':0,'report_json':None,
            'report_sha256':None,'report_size':0,'statuses_json':'[]',
            'status_counts_json':'{}','all_verified':False,'clean':False}


def _parse_line(raw,line_no):
    """Parse one NDJSON line into a validated revision description."""
    try:
        return _parse_line_inner(raw,line_no)
    except EvidenceError:
        raise
    except ValueError as e:
        raise EvidenceError('line %d: %s'%(line_no,e)) from e


def _parse_line_inner(raw,line_no):
    if len(raw)>MAX_LINE:raise EvidenceError('line %d: exceeds the line size bound'%line_no)
    if not raw:raise EvidenceError('line %d: blank line'%line_no)
    try:text=raw.decode('utf-8')
    except UnicodeDecodeError as e:raise EvidenceError('line %d: not UTF-8'%line_no) from e
    try:data=loads(text)
    except ValueError as e:raise EvidenceError('line %d: %s'%(line_no,e)) from e
    if not isinstance(data,dict):raise EvidenceError('line %d: expected a JSON object'%line_no)
    allowed={'archive_id','verification_id','revision','observed_at','report','retracted'}
    if set(data)-allowed:
        raise EvidenceError('line %d: undefined fields: %s'%(line_no,sorted(set(data)-allowed)))
    for field in ('archive_id','verification_id','revision','observed_at'):
        if field not in data:raise EvidenceError('line %d: %s is required'%(line_no,field))
    archive=ident(data['archive_id']);verification=ident(data['verification_id'])
    if type(data['revision']) is not int or not 1<=data['revision']<=MAX_REVISION:
        raise EvidenceError('line %d: revision must be an integer >=1'%line_no)
    if 'retracted' in data and type(data['retracted']) is not bool:
        raise EvidenceError('line %d: retracted must be a boolean'%line_no)
    has_report='report' in data;retracted=data.get('retracted',False)
    if retracted==has_report:
        raise EvidenceError('line %d: provide exactly one of report or retracted:true'%line_no)
    observed_us=parse_timestamp(data['observed_at'])
    if has_report:
        summary=_validate_report(data['report'],line_no)
        kind='report';report_sha=summary['report_sha256']
    else:
        summary=_retraction_summary();kind='retraction';report_sha=None
    return {'archive_id':archive,'verification_id':verification,'revision':data['revision'],
            'observed_us':observed_us,'observed_at':format_timestamp(observed_us),
            'kind':kind,'report_sha256':report_sha,'summary':summary,
            'line_sha256':hashlib.sha256(raw).hexdigest()}


# -------------------------------------------------------------------- ingest

def _latest(con,verification):
    return con.execute('SELECT revision,archive_id,observed_us FROM revisions'
                       ' WHERE verification_id=? ORDER BY revision DESC LIMIT 1',
                       (verification,)).fetchone()


def _existing_revision(con,verification,revision):
    return con.execute('SELECT kind,report_sha256,observed_us,archive_id FROM revisions'
                       ' WHERE verification_id=? AND revision=?',
                       (verification,revision)).fetchone()


def _insert_revision(con,rev):
    summary=rev['summary']
    payload=summary['report_json']
    blob=None if payload is None else zlib.compress(payload.encode('utf-8'),COMPRESS_LEVEL)
    return con.execute(
        'INSERT INTO revisions(verification_id,archive_id,revision,observed_at,observed_us,'
        'kind,line_sha256,report_sha256,report_z,report_size,total_bytes,statuses_json,'
        'status_counts_json,file_count,unlisted_count,all_verified,clean)'
        ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (rev['verification_id'],rev['archive_id'],rev['revision'],rev['observed_at'],
         rev['observed_us'],rev['kind'],rev['line_sha256'],rev['report_sha256'],blob,
         summary['report_size'],summary['total'],summary['statuses_json'],
         summary['status_counts_json'],summary['file_count'],summary['unlisted_count'],
         int(summary['all_verified']),int(summary['clean']))).lastrowid


def _ingest_batch(con,batch,barrier):
    lines=accepted=idempotent=0;first=last=None
    with _open_batch(batch).open('rb') as stream:
        for line_no,raw in enumerate(stream,1):
            if raw.endswith(b'\n'):raw=raw[:-1]
            if raw.endswith(b'\r'):raw=raw[:-1]
            lines+=1
            rev=_parse_line(raw,line_no)
            existing=_latest(con,rev['verification_id'])
            if existing is None:
                if rev['revision']!=1:
                    raise EvidenceError('line %d: the first revision of verification %s must be 1'
                                        %(line_no,rev['verification_id']))
                con.execute('INSERT INTO verifications(verification_id,archive_id) VALUES(?,?)',
                            (rev['verification_id'],rev['archive_id']))
            else:
                last_revision,archive_id,observed_us=existing
                if archive_id!=rev['archive_id'] or observed_us!=rev['observed_us']:
                    raise EvidenceError(
                        'line %d: archive_id and observed_at are fixed for verification %s'
                        %(line_no,rev['verification_id']))
                if rev['revision']>last_revision+1:
                    raise EvidenceError(
                        'line %d: revisions must be contiguous from 1 for verification %s'
                        %(line_no,rev['verification_id']))
                row=_existing_revision(con,rev['verification_id'],rev['revision'])
                if row is not None:
                    if (row[0]!=rev['kind'] or row[1]!=rev['report_sha256'] or
                            row[2]!=rev['observed_us'] or row[3]!=rev['archive_id']):
                        raise EvidenceError(
                            'line %d: revision %d of %s conflicts with stored content'
                            %(line_no,rev['revision'],rev['verification_id']))
                    idempotent+=1
                    if barrier is not None:barrier('idempotent',line_no)
                    continue
                if rev['revision']!=last_revision+1:
                    raise EvidenceError(
                        'line %d: revisions must be contiguous from 1 for verification %s'
                        %(line_no,rev['verification_id']))
            sequence=_insert_revision(con,rev)
            accepted+=1
            if first is None:first=sequence
            last=sequence
            if barrier is not None:barrier('after_insert',line_no)
    head=con.execute('SELECT COALESCE(MAX(revision_id),0) FROM revisions').fetchone()[0]
    return {'schema_version':1,'lines':lines,'accepted':accepted,'idempotent':idempotent,
            'first_knowledge_sequence':first,'last_knowledge_sequence':last,
            'knowledge_head':head,'empty':lines==0}


def _open_batch(path):
    path=_plain(path,'batch')
    if not path.is_file():raise EvidenceError('batch file does not exist: '+str(path))
    return path


def _retryable(error):
    text=str(error).lower()
    return 'locked' in text or 'busy' in text or 'deadlock' in text


def ingest(db_path,batch_path,attempts=DEFAULT_RETRY_ATTEMPTS,
           delay=DEFAULT_RETRY_DELAY,barrier=None,busy_timeout=5000):
    """Atomically ingest one NDJSON batch; return a JSON-ready summary.

    Every line of the batch is applied in one transaction.  A bad line, a
    conflict or any other failure rolls the whole batch back, so no revision
    from it becomes visible and a corrected/unchanged retry starts from the
    same knowledge head.  Transient SQLite lock/busy errors are retried with
    exponential backoff; each attempt re-reads the batch from the start.
    """
    attempts=max(1,attempts);last_error=None
    for attempt in range(attempts):
        con=None
        try:
            con=_open_writable(db_path,busy_timeout)
            _init(con)
            con.execute('BEGIN IMMEDIATE')
            summary=_ingest_batch(con,batch_path,barrier)
            con.execute('COMMIT')
            con.close()
            return summary
        except (sqlite3.OperationalError,EvidenceError) as e:
            # Always release the connection and any open transaction first.
            if con is not None:
                try:con.execute('ROLLBACK')
                except sqlite3.Error:pass
                try:con.close()
                except sqlite3.Error:pass
            # Only transient lock/busy/deadlock failures are retried, whether
            # they surface raw or wrapped while opening the store.  A contract
            # error (bad line, conflict) aborts immediately.
            if not _retryable(e):raise
            last_error=e
            if attempt+1>=attempts:break
            time.sleep(min(delay*(2**attempt),1.0))
        except BaseException:
            if con is not None:
                try:con.execute('ROLLBACK')
                except sqlite3.Error:pass
                try:con.close()
                except sqlite3.Error:pass
            raise
    raise EvidenceError('evidence ingest failed after retries: '+str(last_error))


# --------------------------------------------------------------------- query

# At knowledge cutoff S a candidate revision must be the latest revision of
# its verification.  It must be a report (a retraction is invalid) observed no
# later than T.  The timeline index supplies the required descending order and
# LIMIT 1 stops after the first survivor.
_WINNER=(
 'SELECT r.verification_id,r.revision,r.revision_id,r.observed_at,r.report_sha256,'
 ' r.report_z,r.report_size,r.statuses_json,r.status_counts_json,r.file_count,r.unlisted_count,'
 ' r.all_verified,r.clean'
 ' FROM revisions r'
 ' WHERE r.archive_id=? AND r.revision_id<=? AND r.kind=\'report\' AND r.observed_us<=?'
 ' AND NOT EXISTS (SELECT 1 FROM revisions n'
 '                 WHERE n.verification_id=r.verification_id'
 '                   AND n.revision_id>r.revision_id AND n.revision_id<=?)'
 ' ORDER BY r.observed_us DESC, r.verification_id DESC LIMIT 1')


def _find_path(report,path):
    result=report['result']
    for item in result['files']:
        if item['path']==path:
            observation={'path':path,'status':item['status'],
                         'expected_bytes':item['expected_bytes'],
                         'expected_sha256':item['expected_sha256']}
            if item['status'] in READ_STATUSES:
                observation['actual_bytes']=item['actual_bytes']
                observation['actual_sha256']=item['actual_sha256']
                observation['differences']=item['differences']
            return observation,None
    for item in result['unlisted_entries']:
        if item['path']==path:
            return None,{'path':path,'is_link':item['is_link'],
                         'is_directory':item['is_directory']}
    return None,None


def query(db_path,archive_id,path,observed_before,known_before):
    """Resolve one path at observation cutoff T and knowledge cutoff S.

    ``outcome`` distinguishes ``no_observation`` (no valid observation known at
    S and observed by T), ``not_listed`` (the selected whole report neither
    lists nor inventories the path) and ``observed`` (the selected report
    carries a state for it, which may itself be ``missing``).  An unlisted
    inventory hit is reported as ``not_listed`` with ``unlisted_entry`` set.
    """
    try:
        archive=ident(archive_id);relative(path)
    except ValueError as e:
        raise EvidenceError(str(e)) from e
    if isinstance(observed_before,str):
        cutoff_us=parse_timestamp(observed_before)
    elif type(observed_before) is int:
        cutoff_us=observed_before
    else:
        raise EvidenceError('observed cutoff must be a UTC timestamp or microsecond integer')
    if not 0<=cutoff_us<=MAX_INSTANT_US:
        raise EvidenceError('observed cutoff is outside the representable UTC range')
    knowledge=_knowledge_cutoff(known_before)
    con=_open_existing(db_path)
    try:
        row=con.execute(_WINNER,(archive,knowledge,cutoff_us,knowledge)).fetchone()
        head=con.execute('SELECT COALESCE(MAX(revision_id),0) FROM revisions').fetchone()[0]
        result={'schema_version':1,
                'query':{'archive_id':archive,'path':path,
                         'observed_at_or_before':format_timestamp(cutoff_us),
                         'knowledge_cutoff':knowledge,'knowledge_head':head},
                'outcome':'no_observation','verification_id':None,'revision':None,
                'knowledge_sequence':None,'observed_at':None,'report_sha256':None,
                'source_sha256':None,'report_summary':None,'report':None,
                'observation':None,'unlisted_entry':None}
        if row is None:return result
        (verification,revision,sequence,observed_at,report_sha256,report_z,
         report_size,statuses_json,status_counts_json,file_count,unlisted_count,
         all_verified,clean)=row
        # Bound the inflate to the recorded size so a damaged or hostile BLOB
        # cannot force an unbounded allocation.
        try:
            inflater=zlib.decompressobj()
            payload=inflater.decompress(report_z,MAX_LINE)
        except zlib.error as e:raise EvidenceError('stored report is corrupt') from e
        if (len(payload)!=report_size or inflater.unconsumed_tail or not inflater.eof):
            raise EvidenceError('stored report size does not match its record')
        if hashlib.sha256(payload).hexdigest()!=report_sha256:
            raise EvidenceError('stored report digest does not match its record')
        try:report=loads(payload)
        except ValueError as e:raise EvidenceError('stored report is not valid JSON') from e
        observation,unlisted_entry=_find_path(report,path)
        result.update({'outcome':'not_listed','verification_id':verification,
                       'revision':revision,'knowledge_sequence':sequence,
                       'observed_at':observed_at,'report_sha256':report_sha256,
                       'source_sha256':report['source_sha256'],
                       'report_summary':{'statuses':loads(statuses_json),
                                         'status_counts':loads(status_counts_json),
                                         'file_count':file_count,
                                         'unlisted_count':unlisted_count,
                                         'all_manifest_files_verified':bool(all_verified),
                                         'inventory_clean':bool(clean)},
                       'report':report,'observation':observation,
                       'unlisted_entry':unlisted_entry})
        if observation is not None:result['outcome']='observed'
        return result
    except sqlite3.Error as e:
        raise EvidenceError('evidence query failed: '+str(e)) from e
    finally:
        con.close()


# ----------------------------------------------------------------------- CLI

def _positive_int(value):
    try:number=int(value)
    except (TypeError,ValueError):raise argparse.ArgumentTypeError('expected a positive integer')
    if number<1:raise argparse.ArgumentTypeError('expected a positive integer')
    return number


def _non_negative_int(value):
    try:number=int(value)
    except (TypeError,ValueError):
        raise argparse.ArgumentTypeError('expected a non-negative integer')
    if number<0:raise argparse.ArgumentTypeError('expected a non-negative integer')
    return number


def _non_negative_float(value):
    try:number=float(value)
    except (TypeError,ValueError):
        raise argparse.ArgumentTypeError('expected a non-negative number')
    if number!=number or number<0:
        raise argparse.ArgumentTypeError('expected a non-negative number')
    return number


def _ingest_parser():
    p=argparse.ArgumentParser(prog='archive-fixity evidence-ingest',
                              description='Atomically ingest one NDJSON evidence batch')
    p.add_argument('--db',type=Path,required=True,
                   help='SQLite evidence store to create or extend')
    p.add_argument('--batch',type=Path,required=True,
                   help='NDJSON batch, one revision per line')
    p.add_argument('--retry-attempts',type=_positive_int,default=DEFAULT_RETRY_ATTEMPTS,
                   help='transient lock retries (default %d)'%DEFAULT_RETRY_ATTEMPTS)
    p.add_argument('--retry-delay',type=_non_negative_float,default=DEFAULT_RETRY_DELAY,
                   help='initial retry delay in seconds (default %s)'%DEFAULT_RETRY_DELAY)
    return p


def _query_parser():
    p=argparse.ArgumentParser(prog='archive-fixity evidence-query',
                              description='Resolve one path from the evidence store')
    p.add_argument('--db',type=Path,required=True)
    p.add_argument('--archive',required=True,help='archive identifier')
    p.add_argument('--path',required=True,help='canonical relative payload path')
    p.add_argument('--observed-before',required=True,
                   help='T: UTC instant YYYY-MM-DDTHH:MM:SS[.ffffff]Z; later observations are excluded')
    p.add_argument('--knowledge-cutoff',required=True,type=_non_negative_int,
                   help='S: only revisions with knowledge sequence <= S are visible')
    return p


def ingest_main(argv):
    """CLI entry: ingest one batch, print the JSON summary."""
    a=_ingest_parser().parse_args(argv)
    try:
        summary=ingest(a.db,a.batch,attempts=a.retry_attempts,delay=a.retry_delay)
    except (EvidenceError,OSError,sqlite3.Error) as e:
        print(str(e),file=sys.stderr);return 2
    print(json.dumps(summary,sort_keys=True));return 0


def query_main(argv):
    """CLI entry: resolve one path at (T,S), print the JSON result."""
    a=_query_parser().parse_args(argv)
    try:
        result=query(a.db,a.archive,a.path,a.observed_before,a.knowledge_cutoff)
    except (EvidenceError,OSError,sqlite3.Error) as e:
        print(str(e),file=sys.stderr);return 2
    print(json.dumps(result,sort_keys=True,ensure_ascii=False));return 0
