"""Revisioned SQLite evidence store for archived audit reports.

Schema v2 keeps report bodies in shared, content-addressed objects.  A report
is keyed by the SHA256 of its *canonical* JSON bytes (never by compressed
bytes), so the same report used by several verifications or revisions is
stored exactly once.  A retraction has no object at all.  Objects and
revisions are written in one transaction, so a failed batch can never leave an
orphan object behind.

The store is append-only in knowledge order.  One NDJSON batch supplies whole
audit reports (or retractions) for verification events.  Every accepted
revision receives the next knowledge sequence in the same transaction as its
report object reference and summary; any bad line rolls the entire batch back,
so a failed batch can simply be retried.

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

Schema v1 stores remain readable through :func:`query`; writing to them is
refused.  :func:`migrate` performs the explicit, single-transaction in-place
rebuild described in ``docs/evidence-store.md``.

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

SCHEMA_VERSION=2
V1_SCHEMA_VERSION=1
MAX_LINE=16_000_000
MAX_REPORT_BYTES=MAX_LINE
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


def _open_writable(path,busy_timeout=5000,allow_v1=False):
    """Open a store for writing, refusing a schema-v1 file before touching it.

    The version is read before any journal-mode change, so a refused v1 store
    keeps its bytes and journal mode: v1 writes are always an explicit
    migration, never an implicit side effect of opening.  Only ``migrate``
    passes ``allow_v1=True``; ingest and every other writer keep the default.
    A v1 store being migrated is also left in its current journal mode for the
    duration of the rebuild, so a failed migration rolls back to byte-identical
    v1 content; ``migrate`` switches it to WAL only after commit.
    """
    path=_plain(path,'evidence store')
    try:
        if not path.parent.exists():path.parent.mkdir(parents=True)
        con=sqlite3.connect(str(path),isolation_level=None)
        con.execute('PRAGMA busy_timeout=%d'%busy_timeout)
        try:version=_meta_version(con)
        except sqlite3.DatabaseError as e:
            con.close();raise EvidenceError('not an evidence store: '+str(e)) from e
        if version not in (None,V1_SCHEMA_VERSION,SCHEMA_VERSION):
            con.close();raise EvidenceError('incompatible evidence store schema v%s'%version)
        if version is None and _has_user_tables(con):
            con.close()
            raise EvidenceError('not an evidence store: no evidence_meta table')
        if version==V1_SCHEMA_VERSION and not allow_v1:
            con.close()
            _raise_wrong_version(version)
        if version is None or version==SCHEMA_VERSION:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('PRAGMA synchronous=FULL')
        con.execute('PRAGMA foreign_keys=ON')
    except (sqlite3.Error,OSError) as e:
        raise EvidenceError('cannot open evidence store: '+str(e)) from e
    return con


def _set_write_pragmas(con):
    """Switch a store to the durable write mode; used after a migration commit."""
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=FULL')


def _open_existing(path):
    """Open an existing store read-only and return ``(connection, version)``.

    Both v1 and v2 stores are readable; the caller picks the matching SQL.
    No write or implicit conversion ever happens through a reader.
    """
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
    if row is None or row[0] not in (V1_SCHEMA_VERSION,SCHEMA_VERSION):
        con.close()
        raise EvidenceError('incompatible evidence store schema v%s'
                            %('?' if row is None else row[0]))
    return con,row[0]


def _meta_version(con):
    """Read ``evidence_meta.schema_version`` or ``None`` if the table is absent."""
    try:
        row=con.execute('SELECT schema_version FROM evidence_meta WHERE id=1').fetchone()
    except sqlite3.OperationalError as e:
        if 'no such table' in str(e):return None
        raise
    return None if row is None else row[0]


def _has_user_tables(con):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table'"
                       " AND name NOT LIKE 'sqlite_%' LIMIT 1").fetchone() is not None


_SCHEMA=(
 # Content-addressed report objects: one row per distinct canonical report.
 # The key is the SHA256 of canonical report JSON, never of compressed bytes.
 'CREATE TABLE IF NOT EXISTS report_objects('
 ' report_sha256 TEXT PRIMARY KEY'
 "  CHECK(typeof(report_sha256)='text' AND length(report_sha256)=64),"
 ' report_z BLOB NOT NULL CHECK(length(report_z)>0),'
 ' report_size INTEGER NOT NULL CHECK(report_size>0))',
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
 ' total_bytes INTEGER NOT NULL CHECK(total_bytes>=0),'
 ' statuses_json TEXT NOT NULL,'
 ' status_counts_json TEXT NOT NULL,'
 ' file_count INTEGER NOT NULL CHECK(file_count>=0),'
 ' unlisted_count INTEGER NOT NULL CHECK(unlisted_count>=0),'
 ' all_verified INTEGER NOT NULL CHECK(all_verified IN (0,1)),'
 ' clean INTEGER NOT NULL CHECK(clean IN (0,1)),'
 ' CHECK((kind=\'report\')=(report_sha256 IS NOT NULL)),'
 ' CHECK(kind=\'report\' OR (total_bytes=0 AND file_count=0'
 '       AND unlisted_count=0 AND statuses_json=\'[]\''
 '       AND status_counts_json=\'{}\' AND all_verified=0 AND clean=0)),'
 ' FOREIGN KEY(report_sha256) REFERENCES report_objects(report_sha256)'
 '  DEFERRABLE INITIALLY DEFERRED,'
 ' UNIQUE(verification_id,revision))',
 # Knowledge lookup for "last revision of this verification at S".
 'CREATE INDEX IF NOT EXISTS revisions_verification_lookup'
 ' ON revisions(verification_id,revision_id)',
 # Timeline scan for the winning whole report (time desc, id desc).
 'CREATE INDEX IF NOT EXISTS revisions_timeline'
 ' ON revisions(archive_id,observed_us DESC,verification_id DESC)',
)


def _create_schema(con):
    """Create the v2 tables inside the caller's transaction; no commit here."""
    for statement in _SCHEMA:con.execute(statement)
    row=con.execute('SELECT schema_version FROM evidence_meta WHERE id=1').fetchone()
    if row is None:
        con.execute('INSERT INTO evidence_meta(id,schema_version,created_utc) VALUES(1,?,?)',
                    (SCHEMA_VERSION,_datetime.datetime.now(_datetime.timezone.utc)
                     .strftime('%Y-%m-%dT%H:%M:%S.%fZ')))
    elif row[0]!=SCHEMA_VERSION:
        _raise_wrong_version(row[0])


def _prepare_for_write(con):
    """Ensure a writable v2 store, refusing v1 without touching its contents."""
    con.execute('BEGIN IMMEDIATE')
    try:
        version=_meta_version(con)
        if version is None:
            _create_schema(con)
        elif version!=SCHEMA_VERSION:
            _raise_wrong_version(version)
        con.execute('COMMIT')
    except BaseException:
        try:con.execute('ROLLBACK')
        except sqlite3.Error:pass
        raise


def _raise_wrong_version(version):
    if version==V1_SCHEMA_VERSION:
        raise EvidenceError(
            'evidence store is schema v1; writing requires an explicit migration '
            '(run: archive-fixity evidence-migrate --db <store>)')
    raise EvidenceError('incompatible evidence store schema v%d'%version)


# ---------------------------------------------------------------- validation

def _canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,
                      separators=(',',':'))


def _check_keys(obj,expected,label,where):
    if not isinstance(obj,dict):
        raise EvidenceError(where+': '+label+' must be an object')
    if set(obj)!=set(expected):
        missing=sorted(set(expected)-set(obj));extra=sorted(set(obj)-set(expected))
        raise EvidenceError(where+': '+label+' fields differ (missing %s, unexpected %s)'
                            %(missing,extra))


def _validate_report(report,where):
    """Validate a report against the current static/guarded v1 structure.

    ``where`` is a diagnostic position such as ``line 3`` or
    ``revision_id 17``; it never affects validity.
    """
    if not isinstance(report,dict):
        raise EvidenceError(where+': report must be an object')
    mode=report.get('capture_mode','static')
    expected={'schema_version','source_sha256','result'}
    if 'capture_mode' in report:
        if report['capture_mode']!='guarded':
            raise EvidenceError(where+': capture_mode, when present, must be "guarded"')
        expected.add('capture_mode')
    _check_keys(report,expected,'report',where)
    if type(report['schema_version']) is not int or report['schema_version']!=1:
        raise EvidenceError(where+': report schema_version must be 1')
    if not isinstance(report['source_sha256'],str) or \
       re.fullmatch('[0-9a-f]{64}',report['source_sha256']) is None:
        raise EvidenceError(where+': report source_sha256 must be lowercase SHA256')
    result=report['result'];result_keys=set(STATIC_RESULT_KEYS)
    if mode=='guarded':result_keys.add('observed_stable')
    _check_keys(result,result_keys,'report result',where)
    if mode=='guarded' and result['observed_stable'] is not True:
        raise EvidenceError(where+': guarded report must carry observed_stable:true')

    files=result['files']
    if not isinstance(files,list) or len(files)>MAX_FILES:
        raise EvidenceError(where+': report files must be an array of <=%d'%MAX_FILES)
    listed=set();total=0
    for item in files:
        if not isinstance(item,dict):
            raise EvidenceError(where+': file entry must be an object')
        path=item.get('path');relative(path)
        if path in listed:raise EvidenceError(where+': duplicate report path: '+path)
        listed.add(path)
        status=item.get('status')
        if status not in REPORT_STATUSES:
            raise EvidenceError(where+': invalid file status for '+str(path))
        _check_keys(item,READ_FILE_KEYS if status in READ_STATUSES else UNREAD_FILE_KEYS,
                    'file entry',where)
        size=item['expected_bytes']
        if type(size) is not int or not 0<=size<=MAX_FILE:
            raise EvidenceError(where+': expected_bytes out of range for '+path)
        digest=item['expected_sha256']
        if not isinstance(digest,str) or re.fullmatch('[0-9a-f]{64}',digest) is None:
            raise EvidenceError(where+': expected_sha256 invalid for '+path)
        if status in READ_STATUSES:
            actual_bytes=item['actual_bytes']
            if type(actual_bytes) is not int or not 0<=actual_bytes<=MAX_FILE:
                raise EvidenceError(where+': actual_bytes out of range for '+path)
            actual_sha=item['actual_sha256']
            if not isinstance(actual_sha,str) or re.fullmatch('[0-9a-f]{64}',actual_sha) is None:
                raise EvidenceError(where+': actual_sha256 invalid for '+path)
            diffs=item['differences']
            if not isinstance(diffs,list) or len(diffs)>2:
                raise EvidenceError(where+': differences must be a bounded array')
            if any(d not in DIFFERENCES for d in diffs) or len(set(diffs))!=len(diffs):
                raise EvidenceError(where+': invalid differences for '+path)
            size_differs=actual_bytes!=size;digest_differs=actual_sha!=digest
            if status=='verified' and (diffs or size_differs or digest_differs):
                raise EvidenceError(where+': verified entry is inconsistent for '+path)
            if status=='mismatch':
                if not diffs:
                    raise EvidenceError(where+': mismatch requires differences for '+path)
                if ('size_mismatch' in diffs)!=size_differs or \
                   ('digest_mismatch' in diffs)!=digest_differs:
                    raise EvidenceError(where+': mismatch differences disagree with bytes for '
                                        +path)
            total+=actual_bytes
    if total>MAX_TOTAL:
        raise EvidenceError(where+': report read total exceeds 32 MB')

    unlisted=result['unlisted_entries']
    if not isinstance(unlisted,list) or len(unlisted)>MAX_UNLISTED:
        raise EvidenceError(where+': unlisted_entries must be an array of <=%d'%MAX_UNLISTED)
    extras=set()
    for item in unlisted:
        _check_keys(item,UNLISTED_KEYS,'unlisted entry',where)
        path=item['path'];relative(path)
        if path in extras or path in listed:
            raise EvidenceError(where+': duplicate or listed unlisted path: '+path)
        if type(item['is_link']) is not bool or type(item['is_directory']) is not bool:
            raise EvidenceError(where+': unlisted flags must be booleans')
        extras.add(path)

    counts=result['status_counts']
    if not isinstance(counts,dict):
        raise EvidenceError(where+': status_counts must be an object')
    derived={}
    for item in files:derived[item['status']]=derived.get(item['status'],0)+1
    if counts!=derived:
        raise EvidenceError(where+': status_counts do not match the file entries')
    if type(result['manifest_files']) is not int or result['manifest_files']!=len(files):
        raise EvidenceError(where+': manifest_files does not match the file entry count')
    if type(result['captured_bytes']) is not int or result['captured_bytes']!=total:
        raise EvidenceError(where+': captured_bytes does not match read bytes')
    all_verified=all(item['status']=='verified' for item in files)
    if type(result['all_manifest_files_verified']) is not bool or \
       result['all_manifest_files_verified']!=all_verified:
        raise EvidenceError(where+': all_manifest_files_verified is inconsistent')
    if type(result['inventory_clean']) is not bool:
        raise EvidenceError(where+': inventory_clean must be boolean')
    clean=(not extras) and all_verified
    if result['inventory_clean']!=clean:
        raise EvidenceError(where+': inventory_clean is inconsistent')
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
        return _parse_line_inner(raw,'line %d'%line_no)
    except EvidenceError:
        raise
    except ValueError as e:
        raise EvidenceError('line %d: %s'%(line_no,e)) from e


def _parse_line_inner(raw,where):
    if len(raw)>MAX_LINE:raise EvidenceError(where+': exceeds the line size bound')
    if not raw:raise EvidenceError(where+': blank line')
    try:text=raw.decode('utf-8')
    except UnicodeDecodeError as e:raise EvidenceError(where+': not UTF-8') from e
    try:data=loads(text)
    except ValueError as e:raise EvidenceError(where+': '+str(e)) from e
    if not isinstance(data,dict):raise EvidenceError(where+': expected a JSON object')
    allowed={'archive_id','verification_id','revision','observed_at','report','retracted'}
    if set(data)-allowed:
        raise EvidenceError(where+': undefined fields: '+str(sorted(set(data)-allowed)))
    for field in ('archive_id','verification_id','revision','observed_at'):
        if field not in data:raise EvidenceError(where+': '+field+' is required')
    archive=ident(data['archive_id']);verification=ident(data['verification_id'])
    if type(data['revision']) is not int or not 1<=data['revision']<=MAX_REVISION:
        raise EvidenceError(where+': revision must be an integer >=1')
    if 'retracted' in data and type(data['retracted']) is not bool:
        raise EvidenceError(where+': retracted must be a boolean')
    has_report='report' in data;retracted=data.get('retracted',False)
    if retracted==has_report:
        raise EvidenceError(where+': provide exactly one of report or retracted:true')
    observed_us=parse_timestamp(data['observed_at'])
    if has_report:
        summary=_validate_report(data['report'],where)
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
    """Insert one revision and, for a report, its shared content-addressed object.

    The object row is keyed by the canonical report SHA256, never by compressed
    bytes, so equal reports collapse to one row regardless of how they were
    compressed.  Both writes happen in the caller's transaction: a failed batch
    leaves neither an orphaned object nor a revision.
    """
    summary=rev['summary']
    payload=summary['report_json']
    if payload is not None:
        encoded=payload.encode('utf-8')
        existing=con.execute('SELECT 1 FROM report_objects WHERE report_sha256=?',
                             (rev['report_sha256'],)).fetchone()
        if existing is None:
            con.execute('INSERT INTO report_objects(report_sha256,report_z,report_size)'
                        ' VALUES(?,?,?)',
                        (rev['report_sha256'],
                         zlib.compress(encoded,COMPRESS_LEVEL),len(encoded)))
    return con.execute(
        'INSERT INTO revisions(verification_id,archive_id,revision,observed_at,observed_us,'
        'kind,line_sha256,report_sha256,total_bytes,statuses_json,'
        'status_counts_json,file_count,unlisted_count,all_verified,clean)'
        ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (rev['verification_id'],rev['archive_id'],rev['revision'],rev['observed_at'],
         rev['observed_us'],rev['kind'],rev['line_sha256'],rev['report_sha256'],
         summary['total'],summary['statuses_json'],
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

    A schema-v1 store is refused rather than converted: v1 remains queryable
    (read-only), but writing to it requires the explicit ``migrate`` step.
    """
    attempts=max(1,attempts);last_error=None
    for attempt in range(attempts):
        con=None
        try:
            con=_open_writable(db_path,busy_timeout)
            _prepare_for_write(con)
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


# ------------------------------------------------------------------ migration

_MIGRATION_STATEMENTS=(
 # Real tables, built under temporary names while the v1 ones stay intact.
 'CREATE TABLE report_objects_v2('
 ' report_sha256 TEXT PRIMARY KEY'
 "  CHECK(typeof(report_sha256)='text' AND length(report_sha256)=64),"
 ' report_z BLOB NOT NULL CHECK(length(report_z)>0),'
 ' report_size INTEGER NOT NULL CHECK(report_size>0))',
 'CREATE TABLE revisions_v2('
 ' revision_id INTEGER PRIMARY KEY AUTOINCREMENT,'
 ' verification_id TEXT NOT NULL,'
 ' archive_id TEXT NOT NULL,'
 ' revision INTEGER NOT NULL CHECK(revision>=1),'
 ' observed_at TEXT NOT NULL,'
 ' observed_us INTEGER NOT NULL,'
 ' kind TEXT NOT NULL CHECK(kind IN (\'report\',\'retraction\')),'
 ' line_sha256 TEXT NOT NULL,'
 ' report_sha256 TEXT,'
 ' total_bytes INTEGER NOT NULL CHECK(total_bytes>=0),'
 ' statuses_json TEXT NOT NULL,'
 ' status_counts_json TEXT NOT NULL,'
 ' file_count INTEGER NOT NULL CHECK(file_count>=0),'
 ' unlisted_count INTEGER NOT NULL CHECK(unlisted_count>=0),'
 ' all_verified INTEGER NOT NULL CHECK(all_verified IN (0,1)),'
 ' clean INTEGER NOT NULL CHECK(clean IN (0,1)),'
 ' CHECK((kind=\'report\')=(report_sha256 IS NOT NULL)),'
 ' CHECK(kind=\'report\' OR (total_bytes=0 AND file_count=0'
 '       AND unlisted_count=0 AND statuses_json=\'[]\''
 '       AND status_counts_json=\'{}\' AND all_verified=0 AND clean=0)),'
 ' FOREIGN KEY(report_sha256) REFERENCES report_objects_v2(report_sha256)'
 '  DEFERRABLE INITIALLY DEFERRED,'
 ' UNIQUE(verification_id,revision))',
)


def _decompress_report(blob,size,expected_sha,where):
    """Inflate one stored report with hard bounds and verify its identity.

    Migration must never trust a v1 file blindly: the BLOB is inflated with a
    bounded decompressor, its length must equal the recorded size, and its
    canonical bytes must hash to the recorded ``report_sha256``.  Any deviation
    rejects the whole migration.
    """
    if blob is None:raise EvidenceError(where+': report object is missing')
    try:
        inflater=zlib.decompressobj()
        payload=inflater.decompress(blob,MAX_REPORT_BYTES+1)
    except zlib.error as e:
        raise EvidenceError(where+': stored report is corrupt') from e
    if len(payload)!=size or inflater.unconsumed_tail or not inflater.eof:
        raise EvidenceError(where+': stored report size does not match its record')
    digest=hashlib.sha256(payload).hexdigest()
    if digest!=expected_sha:
        raise EvidenceError(where+': stored report digest does not match its record')
    return payload


def _migrate(con):
    """Rebuild a v1 store as v2 in the caller's single transaction.

    All v1 revisions, verifications, knowledge sequences, ``sqlite_sequence``
    high-water marks and summaries are preserved.  Report bodies are copied
    into content-addressed objects (one row per canonical report SHA256, so
    shared reports collapse even when their v1 compressed bytes differ); each
    revision row is re-pointed at that object via the same SHA256 it already
    stores.  Retractions own no object.  Nothing is loaded wholesale into
    Python: the bodies are streamed row by row from SQLite, and only each
    bounded BLOB is inflated for verification.

    The rebuild is idempotent: a v2 store is left untouched and reported as
    already migrated.  A v1 store that fails validation (bad record, corrupt
    or mislabelled body) aborts the whole migration; the original v1 file is
    unchanged because every write stays inside the transaction.
    """
    version=_meta_version(con)
    if version==SCHEMA_VERSION:
        head=con.execute('SELECT COALESCE(MAX(revision_id),0) FROM revisions').fetchone()[0]
        return {'schema_version':SCHEMA_VERSION,'migrated':False,'from_version':SCHEMA_VERSION,
                'revisions':con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],
                'objects':con.execute('SELECT COUNT(*) FROM report_objects').fetchone()[0],
                'knowledge_head':head}
    if version!=V1_SCHEMA_VERSION:
        raise EvidenceError('incompatible evidence store schema v%s'%version)

    _assert_v1_shape(con)
    high_water=_v1_sequence(con)
    for statement in _MIGRATION_STATEMENTS:con.execute(statement)

    # Stream every report revision one at a time.  Each row's own BLOB is
    # inflated with a hard bound and checked against its recorded length,
    # digest and the report structure/count contract, so a damaged *last* row
    # still rejects the migration.  The object table deduplicates by canonical
    # SHA256; the first validated representation wins, so differently
    # compressed copies of one report collapse to a single object.
    for revision_id,report_sha,blob,size in con.execute(
            'SELECT revision_id,report_sha256,report_z,report_size FROM revisions'
            ' WHERE kind=\'report\' ORDER BY revision_id'):
        where='revision_id %d'%revision_id
        if report_sha is None or blob is None or size is None:
            raise EvidenceError(where+': report revision lacks a body or digest')
        payload=_decompress_report(blob,size,report_sha,where)
        summary=_validate_report(loads(payload),where)
        # The validator already produced the canonical serialization; compare it
        # directly instead of serializing the same report a second time.
        if summary['report_json'].encode('utf-8')!=payload:
            raise EvidenceError(where+': stored body is not canonical JSON')
        con.execute('INSERT OR IGNORE INTO report_objects_v2(report_sha256,report_z,report_size)'
                    ' VALUES(?,?,?)',(report_sha,blob,size))

    # Copy every revision, preserving revision_id (the knowledge sequence) and
    # the summary columns; the object reference is the stored report SHA256.
    con.execute(
        'INSERT INTO revisions_v2(revision_id,verification_id,archive_id,revision,'
        'observed_at,observed_us,kind,line_sha256,report_sha256,total_bytes,'
        'statuses_json,status_counts_json,file_count,unlisted_count,all_verified,clean)'
        ' SELECT revision_id,verification_id,archive_id,revision,observed_at,observed_us,'
        'kind,line_sha256,report_sha256,total_bytes,statuses_json,status_counts_json,'
        'file_count,unlisted_count,all_verified,clean FROM revisions'
        ' ORDER BY revision_id')
    _require_count(con,'SELECT COUNT(*) FROM revisions','SELECT COUNT(*) FROM revisions_v2',
                   'revision count changed during migration')
    _require_count(con,'SELECT COUNT(DISTINCT report_sha256) FROM revisions'
                       ' WHERE kind=\'report\'',
                   'SELECT COUNT(DISTINCT report_sha256) FROM revisions_v2',
                   'report digest count changed during migration')

    # Every report revision must resolve to exactly one object.
    missing=con.execute('SELECT COUNT(*) FROM revisions_v2 r WHERE r.kind=\'report\''
                        ' AND NOT EXISTS (SELECT 1 FROM report_objects_v2 o'
                        '                 WHERE o.report_sha256=r.report_sha256)').fetchone()[0]
    if missing:raise EvidenceError('migration left %d revisions without a report object'%missing)
    _check_v2_integrity(con)

    # Swap real names and keep knowledge order continuous.  ``sqlite_sequence``
    # is restored from the captured high-water mark, so a head above the
    # largest row id still continues from the right next value.
    _swap_tables(con)
    _restore_sequence(con,high_water)
    con.execute('UPDATE evidence_meta SET schema_version=? WHERE id=1',(SCHEMA_VERSION,))
    revisions=con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0]
    objects=con.execute('SELECT COUNT(*) FROM report_objects').fetchone()[0]
    head=con.execute('SELECT COALESCE(MAX(revision_id),0) FROM revisions').fetchone()[0]
    return {'schema_version':SCHEMA_VERSION,'migrated':True,'from_version':V1_SCHEMA_VERSION,
            'revisions':revisions,'objects':objects,'knowledge_head':head}


def _assert_v1_shape(con):
    """Refuse to migrate anything that is not the known v1 layout."""
    expected={
      'revisions':{'revision_id','verification_id','archive_id','revision','observed_at',
                   'observed_us','kind','line_sha256','report_sha256','report_z','report_size',
                   'total_bytes','statuses_json','status_counts_json','file_count',
                   'unlisted_count','all_verified','clean'},
      'verifications':{'verification_id','archive_id'},
      'evidence_meta':{'id','schema_version','created_utc'}}
    for table,columns in expected.items():
        row=con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                        (table,)).fetchone()
        if row is None:raise EvidenceError('not an evidence store v1: missing table '+table)
        actual={r[1] for r in con.execute('PRAGMA table_info(%s)'%table)}
        if actual!=columns:
            raise EvidenceError('not an evidence store v1: unexpected %s columns'%table)


def _v1_sequence(con):
    try:
        row=con.execute("SELECT seq FROM sqlite_sequence WHERE name='revisions'").fetchone()
    except sqlite3.OperationalError:return None
    return None if row is None else int(row[0])


def _require_count(con,left,right,message):
    a=con.execute(left).fetchone()[0];b=con.execute(right).fetchone()[0]
    if a!=b:raise EvidenceError(message+' (%d != %d)'%(a,b))


def _check_v2_integrity(con):
    """Count-based integrity checks, so migration stays near-linear."""
    if con.execute('PRAGMA foreign_key_check').fetchone() is not None:
        raise EvidenceError('migration produced a foreign key violation')
    if con.execute('SELECT COUNT(*) FROM revisions_v2 WHERE kind=\'report\''
                   ' AND report_sha256 IS NULL').fetchone()[0]:
        raise EvidenceError('migration produced a report revision without a digest')
    # Every report revision resolves to an object (checked in _migrate), so
    # objects == distinct referenced digests iff there are no orphan objects.
    object_count=con.execute('SELECT COUNT(*) FROM report_objects_v2').fetchone()[0]
    referenced=con.execute('SELECT COUNT(DISTINCT report_sha256) FROM revisions_v2'
                           ' WHERE kind=\'report\'').fetchone()[0]
    if object_count!=referenced:
        raise EvidenceError('migration produced %d unreferenced objects'
                            %max(0,object_count-referenced))


def _swap_tables(con):
    """Rename the rebuilt tables into place; v1 tables are dropped first."""
    con.execute('DROP TABLE revisions')
    con.execute('ALTER TABLE report_objects_v2 RENAME TO report_objects')
    con.execute('ALTER TABLE revisions_v2 RENAME TO revisions')
    con.execute('CREATE INDEX revisions_verification_lookup'
                ' ON revisions(verification_id,revision_id)')
    con.execute('CREATE INDEX revisions_timeline'
                ' ON revisions(archive_id,observed_us DESC,verification_id DESC)')


def _restore_sequence(con,high_water):
    """Keep the AUTOINCREMENT high-water mark across the table swap.

    The mark is never lowered below the largest surviving id, so continuation
    is correct both when the v1 head exceeded the last row id and when it did
    not.
    """
    largest=con.execute('SELECT COALESCE(MAX(revision_id),0) FROM revisions').fetchone()[0]
    seq=max(largest,0 if high_water is None else int(high_water))
    con.execute("DELETE FROM sqlite_sequence WHERE name='revisions'")
    con.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('revisions',?)",(seq,))


def migrate(db_path,attempts=DEFAULT_RETRY_ATTEMPTS,delay=DEFAULT_RETRY_DELAY,
            busy_timeout=5000):
    """Explicitly migrate a v1 store to the shared-object v2 layout.

    The rebuild, deduplication, reference rewrite and index swap all happen in
    one ``BEGIN IMMEDIATE`` transaction: an interrupted or failing migration
    leaves the original v1 file byte-for-byte usable.  Re-running on a v2
    store is an idempotent no-op (``migrated`` false).  A v1 store is never
    converted implicitly by ingest or query.
    """
    path=_plain(db_path,'evidence store')
    if not path.is_file():raise EvidenceError('evidence store does not exist: '+str(path))
    if path.stat().st_size==0:
        raise EvidenceError('evidence store does not exist (empty file): '+str(path))
    attempts=max(1,attempts);last_error=None
    for attempt in range(attempts):
        con=None
        try:
            con=_open_writable(path,busy_timeout,allow_v1=True)
            con.execute('BEGIN IMMEDIATE')
            summary=_migrate(con)
            con.execute('COMMIT')
            if summary['migrated']:
                try:_set_write_pragmas(con)
                except sqlite3.Error:pass  # durable mode is not part of the contract
            con.close()
            return summary
        except (sqlite3.OperationalError,EvidenceError) as e:
            if con is not None:
                try:con.execute('ROLLBACK')
                except sqlite3.Error:pass
                try:con.close()
                except sqlite3.Error:pass
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
    raise EvidenceError('evidence migration failed after retries: '+str(last_error))


# --------------------------------------------------------------------- query

# At knowledge cutoff S a candidate revision must be the latest revision of
# its verification.  It must be a report (a retraction is invalid) observed no
# later than T.  The timeline index supplies the required descending order and
# LIMIT 1 stops after the first survivor.  v2 joins the shared object; v1 keeps
# its per-revision BLOB in the same result shape.
_WINNER_V2=(
 'SELECT r.verification_id,r.revision,r.revision_id,r.observed_at,r.report_sha256,'
 ' o.report_z,o.report_size,r.statuses_json,r.status_counts_json,r.file_count,r.unlisted_count,'
 ' r.all_verified,r.clean'
 ' FROM revisions r LEFT JOIN report_objects o ON o.report_sha256=r.report_sha256'
 ' WHERE r.archive_id=? AND r.revision_id<=? AND r.kind=\'report\' AND r.observed_us<=?'
 ' AND NOT EXISTS (SELECT 1 FROM revisions n'
 '                 WHERE n.verification_id=r.verification_id'
 '                   AND n.revision_id>r.revision_id AND n.revision_id<=?)'
 ' ORDER BY r.observed_us DESC, r.verification_id DESC LIMIT 1')

_WINNER_V1=(
 'SELECT r.verification_id,r.revision,r.revision_id,r.observed_at,r.report_sha256,'
 ' r.report_z,r.report_size,r.statuses_json,r.status_counts_json,r.file_count,r.unlisted_count,'
 ' r.all_verified,r.clean'
 ' FROM revisions r'
 ' WHERE r.archive_id=? AND r.revision_id<=? AND r.kind=\'report\' AND r.observed_us<=?'
 ' AND NOT EXISTS (SELECT 1 FROM revisions n'
 '                 WHERE n.verification_id=r.verification_id'
 '                   AND n.revision_id>r.revision_id AND n.revision_id<=?)'
 ' ORDER BY r.observed_us DESC, r.verification_id DESC LIMIT 1')

# Kept for callers and tests that inspect the v2 query plan.
_WINNER=_WINNER_V2


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
    con,version=_open_existing(db_path)
    winner=_WINNER_V2 if version==SCHEMA_VERSION else _WINNER_V1
    try:
        row=con.execute(winner,(archive,knowledge,cutoff_us,knowledge)).fetchone()
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
        payload=_decompress_report(report_z,report_size,report_sha256,'knowledge sequence %d'
                                   %sequence)
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


def _migrate_parser():
    p=argparse.ArgumentParser(prog='archive-fixity evidence-migrate',
                              description='Rebuild a v1 evidence store as shared-object v2')
    p.add_argument('--db',type=Path,required=True,help='SQLite evidence store to migrate in place')
    p.add_argument('--retry-attempts',type=_positive_int,default=DEFAULT_RETRY_ATTEMPTS,
                   help='transient lock retries (default %d)'%DEFAULT_RETRY_ATTEMPTS)
    p.add_argument('--retry-delay',type=_non_negative_float,default=DEFAULT_RETRY_DELAY,
                   help='initial retry delay in seconds (default %s)'%DEFAULT_RETRY_DELAY)
    return p


def migrate_main(argv):
    """CLI entry: explicitly migrate one store, print the JSON summary."""
    a=_migrate_parser().parse_args(argv)
    try:
        summary=migrate(a.db,attempts=a.retry_attempts,delay=a.retry_delay)
    except (EvidenceError,OSError,sqlite3.Error) as e:
        print(str(e),file=sys.stderr);return 2
    print(json.dumps(summary,sort_keys=True));return 0
