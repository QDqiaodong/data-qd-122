"""Build genuine schema-v1 evidence stores for migration tests.

The v1 layout is reproduced verbatim (one compressed report BLOB per revision)
so the migration tests exercise the real on-disk contract rather than a
synthetic stand-in.  Reports are still validated by the shipped validator, so
every fixture row is structurally valid; only the storage representation
differs.
"""
import hashlib
import json
import sqlite3
import zlib
from pathlib import Path

from archive_fixity.evidence import _retraction_summary, _validate_report, \
    format_timestamp, parse_timestamp

V1_SCHEMA=(
 "CREATE TABLE evidence_meta(id INTEGER PRIMARY KEY CHECK(id=1),"
 " schema_version INTEGER NOT NULL, created_utc TEXT NOT NULL)",
 "CREATE TABLE verifications(verification_id TEXT PRIMARY KEY, archive_id TEXT NOT NULL)",
 "CREATE TABLE revisions("
 " revision_id INTEGER PRIMARY KEY AUTOINCREMENT,"
 " verification_id TEXT NOT NULL, archive_id TEXT NOT NULL,"
 " revision INTEGER NOT NULL CHECK(revision>=1),"
 " observed_at TEXT NOT NULL, observed_us INTEGER NOT NULL,"
 " kind TEXT NOT NULL CHECK(kind IN ('report','retraction')),"
 " line_sha256 TEXT NOT NULL, report_sha256 TEXT, report_z BLOB,"
 " report_size INTEGER NOT NULL CHECK(report_size>=0),"
 " total_bytes INTEGER NOT NULL CHECK(total_bytes>=0),"
 " statuses_json TEXT NOT NULL, status_counts_json TEXT NOT NULL,"
 " file_count INTEGER NOT NULL CHECK(file_count>=0),"
 " unlisted_count INTEGER NOT NULL CHECK(unlisted_count>=0),"
 " all_verified INTEGER NOT NULL CHECK(all_verified IN (0,1)),"
 " clean INTEGER NOT NULL CHECK(clean IN (0,1)),"
 " CHECK((kind='report')=(report_z IS NOT NULL)),"
 " CHECK((kind='report')=(report_sha256 IS NOT NULL)),"
 " UNIQUE(verification_id,revision))",
 "CREATE INDEX revisions_verification_lookup"
 " ON revisions(verification_id,revision_id)",
 "CREATE INDEX revisions_timeline"
 " ON revisions(archive_id,observed_us DESC,verification_id DESC)",
)


def raw_line(verification,revision,observed_at,body=None,archive='archive-1',
             retracted=False):
    """The exact NDJSON line a v1 ingest would have hashed."""
    item={'archive_id':archive,'verification_id':verification,'revision':revision,
          'observed_at':observed_at}
    if retracted:item['retracted']=True
    else:item['report']=body
    return json.dumps(item,ensure_ascii=False).encode('utf-8')


class V1Store:
    """Incrementally build a v1 database with controllable compression."""

    def __init__(self,path):
        self.path=Path(path)
        self.con=sqlite3.connect(str(self.path),isolation_level=None)
        # The shipped v1 writer always opened in WAL + full synchronous mode.
        self.con.execute('PRAGMA journal_mode=WAL')
        self.con.execute('PRAGMA synchronous=FULL')
        for statement in V1_SCHEMA:self.con.execute(statement)
        self.con.execute('BEGIN')   # one transaction for the whole fixture
        self.verifications={}

    def add(self,verification,revision,observed_at,body=None,archive='archive-1',
            retracted=False,compress_level=6,corrupt=None,report_sha_override=None):
        """Append one revision; ``corrupt`` may damage the stored BLOB on purpose."""
        where='line 1'
        if verification not in self.verifications:
            assert revision==1,(verification,revision)
            self.con.execute('INSERT INTO verifications VALUES(?,?)',(verification,archive))
            self.verifications[verification]=archive
        if body is None:
            summary=_retraction_summary();kind='retraction';report_sha=None;blob=None
        else:
            summary=_validate_report(body,where);kind='report'
            report_sha=report_sha_override or summary['report_sha256']
            encoded=summary['report_json'].encode('utf-8')
            blob=zlib.compress(encoded,compress_level)
            if corrupt:blob=corrupt
        observed_us=parse_timestamp(observed_at)
        raw=raw_line(verification,revision,observed_at,body,archive,retracted)
        self.con.execute(
            'INSERT INTO revisions(verification_id,archive_id,revision,observed_at,'
            'observed_us,kind,line_sha256,report_sha256,report_z,report_size,total_bytes,'
            'statuses_json,status_counts_json,file_count,unlisted_count,all_verified,clean)'
            ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (verification,archive,revision,format_timestamp(observed_us),observed_us,kind,
             hashlib.sha256(raw).hexdigest(),report_sha,blob,summary['report_size'],
             summary['total'],summary['statuses_json'],summary['status_counts_json'],
             summary['file_count'],summary['unlisted_count'],int(summary['all_verified']),
             int(summary['clean'])))
        return self

    def bump_sequence(self,value):
        self.con.execute("UPDATE sqlite_sequence SET seq=? WHERE name='revisions'",(value,))
        return self

    def drop_sequence_row(self):
        self.con.execute("DELETE FROM sqlite_sequence WHERE name='revisions'")
        return self

    def close(self):
        self.con.execute('INSERT INTO evidence_meta VALUES(1,1,\'2026-01-01T00:00:00.000000Z\')'
                         ' ON CONFLICT(id) DO NOTHING')
        self.con.execute('COMMIT')
        self.con.close()


def build(path):
    return V1Store(path)
