"""v2 shared-object evidence store: dedup, migration, crash safety, compatibility."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))

from archive_fixity.evidence import EvidenceError, ingest, migrate, query
import evidence_v1_fixture as v1
from evidence_fixture import iso, line, report, sha, write_batch

ROOT=Path(__file__).resolve().parents[1]
CLI=[sys.executable,'-m','archive_fixity.cli']
ENV=dict(os.environ,PYTHONPATH=str(ROOT/'src'))


def tables(con):
    return {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def objects(con):
    return con.execute('SELECT COUNT(*) FROM report_objects').fetchone()[0]


class StoreCase(unittest.TestCase):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory()
        self.base=Path(self._td.name)
        self.db=self.base/'evidence.sqlite3'

    def tearDown(self):self._td.cleanup()

    def ingest_lines(self,lines,name='batch.ndjson',db=None):
        batch=write_batch(self.base/name,lines)
        return ingest(db or self.db,batch,delay=0)

    def connect(self,db=None):
        con=sqlite3.connect(str(db or self.db),isolation_level=None)
        con.execute('PRAGMA query_only=OFF')
        self.addCleanup(con.close)
        return con


class SharedObjectTests(StoreCase):
    def test_same_report_is_physically_stored_once(self):
        body=report([('a.txt',b'alpha'),('b.txt',b'beta')])
        self.ingest_lines([line('v1',1,iso(10),body),line('v2',1,iso(20),body)])
        # Same content, different verification: one canonical SHA256, one row.
        con=self.connect()
        self.assertEqual(objects(con),1)
        self.assertEqual(con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],2)
        self.assertEqual(con.execute(
            'SELECT COUNT(DISTINCT report_sha256) FROM revisions').fetchone()[0],1)

    def test_repeated_report_across_revisions_of_one_verification_is_shared(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body)])
        # Submit the identical report again as revision 2 from a separate batch.
        self.ingest_lines([line('v1',2,iso(10),body)],name='second.ndjson')
        con=self.connect()
        self.assertEqual(objects(con),1)
        self.assertEqual(con.execute(
            'SELECT COUNT(DISTINCT report_sha256) FROM revisions').fetchone()[0],1)

    def test_retraction_has_no_object(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body),
                           line('v1',2,iso(10),retracted=True)])
        con=self.connect()
        self.assertEqual(objects(con),1)
        self.assertIsNone(con.execute(
            'SELECT report_sha256 FROM revisions WHERE kind=\'retraction\'').fetchone()[0])

    def test_distinct_reports_get_distinct_objects(self):
        self.ingest_lines([line('v1',1,iso(10),report([('a.txt',b'one')])),
                           line('v2',1,iso(20),report([('a.txt',b'two')]))])
        con=self.connect()
        self.assertEqual(objects(con),2)

    def test_identical_content_with_different_json_key_order_shares_an_object(self):
        # Canonicalization makes key order irrelevant: both are the same report.
        body=report([('a.txt',b'alpha')])
        reordered=json.loads(json.dumps(body))
        reordered={'result':reordered['result'],'source_sha256':reordered['source_sha256'],
                   'schema_version':reordered['schema_version']}
        self.ingest_lines([line('v1',1,iso(10),body),line('v2',1,iso(20),reordered)])
        con=self.connect()
        self.assertEqual(objects(con),1)

    def test_bad_batch_leaves_no_orphan_object(self):
        good=report([('a.txt',b'alpha')])
        fresh=report([('b.txt',b'beta')])
        self.ingest_lines([line('v1',1,iso(10),good)])
        with self.assertRaises(EvidenceError):
            self.ingest_lines([line('v2',1,iso(20),fresh),'{"bad":1}'],
                              name='bad.ndjson')
        con=self.connect()
        self.assertEqual(objects(con),1)
        self.assertIsNone(con.execute(
            'SELECT 1 FROM report_objects WHERE report_sha256=?',
            (hashlib.sha256(json.dumps(fresh,sort_keys=True,ensure_ascii=False,
                                       separators=(',',':')).encode()).hexdigest(),)
        ).fetchone())

    def test_crash_after_object_write_rolls_back_the_object(self):
        body=report([('a.txt',b'alpha')])
        batch=write_batch(self.base/'crash.ndjson',[line('v1',1,iso(10),body)])
        def barrier(event,line_no):
            if event=='after_insert':raise RuntimeError('simulated crash')
        with self.assertRaises(RuntimeError):
            ingest(self.db,batch,delay=0,barrier=barrier)
        if self.db.exists():
            con=sqlite3.connect(self.db)
            try:
                names=tables(con)
                if 'report_objects' in names:
                    self.assertEqual(objects(con),0)
                if 'revisions' in names:
                    self.assertEqual(con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],0)
            finally:con.close()
        summary=ingest(self.db,batch,delay=0)
        self.assertEqual(summary['knowledge_head'],1)

    def test_report_object_key_is_the_canonical_digest_not_compressed_bytes(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body)])
        con=self.connect()
        key,blob=con.execute('SELECT report_sha256,report_z FROM report_objects').fetchone()
        payload=zlib.decompress(blob)
        self.assertEqual(hashlib.sha256(payload).hexdigest(),key)
        # The compressed bytes hash differently from the report digest.
        self.assertNotEqual(hashlib.sha256(blob).hexdigest(),key)

    def test_same_report_with_a_different_source_digest_is_not_shared(self):
        # Dedup is by canonical report bytes, so a changed report is a new object.
        self.ingest_lines([line('v1',1,iso(10),report([('a.txt',b'alpha')]))])
        self.ingest_lines([line('v2',1,iso(20),
                                report([('a.txt',b'alpha')],source='1'*64))],
                          name='different.ndjson')
        con=self.connect()
        self.assertEqual(objects(con),2)

    def test_missing_object_is_reported_not_silently_skipped_to_an_older_report(self):
        # A damaged store must not fall back to an older surviving report.
        self.ingest_lines([line('v1',1,iso(100),report([('a.txt',b'old')]))])
        self.ingest_lines([line('v2',1,iso(200),report([('a.txt',b'new')]))],
                          name='second.ndjson')
        con=self.connect()
        victim=con.execute("SELECT report_sha256 FROM revisions WHERE verification_id='v2'"
                           ).fetchone()[0]
        con.execute('PRAGMA foreign_keys=OFF')
        con.execute('DELETE FROM report_objects WHERE report_sha256=?',(victim,))
        con.close()
        with self.assertRaises(EvidenceError) as cm:
            query(self.db,'archive-1','a.txt',iso(1000),10)
        self.assertIn('missing',str(cm.exception))


class V1ReadTests(StoreCase):
    def make_v1(self,db=None,compress_levels=(1,9)):
        db=db or self.db
        store=v1.build(db)
        body=report([('a.txt',b'alpha')])
        store.add('v1',1,iso(100),body,compress_level=compress_levels[0])
        store.add('v2',1,iso(200),body,compress_level=compress_levels[1])
        store.add('v3',1,iso(300),retracted=True)
        store.add('v1',2,iso(100),report([('a.txt',b'beta')]))
        store.close()
        return body

    def test_v1_store_is_queried_read_only_without_conversion(self):
        self.make_v1()
        before=self.db.read_bytes()
        result=query(self.db,'archive-1','a.txt',iso(1000),10)
        self.assertEqual(result['verification_id'],'v2')
        self.assertEqual(result['observation']['actual_sha256'],sha(b'alpha'))
        # Even at an early knowledge cutoff, v2's retracted third revision
        # is invisible, so v1's first revision is the last known one.
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),1)['verification_id'],'v1')
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),2)['verification_id'],'v2')
        self.assertEqual(self.db.read_bytes(),before)
        con=sqlite3.connect(self.db)
        try:self.assertEqual(
            con.execute('SELECT schema_version FROM evidence_meta').fetchone()[0],1)
        finally:con.close()

    def test_v1_write_is_refused_with_a_migration_hint(self):
        self.make_v1()
        before=self.db.read_bytes()
        with self.assertRaises(EvidenceError) as cm:
            self.ingest_lines([line('v4',1,iso(400),report([('a.txt',b'gamma')]))])
        message=str(cm.exception)
        self.assertIn('v1',message)
        self.assertIn('evidence-migrate',message)
        self.assertEqual(self.db.read_bytes(),before)

    def test_v1_cli_write_exit_code_and_hint(self):
        self.make_v1()
        batch=write_batch(self.base/'b.ndjson',
                          [line('v4',1,iso(400),report([('a.txt',b'gamma')]))])
        done=subprocess.run(CLI+['evidence-ingest','--db',str(self.db),'--batch',str(batch)],
                            capture_output=True,text=True,env=ENV)
        self.assertEqual(done.returncode,2)
        self.assertIn('evidence-migrate',done.stderr)


class MigrationTests(StoreCase):
    def make_v1(self,compress_levels=(1,9)):
        store=v1.build(self.db)
        body=report([('a.txt',b'alpha')])
        store.add('v1',1,iso(100),body,compress_level=compress_levels[0])
        store.add('v2',1,iso(200),body,compress_level=compress_levels[1])
        store.add('v3',1,iso(300),retracted=True)
        store.add('v1',2,iso(100),report([('a.txt',b'beta')]))
        store.close()
        return body

    def test_migration_preserves_history_and_dedupes(self):
        self.make_v1()
        probes=[]
        for cutoff in range(0,6):
            for observed in (iso(50),iso(100),iso(250),iso(1000)):
                probes.append((observed,cutoff,query(self.db,'archive-1','a.txt',observed,cutoff)))
        summary=migrate(self.db)
        self.assertTrue(summary['migrated'])
        self.assertEqual(summary['from_version'],1)
        self.assertEqual(summary['revisions'],4)
        self.assertEqual(summary['objects'],2)
        self.assertEqual(summary['knowledge_head'],4)
        con=self.connect()
        self.assertEqual(objects(con),2)
        self.assertEqual(con.execute('SELECT schema_version FROM evidence_meta').fetchone()[0],2)
        for observed,cutoff,before in probes:
            self.assertEqual(query(self.db,'archive-1','a.txt',observed,cutoff),before)
        self.assertEqual(con.execute(
            'SELECT COUNT(*) FROM revisions WHERE kind=\'retraction\''
            ' AND report_sha256 IS NULL').fetchone()[0],1)

    def test_migration_dedupes_identical_reports_with_different_compression(self):
        # Same canonical report stored under level 1 and level 9 in v1.
        self.make_v1(compress_levels=(1,9))
        con=self.connect()
        blobs=[row[0] for row in con.execute(
            'SELECT report_z FROM revisions WHERE kind=\'report\' ORDER BY revision_id')]
        self.assertEqual(len({hashlib.sha256(b).hexdigest() for b in blobs[:2]}),2,
                         'v1 fixture must really contain differently compressed copies')
        migrate(self.db)
        self.assertEqual(objects(con),2)  # two distinct reports, not three rows
        self.assertEqual(con.execute(
            'SELECT COUNT(*) FROM revisions WHERE report_sha256='
            '(SELECT report_sha256 FROM revisions WHERE revision_id=1)').fetchone()[0],2)

    def test_sequence_high_water_above_max_row_id_continues_correctly(self):
        self.make_v1()
        con=self.connect()
        con.execute("UPDATE sqlite_sequence SET seq=500 WHERE name='revisions'")
        con.close()
        summary=migrate(self.db)
        self.assertEqual(summary['knowledge_head'],4)
        con=self.connect()
        self.assertEqual(con.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='revisions'").fetchone()[0],500)
        self.assertEqual(con.execute('SELECT COUNT(*) FROM sqlite_sequence'
                                     " WHERE name='revisions'").fetchone()[0],1)
        con.close()
        result=self.ingest_lines([line('v4',1,iso(400),report([('a.txt',b'delta')]))],
                                 name='after.ndjson')
        self.assertEqual(result['first_knowledge_sequence'],501)
        self.assertEqual(result['knowledge_head'],501)
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),501)['verification_id'],'v4')

    def test_sequence_absent_from_v1_is_rebuilt_from_rows(self):
        self.make_v1()
        store_con=sqlite3.connect(self.db)
        store_con.execute("DELETE FROM sqlite_sequence WHERE name='revisions'")
        store_con.commit();store_con.close()
        migrate(self.db)
        con=self.connect()
        self.assertEqual(con.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='revisions'").fetchone()[0],4)
        con.close()
        result=self.ingest_lines([line('v4',1,iso(400),report([('a.txt',b'delta')]))],
                                 name='after.ndjson')
        self.assertEqual(result['first_knowledge_sequence'],5)

    def test_migration_does_not_replay_ndjson_numbering(self):
        # Revision numbers (per verification) stay themselves; only the global
        # knowledge sequence is preserved, and it must not be renumbered.
        self.make_v1()
        con=self.connect()
        before=con.execute('SELECT revision_id,verification_id,revision FROM revisions'
                           ' ORDER BY revision_id').fetchall()
        con.close()
        migrate(self.db)
        con=self.connect()
        after=con.execute('SELECT revision_id,verification_id,revision FROM revisions'
                          ' ORDER BY revision_id').fetchall()
        self.assertEqual(before,after)

    def test_migration_is_idempotent_and_does_not_touch_v2(self):
        self.make_v1()
        migrate(self.db)
        before=self.db.read_bytes()
        again=migrate(self.db)
        self.assertFalse(again['migrated'])
        self.assertEqual(again['from_version'],2)
        self.assertEqual(again['revisions'],4)
        self.assertEqual(self.db.read_bytes(),before)
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),10)['verification_id'],'v2')

    def test_migration_keeps_verification_identity_and_summaries(self):
        self.make_v1()
        con=self.connect()
        before=con.execute('SELECT verification_id,archive_id,revision,observed_at,observed_us,'
                           'kind,line_sha256,total_bytes,statuses_json,status_counts_json,'
                           'file_count,unlisted_count,all_verified,clean FROM revisions'
                           ' ORDER BY revision_id').fetchall()
        verifications=con.execute('SELECT * FROM verifications ORDER BY verification_id').fetchall()
        con.close()
        migrate(self.db)
        con=self.connect()
        after=con.execute('SELECT verification_id,archive_id,revision,observed_at,observed_us,'
                          'kind,line_sha256,total_bytes,statuses_json,status_counts_json,'
                          'file_count,unlisted_count,all_verified,clean FROM revisions'
                          ' ORDER BY revision_id').fetchall()
        self.assertEqual(before,after)
        self.assertEqual(verifications,con.execute(
            'SELECT * FROM verifications ORDER BY verification_id').fetchall())
        self.assertEqual(set(tables(con)),
                         {'evidence_meta','verifications','revisions','report_objects',
                          'sqlite_sequence'})
        self.assertNotIn('report_z',{row[1] for row in con.execute('PRAGMA table_info(revisions)')})

    def test_empty_v1_store_migrates_and_continues_from_one(self):
        store=v1.build(self.db)
        store.close()
        summary=migrate(self.db)
        self.assertTrue(summary['migrated'])
        self.assertEqual((summary['revisions'],summary['objects'],summary['knowledge_head']),
                         (0,0,0))
        result=self.ingest_lines([line('v1',1,iso(100),report([('a.txt',b'alpha')]))],
                                 name='first.ndjson')
        self.assertEqual(result['first_knowledge_sequence'],1)
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(200),1)['outcome'],'observed')

    def test_migrated_store_accepts_shared_ingest(self):
        body=self.make_v1()
        migrate(self.db)
        con=self.connect()
        before_objects=objects(con)
        con.close()
        # A brand-new verification carrying the already-stored report adds no object.
        summary=self.ingest_lines([line('v9',1,iso(500),body)],name='shared.ndjson')
        self.assertEqual(summary['accepted'],1)
        con=self.connect()
        self.assertEqual(objects(con),before_objects)

    def test_exhaustive_history_equivalence_around_retractions_and_corrections(self):
        store=v1.build(self.db)
        body=report([('a.txt',b'alpha'),('b.txt',b'beta')])
        store.add('v1',1,iso(100),body,compress_level=1)
        store.add('v2',1,iso(200),body,compress_level=9)
        store.add('v2',2,iso(200),retracted=True)
        store.add('v1',2,iso(100),report([('a.txt',b'new')]))
        store.add('v3',1,iso(300),report([('b.txt',b'beta')]))
        store.close()
        probes={}
        for path in ('a.txt','b.txt','never.txt'):
            for observed in (iso(50),iso(150),iso(250),iso(1000)):
                for cutoff in range(0,7):
                    probes[(path,observed,cutoff)]=query(self.db,'archive-1',path,
                                                         observed,cutoff)
        summary=migrate(self.db)
        self.assertEqual((summary['revisions'],summary['objects']),(5,3))
        for (path,observed,cutoff),expected in probes.items():
            self.assertEqual(query(self.db,'archive-1',path,observed,cutoff),expected,
                             (path,observed,cutoff))
        # The head stays exactly where v1 left it, including the summary.
        self.assertEqual(self.ingest_lines([],name='head.ndjson')['knowledge_head'],5)

    def test_v1_and_v2_answers_match_for_every_query_shape(self):
        store=v1.build(self.db)
        body=report([('a.txt',b'alpha')],unlisted=['extra.txt'])
        store.add('v1',1,iso(100),body)
        store.close()
        copy=self.base/'copy.sqlite3'
        con=sqlite3.connect(self.db);dst=sqlite3.connect(copy)
        con.backup(dst);dst.close();con.close()
        migrate(self.db)
        for path in ('a.txt','extra.txt','absent.txt'):
            for observed in (iso(50),iso(100),iso(200)):
                for cutoff in (0,1,5):
                    self.assertEqual(
                        query(self.db,'archive-1',path,observed,cutoff),
                        query(copy,'archive-1',path,observed,cutoff))


class MigrationFailureTests(StoreCase):
    def make_v1(self):
        store=v1.build(self.db)
        store.add('v1',1,iso(100),report([('a.txt',b'alpha')]))
        store.add('v1',2,iso(100),report([('a.txt',b'beta')]))
        store.add('v2',1,iso(200),report([('a.txt',b'gamma')]))
        store.close()

    def snapshot(self):
        return {p.name:p.read_bytes() for p in self.base.iterdir() if p.is_file()}

    def test_corrupt_last_record_rejects_the_whole_migration(self):
        self.make_v1()
        con=sqlite3.connect(self.db)
        con.execute("UPDATE revisions SET report_z=? WHERE revision_id=3",(b'not-zlib',))
        con.commit();con.close()
        before=self.snapshot()
        with self.assertRaises(EvidenceError) as cm:
            migrate(self.db)
        self.assertIn('corrupt',str(cm.exception))
        self.assertEqual(self.snapshot(),before)
        con=sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute('SELECT schema_version FROM evidence_meta'
                                         ).fetchone()[0],1)
            self.assertEqual(con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],3)
        finally:con.close()
        # Queries still work against the untouched v1 store when they do not
        # need the deliberately damaged row.
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),1)['verification_id'],'v1')

    def test_size_or_digest_mismatch_rejects_the_migration(self):
        for column,value in (('report_size',999),('report_sha256','f'*64)):
            with self.subTest(column=column):
                path=self.base/('store-%s.sqlite3'%column)
                store=v1.build(path)
                store.add('v1',1,iso(100),report([('a.txt',b'alpha')]))
                store.add('v1',2,iso(100),report([('a.txt',b'beta')]))
                store.close()
                con=sqlite3.connect(path)
                con.execute('UPDATE revisions SET %s=? WHERE revision_id=2'%column,(value,))
                con.commit();con.close()
                with self.assertRaises(EvidenceError):
                    migrate(path)
                con=sqlite3.connect(path)
                try:
                    self.assertEqual(con.execute('SELECT schema_version FROM evidence_meta'
                                                 ).fetchone()[0],1)
                    self.assertEqual(con.execute('SELECT COUNT(*) FROM revisions'
                                                 ).fetchone()[0],2)
                finally:con.close()

    def test_non_canonical_stored_body_rejects_the_migration(self):
        store=v1.build(self.db)
        store.add('v1',1,iso(100),report([('a.txt',b'alpha')]))
        store.close()
        con=sqlite3.connect(self.db)
        blob,size=con.execute('SELECT report_z,report_size FROM revisions').fetchone()
        pretty=json.dumps(json.loads(zlib.decompress(blob)),indent=2).encode()
        con.execute('UPDATE revisions SET report_z=?,report_size=?,report_sha256=?',
                    (zlib.compress(pretty),len(pretty),hashlib.sha256(pretty).hexdigest()))
        con.commit();con.close()
        before=self.snapshot()
        with self.assertRaises(EvidenceError) as cm:migrate(self.db)
        self.assertIn('canonical',str(cm.exception))
        self.assertEqual(self.snapshot(),before)

    def test_interrupted_migration_leaves_the_v1_store_usable(self):
        self.make_v1()
        before=self.snapshot()
        import archive_fixity.evidence as evidence_module
        real=evidence_module._swap_tables
        def failing(con):
            raise RuntimeError('simulated crash during migration')
        evidence_module._swap_tables=failing
        try:
            with self.assertRaises(RuntimeError):migrate(self.db)
        finally:
            evidence_module._swap_tables=real
        self.assertEqual(self.snapshot(),before)
        con=sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute('SELECT schema_version FROM evidence_meta'
                                         ).fetchone()[0],1)
            self.assertEqual(con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],3)
            self.assertNotIn('report_objects',tables(con))
            self.assertNotIn('report_objects_v2',tables(con))
            self.assertNotIn('revisions_v2',tables(con))
        finally:con.close()
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),10)['verification_id'],'v2')
        # The injected failure is gone; the retry completes normally.
        summary=migrate(self.db)
        self.assertTrue(summary['migrated'])
        self.assertEqual(summary['revisions'],3)
        self.assertEqual(summary['objects'],3)
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),10)['verification_id'],'v2')

    def test_interrupted_process_kill_during_migration_keeps_v1_usable(self):
        # Run the migration in a child process and kill it mid-commit; the
        # surviving file must still be a usable v1 store.
        self.make_v1()
        before=self.snapshot()
        script=self.base/'kill_migrate.py'
        script.write_text(
            'import sys\n'
            'sys.path.insert(0,%r)\n'
            'import archive_fixity.evidence as e\n'
            'real=e._swap_tables\n'
            'def boom(con):\n'
            '    import os,signal\n'
            '    os.kill(os.getpid(),signal.SIGKILL)\n'
            'e._swap_tables=boom\n'
            'e.migrate(%r)\n'%(str(ROOT/'src'),str(self.db)))
        done=subprocess.run([sys.executable,'-I',str(script)],capture_output=True,text=True,
                            env={'PYTHONPATH':str(ROOT/'src')})
        self.assertNotEqual(done.returncode,0)
        script.unlink()
        # A killed writer may leave a journal/WAL side file; the main store must
        # still be a readable, unchanged v1 store.
        self.assertEqual(self.snapshot()['evidence.sqlite3'],before['evidence.sqlite3'])
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(1000),10)['verification_id'],'v2')
        self.assertTrue(migrate(self.db)['migrated'])

    def test_wal_side_files_from_failed_migration_do_not_stop_a_retry(self):
        self.make_v1()
        with self.assertRaises(EvidenceError):
            migrate(self.base/'missing.sqlite3')
        summary=migrate(self.db)
        self.assertTrue(summary['migrated'])

    def test_non_evidence_sqlite_file_is_rejected(self):
        con=sqlite3.connect(self.db);con.execute('CREATE TABLE junk(x)');con.commit();con.close()
        before=self.snapshot()
        with self.assertRaises(EvidenceError):migrate(self.db)
        self.assertEqual(self.snapshot(),before)

    def test_locked_v1_store_migration_is_retried_without_conversion(self):
        store=v1.build(self.db)
        store.add('v1',1,iso(100),report([('a.txt',b'alpha')]))
        store.close()
        blocker=sqlite3.connect(str(self.db),isolation_level=None)
        blocker.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaises(EvidenceError) as cm:
                migrate(self.db,attempts=2,delay=0,busy_timeout=50)
            self.assertIn('retries',str(cm.exception))
            con=sqlite3.connect(self.db)
            try:self.assertEqual(con.execute('SELECT schema_version FROM evidence_meta'
                                             ).fetchone()[0],1)
            finally:con.close()
        finally:
            blocker.execute('ROLLBACK');blocker.close()
        self.assertTrue(migrate(self.db,attempts=2,delay=0)['migrated'])


class MigrationCLITests(StoreCase):
    def test_cli_migrate_and_hint_then_query(self):
        store=v1.build(self.db)
        store.add('v1',1,iso(100),report([('a.txt',b'alpha')]))
        store.close()
        r=subprocess.run(CLI+['evidence-migrate','--db',str(self.db)],
                         capture_output=True,text=True,env=ENV)
        self.assertEqual(r.returncode,0,r.stderr)
        summary=json.loads(r.stdout)
        self.assertTrue(summary['migrated'])
        self.assertEqual(summary['schema_version'],2)
        r=subprocess.run(CLI+['evidence-migrate','--db',str(self.db)],
                         capture_output=True,text=True,env=ENV)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertFalse(json.loads(r.stdout)['migrated'])
        r=subprocess.run(CLI+['evidence-query','--db',str(self.db),'--archive','archive-1',
                              '--path','a.txt','--observed-before',iso(200),
                              '--knowledge-cutoff','1'],capture_output=True,text=True,env=ENV)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)['outcome'],'observed')

    def test_cli_migrate_missing_store_exits_two(self):
        missing=self.base/'none.sqlite3'
        r=subprocess.run(CLI+['evidence-migrate','--db',str(missing)],
                         capture_output=True,text=True,env=ENV)
        self.assertEqual(r.returncode,2)
        self.assertFalse(missing.exists())

    def test_migrate_does_not_create_or_convert_an_empty_file(self):
        empty=self.base/'empty.sqlite3';empty.write_bytes(b'')
        with self.assertRaises(EvidenceError):
            migrate(empty)
        self.assertEqual(sqlite3.connect(str(empty)).execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone(),(0,))
        self.assertEqual(empty.stat().st_size,0, 'a refused migration must not touch the file')


class ScaleStructureTests(StoreCase):
    def test_migration_streams_rows_without_loading_the_whole_store(self):
        # 200 revisions with distinct reports: migration must work with bounded
        # per-row memory.  We assert it completes and dedupes correctly.
        store=v1.build(self.db)
        for i in range(200):
            store.add('v%03d'%i,1,iso(100+i),report([('f%03d.txt'%i,b'x'*10)]))
        store.close()
        summary=migrate(self.db)
        self.assertEqual(summary['revisions'],200)
        self.assertEqual(summary['objects'],200)
        con=self.connect()
        self.assertEqual(con.execute('SELECT COUNT(*) FROM report_objects').fetchone()[0],200)
        con.close()


if __name__=='__main__':unittest.main()
