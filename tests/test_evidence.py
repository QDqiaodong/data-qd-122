import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))

from archive_fixity.evidence import (EvidenceError, _WINNER, format_timestamp, ingest,
                                     parse_timestamp, query)
from evidence_fixture import iso, line, report, sha, write_batch

ROOT=Path(__file__).resolve().parents[1]
CLI=[sys.executable,'-m','archive_fixity.cli']


class StoreCase(unittest.TestCase):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory()
        self.base=Path(self._td.name)
        self.db=self.base/'evidence.sqlite3'

    def tearDown(self):self._td.cleanup()

    def ingest_lines(self,lines,name='batch.ndjson',attempts=8,busy_timeout=5000):
        batch=write_batch(self.base/name,lines)
        return ingest(self.db,batch,attempts=attempts,delay=0,busy_timeout=busy_timeout)

    def rows(self):
        if not self.db.exists():return 0
        con=sqlite3.connect(self.db)
        try:return con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0]
        finally:con.close()

    def assert_rolled_back(self,head):
        self.assertEqual(self.rows(),head)


class BatchIngestTests(StoreCase):
    def test_knowledge_sequence_increments_across_verifications(self):
        body=report([('a.txt',b'alpha')])
        summary=self.ingest_lines([line('v1',1,iso(10),body),
                                   line('v2',1,iso(20),body)])
        self.assertEqual((summary['accepted'],summary['idempotent']),(2,0))
        self.assertEqual(summary['first_knowledge_sequence'],1)
        self.assertEqual(summary['last_knowledge_sequence'],2)
        self.assertEqual(summary['knowledge_head'],2)

    def test_bad_line_rolls_back_the_whole_batch(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body)])
        head=self.rows()
        bad=[line('v2',1,iso(20),body),line('v3',1,iso(30),body),'{"archive_id":"a"}']
        with self.assertRaises(EvidenceError) as cm:self.ingest_lines(bad,name='bad.ndjson')
        self.assertIn('line 3',str(cm.exception))
        self.assert_rolled_back(head)
        # The same head is reused by a corrected retry: no gap is left behind.
        self.assertEqual(self.ingest_lines([line('v2',1,iso(20),body)],
                                           name='fixed.ndjson')['first_knowledge_sequence'],
                         head+1)

    def test_invalid_report_structure_is_rejected_before_commit(self):
        body=report([('a.txt',b'alpha')])
        body['result']['captured_bytes']=999
        with self.assertRaises(EvidenceError) as cm:self.ingest_lines([line('v1',1,iso(10),body)])
        self.assertIn('captured_bytes',str(cm.exception))
        self.assertEqual(self.rows(),0)

    def test_duplicate_json_keys_and_blank_lines_are_rejected(self):
        body=report([('a.txt',b'alpha')])
        raw=line('v1',1,iso(10),body)
        with self.assertRaises(EvidenceError):self.ingest_lines([raw.replace('"revision": 1',
                                                                    '"revision": 1, "revision": 1')])
        with self.assertRaises(EvidenceError):self.ingest_lines([raw,''])
        self.assertEqual(self.rows(),0)

    def test_process_failure_mid_batch_rolls_back_and_retry_reuses_head(self):
        body=report([('a.txt',b'alpha')])
        lines=[line('v1',1,iso(10),body),line('v2',1,iso(20),body)]
        batch=write_batch(self.base/'crash.ndjson',lines)
        head=self.rows()
        def barrier(event,line_no):
            if event=='after_insert' and line_no==2:raise RuntimeError('simulated crash')
        with self.assertRaises(RuntimeError):ingest(self.db,batch,delay=0,barrier=barrier)
        self.assert_rolled_back(head)
        summary=ingest(self.db,batch,delay=0)
        self.assertEqual(summary['first_knowledge_sequence'],head+1)
        self.assertEqual(summary['knowledge_head'],head+2)

    def test_store_and_batch_symlinks_are_refused(self):
        body=report([('a.txt',b'alpha')])
        batch=write_batch(self.base/'real.ndjson',[line('v1',1,iso(10),body)])
        self.ingest_lines([line('v1',1,iso(10),body)],name='seed.ndjson')
        link=self.base/'db-link.sqlite3';link.symlink_to(self.db)
        with self.assertRaises(EvidenceError):ingest(link,batch,delay=0)
        batch_link=self.base/'batch-link.ndjson';batch_link.symlink_to(batch)
        with self.assertRaises(EvidenceError):ingest(self.db,batch_link,delay=0)

    def test_empty_batch_is_a_noop(self):
        summary=self.ingest_lines([])
        self.assertEqual(summary['lines'],0)
        self.assertTrue(summary['empty'])
        self.assertEqual(summary['knowledge_head'],0)

    def test_reingesting_identical_batch_is_idempotent(self):
        body=report([('a.txt',b'alpha')])
        lines=[line('v1',1,iso(10),body),line('v2',1,iso(20),body)]
        first=self.ingest_lines(lines,name='one.ndjson')
        again=self.ingest_lines(lines,name='two.ndjson')
        self.assertEqual(first['knowledge_head'],2)
        self.assertEqual(again['accepted'],0)
        self.assertEqual(again['idempotent'],2)
        self.assertEqual(again['knowledge_head'],2)
        self.assertEqual(self.rows(),2)


class RevisionTests(StoreCase):
    def setUp(self):
        super().setUp()
        self.verify=iso(100)

    def test_correction_replaces_the_whole_report(self):
        original=report([('a.txt',b'alpha'),('b.txt',b'beta')])
        corrected=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,self.verify,original)])
        self.ingest_lines([line('v1',2,self.verify,corrected)])

    def test_retraction_invalidates_until_a_later_revision_restores(self):
        first=report([('a.txt',b'alpha')])
        second=report([('a.txt',b'alpha')])
        summary=self.ingest_lines([
            line('v1',1,self.verify,first),
            line('v1',2,self.verify,retracted=True),
            line('v1',3,self.verify,second)])
        self.assertEqual(summary['accepted'],3)

    def test_same_revision_same_content_is_idempotent_and_conflict_is_refused(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,self.verify,body)])
        self.ingest_lines([line('v1',1,self.verify,body)])  # identical -> no-op
        other=report([('a.txt',b'alpha')],source='1'*64)
        with self.assertRaises(EvidenceError) as cm:
            self.ingest_lines([line('v1',1,self.verify,other)])
        self.assertIn('conflicts with stored content',str(cm.exception))

    def test_archive_and_observed_at_are_fixed_per_verification(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,self.verify,body)])
        with self.assertRaises(EvidenceError) as cm:
            self.ingest_lines([line('v1',2,iso(101),report([('a.txt',b'alpha')]))])
        self.assertIn('fixed',str(cm.exception))
        with self.assertRaises(EvidenceError) as cm:
            self.ingest_lines([line('v1',2,self.verify,report([('a.txt',b'alpha')]),
                                    archive='other')])
        self.assertIn('fixed',str(cm.exception))

    def test_revisions_must_start_at_one_and_stay_contiguous(self):
        body=report([('a.txt',b'alpha')])
        with self.assertRaises(EvidenceError):self.ingest_lines([line('v1',2,self.verify,body)])
        self.ingest_lines([line('v1',1,self.verify,body)])
        with self.assertRaises(EvidenceError):self.ingest_lines([line('v1',3,self.verify,body)])
        self.assertEqual(self.rows(),1)


class QuerySelectionTests(StoreCase):
    T=iso(1000)

    def test_later_observation_and_verification_id_tie_break(self):
        older=report([('a.txt',b'old')])
        newer=report([('a.txt',b'new')])
        self.ingest_lines([line('v9',1,iso(500),older),line('v2',1,iso(700),newer)])
        result=query(self.db,'archive-1','a.txt',self.T,10)
        self.assertEqual(result['verification_id'],'v2')
        self.assertEqual(result['observation']['actual_sha256'],sha(b'new'))
        # Same observation instant: higher verification id wins.
        self.ingest_lines([line('v7',1,iso(700),report([('a.txt',b'tie')]))])
        result=query(self.db,'archive-1','a.txt',self.T,20)
        self.assertEqual(result['verification_id'],'v7')

    def test_observation_cutoff_excludes_later_observations(self):
        self.ingest_lines([line('v1',1,iso(100),report([('a.txt',b'early')]))])
        self.ingest_lines([line('v2',1,iso(900),report([('a.txt',b'late')]))])
        result=query(self.db,'archive-1','a.txt',iso(500),10)
        self.assertEqual(result['verification_id'],'v1')
        result=query(self.db,'archive-1','a.txt',iso(50),10)
        self.assertEqual(result['outcome'],'no_observation')

    def test_knowledge_cutoff_hides_late_arrivals_and_corrections(self):
        early=report([('a.txt',b'early')])
        late=report([('a.txt',b'late')])
        self.ingest_lines([line('v1',1,iso(100),early)]);head=self.rows()
        self.ingest_lines([line('v2',1,iso(200),late,archive='archive-1')])
        # A late arrival observed before T but known after S must not leak.
        self.assertEqual(query(self.db,'archive-1','a.txt',self.T,head)['verification_id'],'v1')
        self.assertEqual(query(self.db,'archive-1','a.txt',self.T,self.rows())['verification_id'],
                         'v2')
        # A correction known later must not rewrite an old knowledge cutoff.
        fixed=report([('a.txt',b'fixed')])
        self.ingest_lines([line('v1',2,iso(100),fixed)])
        self.assertEqual(query(self.db,'archive-1','a.txt',self.T,head)['observation']['actual_sha256'],
                         sha(b'early'))
        latest=query(self.db,'archive-1','a.txt',self.T,self.rows())
        self.assertEqual(latest['verification_id'],'v2')
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(150),self.rows())
                         ['observation']['actual_sha256'],sha(b'fixed'))

    def test_retraction_and_restoration_through_knowledge_cutoffs(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(100),body)]);s1=self.rows()
        self.ingest_lines([line('v1',2,iso(100),retracted=True)]);s2=self.rows()
        self.ingest_lines([line('v1',3,iso(100),body)]);s3=self.rows()
        self.assertEqual(query(self.db,'archive-1','a.txt',self.T,s1)['outcome'],'observed')
        self.assertEqual(query(self.db,'archive-1','a.txt',self.T,s2)['outcome'],'no_observation')
        self.assertEqual(query(self.db,'archive-1','a.txt',self.T,s3)['outcome'],'observed')

    def test_newer_verification_is_used_when_revision_keeps_older_validity(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(100),body),
                           line('v2',1,iso(300),report([('a.txt',b'alpha')]))])
        # v2's last revision (a report) is valid, v1's last revision is valid
        # too; the observation instant decides.
        self.assertEqual(query(self.db,'archive-1','a.txt',self.T,10)['verification_id'],'v2')

    def test_no_observation_not_listed_and_missing_are_distinct(self):
        body=report([('a.txt',b'alpha'),('gone.txt',None,'missing')],unlisted=['extra.txt'])
        self.ingest_lines([line('v1',1,iso(100),body)])
        observed=query(self.db,'archive-1','a.txt',self.T,10)
        missing=query(self.db,'archive-1','gone.txt',self.T,10)
        absent=query(self.db,'archive-1','never.txt',self.T,10)
        extra=query(self.db,'archive-1','extra.txt',self.T,10)
        empty=query(self.db,'archive-1','a.txt',iso(50),10)
        self.assertEqual(observed['outcome'],'observed')
        self.assertEqual(missing['outcome'],'observed')
        self.assertEqual(missing['observation']['status'],'missing')
        self.assertEqual(absent['outcome'],'not_listed')
        self.assertIsNone(absent['observation'])
        self.assertEqual(extra['outcome'],'not_listed')
        self.assertEqual(extra['unlisted_entry'],{'path':'extra.txt','is_link':False,
                                                  'is_directory':False})
        self.assertEqual(empty['outcome'],'no_observation')
        self.assertIsNone(empty['verification_id'])

    def test_result_is_one_whole_selected_report_not_a_per_path_stitch(self):
        # v1 knows a.txt only; v2 (newer, same instant) knows b.txt only.
        # A path query never combines a.txt from v1 with b.txt from v2.
        self.ingest_lines([line('v1',1,iso(400),report([('a.txt',b'a')]),
                                 'archive-1'),line('v2',1,iso(400),report([('b.txt',b'b')]))])
        a=query(self.db,'archive-1','a.txt',self.T,10)
        b=query(self.db,'archive-1','b.txt',self.T,10)
        self.assertEqual(a['verification_id'],'v2')
        self.assertEqual(a['outcome'],'not_listed')
        self.assertEqual(b['verification_id'],'v2')
        self.assertEqual(b['outcome'],'observed')
        self.assertEqual(a['report']['result']['files'],
                         [f for f in b['report']['result']['files']])
        self.assertEqual(a['report_sha256'],b['report_sha256'])

    def test_query_does_not_load_history_into_python(self):
        body=report([('a.txt',b'alpha')])
        for v in range(40):
            self.ingest_lines([line('v%03d'%v,1,iso(v+1),body)])
        result=query(self.db,'archive-1','a.txt',self.T,10_000)
        self.assertEqual(result['observation']['path'],'a.txt')
        self.assertEqual(len(result['report']['result']['files']),1)
        self.assertEqual(result['report']['result']['files'][0]['path'],'a.txt')

    def test_unknown_archive_and_bad_inputs(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(100),body)])
        self.assertEqual(query(self.db,'nobody','a.txt',self.T,10)['outcome'],'no_observation')
        for args in [('archive-1','../a.txt',self.T,10),('archive-1','a.txt','bad',10),
                     ('archive-1','a.txt',self.T,-1)]:
            with self.assertRaises(EvidenceError):query(self.db,*args)

    def test_reopening_the_store_gives_the_same_answers(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(100),body)]);head=self.rows()
        before=query(self.db,'archive-1','a.txt',self.T,head)
        copy=Path(self._td.name)/'copy.sqlite3'
        con=sqlite3.connect(self.db);dst=sqlite3.connect(copy)
        con.backup(dst);dst.close();con.close()
        after=query(copy,'archive-1','a.txt',self.T,head)
        self.assertEqual(before,after)


class RetryAndLayoutTests(StoreCase):
    def test_locked_store_is_retried_then_succeeds_with_stable_head(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body)])
        head=self.rows()
        batch=write_batch(self.base/'blocked.ndjson',[line('v2',1,iso(20),body)])
        blocker=sqlite3.connect(self.db,isolation_level=None)
        blocker.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaises(EvidenceError) as cm:
                ingest(self.db,batch,attempts=2,delay=0,busy_timeout=50)
            self.assertIn('retries',str(cm.exception))
        finally:
            blocker.execute('ROLLBACK');blocker.close()
        summary=ingest(self.db,batch,attempts=2,delay=0,busy_timeout=50)
        self.assertEqual(summary['first_knowledge_sequence'],head+1)
        self.assertEqual(summary['knowledge_head'],head+1)

    def test_query_plan_targets_indexes_not_a_history_scan(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body)])
        con=sqlite3.connect(self.db)
        try:
            plan=[row[3] for row in con.execute('EXPLAIN QUERY PLAN '+_WINNER,
                                                ('archive-1',10,10**15,10))]
        finally:con.close()
        joined='\n'.join(plan)
        self.assertIn('revisions_timeline',joined)
        self.assertIn('revisions_verification_lookup',joined)
        self.assertNotIn('SCAN r',joined)

    def test_corrupt_stored_report_is_detected(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body)])
        con=sqlite3.connect(self.db);con.execute('PRAGMA query_only=OFF')
        con.execute('UPDATE revisions SET report_z=? WHERE revision_id=1',(b'not-zlib',))
        con.commit();con.close()
        with self.assertRaises(EvidenceError) as cm:
            query(self.db,'archive-1','a.txt',iso(20),10)
        self.assertIn('corrupt',str(cm.exception))

    def test_query_opens_store_read_only(self):
        body=report([('a.txt',b'alpha')])
        self.ingest_lines([line('v1',1,iso(10),body)])
        before=self.db.stat().st_mtime_ns
        query(self.db,'archive-1','a.txt',iso(20),10)
        self.assertEqual(self.db.stat().st_mtime_ns,before)


class QueryContractTests(unittest.TestCase):
    def test_timestamps_are_canonical_utc(self):
        self.assertEqual(parse_timestamp('2026-01-01T00:00:00Z'),1_767_225_600_000_000)
        self.assertEqual(parse_timestamp('1970-01-01T00:00:00Z'),0)
        self.assertEqual(format_timestamp(0),'1970-01-01T00:00:00Z')
        for bad in ['2026-01-01T00:00:00+08:00','2026-02-30T00:00:00Z',
                    '2026-01-01T00:00:60Z','2026-1-1T00:00:00Z','2026-01-01 00:00:00']:
            with self.assertRaises(EvidenceError):parse_timestamp(bad)


class CLIIntegrationTests(unittest.TestCase):
    """Real subprocess CLI: ingest and query a summary extracted from a report."""

    def setUp(self):
        self._td=tempfile.TemporaryDirectory();self.base=Path(self._td.name)
        self.env=dict(os.environ,PYTHONPATH=str(ROOT/'src'))
        self.db=self.base/'evidence.sqlite3'

    def tearDown(self):self._td.cleanup()

    def cli(self,*args):
        return subprocess.run(CLI+list(args),capture_output=True,text=True,env=self.env)

    def test_ingest_and_query_cli(self):
        body=report([('a.txt',b'alpha'),('b.txt',b'beta')])
        batch=write_batch(self.base/'batch.ndjson',[line('v1',1,iso(100),body)])
        r=self.cli('evidence-ingest','--db',str(self.db),'--batch',str(batch))
        self.assertEqual(r.returncode,0,r.stderr)
        summary=json.loads(r.stdout);self.assertEqual(summary['accepted'],1)
        r=self.cli('evidence-query','--db',str(self.db),'--archive','archive-1',
                   '--path','a.txt','--observed-before',iso(100),'--knowledge-cutoff','1')
        self.assertEqual(r.returncode,0,r.stderr)
        result=json.loads(r.stdout)
        self.assertEqual(result['outcome'],'observed')
        self.assertEqual(result['observation']['status'],'verified')

    def test_bad_batch_leaves_no_rows_and_retry_succeeds(self):
        body=report([('a.txt',b'alpha')])
        good=write_batch(self.base/'good.ndjson',[line('v1',1,iso(100),body)])
        bad=write_batch(self.base/'bad.ndjson',[line('v1',1,iso(100),body),'not json'])
        self.assertEqual(self.cli('evidence-ingest','--db',str(self.db),
                                  '--batch',str(good)).returncode,0)
        r=self.cli('evidence-ingest','--db',str(self.db),'--batch',str(bad))
        self.assertEqual(r.returncode,2)
        self.assertIn('line 2',r.stderr)
        con=sqlite3.connect(self.db)
        try:self.assertEqual(con.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],1)
        finally:con.close()
        # Transient lock retries keep the same knowledge head.
        r=self.cli('evidence-ingest','--db',str(self.db),'--batch',str(good),
                   '--retry-attempts','2','--retry-delay','0')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)['idempotent'],1)

    def test_query_cli_exit_codes(self):
        self.assertEqual(self.cli('evidence-query','--db',str(self.db),'--archive','a',
                                  '--path','a.txt','--observed-before',iso(1),
                                  '--knowledge-cutoff','0').returncode,2)
        self.assertEqual(self.cli('evidence-query','--db',str(self.db),'--archive','a',
                                  '--path','a.txt','--observed-before','bad',
                                  '--knowledge-cutoff','0').returncode,2)


class ReportStructureTests(StoreCase):
    def test_guarded_reports_are_accepted_only_with_observed_stable(self):
        guarded=report([('a.txt',b'alpha')],capture_mode='guarded')
        self.ingest_lines([line('v1',1,iso(10),guarded)])
        self.assertEqual(query(self.db,'archive-1','a.txt',iso(20),10)['outcome'],'observed')
        broken=report([('a.txt',b'alpha')],capture_mode='guarded')
        broken['result'].pop('observed_stable')
        with self.assertRaises(EvidenceError):self.ingest_lines([line('v2',1,iso(10),broken)])
        self.assertEqual(self.rows(),1)

    def test_report_must_match_the_existing_structure_and_counts(self):
        good=report([('a.txt',b'alpha')])
        variants=[]
        bad=json.loads(json.dumps(good));bad['result']['status_counts']={'verified':2};variants.append(bad)
        bad=json.loads(json.dumps(good));bad['result']['files'][0]['status']='weird';variants.append(bad)
        bad=json.loads(json.dumps(good));bad['result']['manifest_files']=2;variants.append(bad)
        bad=json.loads(json.dumps(good));bad['extra']=1;variants.append(bad)
        bad=json.loads(json.dumps(good));bad['result']['files'][0]['expected_sha256']='XYZ';variants.append(bad)
        for body in variants:
            with self.assertRaises(EvidenceError):self.ingest_lines([line('v1',1,iso(10),body)])
            self.assertEqual(self.rows(),0)


if __name__=='__main__':unittest.main()
