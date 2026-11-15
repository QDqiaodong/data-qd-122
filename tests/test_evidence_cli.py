"""End-to-end evidence tests driven by reports from the real audit CLI.

Each audit report below is produced by the shipped `archive-fixity` CLI over a
real payload tree; no report is hand-built.  The tests then exercise the
evidence ingest/query subcommands as separate processes.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))

from evidence_fixture import iso, line, sha, write_batch

ROOT=Path(__file__).resolve().parents[1]
CLI=[sys.executable,'-m','archive_fixity.cli']
ENV=dict(os.environ,PYTHONPATH=str(ROOT/'src'))


class Archive:
    """A real payload tree + manifest, audited by the real CLI."""

    def __init__(self,base,name='archive'):
        self.base=Path(base)/name
        self.payload=self.base/'payload'
        self.payload.mkdir(parents=True)

    def audit(self,files,expected=None,unlisted=(),capture_mode='static'):
        """Write `files` into the payload tree and run the audit CLI.

        ``expected`` optionally overrides the manifest bytes for a path, so the
        resulting report records a real mismatch; a path listed only in
        ``expected`` is audited as missing.
        """
        expected=dict(files if expected is None else expected)
        manifest={'payload_root':'payload','entries':[]}
        for path,body in sorted(files.items()):
            target=self.payload/path;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(body)
        for path,body in sorted(expected.items()):
            manifest['entries'].append({'path':path,'bytes':len(body),'sha256':sha(body)})
        for path,body in sorted(dict(unlisted).items()):
            target=self.payload/path;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(body)
        source=self.base/'input.json'
        source.write_text(json.dumps(manifest))
        out=self.base/('report-%d.json'%len(list(self.base.glob('report-*.json'))))
        args=CLI+['--source',str(source),'--output',str(out)]
        if capture_mode!='static':args+=['--capture-mode',capture_mode]
        done=subprocess.run(args,capture_output=True,text=True,env=ENV)
        assert done.returncode==0,done.stderr
        return json.loads(out.read_text())


class EvidenceCLITests(unittest.TestCase):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory();self.base=Path(self._td.name)
        self.db=self.base/'evidence.sqlite3'
        self.archive=Archive(self.base)

    def tearDown(self):self._td.cleanup()

    def cli(self,*args):
        return subprocess.run(CLI+list(args),capture_output=True,text=True,env=ENV)

    def ingest(self,lines,name='batch.ndjson'):
        batch=write_batch(self.base/name,lines)
        return self.cli('evidence-ingest','--db',str(self.db),'--batch',str(batch),
                        '--retry-delay','0')

    def query(self,path,observed,known):
        done=self.cli('evidence-query','--db',str(self.db),'--archive','archive-1',
                      '--path',path,'--observed-before',observed,
                      '--knowledge-cutoff',str(known))
        self.assertEqual(done.returncode,0,done.stderr)
        return json.loads(done.stdout)

    def head(self):
        done=self.ingest([])  # empty batch reports the current knowledge head
        self.assertEqual(done.returncode,0,done.stderr)
        return json.loads(done.stdout)['knowledge_head']

    def test_late_arrival_does_not_leak_into_earlier_knowledge_cutoff(self):
        early=self.archive.audit({'docs/a.txt':b'early bytes'})
        later=Archive(self.base,'later').audit({'docs/a.txt':b'later bytes'})
        first=self.ingest([line('verify-early',1,iso(100),early)])
        self.assertEqual(json.loads(first.stdout)['accepted'],1)
        s1=self.head()
        at_s1=self.query('docs/a.txt',iso(1000),s1)
        self.assertEqual(at_s1['verification_id'],'verify-early')
        self.assertEqual(at_s1['observation']['actual_sha256'],sha(b'early bytes'))
        second=self.ingest([line('verify-late',1,iso(200),later)],name='late.ndjson')
        self.assertEqual(json.loads(second.stdout)['accepted'],1)
        s2=self.head()
        self.assertEqual(self.query('docs/a.txt',iso(1000),s1)['verification_id'],'verify-early')
        at_s2=self.query('docs/a.txt',iso(1000),s2)
        self.assertEqual(at_s2['verification_id'],'verify-late')
        self.assertEqual(at_s2['observation']['actual_sha256'],sha(b'later bytes'))
        # Even at the current head, the observation cutoff still excludes it.
        self.assertEqual(self.query('docs/a.txt',iso(150),s2)['verification_id'],'verify-early')

    def test_correction_retraction_and_recovery(self):
        first=self.archive.audit({'docs/a.txt':b'good bytes'})
        correction=Archive(self.base,'correction').audit(
            {'docs/a.txt':b'bad bytes!'},expected={'docs/a.txt':b'good bytes'})
        recovered=Archive(self.base,'recovered').audit({'docs/a.txt':b'good bytes'})
        self.assertEqual(correction['result']['status_counts'],{'mismatch':1})
        self.assertEqual(recovered['result']['status_counts'],{'verified':1})
        steps=[]
        for revision,body in [(1,first),(2,correction),(3,None),(4,recovered)]:
            item=line('verify-1',revision,iso(100),body) if body is not None \
                else line('verify-1',revision,iso(100),retracted=True)
            done=self.ingest([item],name='rev%d.ndjson'%revision)
            self.assertEqual(done.returncode,0,done.stderr)
            steps.append(self.head())
        s1,s2,s3,s4=steps
        at=lambda s:self.query('docs/a.txt',iso(1000),s)
        self.assertEqual(at(s1)['observation']['status'],'verified')
        self.assertEqual(at(s2)['observation']['status'],'mismatch')
        self.assertEqual(at(s2)['revision'],2)
        # The correction replaces the whole report: its expected digest came
        # from the manifest and its actual digest from the byte read.
        files=at(s2)['report']['result']['files']
        self.assertEqual([f['expected_sha256'] for f in files],[sha(b'good bytes')])
        self.assertEqual([f['actual_sha256'] for f in files],[sha(b'bad bytes!')])
        self.assertNotEqual(at(s1)['report_sha256'],at(s2)['report_sha256'])
        self.assertEqual(at(s3)['outcome'],'no_observation')  # retracted
        self.assertEqual(at(s4)['outcome'],'observed')         # later revision restores
        self.assertEqual(at(s4)['observation']['status'],'verified')
        # The old knowledge cutoffs are immutable after later revisions.
        self.assertEqual(at(s1)['revision'],1)
        self.assertEqual(at(s3)['revision'],None)

    def test_duplicate_conflict_is_refused_and_store_unchanged(self):
        body=self.archive.audit({'docs/a.txt':b'alpha'})
        batch=[line('verify-1',1,iso(100),body)]
        first=self.ingest(batch,name='one.ndjson')
        self.assertEqual(json.loads(first.stdout)['accepted'],1)
        same=self.ingest(batch,name='two.ndjson')
        self.assertEqual(same.returncode,0,same.stderr)
        self.assertEqual(json.loads(same.stdout)['idempotent'],1)
        before=self.head()
        conflicting=body
        conflicting['result']['unlisted_entries']=[]
        conflicting['result']['inventory_clean']=conflicting['result']['inventory_clean']
        # Change the stored-content identity without breaking structure.
        conflicting['source_sha256']='f'*64
        bad=self.ingest([line('verify-1',1,iso(100),conflicting)],name='conflict.ndjson')
        self.assertEqual(bad.returncode,2)
        self.assertIn('conflicts with stored content',bad.stderr)
        self.assertEqual(self.head(),before)
        self.assertEqual(self.query('docs/a.txt',iso(100),before)['revision'],1)

    def test_bad_last_line_rolls_back_the_whole_batch(self):
        a=self.archive.audit({'docs/a.txt':b'alpha'})
        b=Archive(self.base,'b').audit({'docs/b.txt':b'beta'})
        good=self.ingest([line('verify-1',1,iso(100),a)],name='good.ndjson')
        head=json.loads(good.stdout)['knowledge_head']
        broken=[line('verify-2',1,iso(200),b),line('verify-3',1,iso(300),b),
                '{"archive_id":"archive-1","verification_id":"verify-4"}']
        failed=self.ingest(broken,name='broken.ndjson')
        self.assertEqual(failed.returncode,2)
        self.assertIn('line 3',failed.stderr)
        self.assertEqual(self.head(),head)
        # verify-1 is still the only known observation, and it never lists b.txt.
        self.assertEqual(self.query('docs/b.txt',iso(1000),head)['outcome'],'not_listed')
        # Retrying with the fixed batch starts exactly at the old head + 1.
        fixed=self.ingest(broken[:2],name='fixed.ndjson')
        self.assertEqual(fixed.returncode,0,fixed.stderr)
        summary=json.loads(fixed.stdout)
        self.assertEqual(summary['first_knowledge_sequence'],head+1)
        self.assertEqual(summary['knowledge_head'],head+2)
        # And the retry result is stable when the same batch is replayed.
        replay=self.ingest(broken[:2],name='replay.ndjson')
        self.assertEqual(json.loads(replay.stdout)['knowledge_head'],head+2)

    def test_new_manifest_removing_a_path_is_not_backfilled(self):
        both=self.archive.audit({'docs/a.txt':b'alpha','docs/old.txt':b'old'})
        only_a=Archive(self.base,'shrunk').audit({'docs/a.txt':b'alpha'})
        self.ingest([line('scan-1',1,iso(100),both)],name='scan1.ndjson')
        s1=self.head()
        self.ingest([line('scan-2',1,iso(200),only_a)],name='scan2.ndjson')
        s2=self.head()
        # At S2 the selected whole report is scan-2; old.txt is not listed even
        # though scan-1 still knows it.
        removed=self.query('docs/old.txt',iso(1000),s2)
        self.assertEqual(removed['outcome'],'not_listed')
        self.assertEqual(removed['verification_id'],'scan-2')
        self.assertIsNone(removed['observation'])
        # At S1 the historical answer is unchanged.
        historical=self.query('docs/old.txt',iso(1000),s1)
        self.assertEqual(historical['outcome'],'observed')
        self.assertEqual(historical['verification_id'],'scan-1')
        self.assertEqual(historical['observation']['status'],'verified')
        # With T before the new scan, the new scan is not an observation at all.
        before_scan=self.query('docs/old.txt',iso(150),s2)
        self.assertEqual(before_scan['verification_id'],'scan-1')

    def test_unlisted_inventory_is_reported_without_per_path_fallback(self):
        report=self.archive.audit({'docs/a.txt':b'alpha'},unlisted={'docs/extra.txt':b'x'})
        self.ingest([line('scan-1',1,iso(100),report)],name='scan.ndjson')
        head=self.head()
        extra=self.query('docs/extra.txt',iso(1000),head)
        self.assertEqual(extra['outcome'],'not_listed')
        self.assertEqual(extra['unlisted_entry']['path'],'docs/extra.txt')
        self.assertIsNone(extra['observation'])
        missing=self.query('docs/never.txt',iso(1000),head)
        self.assertEqual(missing['outcome'],'not_listed')
        self.assertIsNone(missing['unlisted_entry'])
        no_obs=self.query('docs/a.txt',iso(50),head)
        self.assertEqual(no_obs['outcome'],'no_observation')

    def test_guarded_cli_report_is_accepted(self):
        guarded=self.archive.audit({'docs/a.txt':b'stable'},capture_mode='guarded')
        done=self.ingest([line('scan-1',1,iso(100),guarded)],name='guarded.ndjson')
        self.assertEqual(done.returncode,0,done.stderr)
        served=self.query('docs/a.txt',iso(200),self.head())
        self.assertEqual(served['outcome'],'observed')
        self.assertEqual(served['report']['capture_mode'],'guarded')
        self.assertTrue(served['report']['result']['observed_stable'])


if __name__=='__main__':unittest.main()
