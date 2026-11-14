import hashlib,json,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from archive_fixity.cli import run
from archive_fixity.guarded import audit_guarded,GuardInstability
from archive_fixity.model import audit

ROOT=Path(__file__).resolve().parents[1]
MUTATOR=Path(__file__).resolve().parent/'guarded_mutator.py'
EMPTY_SHA=hashlib.sha256(b'').hexdigest()


def sha(body):return hashlib.sha256(body).hexdigest()


def entry(path,body):return {'path':path,'bytes':len(body),'sha256':sha(body)}


def manifest(payload_root,entries):return {'payload_root':payload_root,'entries':entries}


def open_fds():
    return {int(n) for n in os.listdir('/proc/self/fd')} if os.path.isdir('/proc/self/fd') else None


class StaticCompatibilityTests(unittest.TestCase):
    """Guarded mode must keep every static-mode audit finding and contract."""

    def setUp(self):
        self.data=json.loads((ROOT/'fixtures/input.json').read_text())

    def test_fixture_parity_with_static_mode(self):
        static=audit(self.data,ROOT/'fixtures')
        guarded=audit_guarded(self.data,ROOT/'fixtures')
        self.assertTrue(guarded.pop('observed_stable'))
        self.assertEqual(guarded,static)

    def test_cli_default_is_static_and_guarded_flag_works(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);shutil.copytree(ROOT/'fixtures',p/'fixtures')
            source=p/'fixtures/input.json';out_s=p/'static.json';out_g=p/'guarded.json'
            env=dict(os.environ,PYTHONPATH=str(ROOT/'src'))
            r=subprocess.run([sys.executable,'-m','archive_fixity.cli','--source',str(source),'--output',str(out_s)],
                             capture_output=True,env=env)
            self.assertEqual(r.returncode,0,r.stderr.decode())
            static=json.loads(out_s.read_text())
            self.assertNotIn('capture_mode',static)
            r=subprocess.run([sys.executable,'-m','archive_fixity.cli','--source',str(source),
                              '--output',str(out_g),'--capture-mode','guarded'],capture_output=True,env=env)
            self.assertEqual(r.returncode,0,r.stderr.decode())
            guarded=json.loads(out_g.read_text())
            self.assertEqual(guarded['capture_mode'],'guarded')
            self.assertTrue(guarded['result']['observed_stable'])
            self.assertEqual(guarded['result'] | {'observed_stable':True},
                             static['result'] | {'observed_stable':True})
            self.assertEqual(guarded['schema_version'],static['schema_version'])
            self.assertEqual(guarded['source_sha256'],static['source_sha256'])

    def test_run_helper_supports_both_modes(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);shutil.copytree(ROOT/'fixtures',p/'fixtures');source=p/'fixtures/input.json'
            static=run(source);guarded=run(source,'guarded')
            self.assertNotIn('capture_mode',static);self.assertEqual(guarded['capture_mode'],'guarded')

    def test_missing_link_non_regular_non_directory_parent_distinct(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir()
            (p/'payload/empty').write_bytes(b'')
            (p/'payload/link').symlink_to('/etc/passwd')
            os.mkfifo(p/'payload/fifo')
            (p/'payload/blocker').write_bytes(b'')
            d=manifest('payload',[
                {'path':'empty','bytes':0,'sha256':EMPTY_SHA},
                {'path':'missing','bytes':0,'sha256':EMPTY_SHA},
                {'path':'link','bytes':0,'sha256':EMPTY_SHA},
                {'path':'fifo','bytes':0,'sha256':EMPTY_SHA},
                {'path':'blocker/child','bytes':0,'sha256':EMPTY_SHA},
            ])
            static=audit(d,p);guarded=audit_guarded(d,p)
            self.assertTrue(guarded.pop('observed_stable'))
            self.assertEqual(guarded,static)
            by={f['path']:f['status'] for f in static['files']}
            self.assertEqual(by,{'empty':'verified','missing':'missing','link':'unsafe_link',
                                  'fifo':'not_regular_file','blocker/child':'non_directory_parent'})

    def test_nested_tree_and_unlisted_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload/d1/d2').mkdir(parents=True)
            (p/'payload/d1/d2/file.bin').write_bytes(b'nested')
            (p/'payload/loose.txt').write_bytes(b'loose')
            (p/'payload/d1/link').symlink_to('loose.txt')
            d=manifest('payload',[entry('d1/d2/file.bin',b'nested')])
            static=audit(d,p);guarded=audit_guarded(d,p)
            self.assertTrue(guarded.pop('observed_stable'))
            self.assertEqual(guarded,static)
            paths={e['path'] for e in static['unlisted_entries']}
            self.assertEqual(paths,{'loose.txt','d1/link'})
            link=next(e for e in static['unlisted_entries'] if e['path']=='d1/link')
            self.assertTrue(link['is_link']);self.assertFalse(link['is_directory'])

    def test_stable_hash_mismatch_is_an_audit_finding_not_failure(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir();(p/'payload/a.txt').write_bytes(b'actual')
            d=manifest('payload',[{'path':'a.txt','bytes':6,'sha256':EMPTY_SHA}])
            r=audit_guarded(d,p)
            self.assertTrue(r['observed_stable'])
            self.assertEqual(r['status_counts'],{'mismatch':1})
            self.assertEqual(r['files'][0]['differences'],['digest_mismatch'])

    def test_contract_failures_still_exit_two(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir();(p/'payload/a.txt').write_bytes(b'x')
            good=manifest('payload',[entry('a.txt',b'x')])
            bad_dup=manifest('payload',[entry('a.txt',b'x'),entry('a.txt',b'x')])
            bad_digest=manifest('payload',[{'path':'a.txt','bytes':1,'sha256':'nope'}])
            for bad in (bad_dup,bad_digest):
                with self.assertRaises(ValueError):audit_guarded(bad,p)
            (p/'alias').symlink_to(p/'payload')
            with self.assertRaises(ValueError):audit_guarded(manifest('alias',good['entries']),p)

    def test_descriptor_closed_on_success_and_failure(self):
        before=open_fds()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload/d').mkdir(parents=True)
            (p/'payload/d/a.txt').write_bytes(b'abc');(p/'payload/b.txt').write_bytes(b'def')
            d=manifest('payload',[entry('d/a.txt',b'abc'),entry('b.txt',b'def')])
            audit_guarded(d,p)
            def barrier(event,name):
                if event=='read_chunk' and name=='d/a.txt':
                    (p/'payload/d/a.txt').unlink();(p/'payload/d/a.txt').symlink_to('/etc/passwd')
            with self.assertRaises(GuardInstability):audit_guarded(d,p,barrier=barrier)
        if before is not None:
            self.assertEqual(open_fds()-before,set(),'descriptor leaked from guarded capture')


class FIFOGuardTests(unittest.TestCase):
    def test_fifo_never_blocks_and_is_not_verified(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir();os.mkfifo(p/'payload/pipe.fifo')
            d=manifest('payload',[{'path':'pipe.fifo','bytes':0,'sha256':EMPTY_SHA}])
            start=time.monotonic();r=audit_guarded(d,p);elapsed=time.monotonic()-start
            self.assertLess(elapsed,5.0)
            self.assertEqual(r['files'][0]['status'],'not_regular_file')
            self.assertNotIn('verified',r['status_counts'])
            self.assertTrue(r['observed_stable'])

    def test_io_failure_aborts_and_cli_preserves_old_report(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir();body=b'need read permission'
            target=p/'payload/a.txt';target.write_bytes(body)
            d=manifest('payload',[entry('a.txt',body)])
            source=p/'input.json';source.write_text(json.dumps(d))
            out=p/'report.json';out.write_text('PREVIOUS-REPORT')
            target.chmod(0o000)
            try:
                if os.geteuid()==0:self.skipTest('root bypasses file permissions')
                r=subprocess.run([sys.executable,'-m','archive_fixity.cli','--source',str(source),
                                  '--output',str(out),'--capture-mode','guarded'],
                                 capture_output=True,env=dict(os.environ,PYTHONPATH=str(ROOT/'src')))
                self.assertEqual(r.returncode,2)
                self.assertEqual(out.read_text(),'PREVIOUS-REPORT')
            finally:
                target.chmod(0o644)

    def test_symlink_to_fifo_target_is_not_opened(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir();os.mkfifo(p/'blocked.fifo')
            (p/'payload/link').symlink_to(p/'blocked.fifo')
            d=manifest('payload',[{'path':'link','bytes':0,'sha256':EMPTY_SHA}])
            start=time.monotonic();r=audit_guarded(d,p);elapsed=time.monotonic()-start
            self.assertLess(elapsed,5.0)
            self.assertEqual(r['files'][0]['status'],'unsafe_link')
            self.assertTrue(r['observed_stable'])

    def test_intermediate_segment_swap_to_fifo_does_not_block(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload/sub').mkdir(parents=True);body=b'nested body'
            (p/'payload/sub/a.txt').write_bytes(body)
            os.mkfifo(p/'trap.fifo')
            d=manifest('payload',[entry('sub/a.txt',body)])
            def barrier(event,name):
                if event=='pre_final_snapshot':
                    (p/'payload/sub').rename(p/'payload/sub_real')
                    os.symlink(p/'trap.fifo',p/'payload/sub')
            start=time.monotonic()
            with self.assertRaises(GuardInstability):audit_guarded(d,p,barrier=barrier)
            self.assertLess(time.monotonic()-start,5.0)


class BarrierRaceTests(unittest.TestCase):
    """Deterministic races via synchronization barriers inside the capture."""

    def _tree(self):
        td=tempfile.TemporaryDirectory();p=Path(td.name);(p/'payload').mkdir()
        return td,p

    def test_external_link_swap_after_check_is_not_followed(self):
        td,p=self._tree()
        try:
            body=b'stable anchor bytes';(p/'payload/a.txt').write_bytes(body)
            outside=p/'outside.txt';outside.write_bytes(b'EXTERNAL-SECRET')
            d=manifest('payload',[entry('a.txt',body)])
            def barrier(event,name):
                if event=='read_chunk' and name=='a.txt':
                    victim=p/'payload/a.txt';victim.unlink();victim.symlink_to(outside)
            before_fds=open_fds()
            # The held descriptor keeps reading the original inode; the path
            # swap must surface as instability (final tree snapshot at the
            # latest) rather than as a verified result or a followed link.
            with self.assertRaises(GuardInstability):audit_guarded(d,p,barrier=barrier)
            self.assertTrue((p/'outside.txt').exists())
            self.assertTrue((p/'payload/a.txt').is_symlink())
            if before_fds is not None:self.assertEqual(open_fds()-before_fds,set())
        finally:td.cleanup()

    def test_link_swap_to_fifo_does_not_block(self):
        td,p=self._tree()
        try:
            body=b'stable anchor bytes';(p/'payload/a.txt').write_bytes(body)
            fifo=p/'pipe.fifo';os.mkfifo(fifo)
            d=manifest('payload',[entry('a.txt',body)])
            def barrier(event,name):
                if event=='read_chunk' and name=='a.txt':
                    victim=p/'payload/a.txt';victim.unlink();victim.symlink_to(fifo)
            start=time.monotonic()
            with self.assertRaises(GuardInstability):audit_guarded(d,p,barrier=barrier)
            self.assertLess(time.monotonic()-start,5.0)
        finally:td.cleanup()

    def test_parent_directory_replacement_is_observed(self):
        td,p=self._tree()
        try:
            (p/'payload/sub').mkdir();body=b'parent anchor bytes'
            (p/'payload/sub/a.txt').write_bytes(body)
            d=manifest('payload',[entry('sub/a.txt',body)])
            def barrier(event,name):
                if event=='read_chunk' and name=='sub/a.txt':
                    (p/'payload/sub').rename(p/'payload/sub_old')
                    new=p/'payload/sub';new.mkdir();(new/'a.txt').write_bytes(b'REPLACED')
            with self.assertRaises(GuardInstability) as cm:audit_guarded(d,p,barrier=barrier)
            # Renaming a child also bumps the payload root's mtime/ctime, so the
            # instability may surface either at the root-chain check or in the
            # full-tree snapshot; both are valid instability detections.
            self.assertTrue('observed change' in str(cm.exception)
                            or 'payload root path changed' in str(cm.exception))
        finally:td.cleanup()

    def test_payload_root_replacement_is_observed(self):
        td,p=self._tree()
        try:
            body=b'stable anchor bytes';(p/'payload/a.txt').write_bytes(body)
            d=manifest('payload',[entry('a.txt',body)])
            def barrier(event,name):
                if event=='pre_final_snapshot':
                    (p/'payload').rename(p/'payload_old')
                    new=p/'payload';new.mkdir();(new/'a.txt').write_bytes(b'NEW-ROOT')
            with self.assertRaises(GuardInstability) as cm:audit_guarded(d,p,barrier=barrier)
            self.assertIn('payload root path changed',str(cm.exception))
        finally:td.cleanup()

    def test_append_during_read_is_observed_and_reported_as_instability(self):
        td,p=self._tree()
        try:
            body=b'Z'*100000;(p/'payload/big.bin').write_bytes(body)
            d=manifest('payload',[entry('big.bin',body)])
            def barrier(event,name):
                if event=='read_chunk' and name=='big.bin':
                    with (p/'payload/big.bin').open('ab') as s:s.write(b'X'*10)
            with self.assertRaises(GuardInstability) as cm:audit_guarded(d,p,barrier=barrier)
            self.assertIn('changed during read',str(cm.exception))
        finally:td.cleanup()

    def test_new_file_before_final_snapshot_is_observed(self):
        td,p=self._tree()
        try:
            body=b'stable anchor bytes';(p/'payload/a.txt').write_bytes(body)
            d=manifest('payload',[entry('a.txt',body)])
            def barrier(event,name):
                if event=='pre_final_snapshot':(p/'payload/brand_new.txt').write_bytes(b'late')
            with self.assertRaises(GuardInstability) as cm:audit_guarded(d,p,barrier=barrier)
            # Creating an entry also bumps the containing directory's ctime/mtime,
            # so either the root-chain check or the tree diff may report first.
            self.assertTrue('observed change' in str(cm.exception)
                            or 'payload root path changed' in str(cm.exception))
        finally:td.cleanup()

    def test_missing_file_then_reappearing_still_stable_observation(self):
        td,p=self._tree()
        try:
            body=b'stable anchor bytes';(p/'payload/a.txt').write_bytes(body)
            d=manifest('payload',[entry('a.txt',body),{'path':'gone.txt','bytes':0,'sha256':EMPTY_SHA}])
            r=audit_guarded(d,p)
            self.assertEqual(r['status_counts'],{'verified':1,'missing':1})
            self.assertTrue(r['observed_stable'])
        finally:td.cleanup()


class MutatorSubprocessTests(unittest.TestCase):
    """End-to-end barrier races in a separate process."""

    def run_mutator(self,scenario):
        with tempfile.TemporaryDirectory() as td:
            cmd=[sys.executable,str(MUTATOR),'--base',td,'--scenario',scenario]
            r=subprocess.run(cmd,capture_output=True,env=dict(os.environ,PYTHONPATH=str(ROOT/'src')))
            return r

    def test_all_scenarios_exit_two_without_false_verified(self):
        for scenario in ('link_swap','link_to_fifo','parent_replace','root_replace','new_file'):
            with self.subTest(scenario=scenario):
                start=time.monotonic();r=self.run_mutator(scenario)
                self.assertLess(time.monotonic()-start,10.0)
                self.assertEqual(r.returncode,2,r.stderr.decode())
                out=r.stdout.decode()
                self.assertIn('GUARD_INSTABILITY',out)
                self.assertNotIn('verified',out)

    def test_append_scenario_exits_two(self):
        start=time.monotonic();r=self.run_mutator('append')
        self.assertLess(time.monotonic()-start,10.0)
        self.assertEqual(r.returncode,2,r.stderr.decode())
        self.assertIn('GUARD_INSTABILITY',r.stdout.decode())


class CLIReportProtectionTests(unittest.TestCase):
    def test_guarded_instability_preserves_old_report(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);out=p/'report.json';out.write_text('{"untouched":true}')
            # The mutator builds its own payload tree and only writes the
            # report through common.save after a fully stable capture.
            r=subprocess.run([sys.executable,str(MUTATOR),'--base',str(p),
                              '--scenario','new_file','--output',str(out)],
                             capture_output=True,env=dict(os.environ,PYTHONPATH=str(ROOT/'src')))
            self.assertEqual(r.returncode,2,r.stderr.decode())
            self.assertIn('GUARD_INSTABILITY',r.stdout.decode())
            self.assertEqual(out.read_text(),'{"untouched":true}')

    def test_cli_guarded_failure_preserves_old_report(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir();body=b'stable anchor bytes'
            (p/'payload/a.txt').write_bytes(body)
            d=manifest('payload',[entry('a.txt',body)])
            source=p/'input.json';source.write_text(json.dumps(d))
            out=p/'report.json';out.write_text('old-report')
            env=dict(os.environ,PYTHONPATH=str(ROOT/'src'))
            ok=subprocess.run([sys.executable,'-m','archive_fixity.cli','--source',str(source),
                               '--output',str(out),'--capture-mode','guarded'],capture_output=True,env=env)
            self.assertEqual(ok.returncode,0,ok.stderr.decode())
            saved=out.read_text();self.assertIn('observed_stable',saved)
            # A contract failure (non-hex digest) aborts before any report write.
            bad=manifest('payload',[{'path':'a.txt','bytes':len(body),'sha256':'z'*64}])
            source.write_text(json.dumps(bad))
            r=subprocess.run([sys.executable,'-m','archive_fixity.cli','--source',str(source),
                              '--output',str(out),'--capture-mode','guarded'],capture_output=True,env=env)
            self.assertEqual(r.returncode,2)
            self.assertEqual(out.read_text(),saved)

    def test_cli_rejects_unknown_capture_mode(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);shutil.copytree(ROOT/'fixtures',p/'fixtures')
            r=subprocess.run([sys.executable,'-m','archive_fixity.cli','--source',str(p/'fixtures/input.json'),
                              '--output',str(p/'r.json'),'--capture-mode','bogus'],
                             capture_output=True,env=dict(os.environ,PYTHONPATH=str(ROOT/'src')))
            self.assertEqual(r.returncode,2)


if __name__=='__main__':unittest.main()
