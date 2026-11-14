import hashlib,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from archive_fixity.restore import restore,RestoreError
from archive_fixity.common import read

ROOT=Path(__file__).resolve().parents[1]
CRASH_HELPER=Path(__file__).resolve().parent/'restore_crash.py'


def sha(body):return hashlib.sha256(body).hexdigest()


def entry(path,body):return {'path':path,'bytes':len(body),'sha256':sha(body)}


def write_tree(root,files):
    for name,body in files.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)


class RestoreHarness:
    def __init__(self,td):
        self.p=Path(td)
        self.meta=self.p/'meta';self.meta.mkdir()
        self.r0=self.p/'replica0';self.r1=self.p/'replica1';self.r2=self.p/'replica2'
        for r in (self.r0,self.r1,self.r2):r.mkdir()
        self.target=self.p/'out/package'
        self.state=self.p/'work'
        self.plan_path=self.p/'plan.json'
        self.files={}

    def manifest(self,files,payload_root='unused'):
        self.files=dict(files)
        data={'payload_root':payload_root,
              'entries':[entry(n,b) for n,b in sorted(files.items())]}
        (self.meta/'manifest.json').write_text(json.dumps(data))
        return data

    def plan(self,replicas=None,target=None,state=None,manifest='meta/manifest.json'):
        replicas=replicas or ['replica0','replica1','replica2']
        data={'manifest':manifest,'replicas':replicas,
              'target':target or 'out/package','state':state or 'work'}
        self.plan_path.write_text(json.dumps(data))
        return data

    def run_restore(self,barrier=None):
        return restore(self.plan_path,barrier=barrier)

    def payload(self):
        return self.target/'payload'

    def verify_bytes(self):
        for name,body in self.files.items():
            self.assertEqual_bytes((self.payload()/name).read_bytes(),body,name)

    def assertEqual_bytes(self,actual,expected,name):
        self.assertEqual(actual,expected,'byte mismatch at '+name)
        self.assertEqual(sha(actual),sha(expected))


class HappyPathTests(unittest.TestCase,RestoreHarness):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory()
        RestoreHarness.__init__(self,self._td.name)

    def tearDown(self):self._td.cleanup()

    def test_packages_payload_and_receipts_from_ordered_replicas(self):
        files={'a.txt':b'alpha'*100,'sub/b.bin':b'\x00\x01'*300,'empty.txt':b''}
        self.manifest(files)
        # r0 complete; it must win for every entry.
        write_tree(self.r0,files)
        write_tree(self.r1,{n:(b+b) for n,b in files.items()})  # wrong sizes everywhere
        self.plan()
        summary=self.run_restore()
        self.assertEqual(summary['files'],3);self.assertEqual(summary['bytes'],
                                                              sum(len(b) for b in files.values()))
        self.assertFalse(summary['resumed']);self.assertFalse(summary['recognized_existing'])
        self.assertTrue(self.target.is_dir())
        self.verify_bytes()
        receipts,_=read(self.target/'receipts.json')
        self.assertEqual([r['path'] for r in receipts],sorted(files))
        for r in receipts:
            self.assertEqual(r['source']['index'],0)
            self.assertEqual(r['bytes'],len(files[r['path']]))
            self.assertEqual(r['sha256'],sha(files[r['path']]))
            self.assertTrue(Path(r['source']['path']).is_file())

    def test_replica_fallthrough_for_missing_corrupt_link_and_special(self):
        files={'a.txt':b'good-bytes','b.txt':b'other-good','c.txt':b'from-r2'}
        self.manifest(files)
        # r0: a correct, b corrupt (same size, wrong digest), c missing.
        write_tree(self.r0,{'a.txt':files['a.txt'],'b.txt':b'XXXXXXXXXX'})
        os.symlink('/etc/passwd',self.r0/'c.txt')
        # r1: a wrong, b correct, c a FIFO.
        write_tree(self.r1,{'a.txt':b'WRONG-LEN!','b.txt':files['b.txt']})
        os.mkfifo(self.r1/'c.txt')
        # r2: everything correct.
        write_tree(self.r2,files)
        self.plan()
        summary=self.run_restore()
        by={r['path']:r['source']['index'] for r in summary['receipts']}
        self.assertEqual(by,{'a.txt':0,'b.txt':1,'c.txt':2})
        self.verify_bytes()

    def test_no_qualifying_source_fails_without_target_or_input_changes(self):
        files={'a.txt':b'alpha','b.txt':b'beta'}
        self.manifest(files)
        write_tree(self.r0,{'a.txt':files['a.txt'],'b.txt':b'WRONG'})
        self.plan(['replica0'])
        before={str(p):p.read_bytes() for p in self.r0.rglob('*') if p.is_file()}
        with self.assertRaises(RestoreError) as cm:self.run_restore()
        self.assertIn('no qualifying replica source',str(cm.exception))
        self.assertFalse(self.target.exists())
        after={str(p):p.read_bytes() for p in self.r0.rglob('*') if p.is_file()}
        self.assertEqual(before,after)
        # State is retained so the operator can add a replica and resume.
        self.assertTrue((self.state/'.restore-state/journal.json').exists())

    def test_empty_file_entry_restores_empty_payload(self):
        files={'zero.bin':b''}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        self.run_restore()
        self.assertEqual((self.payload()/'zero.bin').read_bytes(),b'')

    def test_absolute_plan_paths_are_accepted(self):
        files={'a.txt':b'abs'}
        self.manifest(files);write_tree(self.r0,files)
        self.plan_path.write_text(json.dumps({
            'manifest':str(self.meta/'manifest.json'),
            'replicas':[str(self.r0)],
            'target':str(self.target),'state':str(self.state)}))
        self.run_restore();self.verify_bytes()


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory();self.p=Path(self._td.name)
        self.meta=self.p/'meta';self.meta.mkdir()
        self.r0=self.p/'replica0';self.r0.mkdir()
        self.manifest=self.meta/'manifest.json'
        self.manifest.write_text(json.dumps({'payload_root':'unused','entries':[entry('a',b'x')]}))

    def tearDown(self):self._td.cleanup()

    def write_plan(self,**over):
        data={'manifest':'meta/manifest.json','replicas':['replica0'],
              'target':'out/package','state':'work'};data.update(over)
        plan=self.p/'plan.json';plan.write_text(json.dumps(data));return plan

    def assert_rejected(self,plan):
        with self.assertRaises(RestoreError):restore(plan)

    def test_target_inside_replica_tree_rejected(self):
        self.assert_rejected(self.write_plan(target='replica0/out'))
        self.assert_rejected(self.write_plan(target='replica0'))

    def test_state_inside_manifest_tree_rejected(self):
        self.assert_rejected(self.write_plan(state='meta/work'))

    def test_target_and_state_must_be_separate(self):
        self.assert_rejected(self.write_plan(target='out/x',state='out/x'))
        self.assert_rejected(self.write_plan(target='out/x',state='out'))
        self.assert_rejected(self.write_plan(target='out',state='out/x'))

    def test_replica_missing_or_symlinked_rejected(self):
        self.assert_rejected(self.write_plan(replicas=['replica-missing']))
        link=self.p/'link';os.symlink(self.r0,link)
        self.assert_rejected(self.write_plan(replicas=['link']))

    def test_target_symlink_refused(self):
        files={'a':b'x'};write_tree(self.r0,files)
        plan=self.write_plan()
        other=self.p/'other';other.mkdir();os.symlink(other,self.p/'out-link')
        plan.write_text(json.dumps({'manifest':'meta/manifest.json','replicas':['replica0'],
                                    'target':'out-link','state':'work'}))
        self.assert_rejected(plan)

    def test_plan_inside_target_or_state_rejected(self):
        nested=self.p/'work';nested.mkdir()
        plan=nested/'plan.json'
        plan.write_text(json.dumps({'manifest':'meta/manifest.json','replicas':['replica0'],
                                    'target':'out/package','state':'work'}))
        self.assert_rejected(plan)

    def test_bad_plan_shapes_rejected(self):
        for raw in ('{}','[]','null','{"manifest":"x"}','42',
                    json.dumps({'manifest':'meta/manifest.json','replicas':[],
                                'target':'t','state':'s'}),
                    json.dumps({'manifest':'meta/manifest.json','replicas':['replica0','replica0'],
                                'target':'t','state':'s'})):
            plan=self.p/'bad.json';plan.write_text(raw)
            with self.assertRaises(RestoreError):restore(plan)

    def test_different_filesystem_target_rejected(self):
        files={'a':b'x'};write_tree(self.r0,files);plan=self.write_plan()
        real_rename=os.rename
        def fake_rename(src,dst):
            import errno
            raise OSError(errno.EXDEV,'simulated cross-device link')
        os.rename=fake_rename
        try:
            with self.assertRaises(RestoreError) as cm:restore(plan)
            self.assertIn('atomic publication failed',str(cm.exception))
        finally:
            os.rename=real_rename
        self.assertFalse((self.p/'out/package').exists())
        # Staging stays in the state directory for a corrected resume.
        self.assertTrue((self.p/'work/.restore-state/package/payload').is_dir())


class ResumeTests(unittest.TestCase,RestoreHarness):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory()
        RestoreHarness.__init__(self,self._td.name)

    def tearDown(self):self._td.cleanup()

    def test_resume_after_interruption_mid_copy(self):
        files={'a.txt':b'A'*100000,'b.txt':b'B'*100000}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        def barrier(event,name):
            if event=='copy_chunk' and name=='a.txt':
                raise RuntimeError('simulated crash during copy')
        with self.assertRaises(RuntimeError):self.run_restore(barrier=barrier)
        self.assertFalse(self.target.exists())
        # No journal entry exists; partial temp file is cleaned on resume.
        journal,_=read(self.state/'.restore-state/journal.json')
        self.assertEqual(journal['entries'],{});self.assertFalse(journal['published'])
        summary=self.run_restore()
        self.assertTrue(summary['resumed']);self.verify_bytes()

    def test_resume_after_file_completed_but_unjournaled(self):
        files={'a.txt':b'A'*5000,'b.txt':b'B'*5000}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        def barrier(event,name):
            if event=='file_unjournaled' and name=='a.txt':
                raise RuntimeError('simulated crash after write, before journal')
        with self.assertRaises(RuntimeError):self.run_restore(barrier=barrier)
        journal,_=read(self.state/'.restore-state/journal.json')
        self.assertEqual(journal['entries'],{})
        staged=self.state/'.restore-state/package/payload/a.txt'
        self.assertTrue(staged.is_file())  # complete bytes, not yet accounted
        # Resume must re-fetch from a source rather than trust the unlogged file.
        summary=self.run_restore()
        self.assertTrue(summary['resumed']);self.verify_bytes()
        by={r['path']:r['source']['index'] for r in summary['receipts']}
        self.assertEqual(by,{'a.txt':0,'b.txt':0})

    def test_resume_reverifies_journaled_bytes_and_rejects_tampered_staging(self):
        files={'a.txt':b'AAAA','b.txt':b'BBBB'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0','replica1'])
        write_tree(self.r1,files)
        # Interrupt after every entry is journaled but before publication, so
        # the staging tree and journal survive in the state directory.
        def stop(event,name):
            if event=='before_publish':raise RuntimeError('crash before publish')
        with self.assertRaises(RuntimeError):self.run_restore(barrier=stop)
        journal_path=self.state/'.restore-state/journal.json'
        journal,_=read(journal_path)
        self.assertFalse(journal['published'])
        # Tamper with staged bytes: the journal must not save them.
        staged=self.state/'.restore-state/package/payload/a.txt'
        staged.write_bytes(b'TAMP')
        events=[]
        summary=self.run_restore(barrier=lambda e,n:events.append((e,n)))
        self.assertIn(('resume_verified','b.txt'),events)  # intact entry only re-verified
        self.verify_bytes()
        receipt=next(r for r in summary['receipts'] if r['path']=='a.txt')
        self.assertEqual(receipt['source']['index'],0)  # re-sourced, not the tampered bytes

    def test_staging_tamper_before_publish_falls_back_to_other_replica(self):
        files={'a.txt':b'only-in-r1'}
        self.manifest(files)
        # All three replicas are bound into the plan identity up front; the
        # first run selects r1, the resumed run must fall through to r2.
        write_tree(self.r1,files);write_tree(self.r2,files)
        self.plan(['replica0','replica1','replica2'])
        def barrier(event,name):
            if event=='after_journal' and name=='a.txt':
                # After accounting, corrupt the staged bytes and remove r1;
                # the next attempt must find another qualifying replica (r2).
                staged=self.state/'.restore-state/package/payload/a.txt'
                staged.write_bytes(b'corrupt-bytes-here')
                shutil.rmtree(self.r1);self.r1.mkdir()
        with self.assertRaises(RestoreError):self.run_restore(barrier=barrier)
        summary=self.run_restore()
        receipt=summary['receipts'][0]
        self.assertEqual(receipt['source']['index'],2)
        self.verify_bytes()

    def test_switching_replica_order_on_resume_keeps_identity_stable(self):
        files={'a.txt':b'alpha','b.txt':b'beta'}
        self.manifest(files);write_tree(self.r0,files);write_tree(self.r1,files)
        self.plan(['replica0','replica1'])
        def barrier(event,name):
            if event=='file_unjournaled' and name=='b.txt':raise RuntimeError('stop')
        with self.assertRaises(RuntimeError):self.run_restore(barrier=barrier)
        # Re-ordering replicas changes the bound identity: resume must refuse.
        self.plan(['replica1','replica0'])
        with self.assertRaises(RestoreError) as cm:self.run_restore()
        self.assertIn('identity mismatch',str(cm.exception))

    def test_manifest_change_rejected_on_resume(self):
        files={'a.txt':b'alpha'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        def barrier(event,name):
            if event=='file_unjournaled':raise RuntimeError('stop')
        with self.assertRaises(RuntimeError):self.run_restore(barrier=barrier)
        self.manifest({'a.txt':b'changed-bytes!!'})
        with self.assertRaises(RestoreError) as cm:self.run_restore()
        self.assertIn('identity mismatch',str(cm.exception))

    def test_target_change_rejected_on_resume(self):
        files={'a.txt':b'alpha'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        def barrier(event,name):
            if event=='file_unjournaled':raise RuntimeError('stop')
        with self.assertRaises(RuntimeError):self.run_restore(barrier=barrier)
        self.plan(target='out/elsewhere')
        with self.assertRaises(RestoreError) as cm:self.run_restore()
        self.assertIn('identity mismatch',str(cm.exception))

    def test_published_journal_rerun_is_idempotent_success(self):
        files={'a.txt':b'alpha','b.txt':b'beta'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        first=self.run_restore();self.assertTrue(self.target.is_dir())
        second=self.run_restore()
        self.assertTrue(second['resumed']);self.assertTrue(second['recognized_existing'])
        self.assertEqual(second['receipts'],first['receipts'])
        self.verify_bytes()


class PublicationTests(unittest.TestCase,RestoreHarness):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory()
        RestoreHarness.__init__(self,self._td.name)

    def tearDown(self):self._td.cleanup()

    def test_unjournaled_publication_is_recognized_and_completed(self):
        files={'a.txt':b'alpha','b.txt':b'beta'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        def barrier(event,name):
            if event=='publish_unjournaled':raise RuntimeError('crash after rename')
        with self.assertRaises(RuntimeError):self.run_restore(barrier=barrier)
        # The package is already at the target but the journal is unpublished.
        self.assertTrue(self.target.is_dir())
        journal,_=read(self.state/'.restore-state/journal.json')
        self.assertFalse(journal['published'])
        summary=self.run_restore()
        self.assertTrue(summary['recognized_existing'])
        journal,_=read(self.state/'.restore-state/journal.json')
        self.assertTrue(journal['published'])
        self.verify_bytes()

    def test_existing_foreign_directory_is_never_overwritten(self):
        files={'a.txt':b'alpha'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        self.target.parent.mkdir(parents=True)
        self.target.mkdir()
        marker=self.target/'important.txt';marker.write_text('do not touch')
        with self.assertRaises(RestoreError) as cm:self.run_restore()
        self.assertIn('refusing to overwrite',str(cm.exception))
        self.assertEqual(marker.read_text(),'do not touch')

    def test_existing_directory_with_tampered_package_is_refused(self):
        files={'a.txt':b'alpha'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        self.run_restore()
        (self.payload()/'a.txt').write_bytes(b'TAMPERED')  # break the product
        with self.assertRaises(RestoreError) as cm:self.run_restore()
        self.assertIn('refusing to overwrite',str(cm.exception))

    def test_whole_package_reverification_catches_receipt_swap(self):
        files={'a.txt':b'alpha'}
        self.manifest(files);write_tree(self.r0,files);self.plan(['replica0'])
        self.run_restore()
        # A valid-looking package at the target but with receipts pointing at
        # bytes that no longer qualify must be treated as foreign.
        receipts_path=self.target/'receipts.json'
        receipts,_=read(receipts_path)
        receipts[0]['sha256']='f'*64
        receipts_path.write_text(json.dumps(receipts))
        with self.assertRaises(RestoreError):self.run_restore()


class CrashSubprocessTests(unittest.TestCase):
    """End-to-end fault injection in a separate process, then CLI resume."""

    def run_crash(self,scenario):
        td=tempfile.mkdtemp()
        env=dict(os.environ,PYTHONPATH=str(ROOT/'src'))
        r=subprocess.run([sys.executable,str(CRASH_HELPER),'--base',td,'--scenario',scenario],
                         capture_output=True,env=env)
        self.assertEqual(r.returncode,3,r.stderr.decode()+r.stdout.decode())
        self.assertIn('RESTORE_CRASH',r.stdout.decode())
        return Path(td),env

    def resume_via_cli(self,base,env):
        return subprocess.run([sys.executable,'-m','archive_fixity.cli','restore',
                               '--plan',str(base/'plan.json')],capture_output=True,env=env)

    def test_copy_chunk_crash_then_cli_resume(self):
        base,env=self.run_crash('copy_chunk')
        self.assertFalse((base/'out/package').exists())
        r=self.resume_via_cli(base,env)
        self.assertEqual(r.returncode,0,r.stderr.decode())
        summary=json.loads(r.stdout)
        self.assertTrue(summary['resumed'])
        self._assert_complete_product(base)

    def test_file_unjournaled_crash_then_cli_resume(self):
        base,env=self.run_crash('file_unjournaled')
        r=self.resume_via_cli(base,env)
        self.assertEqual(r.returncode,0,r.stderr.decode())
        self._assert_complete_product(base)

    def test_publish_unjournaled_crash_then_cli_resume_is_idempotent(self):
        base,env=self.run_crash('publish_unjournaled')
        self.assertTrue((base/'out/package').is_dir())
        r=self.resume_via_cli(base,env)
        self.assertEqual(r.returncode,0,r.stderr.decode())
        summary=json.loads(r.stdout)
        self.assertTrue(summary['recognized_existing'])
        self._assert_complete_product(base)
        # A second CLI invocation is still a stable idempotent success.
        again=self.resume_via_cli(base,env)
        self.assertEqual(again.returncode,0,again.stderr.decode())
        self.assertTrue(json.loads(again.stdout)['recognized_existing'])

    def _assert_complete_product(self,base):
        package=base/'out/package'
        receipts=json.loads((package/'receipts.json').read_text())
        manifest=json.loads((base/'meta/manifest.json').read_text())
        self.assertEqual(len(receipts),len(manifest['entries']))
        for e in manifest['entries']:
            path=package/'payload'/e['path']
            raw=path.read_bytes()
            self.assertEqual(len(raw),e['bytes'])
            self.assertEqual(sha(raw),e['sha256'])
        # Receipts name the replica that supplied each entry.
        for r in receipts:
            self.assertTrue(Path(r['source']['path']).is_file())
            self.assertEqual(r['sha256'],sha(Path(r['source']['path']).read_bytes()))
        # b.bin is absent from replica 0, so its receipt must name replica 1.
        b=next(r for r in receipts if r['path']=='sub/b.bin')
        self.assertEqual(b['source']['index'],1)


class CLITests(unittest.TestCase):
    def test_restore_subcommand_and_flat_audit_interface_coexist(self):
        env=dict(os.environ,PYTHONPATH=str(ROOT/'src'))
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);files={'a.txt':b'cli bytes'}
            meta=base/'meta';meta.mkdir();r=base/'replica';r.mkdir()
            (meta/'manifest.json').write_text(json.dumps(
                {'payload_root':'unused','entries':[entry(n,b) for n,b in sorted(files.items())]}))
            write_tree(r,files)
            plan=base/'plan.json'
            plan.write_text(json.dumps({'manifest':'meta/manifest.json','replicas':['replica'],
                                        'target':'out/package','state':'work'}))
            ok=subprocess.run([sys.executable,'-m','archive_fixity.cli','restore',
                               '--plan',str(plan)],capture_output=True,env=env)
            self.assertEqual(ok.returncode,0,ok.stderr.decode())
            self.assertEqual((base/'out/package/payload/a.txt').read_bytes(),b'cli bytes')
            bad=subprocess.run([sys.executable,'-m','archive_fixity.cli','restore',
                                '--plan',str(base/'missing.json')],capture_output=True,env=env)
            self.assertEqual(bad.returncode,2)
            # The historical flat audit invocation remains unchanged.
            audit=subprocess.run([sys.executable,'-m','archive_fixity.cli',
                                  '--source',str(ROOT/'fixtures/input.json'),
                                  '--output',str(base/'report.json')],capture_output=True,env=env)
            self.assertEqual(audit.returncode,0,audit.stderr.decode())
            report=json.loads((base/'report.json').read_text())
            self.assertNotIn('capture_mode',report)


if __name__=='__main__':unittest.main()
