import hashlib,json,os,re,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from archive_fixity import bag as bagmod
from archive_fixity.bag import import_bag,BagError

ROOT=Path(__file__).resolve().parents[1]
CLI=[sys.executable,'-m','archive_fixity.cli']
ENV={**os.environ,'PYTHONPATH':str(ROOT/'src')}


def sha(body,algorithm='sha256'):
    return getattr(hashlib,algorithm)(body).hexdigest()


def run_cli(*args):
    return subprocess.run(CLI+list(args),capture_output=True,text=True,env=ENV)


def snapshot(root):
    """Map every path under root to its type/bytes so tests can prove it unchanged."""
    result={}
    for current,dirs,names in os.walk(root,followlinks=False):
        base=Path(current)
        for name in sorted(dirs+names):
            path=base/name;rel=path.relative_to(root).as_posix()
            if path.is_symlink():result[rel]=('link',os.readlink(path))
            elif path.is_dir():result[rel]=('dir',)
            else:result[rel]=('file',hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def make_bag(root,files,payload_algorithms=('sha256',),tag_algorithms=('sha256',),
             oxum='auto',bag_info=True,version='1.0',encoding='UTF-8'):
    """Write a well-formed BagIt 1.0 bag; return the generated line numbers."""
    root=Path(root);(root/'data').mkdir(parents=True)
    for name,body in files.items():
        path=root/'data'/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(body)
    (root/'bagit.txt').write_text('BagIt-Version: %s\nTag-File-Character-Encoding: %s\n'
                                  %(version,encoding))
    payload_lines={}
    payload_names=sorted('data/'+name for name in files)
    for algorithm in payload_algorithms:
        rows=['%s  %s'%(sha(files[name[5:]],algorithm),name) for name in payload_names]
        (root/('manifest-%s.txt'%algorithm)).write_text('\n'.join(rows)+('\n' if rows else ''))
        payload_lines[algorithm]={name[5:]:index for index,name in enumerate(payload_names,1)}
    info=''
    if bag_info:
        total=sum(len(body) for body in files.values())
        if oxum=='auto':oxum='%d.%d'%(total,len(files))
        if oxum is not None:info+='Payload-Oxum: '+oxum+'\n'
        info+='Bagging-Date: 2026-11-15\n'
        (root/'bag-info.txt').write_text(info)
    tag_names=sorted(name for name in ('bagit.txt','bag-info.txt')+(tuple('manifest-%s.txt'%a
                     for a in payload_algorithms)) if (root/name).is_file())
    tag_lines={}
    for algorithm in tag_algorithms:
        rows=['%s  %s'%(sha((root/name).read_bytes(),algorithm),name) for name in tag_names]
        (root/('tagmanifest-%s.txt'%algorithm)).write_text('\n'.join(rows)+'\n')
        tag_lines[algorithm]={name:index for index,name in enumerate(tag_names,1)}
    return {'payload_lines':payload_lines,'tag_lines':tag_lines,'tag_names':tag_names}


class Harness(unittest.TestCase):
    """Shared temp-directory bag/CLI harness with failure-preservation helper."""

    def setUp(self):
        self._td=tempfile.TemporaryDirectory();self.p=Path(self._td.name)
        self.output=self.p/'out'/'manifest.json'
        self.output.parent.mkdir()
        self.old=b'{"old": true}\n';self.output.write_bytes(self.old)

    def tearDown(self):self._td.cleanup()

    def bag(self,name='bag',files=None,**kw):
        files={'a.txt':b'alpha','empty':b'','sub/b.bin':bytes(range(256))} if files is None else files
        return make_bag(self.p/name,files,**kw)

    def import_cli(self,bag='bag',output=None):
        return run_cli('bag-import','--bag',str(self.p/bag),'--output',str(output or self.output))

    def assert_failed(self,result,needles=(),output=None):
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        for needle in needles:
            self.assertIn(needle,result.stderr)
        self.assertEqual((output or self.output).read_bytes(),self.old)

    def assert_no_stray_files(self,directory=None):
        directory=directory or self.output.parent
        stray=[p.name for p in directory.iterdir() if p!=self.output]
        self.assertEqual(stray,[])


class SuccessTests(Harness):
    def test_single_algorithm_conversion_and_summary(self):
        lines=self.bag()
        result=self.import_cli()
        self.assertEqual(result.returncode,0,result.stderr)
        summary=json.loads(result.stdout)
        manifest=json.loads(self.output.read_bytes())
        self.assertEqual(manifest['payload_root'],'data')
        self.assertEqual([e['path'] for e in manifest['entries']],['a.txt','empty','sub/b.bin'])
        by_path={e['path']:e for e in manifest['entries']}
        self.assertEqual(by_path['sub/b.bin']['bytes'],256)
        self.assertEqual(by_path['sub/b.bin']['sha256'],sha(bytes(range(256))))
        self.assertEqual(summary['payload_files'],3)
        self.assertEqual(summary['payload_bytes'],261)
        self.assertEqual(summary['payload_oxum'],'261.3')
        self.assertEqual(summary['algorithms'],['sha256'])
        self.assertEqual(summary['tag_algorithms'],['sha256'])
        self.assertEqual(summary['bagit_version'],'1.0')
        raw=self.output.read_bytes()
        self.assertEqual(summary['manifest_bytes'],len(raw))
        self.assertEqual(summary['manifest_sha256'],hashlib.sha256(raw).hexdigest())
        self.assert_no_stray_files()

    def test_sha512_only_bag_converts_with_sha256_manifest(self):
        self.bag(payload_algorithms=('sha512',),tag_algorithms=('sha512',))
        result=self.import_cli()
        self.assertEqual(result.returncode,0,result.stderr)
        manifest=json.loads(self.output.read_bytes())
        for entry in manifest['entries']:
            body=(self.p/'bag/data'/entry['path']).read_bytes()
            self.assertEqual(entry['sha256'],sha(body))
        self.assertEqual(json.loads(result.stdout)['algorithms'],['sha512'])

    def test_dual_algorithm_bag_verifies_both_manifests(self):
        lines=self.bag(payload_algorithms=('sha256','sha512'))
        result=self.import_cli()
        self.assertEqual(result.returncode,0,result.stderr)
        summary=json.loads(result.stdout)
        self.assertEqual(summary['algorithms'],['sha256','sha512'])
        self.assertEqual(summary['tag_algorithms'],['sha256'])

    def test_generated_manifest_audits_a_matching_payload_tree(self):
        self.bag()
        view=self.p/'view';shutil.copytree(self.p/'bag/data',view/'data')
        view.mkdir(exist_ok=True)
        output=view/'manifest.json'
        result=self.import_cli(output=output)
        self.assertEqual(result.returncode,0,result.stderr)
        report=run_cli('--source',str(output),'--output',str(self.p/'report.json'))
        self.assertEqual(report.returncode,0,report.stderr)
        result=json.loads((self.p/'report.json').read_text())['result']
        self.assertTrue(result['inventory_clean'])
        self.assertEqual(result['captured_bytes'],261)

    def test_generated_manifest_is_accepted_by_restore(self):
        self.bag()
        result=self.import_cli()
        self.assertEqual(result.returncode,0,result.stderr)
        replica=self.p/'replica';replica.mkdir()
        for current,dirs,names in os.walk(self.p/'bag/data'):
            for name in names:
                src=Path(current)/name;dst=replica/src.relative_to(self.p/'bag/data')
                dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
        plan=self.p/'plan.json'
        plan.write_text(json.dumps({'manifest':'out/manifest.json','replicas':['replica'],
                                    'target':'restored','state':'work'}))
        restored=run_cli('restore','--plan',str(plan))
        self.assertEqual(restored.returncode,0,restored.stderr)
        summary=json.loads(restored.stdout)
        self.assertEqual(summary['files'],3)
        self.assertEqual(summary['bytes'],261)

    def test_rerun_is_byte_identical_and_bag_untouched(self):
        self.bag()
        before=snapshot(self.p/'bag')
        first=self.import_cli();self.assertEqual(first.returncode,0,first.stderr)
        original=self.output.read_bytes()
        second=self.import_cli();self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual(self.output.read_bytes(),original)
        self.assertEqual(json.loads(first.stdout),json.loads(second.stdout))
        self.assertEqual(snapshot(self.p/'bag'),before)
        self.assert_no_stray_files()

    def test_empty_payload_bag_is_valid(self):
        make_bag(self.p/'bag',{},payload_algorithms=('sha256',),tag_algorithms=('sha256',))
        result=self.import_cli()
        self.assertEqual(result.returncode,0,result.stderr)
        manifest=json.loads(self.output.read_bytes())
        self.assertEqual(manifest,{'payload_root':'data','entries':[]})
        self.assertEqual(json.loads(result.stdout)['payload_oxum'],'0.0')

    def test_only_last_payload_entry_is_read_once_per_file(self):
        self.bag(payload_algorithms=('sha256','sha512'),tag_algorithms=('sha256','sha512'))
        counts={};real=bagmod._hash_file
        def counting(path,label,algorithms,limit=None):
            counts[label]=counts.get(label,0)+1
            return real(path,label,algorithms,limit)
        with mock.patch.object(bagmod,'_hash_file',counting):
            import_bag(self.p/'bag',self.p/'out/once.json')
        self.assertEqual(counts,{'data/a.txt':1,'data/empty':1,'data/sub/b.bin':1,
                                 'bag-info.txt':1,'bagit.txt':1,
                                 'manifest-sha256.txt':1,'manifest-sha512.txt':1})


class ManifestFailureTests(Harness):
    def test_dual_algorithm_sha512_tamper_is_detected_with_line(self):
        lines=self.bag(payload_algorithms=('sha256','sha512'))
        path=self.p/'bag/manifest-sha512.txt'
        rows=path.read_text().splitlines()
        line=lines['payload_lines']['sha512']['sub/b.bin']
        digest,_,name=rows[line-1].partition('  ')
        rows[line-1]=('0' if digest[0]!='0' else '1')+digest[1:]+'  '+name
        path.write_text('\n'.join(rows)+'\n')
        result=self.import_cli()
        self.assert_failed(result,['manifest-sha512.txt:%d:'%line,'digest mismatch','sub/b.bin'])
        self.assert_no_stray_files()

    def test_sha256_tamper_detected_even_when_sha512_is_correct(self):
        lines=self.bag(payload_algorithms=('sha256','sha512'))
        path=self.p/'bag/manifest-sha256.txt'
        rows=path.read_text().splitlines()
        line=lines['payload_lines']['sha256']['a.txt']
        rows[line-1]='0'*64+'  data/a.txt'
        path.write_text('\n'.join(rows)+'\n')
        self.assert_failed(self.import_cli(),['manifest-sha256.txt:%d:'%line,'a.txt'])

    def test_unsupported_algorithm(self):
        self.bag();(self.p/'bag/manifest-md5.txt').write_text('d41d8cd98f00b204e9800998ecf8427e  data/a.txt\n')
        self.assert_failed(self.import_cli(),['manifest-md5.txt','unsupported manifest algorithm'])

    def test_missing_payload_file_names_manifest_and_line(self):
        lines=self.bag()
        (self.p/'bag/data/a.txt').unlink()
        self.assert_failed(self.import_cli(),
                           ['manifest-sha256.txt:%d:'%lines['payload_lines']['sha256']['a.txt'],
                            'missing','data/a.txt'])

    def test_extra_payload_file_is_rejected(self):
        self.bag();(self.p/'bag/data/extra.bin').write_bytes(b'x')
        self.assert_failed(self.import_cli(),['data/extra.bin','not listed'])

    def test_duplicate_manifest_path_names_second_line(self):
        self.bag();path=self.p/'bag/manifest-sha256.txt'
        rows=path.read_text().splitlines();rows.append(rows[0]);path.write_text('\n'.join(rows)+'\n')
        self.assert_failed(self.import_cli(),['manifest-sha256.txt:4:','duplicate path'])

    def test_unsafe_paths_rejected_with_line(self):
        for bad in ['../escape','/etc/passwd','data//x','data/./x','data\\x']:
            with self.subTest(bad=bad):
                setUp_dirs=self.p/'case';shutil.rmtree(setUp_dirs,ignore_errors=True)
                make_bag(setUp_dirs,{'a.txt':b'a'})
                rows=['%s  %s'%(sha(b'a'),bad)]
                (setUp_dirs/'manifest-sha256.txt').write_text('\n'.join(rows)+'\n')
                out=self.p/('out-%s.json'%bad.replace('/','_').replace('\\','_').replace('.','_'))
                result=run_cli('bag-import','--bag',str(setUp_dirs),'--output',str(out))
                self.assertEqual(result.returncode,2)
                self.assertIn('manifest-sha256.txt:1:',result.stderr)
                self.assertFalse(out.exists())

    def test_payload_manifest_must_address_data(self):
        self.bag()
        (self.p/'bag/manifest-sha256.txt').write_text('%s  a.txt\n'%sha(b'alpha'))
        self.assert_failed(self.import_cli(),['manifest-sha256.txt:1:','under data/'])

    def test_manifest_requires_lowercase_hex(self):
        self.bag()
        (self.p/'bag/manifest-sha256.txt').write_text('%s  data/a.txt\n'%sha(b'alpha').upper())
        self.assert_failed(self.import_cli(),['manifest-sha256.txt:1:','lowercase sha256 digest'])


class TagFailureTests(Harness):
    def test_tampered_tag_file_is_detected_with_line(self):
        lines=self.bag()
        with (self.p/'bag/bag-info.txt').open('a') as stream:stream.write('Source-Organization: forged\n')
        result=self.import_cli()
        self.assert_failed(result,['tagmanifest-sha256.txt:%d:'
                                   %lines['tag_lines']['sha256']['bag-info.txt'],
                                   'digest mismatch','bag-info.txt'])
        self.assert_no_stray_files()

    def test_tampered_tagmanifest_does_not_hide_bagit_change(self):
        self.bag()
        (self.p/'bag/bagit.txt').write_text('BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\nX: y\n')
        self.assert_failed(self.import_cli(),['bagit.txt:3:','unexpected field: X'])

    def test_tagmanifest_must_cover_every_non_payload_tag(self):
        self.bag();(self.p/'bag/notes.txt').write_text('uncovered\n')
        self.assert_failed(self.import_cli(),['required tag file is not listed: notes.txt'])

    def test_tagmanifest_listed_file_missing(self):
        lines=self.bag();(self.p/'bag/bag-info.txt').unlink()
        self.assert_failed(self.import_cli(),
                           ['tagmanifest-sha256.txt:%d:'%lines['tag_lines']['sha256']['bag-info.txt'],
                            'listed tag file is missing: bag-info.txt'])

    def test_tagmanifest_cannot_list_payload_or_itself(self):
        for bad,needle in [('data/a.txt','tag manifest lists payload path'),
                           ('tagmanifest-sha512.txt','tag manifest must not list itself')]:
            with self.subTest(bad=bad):
                shutil.rmtree(self.p/'bag',ignore_errors=True)
                self.bag(tag_algorithms=())
                (self.p/'bag/tagmanifest-sha512.txt').write_text(
                    '%s  %s\n'%(sha(b'x','sha512'),bad))
                self.assert_failed(self.import_cli(),['tagmanifest-sha512.txt:1:',needle])

    def test_tagmanifest_may_cross_list_another_tagmanifest_and_is_checked(self):
        self.bag(tag_algorithms=('sha256','sha512'))
        bag=self.p/'bag'
        names=['bag-info.txt','bagit.txt','manifest-sha256.txt','tagmanifest-sha256.txt']
        (bag/'tagmanifest-sha512.txt').write_text(''.join(
            '%s  %s\n'%(sha((bag/name).read_bytes(),'sha512'),name) for name in names))
        result=self.import_cli()
        self.assertEqual(result.returncode,0,result.stderr)
        published=self.output.read_bytes()
        # The cross-listed digest is verified: a benign-looking reordering of
        # that tag manifest still changes its bytes and is caught.
        other=self.p/'bag/tagmanifest-sha256.txt'
        other.write_text('\n'.join(reversed(other.read_text().splitlines()))+'\n')
        failed=self.import_cli()
        self.assertEqual(failed.returncode,2)
        for needle in ('tagmanifest-sha512.txt:4:','digest mismatch','tagmanifest-sha256.txt'):
            self.assertIn(needle,failed.stderr)
        self.assertEqual(self.output.read_bytes(),published)

    def test_unsupported_tag_algorithm(self):
        self.bag();(self.p/'bag/tagmanifest-md5.txt').write_text('d41d8cd98f00b204e9800998ecf8427e  bagit.txt\n')
        self.assert_failed(self.import_cli(),['tagmanifest-md5.txt','unsupported manifest algorithm'])


class MetadataFailureTests(Harness):
    def test_bagit_version_must_be_1_0(self):
        self.bag(version='0.97')
        self.assert_failed(self.import_cli(),['bagit.txt:1:','unsupported BagIt-Version'])

    def test_bagit_requires_utf8_tag_encoding(self):
        self.bag(encoding='ISO-8859-1')
        self.assert_failed(self.import_cli(),['bagit.txt:2:','Tag-File-Character-Encoding'])

    def test_missing_bagit_txt(self):
        self.bag();(self.p/'bag/bagit.txt').unlink()
        self.assert_failed(self.import_cli(),['bagit.txt','missing'])
        self.assertEqual(snapshot(self.p/'bag')['data'],('dir',))

    def test_no_supported_payload_manifest(self):
        self.bag();(self.p/'bag/manifest-sha256.txt').unlink()
        self.assert_failed(self.import_cli(),['no supported payload manifest'])

    def test_oxum_byte_mismatch(self):
        self.bag(oxum='260.3')
        self.assert_failed(self.import_cli(),['bag-info.txt:1:','byte count 260 != 261'])

    def test_oxum_file_count_mismatch(self):
        self.bag(oxum='261.4')
        self.assert_failed(self.import_cli(),['bag-info.txt:1:','file count 4 != 3'])

    def test_oxum_malformed_and_duplicate(self):
        self.bag(oxum='261')
        self.assert_failed(self.import_cli(),['bag-info.txt:1:','malformed Payload-Oxum'])
        shutil.rmtree(self.p/'bag')
        self.bag()
        with (self.p/'bag/bag-info.txt').open('a') as stream:stream.write('Payload-Oxum: 261.3\n')
        self.assert_failed(self.import_cli(),['duplicate Payload-Oxum'])

    def test_bagit_txt_duplicate_field(self):
        self.bag();(self.p/'bag/bagit.txt').write_text(
            'BagIt-Version: 1.0\nBagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n')
        self.assert_failed(self.import_cli(),['bagit.txt:2:','duplicate field'])


class SafetyTests(Harness):
    def test_symlink_anywhere_in_bag_is_rejected(self):
        self.bag();(self.p/'bag/data/link.txt').symlink_to('/etc/passwd')
        self.assert_failed(self.import_cli(),['data/link.txt: symbolic link is not allowed'])
        self.assert_no_stray_files()

    def test_symlinked_bag_root_and_output_are_rejected(self):
        self.bag();(self.p/'alias').symlink_to(self.p/'bag',target_is_directory=True)
        result=self.import_cli(bag='alias')
        self.assert_failed(result,['bag: cannot be a symbolic link'])
        link=self.p/'out/link.json';link.symlink_to(self.output)
        result=self.import_cli(output=link)
        self.assertEqual(result.returncode,2)
        self.assertIn('cannot be a symlink',result.stderr)

    def test_output_inside_bag_is_refused_before_writing(self):
        self.bag();before=snapshot(self.p/'bag')
        for target in ['bag/manifest-out.json','bag/data/manifest.json','bag']:
            with self.subTest(target=target):
                result=run_cli('bag-import','--bag',str(self.p/'bag'),
                               '--output',str(self.p/target))
                self.assertEqual(result.returncode,2)
                self.assertIn('outside the bag',result.stderr)
                self.assertEqual(snapshot(self.p/'bag'),before)

    def test_last_entry_error_leaves_old_manifest_and_no_half_product(self):
        files={'a.txt':b'a','m.txt':b'm','z-last.txt':b'z'}
        self.bag(files=files)
        before=snapshot(self.p/'bag')
        first=self.import_cli();self.assertEqual(first.returncode,0,first.stderr)
        original=self.output.read_bytes()
        # Damage only the final sorted entry, after the earlier ones verified.
        (self.p/'bag/data/z-last.txt').write_bytes(b'Z')
        result=self.import_cli()
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('z-last.txt',result.stderr)
        self.assertIn('manifest-sha256.txt:3:',result.stderr)
        self.assertEqual(self.output.read_bytes(),original)
        self.assert_no_stray_files()
        self.assertNotEqual(snapshot(self.p/'bag'),before)  # the test's own damage
        (self.p/'bag/data/z-last.txt').write_bytes(b'z')
        restored=self.import_cli();self.assertEqual(restored.returncode,0,restored.stderr)
        self.assertEqual(self.output.read_bytes(),original)

    def test_failure_does_not_create_output_when_absent(self):
        self.bag();(self.p/'bag/data/a.txt').write_bytes(b'X')
        fresh=self.p/'fresh-dir/fresh.json'
        result=self.import_cli(output=fresh)
        self.assertEqual(result.returncode,2)
        self.assertFalse(fresh.exists())
        self.assertFalse(fresh.parent.exists())

    def test_bag_is_never_written_even_on_success(self):
        self.bag()
        before=snapshot(self.p/'bag')
        self.assertEqual(self.import_cli().returncode,0)
        self.assertEqual(snapshot(self.p/'bag'),before)


if __name__=='__main__':unittest.main()


class LimitTests(Harness):
    """Limits are patched in-process: subprocesses would not see the override."""

    def assert_limit(self,needles):
        with self.assertRaises(BagError) as caught:
            import_bag(self.p/'bag',self.output)
        for needle in needles:self.assertIn(needle,str(caught.exception))
        self.assertEqual(self.output.read_bytes(),self.old)

    def test_payload_file_limit_is_enforced_at_scan(self):
        self.bag(files={'a.txt':b'a','b.txt':b'b'})
        with mock.patch.object(bagmod,'MAX_FILES',1):self.assert_limit(['payload file limit (1)'])

    def test_inventory_limit_is_enforced(self):
        self.bag(files={'a.txt':b'a'})
        with mock.patch.object(bagmod,'MAX_ENTRIES',2):
            self.assert_limit(['inventory exceeds 5000 entries'])

    def test_payload_byte_limit_is_enforced_while_hashing(self):
        self.bag(files={'a.txt':b'a'*4})
        with mock.patch.object(bagmod,'MAX_TOTAL',3):
            self.assert_limit(['payload total exceeds 32 MB limit'])

    def test_single_file_byte_limit_is_enforced(self):
        self.bag(files={'big':b'a'*10})
        with mock.patch.object(bagmod,'MAX_FILE',9):
            with self.assertRaises(BagError) as caught:
                import_bag(self.p/'bag',self.output)
        self.assertIn('data/big: file exceeds 8 MB limit',str(caught.exception))
        self.assertEqual(self.output.read_bytes(),self.old)

    def test_tag_file_byte_limit_is_enforced(self):
        self.bag()
        with mock.patch.object(bagmod,'MAX_TAG_FILE',100):
            self.assert_limit(['manifest-sha256.txt: file exceeds 8 MB limit'])

    def test_manifest_entry_limit_is_enforced(self):
        self.bag(files={'a.txt':b'a','b.txt':b'b'})
        with mock.patch.object(bagmod,'MAX_PAYLOAD_ENTRIES',1):
            self.assert_limit(['entry limit (1)','manifest-sha256.txt:2:'])

    def test_tag_entry_limit_is_enforced(self):
        self.bag()
        with mock.patch.object(bagmod,'MAX_TAG_ENTRIES',2):
            self.assert_limit(['tagmanifest-sha256.txt:3:','entry limit (2)'])
