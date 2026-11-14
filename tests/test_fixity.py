import json,unittest,tempfile,hashlib
from pathlib import Path
from archive_fixity.model import audit
from archive_fixity.files import relative
ROOT=Path(__file__).resolve().parents[1]
class FixityTests(unittest.TestCase):
    def setUp(self):self.d=json.loads((ROOT/'fixtures/input.json').read_text())
    def test_known_changes_and_unlisted_entry(self):
        r=audit(self.d,ROOT/'fixtures');self.assertEqual(r['status_counts'],{'mismatch':1,'missing':1,'verified':1})
        self.assertFalse(r['inventory_clean']);self.assertEqual(r['unlisted_entries'][0]['path'],'unlisted.txt')
        changed=next(f for f in r['files'] if f['path']=='changed.txt');self.assertEqual(changed['differences'],['digest_mismatch'])
    def test_missing_empty_and_symlink_are_distinct(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'payload').mkdir();(p/'payload/empty').write_bytes(b'');(p/'payload/link').symlink_to('/etc/passwd')
            d={'payload_root':'payload','entries':[{'path':f,'bytes':0,'sha256':hashlib.sha256(b'').hexdigest()} for f in ['empty','missing','link']]}
            r=audit(d,p);self.assertEqual([f['status'] for f in r['files']],['verified','unsafe_link','missing'])
    def test_root_symlink_and_unsafe_paths_rejected(self):
        for name in ['../a','/a','a//b','a/./b','a\\b']:
            with self.assertRaises(ValueError):relative(name)
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'alias').symlink_to(ROOT/'fixtures/payload')
            self.d['payload_root']='alias'
            with self.assertRaises(ValueError):audit(self.d,p)
    def test_duplicate_manifest_and_bad_digest_rejected(self):
        self.d['entries'].append(self.d['entries'][0])
        with self.assertRaises(ValueError):audit(self.d,ROOT/'fixtures')
        self.setUp();self.d['entries'][0]['sha256']='notsha'
        with self.assertRaises(ValueError):audit(self.d,ROOT/'fixtures')
    def test_non_directory_parent_is_reported(self):
        self.d['entries']=[{'path':'notes.txt/child','bytes':0,'sha256':hashlib.sha256(b'').hexdigest()}]
        self.assertEqual(audit(self.d,ROOT/'fixtures')['files'][0]['status'],'non_directory_parent')
    def test_verified_file_hash_and_read_bytes(self):
        r=audit(self.d,ROOT/'fixtures');f=next(f for f in r['files'] if f['path']=='notes.txt')
        raw=(ROOT/'fixtures/payload/notes.txt').read_bytes();self.assertEqual(f['actual_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(f['actual_bytes'],len(raw))
    def test_order_invariance(self):
        r=audit(self.d,ROOT/'fixtures');self.d['entries'].reverse();self.assertEqual(r,audit(self.d,ROOT/'fixtures'))
if __name__=='__main__':unittest.main()
