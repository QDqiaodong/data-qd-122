import unittest,subprocess,sys,tempfile,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class OutputProtectionTests(unittest.TestCase):
    def test_report_cannot_change_payload(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);shutil.copytree(ROOT/'fixtures',p/'fixtures');source=p/'fixtures/input.json';out=p/'fixtures/payload/unlisted.txt'
            before=out.read_bytes();r=subprocess.run([sys.executable,'-m','archive_fixity.cli','--source',str(source),'--output',str(out)],capture_output=True)
            self.assertEqual(r.returncode,2);self.assertEqual(out.read_bytes(),before)
if __name__=='__main__':unittest.main()
