"""Synthetic fixtures only; never read a live agent deployment."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'audit_public.py'
class AuditTest(unittest.TestCase):
    def fixture(self):
        scratch=os.environ.get('TMPDIR') or os.environ.get('TEMP')
        t=tempfile.TemporaryDirectory(prefix='public-audit-test-',dir=scratch)
        self.addCleanup(t.cleanup);root=Path(t.name)
        (root/'README.md').write_text('# A safe draft\n',encoding='utf-8')
        (root/'upload-manifest.json').write_text(json.dumps({'files':['README.md','upload-manifest.json']}),encoding='utf-8')
        return root
    def run_audit(self,root):
        return subprocess.run([sys.executable,'-B',str(SCRIPT),'--root',str(root)],capture_output=True,text=True)
    def test_clean_bundle_succeeds(self):
        result=self.run_audit(self.fixture())
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['findings'],[])
    def test_unsafe_bundle_is_rejected_without_echoing_secret(self):
        cases={
            'address':'.'.join(['192','0','2','123']),
            'unc_path':chr(92)*2+'private-host'+chr(92)+'share',
            'absolute_path':chr(72)+':/'+'private/'+'notes',
            'tailnet': 'device.'+'private-zone.'+'ts' + '.net',
            'secret_url':'https://example.invalid/?'+'token='+'not-a-real-secret',
            'private_key':'-----BEGIN '+'PRIVATE KEY-----',
            'nul':'hello'+chr(0)+'hidden',
            'broken_link':'[missing](missing.md)',
        }
        for name,text in cases.items():
            with self.subTest(name=name):
                root=self.fixture();(root/'README.md').write_text(text,encoding='utf-8')
                result=self.run_audit(root)
                self.assertNotEqual(result.returncode,0)
                self.assertTrue(json.loads(result.stdout)['findings'])
                self.assertNotIn('not-a-real-secret',result.stdout)
        root=self.fixture();(root/'unexpected.log').write_text('private',encoding='utf-8')
        result=self.run_audit(root);self.assertNotEqual(result.returncode,0)
        self.assertTrue(json.loads(result.stdout)['findings'])
    def test_rule_definitions_are_not_private_paths(self):
        root=self.fixture()
        (root/'README.md').write_text('Generic scanner',encoding='utf-8')
        (root/'scanner.py').write_bytes(SCRIPT.read_bytes())
        (root/'upload-manifest.json').write_text(json.dumps({'files':['README.md','scanner.py','upload-manifest.json']}),encoding='utf-8')
        result=self.run_audit(root)
        self.assertEqual(result.returncode,0,result.stdout)
    def test_reviewed_mock_assets_are_allowed_but_tampering_fails(self):
        import hashlib
        root=self.fixture();(root/'examples/screenshots').mkdir(parents=True)
        (root/'examples/phone-ui.html').write_text('<!doctype html><title>Offline fictional example</title>',encoding='utf-8')
        image=b'\x89PNG\r\n\x1a\n'+b'synthetic fixture bytes'
        image_name='examples/screenshots/list.png';(root/image_name).write_bytes(image)
        payload={'files':['README.md','upload-manifest.json','examples/phone-ui.html',image_name],
                 'reviewed_images':{image_name:hashlib.sha256(image).hexdigest()}}
        (root/'upload-manifest.json').write_text(json.dumps(payload),encoding='utf-8')
        result=self.run_audit(root);self.assertEqual(result.returncode,0,result.stdout)
        (root/image_name).write_bytes(image+b'changed')
        result=self.run_audit(root);self.assertNotEqual(result.returncode,0)
        self.assertIn('image-hash-mismatch',result.stdout)
    def test_relative_document_links_stay_inside_manifest(self):
        root=self.fixture();(root/'docs').mkdir()
        (root/'docs/guide.md').write_text('[start](../README.md)',encoding='utf-8')
        (root/'upload-manifest.json').write_text(json.dumps({'files':['README.md','docs/guide.md','upload-manifest.json']}),encoding='utf-8')
        result=self.run_audit(root);self.assertEqual(result.returncode,0,result.stdout)
        (root/'docs/guide.md').write_text('[escape](../../outside.md)',encoding='utf-8')
        self.assertNotEqual(self.run_audit(root).returncode,0)
    def test_license_is_allowed_when_listed(self):
        root=self.fixture();(root/'LICENSE').write_text('MIT License\nCopyright project contributors\n',encoding='utf-8')
        (root/'upload-manifest.json').write_text(json.dumps({'files':['README.md','LICENSE','upload-manifest.json']}),encoding='utf-8')
        result=self.run_audit(root);self.assertEqual(result.returncode,0,result.stdout)
    def test_bad_manifest_fails_closed(self):
        for payload in ['not JSON',json.dumps({'files':['../outside.md']}),json.dumps({'files':['README.md','README.md']})]:
            with self.subTest(payload=payload):
                root=self.fixture();(root/'upload-manifest.json').write_text(payload,encoding='utf-8')
                result=self.run_audit(root)
                self.assertNotEqual(result.returncode,0)
                self.assertTrue(json.loads(result.stdout)['findings'])
if __name__=='__main__':unittest.main(verbosity=2)
