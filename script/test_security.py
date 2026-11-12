"""Isolated security transaction tests: no host services or firewall commands run."""
import importlib.util, pathlib, tempfile, unittest, json, builtins, os, time
from unittest.mock import patch
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'Sources/CascadeCore/Resources/security.py'
spec=importlib.util.spec_from_file_location('security',SOURCE); s=importlib.util.module_from_spec(spec); spec.loader.exec_module(s)

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name)
        self.settings=self.root/'config'; self.settings.write_text('original')
        self.dir=self.root/'ufw'; self.dir.mkdir(); (self.dir/'user.rules').write_text('original v4'); (self.dir/'user6.rules').write_text('original v6')
        self.calls=[]; self.fail=None
        def run(args,check=True,timeout=35,input=None):
            self.calls.append(args)
            if self.fail and self.fail(args): raise RuntimeError('simulated failure')
            if args[:2]==['systemctl','is-active']: return 'active' if args[2]=='bp-cascade' else 'inactive'
            if args[:2]==['systemctl','is-enabled']: return 'disabled'
            if args[:2]==['ufw','status']:return 'Status: active'
            return ''
        original_open=builtins.open
        def safe_open(file,*args,**kwargs):
            if str(file)=='/run/lock/bp-cascade.lock':file=self.root/'deployment.lock'
            return original_open(file,*args,**kwargs)
        self.patches=[patch('builtins.open',safe_open),patch.object(s,'ROOT',self.root/'state'),patch.object(s,'MANAGED',[(str(self.settings),'file'),(str(self.dir),'dir'),(str(self.root/'absent'),'file')]),patch.object(s,'run',run),patch.object(s.shutil,'which',lambda x:'/usr/sbin/'+x)]
        for p in self.patches:p.start()
        s.ROOT.mkdir(mode=0o700)
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def test_snapshot_then_restore_file_directory_absent_and_mode(self):
        self.settings.chmod(0o640); tx='a'*32; s.snapshot(tx)
        self.settings.write_text('changed'); (self.dir/'user6.rules').write_text('changed'); (self.root/'absent').write_text('new')
        s.restore(tx)
        self.assertEqual(self.settings.read_text(),'original'); self.assertEqual((self.dir/'user6.rules').read_text(),'original v6'); self.assertFalse((self.root/'absent').exists()); self.assertEqual(self.settings.stat().st_mode&0o777,0o640)
        self.assertFalse((s.ROOT/'pending').exists()); self.assertIn(['ufw','--force','enable'],self.calls)
    def test_timer_is_armed_with_persistent_controller_and_request(self):
        d=s.snapshot('b'*32); cmd=next(x for x in self.calls if x[0]=='systemd-run')
        self.assertIn('--on-active=240s',cmd); self.assertEqual(pathlib.Path(cmd[-2]).read_bytes(),SOURCE.read_bytes()); self.assertEqual(json.loads(pathlib.Path(cmd[-1]).read_text())['action'],'rollback'); self.assertEqual(d.stat().st_mode&0o777,0o700)
    def test_timer_failure_leaves_no_pending_or_changes(self):
        self.fail=lambda args:args[0]=='systemd-run'
        with self.assertRaises(RuntimeError):s.snapshot('c'*32)
        self.assertFalse((s.ROOT/'pending').exists()); self.assertEqual(self.settings.read_text(),'original')
    def test_restore_without_finish_preserves_new_timer(self):
        s.snapshot('d'*32); self.settings.write_text('committed'); (s.ROOT/'pending').unlink(); s.snapshot('e'*32)
        s.restore('d'*32,finish=False)
        self.assertEqual(self.settings.read_text(),'original'); self.assertEqual((s.ROOT/'pending').read_text(),'e'*32)
        s.restore('e'*32); self.assertEqual(self.settings.read_text(),'committed')
    def test_invalid_requests(self):
        base=dict(role='entry',sshPort=22,user='admin',client='2001:db8::1',sources=['203.0.113.5'])
        for changes in [dict(sshPort=0),dict(user='a; id'),dict(client='$(id)'),dict(sources=['::/0']),dict(tx='../bad'),dict(retry=0),dict(bantime=99999999)]:
            with self.subTest(changes=changes),self.assertRaises((ValueError,AssertionError)):s.validate(base|changes)
    def test_ipv6_canonicalization(self):
        q=s.validate(dict(role='exit',sshPort='2222',user='admin',client='2001:0db8::1',sources=['2001:db8::2']))
        self.assertEqual(q['client'],'2001:db8::1');self.assertEqual(q['sshPort'],2222)
    def test_firewall_exit_denies_both_families_then_prepends_peer(self):
        default=self.root/'default';default.write_text('IPV6=no\n')
        real=s.P
        with patch.object(s,'P',lambda x:default if x=='/etc/default/ufw' else real(x)),patch.object(s,'config',lambda:{'inbounds':[{'type':'naive','network':'udp'}]}):
            s.firewall(dict(role='exit',sshPort=2222,restrictExit=True,sources=['203.0.113.1','2001:db8::1']))
        self.assertEqual(default.read_text(),'IPV6=yes\n')
        guard=['ufw','insert','1','deny','proto','udp','from','any','to','any','port','443','comment','Cascade exit guard']
        peer=['ufw','insert','1','allow','proto','udp','from','2001:db8::1','to','any','port','443','comment','Cascade entry peer']
        self.assertLess(self.calls.index(guard),self.calls.index(peer));self.assertIn(['ufw','insert','1','allow','2222/tcp','comment','Cascade SSH'],self.calls)
        self.assertNotIn('reset',[v for cmd in self.calls for v in cmd])
    def test_root_password_hardening_requires_verified_admin_before_packages(self):
        q=dict(role='entry',user='root',noRoot=True,keyVerified=False)
        with patch.object(s,'config',lambda:{}),patch.object(s,'supported',lambda:'ubuntu'),patch.object(s,'P') as paths:
            paths.return_value.read_text.return_value='entry'
            with self.assertRaises(RuntimeError):s.apply(q)
        self.assertFalse(any(x[0]=='apt-get' for x in self.calls))
    def test_failed_configuration_rolls_back(self):
        q=dict(role='entry',user='admin',tx='f'*32,firewall=True)
        real=s.P
        with patch.object(s,'config',lambda:{}),patch.object(s,'supported',lambda:'ubuntu'),patch.object(s,'install',lambda p:None),patch.object(s,'firewall',side_effect=RuntimeError('invalid')),patch.object(s,'P',lambda x:self.root/'role' if x=='/etc/bp-cascade/role' else real(x)):
            (self.root/'role').write_text('entry')
            with self.assertRaises(RuntimeError):s.apply(q)
        self.assertFalse((s.ROOT/'pending').exists()); self.assertEqual((s.ROOT/('f'*32)/'result').read_text(),'ROLLED_BACK')
    def test_existing_admin_never_gets_sudo_implicitly(self):
        with patch.object(s.pwd,'getpwnam',lambda u:object()):
            with self.assertRaises(RuntimeError):s.key_setup(dict(admin='existing',publicKey='ssh-ed25519 AAAA'))
        self.assertEqual(self.calls,[])
    def test_bad_key_and_root_rejected(self):
        for user,pub in [('root','ssh-ed25519 AAAA'),('admin','ssh-ed25519 AAAA\ncommand=id'),('admin','ssh-rsa AAAA')]:
            with self.assertRaises(ValueError):s.key_setup(dict(admin=user,publicKey=pub))
    def test_commit_cancels_timer_only_before_deadline(self):
        tx='2'*32; s.snapshot(tx)
        state=s.ROOT/tx/'state.json'; os.utime(state,(time.time()-230,time.time()-230))
        with self.assertRaises(RuntimeError):s.main(dict(action='commit',tx=tx))
        self.assertTrue((s.ROOT/'pending').exists()); self.assertNotIn(['systemctl','stop','bp-security-'+tx+'.timer'],self.calls)
        os.utime(state,None); s.main(dict(action='commit',tx=tx))
        self.assertFalse((s.ROOT/'pending').exists()); self.assertEqual((s.ROOT/'latest').read_text(),tx)
        with self.assertRaises(RuntimeError):s.main(dict(action='rollback',tx=tx))
        self.assertEqual((s.ROOT/tx/'result').read_text(),'COMMITTED')
    def test_manual_restore_has_its_own_timer_and_can_be_reversed(self):
        old='3'*32; new='4'*32; s.snapshot(old); s.main(dict(action='commit',tx=old))
        self.settings.write_text('healthy current')
        result=s.main(dict(action='restore',tx=new))
        self.assertEqual(result['pending'],new); self.assertEqual(self.settings.read_text(),'original')
        s.main(dict(action='rollback',tx=new)); self.assertEqual(self.settings.read_text(),'healthy current')
    def test_pending_transaction_rejects_second_apply(self):
        tx='5'*32;s.snapshot(tx)
        with patch.object(s,'config',lambda:{}),patch.object(s,'supported',lambda:'ubuntu'),patch.object(s,'P') as paths:
            paths.return_value.read_text.return_value='entry'
            with self.assertRaises(RuntimeError):s.apply(dict(role='entry',user='admin',tx='6'*32))
        self.assertEqual((s.ROOT/'pending').read_text(),tx)
    def test_snapshot_refuses_symlink(self):
        self.settings.unlink(); self.settings.symlink_to(self.root/'outside')
        (self.root/'outside').write_text('keep')
        with self.assertRaises(RuntimeError):s.snapshot('1'*32)
        self.assertEqual((self.root/'outside').read_text(),'keep')

if __name__=='__main__':unittest.main(verbosity=2)
