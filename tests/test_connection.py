"""Transport selection and native configuration transactions, without a real firewall."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import fail2ban_connection as connection

class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.env=patch.dict(os.environ,{'FCP_CONNECTION_FILE':self.tmp.name+'/connection.json'})
        self.env.start();self.addCleanup(self.env.stop)

    def native(self):
        s=connection.defaults();s.update(mode='native',config_dir=self.tmp.name+'/config',socket=self.tmp.name+'/service.sock',log_path=self.tmp.name+'/service.log');return s

    def test_native_client_uses_socket_without_docker_or_sudo(self):
        s=self.native()
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'pong','')) as run:
            connection.client('ping',settings=s)
        self.assertEqual(run.call_args.args[0],['fail2ban-client','-c',s['config_dir'],'-s',s['socket'],'ping'])

    def test_invalid_inputs_never_execute(self):
        for change in ({'mode':'ssh'},{'container':'name;id'},{'config_dir':'/etc/../root'},{'socket':'relative'},{'read_only':'false'}):
            s=self.native();s.update(change)
            with patch('subprocess.run') as run:
                with self.assertRaises(ValueError):connection.test(s)
                run.assert_not_called()

    def test_failed_save_preserves_previous_settings(self):
        current=connection.read();s=self.native()
        with patch.object(connection,'test',return_value={'reachable':False}):
            with self.assertRaises(ValueError):connection.save(s,current['revision'])
        self.assertEqual(current,connection.read())

    def test_save_retests_persists_and_rejects_stale_revision(self):
        current=connection.read();s=self.native()
        with patch.object(connection,'test',return_value={'reachable':True,'level':'administration'}) as test:
            connection.save(s,current['revision']);test.assert_called_once_with(s)
        self.assertEqual(connection.read()['settings'],s)
        self.assertEqual(connection.settings_path().stat().st_mode & 0o777,0o600)
        with self.assertRaises(ValueError):connection.save(s,current['revision'])

    def test_readonly_requires_explicit_selection_and_blocks_writes(self):
        current=connection.read();s=self.native()
        with patch.object(connection,'test',return_value={'reachable':True,'level':'readonly'}):
            with self.assertRaises(ValueError):connection.save(s,current['revision'])
            s['read_only']=True;connection.save(s,current['revision'])
        with self.assertRaises(ValueError):connection.require_write()

    def test_native_journal_is_bounded_and_uses_fixed_unit(self):
        s=self.native();s['log_source']='journal'
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'event','')) as run:
            self.assertEqual(connection.logs(lines=20,since='24h',settings=s),'event')
        argv=run.call_args.args[0];self.assertIn('fail2ban.service',argv);self.assertIn('20',argv);self.assertIn('24 hours ago',argv)

    def test_missing_logs_are_reported_without_claiming_full_visibility(self):
        s=self.native()
        def command(args,**kwargs):
            out=json.dumps({'config_readable':True,'config_writable':True}) if args[0]=='python3' else ('pong' if args[-1]=='ping' else 'Status')
            return subprocess.CompletedProcess(args,0,out,'')
        with patch.object(connection,'command',side_effect=command):result=connection.test(s)
        self.assertTrue(result['reachable']);self.assertFalse(result['logs_readable'])
        self.assertTrue(any('Journaux indisponibles' in x for x in result['checks']))

    def test_application_connection_form_auth_csrf_and_failed_save(self):
        import re
        from flask import Flask
        from security import install_auth
        env={'FCP_AUTH_DATABASE':self.tmp.name+'/auth.sqlite3','FCP_ADMIN_PASSWORD':'connection-test-password-long-enough','FCP_ALLOW_HTTP':'0','FCP_PUBLIC_URL':'','FCP_ALLOWED_NETWORKS':''}
        with patch.dict(os.environ,env):
            app=Flask('connection-routes');install_auth(app);client=app.test_client()
            def get(path):return client.get(path,base_url='https://localhost')
            def post(data):return client.post('/application',base_url='https://localhost',data=data)
            self.assertEqual(get('/application').status_code,303)
            token=re.search(r'name="csrf" value="([^"]+)"',get('/login').get_data(as_text=True)).group(1)
            login=client.post('/login',base_url='https://localhost',data={'csrf':token,'username':'admin','password':env['FCP_ADMIN_PASSWORD']});self.assertEqual(login.status_code,303)
            page=get('/application').get_data(as_text=True);self.assertIn('Connexion à Fail2ban',page)
            token=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
            data={'action':'connection_save','revision':connection.read()['revision'],'connection_access':'administration'}
            data.update({'connection_'+k:v for k,v in self.native().items() if k!='read_only'})
            self.assertEqual(post(data).status_code,403)
            data['csrf']=token
            with patch.object(connection,'test',return_value={'reachable':False}):self.assertEqual(post(data).status_code,400)
            self.assertFalse(connection.settings_path().exists())
            self.assertEqual(client.post('/application',base_url='https://localhost',data=data,headers={'Origin':'https://evil.example'}).status_code,403)

    def test_native_file_transactions_preserve_metadata_and_rollback(self):
        root=Path(self.tmp.name)/'config';root.mkdir()
        for d in ('jail.d','filter.d','action.d'):(root/d).mkdir()
        path=root/'jail.d'/'test.local';original=b'[test]\nenabled = true\nmaxretry = 2\n';path.write_bytes(original);path.chmod(0o640)
        bindir=Path(self.tmp.name)/'bin';bindir.mkdir();client=bindir/'fail2ban-client'
        marker=Path(self.tmp.name)/'fail-next-reload'
        client.write_text('#!'+sys.executable+'\nimport pathlib,sys\np=pathlib.Path('+repr(str(marker))+')\nif sys.argv[-1]=="reload" and p.exists():\n p.unlink();sys.exit(1)\nprint("OK")\n');client.chmod(0o755)
        tool=Path(__file__).resolve().parents[1]/'src/native_config_tool.py'
        def run(op,content,checksum):
            q={'op':op,'kind':'jail','name':'test.local','content':content,'hash':checksum,'_config_dir':str(root),'_backup_dir':self.tmp.name+'/backups','_socket':self.tmp.name+'/test.sock'}
            result=subprocess.run([sys.executable,str(tool)],input=json.dumps(q),text=True,capture_output=True,env={**os.environ,'PATH':str(bindir)+os.pathsep+os.environ['PATH']})
            return result
        h=hashlib.sha256(original).hexdigest();changed=original.decode().replace('maxretry = 2','maxretry = 3')
        response=run('validate',changed,h);self.assertTrue(json.loads(response.stdout)['ok']);self.assertEqual(path.read_bytes(),original)
        marker.touch();response=run('save',changed,h);data=json.loads(response.stdout)
        self.assertFalse(data['ok']);self.assertTrue(data['rollback_ok']);self.assertEqual(path.read_bytes(),original)
        response=run('save',changed,h);self.assertTrue(json.loads(response.stdout)['ok']);self.assertEqual(path.read_text(),changed);self.assertEqual(path.stat().st_mode & 0o777,0o640)
        response=run('save',original.decode(),h);self.assertNotEqual(response.returncode,0);self.assertEqual(path.read_text(),changed)
        manifests=list((Path(self.tmp.name)/'backups').glob('*/manifest.json'));self.assertEqual(len(manifests),2)
        for m in manifests:self.assertEqual(json.loads(m.read_text())['sha256'],h)

if __name__=='__main__':unittest.main()
