"""Offline tests: no Docker socket, mail, RDAP or AbuseIPDB connection."""
import ast
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
SANDBOX = tempfile.TemporaryDirectory()
os.environ.update(FCP_ADMIN_PASSWORD='test-password-longer-than-twenty',
    FCP_AUTOMATION_FILE=SANDBOX.name+'/data/automation.json',
    FCP_CONFIG=SANDBOX.name+'/config.json', FCP_FAIL2BAN_CONTAINER='isolated-f2b',
    FCP_DATABASE=SANDBOX.name+'/data/history.sqlite3', FCP_ABUSE_SETTINGS=SANDBOX.name+'/data/auxiliary.sqlite3', FCP_HTTP_LOG=SANDBOX.name+'/missing-access.log')
Path(os.environ['FCP_CONFIG']).write_text(json.dumps({'container':'isolated-f2b',
    'output':SANDBOX.name+'/state','ssh_port':2200,'ssh_log':'/custom/ssh.log',
    'ssh_jails':['custom-ssh'],'sftp_container':'','http_enabled':False}))
import runtime
import ui


def load_script(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'automation'/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class PortabilityTests(unittest.TestCase):
    def setUp(self):
        self.client=ui.app.test_client()
        self.auth={'Authorization':'Basic '+base64.b64encode(b'admin:test-password-longer-than-twenty').decode()}

    def test_all_routes_require_auth(self):
        for route in ('/','/manage','/geo/status','/http/history','/admin/api'):
            response=self.client.get(route) if route!='/admin/api' else self.client.post(route,json={'op':'overview'})
            self.assertEqual(response.status_code,401,route)
        self.assertEqual(self.client.get('/geo/status',headers=self.auth).status_code,200)
        self.assertEqual(self.client.get('/manage',headers=self.auth).status_code,200)

    def test_password_required(self):
        from flask import Flask
        from security import install_auth
        with patch.dict(os.environ,{'FCP_ADMIN_PASSWORD':''}):
            with self.assertRaises(RuntimeError): install_auth(Flask('missing-secret'))

    def test_default_disabled_and_preserved(self):
        raw=runtime.settings_path().read_bytes();settings=json.loads(raw)
        self.assertFalse(settings['email_enabled']);self.assertFalse(settings['report_enabled']);self.assertFalse(settings['abuseipdb_enabled'])
        runtime.ensure_settings();self.assertEqual(raw,runtime.settings_path().read_bytes())
        self.assertEqual(runtime.settings_path().stat().st_mode & 0o777,0o600)

    def test_admin_csrf_and_origin(self):
        self.assertEqual(self.client.post('/admin/api',headers=self.auth,json={'op':'overview'}).status_code,403)
        headers={**self.auth,'X-Fail2ban-Token':ui.admin_token,'Origin':'https://untrusted.example'}
        self.assertEqual(self.client.post('/admin/api',headers=headers,json={'op':'overview'}).status_code,403)

    def test_automation_validation_and_stale_revision(self):
        original=runtime.settings_path().read_bytes()
        try:
            current=ui.automation_read()
            values=dict(current['settings'])
            self.assertNotIn('jails',values)
            saved=ui.automation_save({'revision':current['revision'],'settings':values})
            self.assertFalse(saved['settings']['email_enabled'])
            with self.assertRaises(ValueError):
                ui.automation_save({'revision':'stale','settings':values})
            values['email_enabled']=True
            with self.assertRaises(ValueError):
                ui.automation_save({'revision':saved['revision'],'settings':values})
            self.assertEqual(runtime.settings_path().stat().st_mode&0o777,0o600)
        finally:
            runtime.settings_path().write_bytes(original)

    def test_configured_container_no_jails(self):
        commands=[]
        def docker(args,**kwargs):
            commands.append(args)
            output='Status\n|- Number of jail: 0\n`- Jail list: \n' if 'status' in args else 'Server replied: pong\n'
            if 'date' in args:output='2026-10-10T12:00:00+0000\n'
            if 'logs' in args:output=''
            return subprocess.CompletedProcess(args,0,output,'')
        with patch('subprocess.run',side_effect=docker):
            html=ui.dashboard.__wrapped__()
        self.assertIn('Map Monde',html)
        self.assertTrue(commands)
        for args in commands:
            if args[0]=='docker':self.assertIn('isolated-f2b',args)

    def test_ssh_evidence_without_http_or_sftp(self):
        collector=load_script('fail2ban-abuse.py');now=time.time()
        log=dt.datetime.fromtimestamp(now-10,dt.timezone.utc).isoformat()+' server sshd: Failed password for invalid user PRIVATE from 8.8.8.8 port 44444 ssh2\n'
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,log,'')) as run:
            evidence=collector.collect_evidence('8.8.8.8',now)
        self.assertEqual(run.call_count,1)
        self.assertIn('isolated-f2b',run.call_args.args[0]);self.assertIn('/custom/ssh.log',run.call_args.args[0])
        self.assertEqual(evidence['strong_count'],1);self.assertEqual(evidence['ssh'][0]['port'],2200)
        self.assertFalse(evidence['http_summary']['available'])
        text=collector.evidence_text('8.8.8.8',evidence)
        self.assertIn('TCP 2200',text);self.assertNotIn('PRIVATE',text);self.assertNotIn('2222',text)
        cfg=runtime.load_config();cfg.update(sender='sender@example.org',recipient='reply@example.org')
        record={'bans':{'one':{'time':now-30,'jails':['custom-ssh']}},'found':1,'detections':[]}
        msg=collector.message(cfg,'8.8.8.8',record,['abuse@example.net'],now,evidence)
        attachment=list(msg.iter_attachments())[0].get_payload(decode=True)
        self.assertIn(hashlib.sha256(attachment).hexdigest(),msg.get_body(preferencelist=('plain',)).get_content())
        self.assertIn('@localhost>',msg['Message-ID'])

    def test_duplicates_and_uncertain_blocked(self):
        collector=load_script('fail2ban-abuse.py');now=time.time()
        record={'bans':{'one':{'time':now-30,'jails':['custom-ssh']},'two':{'time':now-10,'jails':['custom-ssh']}}}
        for status in ('submitting','uncertain'):
            self.assertFalse(collector.eligible(record,{'status':status},now))
        self.assertFalse(collector.eligible(record,{'status':'submitted','submitted_at':now-10,'last_episode':now-100},now))

    def test_custom_abuseipdb_jail(self):
        worker=load_script('fail2ban-abuseipdb.py');now=time.time()
        record={'bans':{str(i):{'time':now-i,'jails':['custom-ssh']} for i in (10,20)}}
        verified=worker.qualified(record,[])
        self.assertIsNotNone(verified);self.assertEqual(worker.payload('8.8.8.8',verified)['categories'],'18')
        web={'bans':{str(i):{'time':now-i,'jails':['npmplus']} for i in (10,20)}}
        self.assertIsNone(worker.qualified(web,[]))

    def test_http_privacy_and_exact_source(self):
        collector=load_script('fail2ban-abuse.py');tree=ast.parse((ROOT/'automation/fail2ban-abuse.py').read_text())
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='collect_evidence')
        query=ast.literal_eval(next(n.value for n in function.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='query' for t in n.targets)))
        with tempfile.TemporaryDirectory() as tmp:
            dbpath=Path(tmp)/'sample.sqlite3';db=sqlite3.connect(dbpath)
            db.execute('CREATE TABLE requests(occurred_at REAL,method TEXT,path TEXT,status INTEGER,ip TEXT)');now=time.time()
            db.executemany('INSERT INTO requests VALUES(?,?,?,?,?)',[(now-20,'GET','/.env?secret=PRIVATE',404,'8.8.8.8'),(now-10,'GET','/private?token=PRIVATE',403,'8.8.8.8'),(now-30,'GET','/.env',200,'1.1.1.1')]);db.commit();db.close()
            query=query.replace('/app/data/fcp.sqlite3',str(dbpath))
            result=subprocess.run([sys.executable,'-c',query,json.dumps(['8.8.8.8',now,['/.env'],24])],capture_output=True,text=True,check=True)
            data=json.loads(result.stdout);self.assertEqual(data['total'],2);self.assertEqual(data['scan_count'],1)
            self.assertNotIn('PRIVATE',result.stdout);self.assertNotIn('/private',result.stdout)

    def test_installer_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            script=Path(tmp)/'install.py';script.write_bytes((ROOT/'install.py').read_bytes())
            subprocess.run([sys.executable,str(script)],check=True,capture_output=True)
            original=(Path(tmp)/'.env').read_bytes()
            subprocess.run([sys.executable,str(script)],check=True,capture_output=True)
            self.assertEqual(original,(Path(tmp)/'.env').read_bytes())
            self.assertEqual((Path(tmp)/'.env').stat().st_mode&0o777,0o600)


if __name__=='__main__':unittest.main()
