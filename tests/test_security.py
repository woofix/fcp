"""Authentication invariants tested against an isolated database, without Docker."""
import os
import re
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from flask import Flask
from security import install_auth, digest

PASSWORD='test-password-longer-than-twenty'

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.env=patch.dict(os.environ,{'FCP_AUTH_DATABASE':self.tmp.name+'/auth.sqlite3','FCP_ADMIN_PASSWORD':PASSWORD,'FCP_PUBLIC_URL':'','FCP_ALLOWED_NETWORKS':'','FCP_ALLOW_HTTP':'0'})
        self.env.start()
        self.app=self.make_app();self.client=self.app.test_client()
    def tearDown(self):
        self.env.stop();self.tmp.cleanup()
    def make_app(self):
        app=Flask(__name__);install_auth(app)
        app.add_url_rule('/',view_func=lambda:'private')
        return app
    def get(self,path,client=None,**kwargs):
        return (client or self.client).get(path,base_url='https://localhost',**kwargs)
    def post(self,path,data,client=None,**kwargs):
        return (client or self.client).post(path,data=data,base_url='https://localhost',**kwargs)
    def csrf(self,path='/login',client=None):
        return re.search(r'name="csrf" value="([^"]+)"',self.get(path,client).get_data(as_text=True)).group(1)
    def login(self,client=None,otp='',password=PASSWORD):
        return self.post('/login',{'csrf':self.csrf(client=client),'username':'admin','password':password,'otp':otp},client)
    def db(self):
        return sqlite3.connect(self.tmp.name+'/auth.sqlite3')
    def test_basic_rejected_and_https_required(self):
        self.assertEqual(self.get('/',headers={'Authorization':'Basic YWRtaW46cGFzc3dvcmQ='}).status_code,303)
        self.assertEqual(self.client.get('/login').status_code,403)
        self.assertEqual(self.client.post('/login',data={'password':PASSWORD}).status_code,403)
    def test_csrf_login_and_origin(self):
        self.get('/login')
        self.assertEqual(self.post('/login',{'username':'admin','password':PASSWORD}).status_code,403)
        self.assertEqual(self.post('/login',{'csrf':self.csrf(),'username':'admin','password':PASSWORD},headers={'Origin':'https://evil.example'}).status_code,403)
    def test_session_cookie_rotation_and_server_storage(self):
        pre=self.get('/login').headers['Set-Cookie']
        response=self.login();cookie=response.headers['Set-Cookie']
        for attribute in ('Secure','HttpOnly','SameSite=Lax','Path=/'): self.assertIn(attribute,cookie)
        self.assertNotEqual(pre.split(';')[0],cookie.split(';')[0])
        self.assertEqual(self.get('/').status_code,200)
        with self.db() as db:
            stored=db.execute('SELECT password FROM administrator').fetchone()[0]
            self.assertTrue(stored.startswith('$argon2id$'));self.assertNotIn(PASSWORD,stored)
            token=cookie.split(';')[0].split('=',1)[1]
            self.assertEqual(db.execute('SELECT token FROM sessions WHERE authenticated=1').fetchone()[0],digest(token))
        self.assertEqual(os.stat(self.tmp.name+'/auth.sqlite3').st_mode&0o777,0o600)
    def test_logout_invalidates_session_and_requires_csrf(self):
        self.login()
        self.assertEqual(self.post('/logout',{}).status_code,403)
        self.assertEqual(self.post('/logout',{'csrf':self.csrf('/application')}).status_code,303)
        self.assertEqual(self.get('/').status_code,303)
    def test_idle_and_absolute_expiry(self):
        for column,age in (('touched',1801),('created',28801)):
            self.login()
            with self.db() as db: db.execute('UPDATE sessions SET '+column+'=?',(time.time()-age,))
            self.assertEqual(self.get('/').status_code,303)
    def test_password_rotation_revokes_all_and_survives_restart(self):
        other=self.app.test_client();self.login();self.login(other)
        changed=PASSWORD+'-changed'
        self.assertEqual(self.post('/application',{'csrf':self.csrf('/application'),'action':'password','current':PASSWORD,'password':changed,'confirmation':changed}).status_code,303)
        self.assertEqual(self.get('/',other).status_code,303)
        self.assertEqual(self.login().status_code,200)
        restarted=self.make_app().test_client()
        self.assertEqual(self.login(restarted,password=changed).status_code,303)
    def test_rate_limit_persists_restart(self):
        for _ in range(5):self.assertEqual(self.login(password='bad').status_code,200)
        self.assertEqual(self.login().status_code,429)
        self.assertEqual(self.login(self.make_app().test_client()).status_code,429)
    def test_revoke_other_sessions(self):
        other=self.app.test_client();self.login();self.login(other)
        self.post('/application',{'csrf':self.csrf('/application'),'action':'revoke'})
        self.assertEqual(self.get('/',other).status_code,303);self.assertEqual(self.get('/').status_code,200)
    def test_network_restriction(self):
        with patch.dict(os.environ,{'FCP_ALLOWED_NETWORKS':'192.168.1.0/24'}):app=self.make_app()
        client=app.test_client()
        self.assertEqual(self.get('/login',client).status_code,403)
        self.assertEqual(self.get('/login',client,environ_overrides={'REMOTE_ADDR':'192.168.1.42'}).status_code,200)
    def test_local_http_requires_explicit_opt_in(self):
        with patch.dict(os.environ,{'FCP_ALLOW_HTTP':'1'}):app=self.make_app()
        response=app.test_client().get('/login')
        self.assertEqual(response.status_code,200)
        self.assertIn('HttpOnly',response.headers['Set-Cookie'])
        self.assertNotIn('Secure;',response.headers['Set-Cookie'])
    def test_malformed_unicode_inputs_fail_cleanly(self):
        self.assertEqual(self.post('/login',{'csrf':'é','username':'admin','password':PASSWORD}).status_code,403)
        self.assertEqual(self.post('/login',{'csrf':self.csrf(),'username':'é','password':PASSWORD}).status_code,200)
    def test_no_secret_in_audit(self):
        self.login(password='bad');self.login()
        with self.db() as db:events=str(db.execute('SELECT * FROM audit').fetchall())
        self.assertNotIn(PASSWORD,events);self.assertNotIn('bad',events)

if __name__=='__main__':unittest.main()
