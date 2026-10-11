# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
"""Single-administrator authentication with persistent, revocable server sessions."""
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import urlsplit
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from flask import request, redirect, g, render_template_string, abort, jsonify
import fail2ban_connection as f2b
from navigation import NAVIGATION

COOKIE = '__Host-fcp'
HASHER = PasswordHasher()
ABSOLUTE = 8 * 3600
IDLE = 30 * 60
PRELOGIN = 10 * 60

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

PAGE = '''<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>FCP · {{ title }}</title>
<link rel="stylesheet" href="/static/theme.css"><link rel="stylesheet" href="/static/application.css?v=connection-form-2">
<body class="{% if login %}login-page{% else %}with-navigation{% endif %}">{% if not login %}__NAVIGATION__{% endif %}<header><h1>FCP · {{ title }}</h1>{% if not login %}<a href="/">← Tableau de bord</a>{% endif %}</header><main class="application-layout{% if login %} login-layout{% endif %}">{% if message %}<p class="message card app-wide" role="status">{{ message }}</p>{% endif %}
{% macro fields() %}<input type="hidden" name="csrf" value="{{ csrf }}">{% endmacro %}
{% if login %}<section class="card"><form method="post">{{ fields() }}<label>Identifiant<input name="username" autocomplete="username" required maxlength="100"></label><label>Mot de passe<input type="password" name="password" autocomplete="current-password" required maxlength="256"></label><button>Se connecter</button></form><p class="muted">Session : 30 minutes d’inactivité, 8 heures maximum.</p><p><a href="/language?lang=fr&next=/login">Français</a> · <a href="/language?lang=en&next=/login">English</a></p></section>
{% else %}<p class="card app-wide app-status">{{ transport }} · Mot de passe Argon2id · Sessions révocables</p>
<nav class="section-tabs app-wide" aria-label="Rubriques des réglages"><button type="button" data-setting="general">Général</button><button type="button" data-setting="connection">Connexion Fail2ban</button><button type="button" data-setting="security">Sécurité</button></nav><section class="card app-wide" data-settings-panel="general"><h2>Langue</h2><a href="/language?lang=fr&next=/application">Français</a> · <a href="/language?lang=en&next=/application">English</a></section>
<section class="card app-wide" id="fail2ban-connection" data-settings-panel="connection"><h2>Connexion à Fail2ban</h2>
<p>Connexion active : <strong>{{ 'Docker sur cette machine' if connection.mode == 'docker' else 'Installation Linux native' }}</strong>{% if connection.read_only %} · Consultation uniquement{% endif %}.</p>
<p>Choisis comment FCP accède à Fail2ban. Les règles et les bannissements existants sont conservés.</p>
<form method="post">{{ fields() }}<input type="hidden" name="revision" value="{{ connection_revision }}">
<div class="connection-grid"><label>Mode de connexion<select name="connection_mode" id="connection-mode"><option value="docker" {% if draft.mode=='docker' %}selected{% endif %}>Docker sur cette machine</option><option value="native" {% if draft.mode=='native' %}selected{% endif %}>Installation Linux native</option></select></label>
<label id="connection-container-label">Nom du conteneur<input name="connection_container" value="{{ draft.container }}" required maxlength="128"></label>
<label>Accès demandé<select name="connection_access"><option value="administration" {% if not draft.read_only %}selected{% endif %}>Administration</option><option value="readonly" {% if draft.read_only %}selected{% endif %}>Consultation uniquement</option></select></label></div>
<fieldset id="connection-native"><legend>Installation Linux native</legend><div class="connection-grid">
<label>Dossier de configuration<input name="connection_config_dir" value="{{ draft.config_dir }}" required></label>
<label>Socket Fail2ban<input name="connection_socket" value="{{ draft.socket }}" required></label>
<label>Source des journaux<select name="connection_log_source"><option value="file" {% if draft.log_source=='file' %}selected{% endif %}>Fichier journal</option><option value="journal" {% if draft.log_source=='journal' %}selected{% endif %}>Journal système</option></select></label>
<label>Fichier journal<input name="connection_log_path" value="{{ draft.log_path }}" required></label></div>
<p>Les chemins sont ceux accessibles depuis FCP. Si FCP tourne dans Docker, monte la configuration, le socket et les journaux de l’hôte dans son conteneur. Le client Fail2ban doit être installé dans l’environnement FCP et compatible avec le serveur.</p>
<p>Les droits du compte FCP sont utilisés, sans élévation automatique. La détection et le test ne modifient pas Fail2ban.</p></fieldset>
<div class="connection-actions"><button name="action" value="connection_detect">Détecter les chemins</button><button name="action" value="connection_test">Tester la connexion</button><button name="action" value="connection_save">Enregistrer la connexion</button></div></form>
{% if connection_result %}<div class="connection-result" role="status"><h3>{{ connection_result.output or 'Connexion impossible' }}</h3><ul>{% for check in connection_result.checks %}<li>{{ check }}</li>{% endfor %}</ul></div>{% endif %}
<p class="muted">L’enregistrement vérifie à nouveau la connexion. En cas d’échec, le mode actuel est conservé. Le démarrage et l’arrêt d’un service Linux natif se font sur son hôte lorsque FCP est conteneurisé. Les automatisations externes ont leur propre connexion et ne sont pas déplacées par ce formulaire.</p>
<script>function connectionFields(){const native=document.getElementById('connection-mode').value==='native';document.getElementById('connection-native').hidden=!native;document.getElementById('connection-container-label').hidden=native;}document.getElementById('connection-mode').addEventListener('change',connectionFields);connectionFields();</script>
</section>
<section class="card" data-settings-panel="security"><h2>Mot de passe</h2><form method="post">{{ fields() }}<input type="hidden" name="action" value="password"><label>Mot de passe actuel<input type="password" name="current" autocomplete="current-password" required maxlength="256"></label><label>Nouveau mot de passe (20 caractères minimum)<input type="password" name="password" autocomplete="new-password" required minlength="20" maxlength="256"></label><label>Confirmer le nouveau mot de passe<input type="password" name="confirmation" autocomplete="new-password" required maxlength="256"></label><button>Modifier le mot de passe</button></form><p>Toutes les sessions seront fermées.</p></section>
<section class="card" data-settings-panel="security"><h2>Sessions</h2><form method="post">{{ fields() }}<input type="hidden" name="action" value="revoke"><button>Fermer les autres sessions</button></form><form action="/logout" method="post">{{ fields() }}<button>Déconnexion</button></form></section>
<section class="card" data-settings-panel="security"><h2>Journal de sécurité</h2><table>{% for event in events %}<tr><td>{{ event[0] }}</td><td>{{ event[1] }}</td><td>{{ event[2] }}</td></tr>{% endfor %}</table></section>{% endif %}</main>{% if not login %}<script>
let settingTab=new URL(location.href).searchParams.get('tab')||sessionStorage.getItem('fcp-setting-tab')||'general';
{% if connection_result or draft != connection %}settingTab='connection';{% endif %}
function showSetting(name){if(!['general','connection','security'].includes(name))name='general';document.querySelectorAll('[data-settings-panel]').forEach(p=>p.hidden=p.dataset.settingsPanel!==name);document.querySelectorAll('[data-setting]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.setting===name)));sessionStorage.setItem('fcp-setting-tab',name);}
document.querySelectorAll('[data-setting]').forEach(b=>b.onclick=()=>showSetting(b.dataset.setting));showSetting(settingTab);document.querySelector('[data-main="settings"]').setAttribute('aria-current','page');
</script>{% endif %}</body></html>'''.replace('__NAVIGATION__',NAVIGATION)

def install_auth(app):
    path = Path(os.environ.get('FCP_AUTH_DATABASE', '/app/data/auth.sqlite3'))
    path.parent.mkdir(parents=True, exist_ok=True)
    def connect():
        db = sqlite3.connect(path, timeout=15)
        db.row_factory = sqlite3.Row
        return db
    with connect() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS administrator(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, csrf TEXT NOT NULL, authenticated INTEGER NOT NULL, created REAL NOT NULL, touched REAL NOT NULL, ip TEXT);
        CREATE TABLE IF NOT EXISTS failures(ip TEXT PRIMARY KEY, count INTEGER NOT NULL, started REAL NOT NULL, blocked REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(at REAL NOT NULL, event TEXT NOT NULL, ip TEXT NOT NULL);''')
        if not db.execute('SELECT 1 FROM administrator').fetchone():
            password = os.environ.get('FCP_ADMIN_PASSWORD', '')
            if not 20 <= len(password) <= 256:
                raise RuntimeError('An initial FCP_ADMIN_PASSWORD of 20–256 characters is required.')
            db.execute('INSERT INTO administrator(id,username,password) VALUES(1,?,?)', (os.environ.get('FCP_ADMIN_USER','admin'), HASHER.hash(password)))
        if 'totp' in [row[1] for row in db.execute('PRAGMA table_info(administrator)')]:
            db.execute('UPDATE administrator SET totp=NULL,pending=NULL,pending_until=0,counter=-1 WHERE id=1')
        db.execute('DROP TABLE IF EXISTS recovery')
    os.chmod(path, 0o600)
    app.extensions['fcp_auth_database'] = str(path)
    canonical = os.environ.get('FCP_PUBLIC_URL', '').rstrip('/')
    if canonical and (urlsplit(canonical).scheme != 'https' or urlsplit(canonical).path):
        raise RuntimeError('FCP_PUBLIC_URL must be an HTTPS origin.')
    allow_http = os.environ.get('FCP_ALLOW_HTTP') == '1'
    cookie_name = 'fcp_session' if allow_http else COOKIE
    allowed = os.environ.get('FCP_ALLOWED_NETWORKS', '')
    networks = [ipaddress.ip_network(x.strip()) for x in allowed.split(',') if x.strip()]

    def audit(db, event):
        db.execute('INSERT INTO audit VALUES(?,?,?)', (time.time(), event, request.remote_addr or 'unknown'))
        db.execute('DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY rowid DESC LIMIT 1000)')
    def new_session(db, authenticated=False):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = time.time()
        db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)', (digest(token), csrf, int(authenticated), now, now, request.remote_addr))
        g.new_cookie = token
        g.auth = {'token':digest(token), 'csrf':csrf, 'authenticated':int(authenticated), 'created':now}
        return g.auth
    def csrf_valid():
        return (g.auth and hmac.compare_digest(request.form.get('csrf','').encode(), g.auth['csrf'].encode())
                and (not request.headers.get('Origin') or request.headers['Origin'] == request.host_url.rstrip('/')))
    def password_ok(admin, password):
        if not password or len(password)>256: return False
        try: return HASHER.verify(admin['password'], password)
        except (VerificationError, InvalidHashError): return False
    def blocked(db):
        now=time.time()
        keys=(request.remote_addr or 'unknown','*')
        return any(db.execute('SELECT 1 FROM failures WHERE ip=? AND blocked>?', (key,now)).fetchone() for key in keys)
    def failure(db):
        now=time.time()
        for key,limit in ((request.remote_addr or 'unknown',5),('*',30)):
            row=db.execute('SELECT * FROM failures WHERE ip=?', (key,)).fetchone()
            count=row['count']+1 if row and now-row['started']<900 else 1
            started=row['started'] if row and now-row['started']<900 else now
            db.execute('INSERT OR REPLACE INTO failures VALUES(?,?,?,?)',(key,count,started,now+900 if count>=limit else 0))
        audit(db,'authentication_failed')

    @app.before_request
    def authenticate():
        # Health endpoint exposes no application data, and is loopback-only.
        if request.path=='/healthz':
            if request.remote_addr not in ('127.0.0.1','::1'): abort(404)
            return jsonify(status='ok')
        if networks:
            try: permitted=any(ipaddress.ip_address(request.remote_addr) in net for net in networks)
            except ValueError: permitted=False
            if not permitted: abort(403)
        if not request.is_secure and not allow_http:
            if canonical and request.method in ('GET','HEAD'): return redirect(canonical+'/login',308)
            abort(403)
        if canonical and request.host != urlsplit(canonical).netloc:
            abort(400)
        now=time.time()
        g.auth=None
        with connect() as db:
            token=request.cookies.get(cookie_name,'')
            row=db.execute('SELECT * FROM sessions WHERE token=?',(digest(token),)).fetchone() if token else None
            db.execute('DELETE FROM sessions WHERE created<? OR touched<? OR (authenticated=0 AND created<?)',(now-ABSOLUTE,now-IDLE,now-PRELOGIN))
            if row and now-row['created'] < (ABSOLUTE if row['authenticated'] else PRELOGIN) and now-row['touched']<IDLE:
                g.auth=dict(row)
                db.execute('UPDATE sessions SET touched=? WHERE token=?',(now,row['token']))
            if request.method not in ('GET','HEAD','OPTIONS') and request.headers.get('Origin') and request.headers['Origin'] != request.host_url.rstrip('/'):
                abort(403)
            if request.path in ('/static/theme.css','/static/application.css') and request.method in ('GET','HEAD'):
                return None
            if request.path in ('/login','/language'):
                if not g.auth: new_session(db)
                return None
            if g.auth and g.auth['authenticated']: return None
        if request.method not in ('GET','HEAD') or request.path.startswith(('/admin/','/geo/','/http/')):
            return jsonify(error='Authentication required'),401
        return redirect('/login',303)

    @app.route('/login',methods=['GET','POST'])
    def login():
        if g.auth['authenticated']: return redirect('/',303)
        message=''
        if request.method=='POST':
            if not csrf_valid(): abort(403)
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                if blocked(db):
                    response=app.make_response(render_page(login=True,message='Trop de tentatives. Réessaie dans 15 minutes.'))
                    response.status_code=429;response.headers['Retry-After']='900';return response
                admin=db.execute('SELECT * FROM administrator').fetchone()
                valid=password_ok(admin, request.form.get('password',''))
                valid=valid and hmac.compare_digest(request.form.get('username','').encode(),admin['username'].encode())
                if valid:
                    if HASHER.check_needs_rehash(admin['password']):
                        db.execute('UPDATE administrator SET password=? WHERE id=1',(HASHER.hash(request.form['password']),))
                    db.execute('DELETE FROM sessions WHERE token=?',(g.auth['token'],))
                    db.execute('DELETE FROM failures WHERE ip=?',(request.remote_addr or 'unknown',))
                    new_session(db,True);audit(db,'login_success');return redirect('/',303)
                failure(db)
            message='Identifiant ou mot de passe incorrect.'
        return render_page(login=True,message=message)

    def render_page(login=False,message='',connection_result=None,draft=None):
        with connect() as db:
            admin=db.execute('SELECT * FROM administrator').fetchone()
            events=[(time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime(r['at'])),r['event'],r['ip']) for r in db.execute('SELECT * FROM audit ORDER BY rowid DESC LIMIT 30')]
        connection=f2b.read() if not login else {'settings':f2b.defaults(),'revision':''}
        return render_template_string(PAGE,connection=connection['settings'],connection_revision=connection['revision'],draft=draft or connection['settings'],connection_result=connection_result,title='Connexion' if login else 'Réglages',login=login,message=message,csrf=g.auth['csrf'],transport='HTTP local : échanges non chiffrés' if allow_http else 'Connexion HTTPS',events=events)

    @app.route('/application',methods=['GET','POST'])
    def fcp_application():
        message=''
        if request.method=='POST':
            if not csrf_valid(): abort(403)
            action=request.form.get('action','')
            if action in ('connection_detect','connection_test','connection_save'):
                try:
                    settings={key:request.form.get('connection_'+key,'') for key in ('mode','container','config_dir','socket','log_source','log_path')}
                    settings['read_only']=request.form.get('connection_access')=='readonly'
                    settings=f2b.validate(settings)
                    if action=='connection_detect':
                        settings=f2b.detect(settings)
                        return render_page(message='Chemins détectés ou valeurs habituelles proposées. Teste la connexion avant d’enregistrer.',draft=settings)
                    if action=='connection_test':
                        result=f2b.test(settings)
                    else:
                        callback=app.extensions.get('fcp_connection_save')
                        result=callback(settings,request.form.get('revision','')) if callback else f2b.save(settings,request.form.get('revision',''))
                        with connect() as db: audit(db,'fail2ban_connection_changed')
                    return render_page(connection_result=result,draft=settings)
                except (ValueError,OSError) as error:
                    return render_page(message=str(error),draft=settings if isinstance(settings,dict) and set(settings)==f2b.FIELDS else None),400
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                admin=db.execute('SELECT * FROM administrator').fetchone()
                if action=='revoke':
                    db.execute('DELETE FROM sessions WHERE token!=?',(g.auth['token'],));audit(db,'sessions_revoked');message='Autres sessions fermées.'
                elif action=='password':
                    if blocked(db): return render_page(message='Trop de tentatives. Réessaie dans 15 minutes.'),429
                    if not password_ok(admin,request.form.get('current','')):
                        failure(db);message='Mot de passe actuel incorrect.'
                    else:
                        password=request.form.get('password','')
                        if not 20<=len(password)<=256 or password!=request.form.get('confirmation') or password_ok(admin,password):
                            message='Utilise un nouveau mot de passe de 20 à 256 caractères et deux saisies identiques.'
                        else:
                            db.execute('UPDATE administrator SET password=? WHERE id=1',(HASHER.hash(password),))
                            db.execute('DELETE FROM sessions');audit(db,'password_changed');g.clear_cookie=True;return redirect('/login',303)
                else: abort(400)
        return render_page(message=message)

    @app.post('/logout')
    def logout():
        if not csrf_valid(): abort(403)
        with connect() as db:
            db.execute('DELETE FROM sessions WHERE token=?',(g.auth['token'],));audit(db,'logout')
        g.clear_cookie=True
        return redirect('/login',303)

    @app.after_request
    def private_response(response):
        if getattr(g,'new_cookie',None):
            response.set_cookie(cookie_name,g.new_cookie,max_age=ABSOLUTE,secure=not allow_http,httponly=True,samesite='Lax',path='/')
        if getattr(g,'clear_cookie',False): response.delete_cookie(cookie_name,secure=not allow_http,httponly=True,samesite='Lax',path='/')
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'SAMEORIGIN','Referrer-Policy':'same-origin'})
        if request.is_secure: response.headers['Strict-Transport-Security']='max-age=31536000'
        return response
