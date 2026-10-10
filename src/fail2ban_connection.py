# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
"""Fail2ban transports. Settings never contain a shell command or implicit sudo."""
import collections
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
from runtime import load_config

LOCK = threading.RLock()
FIELDS = {'mode', 'container', 'config_dir', 'socket', 'log_source', 'log_path', 'read_only'}

def settings_path():
    return Path(os.environ.get('FCP_CONNECTION_FILE', '/app/data/connection.json'))

def defaults():
    return dict(mode='docker', container=load_config()['container'], config_dir='/etc/fail2ban',
                socket='/var/run/fail2ban/fail2ban.sock', log_source='file',
                log_path='/var/log/fail2ban.log', read_only=False)

def read():
    path = settings_path()
    raw = path.read_bytes() if path.exists() else b''
    settings = defaults()
    if raw:
        settings.update(json.loads(raw))
    return {'settings': validate(settings), 'revision': hashlib.sha256(raw).hexdigest()}

def validate(settings):
    if not isinstance(settings, dict) or set(settings) != FIELDS:
        raise ValueError('Réglages de connexion incomplets ou inconnus.')
    if settings['mode'] not in ('docker', 'native') or settings['log_source'] not in ('file', 'journal') or type(settings['read_only']) is not bool:
        raise ValueError('Mode de connexion invalide.')
    if not isinstance(settings['container'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', settings['container']):
        raise ValueError('Nom de conteneur invalide.')
    for key in ('config_dir', 'socket', 'log_path'):
        value = settings[key]
        if not isinstance(value, str) or len(value) > 1024 or not value.startswith('/') or any(c in value for c in ('\x00','\n','\r')) or '..' in Path(value).parts:
            raise ValueError('Chemin absolu invalide : '+key)
    return dict(settings)

def command(arguments, settings=None, input=None, timeout=35, check=True):
    s = validate(settings) if settings is not None else read()['settings']
    args = list(arguments)
    if s['mode'] == 'docker':
        argv = ['docker', 'exec'] + (['-i'] if input is not None else []) + [s['container'], *args]
    else:
        argv = args
        if argv[0] == 'fail2ban-client':
            argv = [argv[0], '-c', s['config_dir'], '-s', s['socket'], *argv[1:]]
        elif argv[0] == 'python3':
            argv[0] = sys.executable
    result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise ValueError((result.stderr+'\n'+result.stdout)[-12000:] or 'Fail2ban ne répond pas.')
    return result

def client(*args, settings=None, timeout=35):
    return command(['fail2ban-client', *args], settings=settings, timeout=timeout).stdout

def logs(lines=5000, since=None, settings=None):
    s = validate(settings) if settings is not None else read()['settings']
    lines = max(1, min(int(lines), 100000))
    if s['mode'] == 'docker':
        argv = ['docker','logs','--tail',str(lines)]
        if since: argv += ['--since',str(since)]
        result = subprocess.run([*argv, s['container']], capture_output=True,text=True,timeout=30)
        if result.returncode: raise ValueError(result.stderr[-12000:])
        return result.stdout+'\n'+result.stderr
    if s['log_source'] == 'journal':
        argv = ['journalctl','-u','fail2ban.service','--no-pager','--output=cat','-n',str(lines)]
        if since and re.fullmatch(r'\d+h', str(since)): argv += ['--since', str(since)[:-1]+' hours ago']
        result = subprocess.run(argv,capture_output=True,text=True,timeout=30)
        if result.returncode: raise ValueError(result.stderr[-12000:])
        # journalctl can succeed while hiding journals from an unprivileged account.
        if 'not seeing messages' in result.stderr or 'No journal files' in result.stderr:
            raise ValueError('Accès au journal système insuffisant.')
        return result.stdout
    with open(s['log_path'], 'rb') as handle:
        handle.seek(0, 2); length=handle.tell(); handle.seek(max(0,length-32*1024*1024))
        if length > 32*1024*1024: handle.readline()
        raw=b''.join(collections.deque(handle,maxlen=lines)).decode('utf-8','replace')
    if since and re.fullmatch(r'\d+h',str(since)):
        import datetime
        cutoff=(datetime.datetime.now()-datetime.timedelta(hours=int(str(since)[:-1]))).strftime('%Y-%m-%d %H:%M:%S')
        raw='\n'.join(line for line in raw.splitlines() if line[:19]>=cutoff)
    return raw

PROBE = r'''
import json,os,pathlib,sys
s=json.loads(sys.argv[1]); docker=s['mode']=='docker'; root=pathlib.Path('/etc/fail2ban' if docker else s['config_dir'])
files=root.is_dir() and (root/'fail2ban.conf').is_file() and (root/'jail.conf').is_file()
readable=files and all(os.access(p,os.R_OK) for p in root.rglob('*') if p.is_file())
dirs=[root/d for d in ('jail.d','filter.d','action.d')]
write_root=pathlib.Path('/data') if docker else root
writable=all((write_root/d).is_dir() and os.access(write_root/d,os.W_OK|os.X_OK) for d in ('jail.d','filter.d','action.d'))
if not docker: writable=writable and all(os.access(p,os.W_OK) for d in dirs if d.exists() for p in d.iterdir() if p.is_file())
backup_parent=write_root if docker else pathlib.Path(s['backup_dir']).parent
while not backup_parent.exists() and backup_parent!=backup_parent.parent: backup_parent=backup_parent.parent
writable=writable and os.access(backup_parent,os.W_OK|os.X_OK)
print(json.dumps({'config_readable':bool(readable),'config_writable':bool(writable)}))
'''

def backup_dir(settings):
    if settings['mode']=='docker': return '/data/backups/ui'
    # Kept outside /etc/fail2ban, and persistent with the application's state.
    key=hashlib.sha256((settings['config_dir']+'\0'+settings['socket']).encode()).hexdigest()[:16]
    return str(settings_path().parent/'fail2ban-backups'/key/'ui')

def test(settings):
    s=validate(settings)
    result={'reachable':False,'level':'unavailable','checks':[], 'settings':s}
    try:
        ping=client('ping',settings=s,timeout=10)
        if 'pong' not in ping.lower(): raise ValueError('Réponse Fail2ban inattendue.')
        status=client('status',settings=s,timeout=10)
        result.update(reachable=True,status=status)
        result['checks'].append('Fail2ban répond ; les jails sont accessibles.')
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        result['checks'].append('Connexion impossible : '+str(error)[-1500:]);return result
    admin=True
    try:
        probe=dict(s,backup_dir=backup_dir(s))
        permissions=json.loads(command(['python3','-c',PROBE,json.dumps(probe)],settings=s,timeout=15).stdout)
        result.update(permissions)
        if not permissions['config_readable'] or not permissions['config_writable']: admin=False
        result['checks'].append('Configuration accessible en lecture et écriture.' if permissions['config_readable'] and permissions['config_writable'] else 'Configuration inaccessible ou droits de modification insuffisants.')
        checked=client('-t',settings=s,timeout=30)
        result['checks'].append('Configuration Fail2ban valide.')
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        admin=False;result['checks'].append('Administration indisponible : '+str(error)[-1500:])
    try:
        logs(lines=10,settings=s)
        result['checks'].append('Journaux accessibles.')
        result['logs_readable']=True
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        result['logs_readable']=False
        result['checks'].append('Journaux indisponibles : '+str(error)[-1500:])
    result['level']='administration' if admin and not s['read_only'] else 'readonly'
    result['output']={'administration':'Administration disponible','readonly':'Consultation uniquement'}[result['level']]
    if s['mode']=='native':
        result['checks'].append('Les chemins et le socket doivent être accessibles depuis la machine ou le conteneur FCP.')
    return result

def save(settings, revision):
    s=validate(settings);path=settings_path();path.parent.mkdir(parents=True,exist_ok=True)
    with LOCK, open(str(path)+'.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        current=read()
        if revision!=current['revision']: raise ValueError('Connexion modifiée ailleurs : recharge la page.')
        result=test(s)
        if not result['reachable']: raise ValueError('Connexion impossible : les réglages actuels sont conservés.')
        if result['level']=='readonly' and not s['read_only']:
            raise ValueError('Droits insuffisants : choisis Consultation uniquement ou corrige les accès avant d’enregistrer.')
        fd,name=tempfile.mkstemp(prefix='.connection-',dir=path.parent)
        try:
            with os.fdopen(fd,'w') as handle:
                json.dump(s,handle,ensure_ascii=False,indent=2);handle.write('\n');handle.flush();os.fsync(handle.fileno())
            os.chmod(name,0o600);os.replace(name,path)
        finally:
            if os.path.exists(name): os.unlink(name)
        return dict(result, revision=read()['revision'], output='Connexion enregistrée. Les règles Fail2ban sont conservées.')

def require_write():
    if read()['settings']['read_only']:
        raise ValueError('Connexion en consultation uniquement : modification refusée.')

def service(action):
    require_write();s=read()['settings']
    if s['mode']=='docker':
        result=subprocess.run(['docker',action,s['container']],capture_output=True,text=True,timeout=45)
        if result.returncode: raise ValueError(result.stderr[-12000:])
        return result.stdout
    # A container must not attempt to start a second daemon against the host socket.
    if Path('/.dockerenv').exists():
        raise ValueError('Pilote le service natif sur son hôte ; le rechargement des jails reste disponible ici.')
    result=subprocess.run(['systemctl',action,'fail2ban.service'],capture_output=True,text=True,timeout=45)
    if result.returncode: raise ValueError(result.stderr[-12000:])
    return result.stdout

def detect(settings):
    s=validate(settings)
    if s['mode']=='native':
        for value in (s['config_dir'],'/etc/fail2ban','/host/etc/fail2ban'):
            if (Path(value)/'fail2ban.conf').is_file(): s['config_dir']=value;break
        for value in (s['socket'],'/run/fail2ban/fail2ban.sock','/host/run/fail2ban/fail2ban.sock'):
            if Path(value).exists(): s['socket']=value;break
        for value in (s['log_path'],'/var/log/fail2ban.log','/host/var/log/fail2ban.log'):
            if Path(value).is_file(): s['log_path']=value;s['log_source']='file';break
    return s
