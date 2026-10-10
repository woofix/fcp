# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
"""Executed locally with the FCP service account, without shell or privilege escalation."""
import configparser
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def main():
    q=json.load(sys.stdin)
    root=Path(q.pop('_config_dir'));backups=Path(q.pop('_backup_dir'));socket=q.pop('_socket')
    dirs={'jail':'jail.d','filter':'filter.d','action':'action.d'}
    op=q['op'];kind=q.get('kind','jail');name=q.get('name','')
    def digest(data):return hashlib.sha256(data).hexdigest()
    def custom(k,p):return k=='jail' or p.suffix=='.local'
    if op=='inventory':
        print(json.dumps({k:[{'name':p.name,'custom':custom(k,p)} for p in sorted((root/d).glob('*')) if p.is_file() and p.suffix in ('.conf','.local')] for k,d in dirs.items()}));return
    if op=='backups':
        print(json.dumps([{'id':p.name,**json.loads((p/'manifest.json').read_text())} for p in sorted(backups.glob('*'),reverse=True) if (p/'manifest.json').is_file()][:100]));return
    if kind not in dirs or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.(conf|local)',name):raise ValueError('Nom de fichier invalide')
    path=root/dirs[kind]/name
    old=path.read_bytes() if path.is_file() else b''
    if op=='read':
        print(json.dumps({'content':old.decode(),'hash':digest(old),'custom':custom(kind,path)}));return
    if op not in ('validate','save','delete','restore'):raise ValueError('Operation invalide')
    if q.get('hash')!=digest(old):raise ValueError('Le fichier a change depuis son ouverture. Rechargez-le.')
    existed=path.is_file()
    if op=='restore':
        backup=q.get('backup','')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',backup):raise ValueError('Sauvegarde invalide')
        manifest=json.loads((backups/backup/'manifest.json').read_text())
        if manifest['kind']!=kind or manifest['name']!=name:raise ValueError('Sauvegarde incompatible')
        content=(backups/backup/'previous').read_bytes() if manifest['existed'] else None
        if content is not None and digest(content)!=manifest['sha256']:raise ValueError('Sauvegarde endommagée')
    elif op=='delete':
        if not existed or not custom(kind,path):raise ValueError('Seuls les fichiers personnalises peuvent etre supprimes')
        content=None
    else:content=q['content'].encode()
    if content is not None:
        if len(content)>131072:raise ValueError('Fichier trop volumineux')
        parser=configparser.RawConfigParser(strict=True);parser.read_string(content.decode())
    with tempfile.TemporaryDirectory(prefix='fcp-native-') as tmp:
        staged=Path(tmp)/'config';shutil.copytree(root,staged,symlinks=False)
        candidate=staged/dirs[kind]/name
        if content is None:candidate.unlink(missing_ok=True)
        else:candidate.write_bytes(content)
        result=subprocess.run(['fail2ban-client','-c',str(staged),'-s',socket,'-t'],capture_output=True,text=True,timeout=25)
        if result.returncode==0 and kind=='filter' and content is not None:
            result=subprocess.run(['fail2ban-regex','-c',str(staged),'/dev/null',str(candidate)],capture_output=True,text=True,timeout=20)
        output=(result.stdout+'\n'+result.stderr)[-12000:]
        if result.returncode or op=='validate':
            print(json.dumps({'ok':result.returncode==0,'output':output}));return
        stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')+'-'+kind+'-'+name
        backup=backups/stamp;backup.mkdir(parents=True,mode=0o700)
        metadata=path.stat() if existed else None
        manifest={'kind':kind,'name':name,'existed':existed,'sha256':digest(old),'source':str(path),'mode':metadata.st_mode & 0o777 if metadata else 0o600}
        if existed:
            shutil.copy2(path,backup/'previous');assert digest((backup/'previous').read_bytes())==digest(old)
        (backup/'manifest.json').write_text(json.dumps(manifest))
        # Atomic replacement of the target keeps an existing configuration symlink intact.
        link=os.readlink(path) if path.is_symlink() else None
        target=path.resolve() if path.is_symlink() else path
        def install(data):
            if data is None:path.unlink(missing_ok=True);return
            fd,temp=tempfile.mkstemp(prefix='.fcp-',dir=target.parent)
            try:
                with os.fdopen(fd,'wb') as handle:handle.write(data);handle.flush();os.fsync(handle.fileno())
                os.chmod(temp,manifest['mode'])
                if metadata and os.geteuid()==0:os.chown(temp,metadata.st_uid,metadata.st_gid)
                os.replace(temp,target)
                if link is not None and not path.is_symlink():path.symlink_to(link)
            finally:
                if os.path.exists(temp):os.unlink(temp)
        def reload():return subprocess.run(['fail2ban-client','-c',str(root),'-s',socket,'reload'],capture_output=True,text=True,timeout=30)
        try:
            install(content);loaded=reload()
            if loaded.returncode:raise RuntimeError(loaded.stdout+'\n'+loaded.stderr)
        except Exception as error:
            install(old if existed else None);restored=reload()
            print(json.dumps({'ok':False,'output':'Application refusee; fichier restaure. '+str(error),'rollback_ok':restored.returncode==0,'backup':stamp}));return
        print(json.dumps({'ok':True,'output':loaded.stdout+'\n'+loaded.stderr,'backup':stamp}))

if __name__=='__main__':main()
