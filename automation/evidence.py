#!/usr/bin/python3
# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Collect sanitized Fail2ban evidence and guard API submission retries."""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
from runtime import load_config, settings_path, ensure_settings
import re
import subprocess
import time


AUTOMATION_PATH = settings_path()
ensure_settings()
AUTOMATION = json.loads(AUTOMATION_PATH.read_text())

UTC = dt.timezone.utc
EVENT = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*?\[([^]]+)\] (Ban|Found) (\S+)')


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(path)

def collect(raw, allowed, now, min_bans=None, since=0):
    result = {}
    start = now - int(AUTOMATION.get('window_hours',24))*3600
    for line in raw.splitlines():
        match = EVENT.search(line)
        if not match:
            continue
        stamp, jail, action, raw_ip = match.groups()
        try:
            when = dt.datetime.fromisoformat(line.split(' ', 1)[0].replace('Z', '+00:00'))
            address = ipaddress.ip_address(raw_ip)
            if when.tzinfo is None or not start <= when.timestamp() <= now or not address.is_global or jail not in allowed:
                continue
        except ValueError:
            continue
        record = result.setdefault(str(address), {'bans': {}, 'found': 0, 'detections': []})
        if action == 'Ban':
            if when.timestamp() < since:
                continue
            # Duplicate lines and simultaneous jails are one episode; restored bans never match.
            episode = record['bans'].setdefault(stamp, {'time': when.timestamp(), 'jails': []})
            if jail not in episode['jails']:
                episode['jails'].append(jail)
        else:
            record['found'] += 1
            if len(record['detections']) < 50:
                record['detections'].append({'time': when.timestamp(), 'jail': jail})
    return {ip: record for ip, record in result.items() if len(record['bans']) >= int(AUTOMATION.get('min_bans',2) if min_bans is None else min_bans)}
# Export only known scan paths; never export arbitrary paths, queries or hostnames.
SCAN_PATHS = frozenset({
    '/.env', '/.env.local', '/.env.production', '/.env.backup', '/.env.old',
    '/.env.example', '/.git/config', '/.git/HEAD', '/wp-config.php',
    '/wp-config.php.bak', '/wp-config.php.old', '/xmlrpc.php', '/wp-login.php',
    '/.aws/credentials', '/.env/.aws/credentials', '/server-status',
    '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
})

def collect_evidence(ip, now):
    cfg = load_config()
    # Query inside FCP: its private SQLite database is not copied out.
    query = r'''
import sqlite3,json,sys
from urllib.parse import urlsplit,unquote
ip,now,allowed,hours=json.loads(sys.argv[1]);allowed=set(allowed);start=now-hours*3600
db=sqlite3.connect('file:/app/data/fcp.sqlite3?mode=ro',uri=True,timeout=10)
try:
 total,first,last=db.execute('SELECT COUNT(*),MIN(occurred_at),MAX(occurred_at) FROM requests WHERE ip=? AND occurred_at BETWEEN ? AND ?',(ip,start,now)).fetchone()
 statuses=dict(db.execute('SELECT status,COUNT(*) FROM requests WHERE ip=? AND occurred_at BETWEEN ? AND ? GROUP BY status',(ip,start,now)).fetchall())
 rows=db.execute('SELECT occurred_at,method,path,status FROM requests WHERE ip=? AND occurred_at BETWEEN ? AND ? ORDER BY occurred_at DESC LIMIT 10000',(ip,start,now))
 result=[];examined=0;scan_count=0;targets={}
 for stamp,method,path,status in rows:
  examined+=1;path=unquote(urlsplit(path).path);match=path in allowed
  if match:
   scan_count+=1;targets[path]=targets.get(path,0)+1
  row={'time':stamp,'method':method if method in ('GET','POST','HEAD','PUT','DELETE','OPTIONS','PATCH') else 'OTHER','path':path if match else '[path omitted]','status':str(status) if str(status).isdigit() else 'unknown','scan_path':match}
  if match: result.append(row)
  elif len(result)<100: result.append(row)
 # Prefer relevant scan requests over generic HTTP failures.
 result=sorted(result,key=lambda r:(r['scan_path'],r['time']),reverse=True)[:100]
 print(json.dumps({'rows':result,'total':total,'first':first,'last':last,'statuses':statuses,'examined':examined,'scan_count':scan_count,'targets':targets,'window_hours':hours}))
finally:
 db.close()
'''
    http_data = {'rows':[], 'total':0, 'first':None, 'last':None, 'statuses':{}, 'examined':0, 'scan_count':0, 'targets':{}, 'available':False}
    if cfg.get('http_enabled'):
        try:
            data = subprocess.run(['docker','exec',cfg['fcp_container'],'python','-c',query,
                json.dumps([ip,now,sorted(SCAN_PATHS),int(AUTOMATION.get('window_hours',24))])], capture_output=True,text=True,check=True,timeout=30)
            http_data.update(json.loads(data.stdout), available=True)
        except (subprocess.SubprocessError, ValueError, OSError):
            pass
    http = http_data['rows']
    ssh = []
    logs = subprocess.CompletedProcess([],0,'','')
    if cfg.get('sftp_container'):
        logs = subprocess.run(['docker','logs','--timestamps','--since',str(AUTOMATION.get('window_hours',24))+'h','--tail','100000',cfg['sftp_container']], capture_output=True,text=True,timeout=30)
    pattern = re.compile(r'(Failed (?:password|publickey)|Invalid user|authentication failure).*?(?:from|rhost=)\s*' + re.escape(ip) + r'(?![\w.:])', re.I)
    for line in (logs.stdout + '\n' + logs.stderr).splitlines():
        match = pattern.search(line)
        if not match:
            continue
        try:
            stamp = dt.datetime.fromisoformat(line.split(' ', 1)[0].replace('Z', '+00:00'))
            if stamp.tzinfo is None or not now-int(AUTOMATION.get('window_hours',24))*3600 <= stamp.timestamp() <= now:
                continue
        except ValueError:
            continue
        ssh.append({'time':stamp.timestamp(),'event':match[1].lower(),'port':cfg.get('sftp_port',22)})
        if len(ssh) >= 100:
            break
    host = subprocess.run(['docker','exec',cfg['container'],'tail','-n','100000',cfg['ssh_log']],capture_output=True,text=True,timeout=30)
    if host.returncode == 0:
        count = 0
        for line in host.stdout.splitlines():
            match=pattern.search(line)
            if not match: continue
            try:
                stamp=dt.datetime.fromisoformat(line.split(' ',1)[0].replace('Z','+00:00'))
                if stamp.tzinfo is None or not now-int(AUTOMATION.get('window_hours',24))*3600 <= stamp.timestamp() <= now: continue
            except ValueError: continue
            ssh.append({'time':stamp.timestamp(),'event':match[1].lower(),'port':cfg.get('ssh_port',22)})
            count+=1
            if count>=100: break
    return {'http':http,'http_summary':{k:v for k,v in http_data.items() if k!='rows'},'ssh':ssh,'host_ssh_available':host.returncode==0,'strong_count':http_data['scan_count']+len(ssh),'checked_at':now}

def evidence_text(ip, evidence):
    def stamp(value):
        return dt.datetime.fromtimestamp(value,UTC).isoformat() if value is not None else 'not observed'
    summary=evidence.get('http_summary',{})
    hours=int(AUTOMATION.get('window_hours',24))
    now=evidence.get('checked_at',time.time())
    lines=['Technical security evidence','Source IP: '+ip,'All timestamps: UTC',
           'Observation window: '+stamp(now-hours*3600)+' to '+stamp(now),
           'Generated at: '+stamp(now),'',
           'Affected services: '+load_config().get('service_description','See configured services and evidence below.'),
           'Only services with observations below are implicated.',
           'HTTP source: FCP persistent database populated from configured compatible access logs.',
           'SSH source: host sshd log; SFTP source: Docker OpenSSH container logs.',
           'HTTP evidence available: '+str(summary.get('available',False)),
           'Host SSH evidence log available: '+str(evidence.get('host_ssh_available',False)),
           'This is a normalized, sanitized log extract; it is not an unmodified raw log.',
           'Passwords, usernames, destination hostnames, arbitrary paths and query strings are excluded.','',
           'HTTP observations in the configured window:',
           'Total matching-source HTTP requests: '+str(summary.get('total',len(evidence['http']))),
           'First HTTP observation: '+stamp(summary.get('first')),
           'Latest HTTP observation: '+stamp(summary.get('last')),
           'HTTP response counts: '+', '.join(str(k)+'='+str(v) for k,v in sorted(summary.get('statuses',{}).items(),key=lambda x:str(x[0]))),
           'Recent HTTP rows examined: '+str(summary.get('examined',len(evidence['http'])))+' (maximum 10000).',
           'Known sensitive/scan-path requests among examined rows: '+str(summary.get('scan_count',sum(r['scan_path'] for r in evidence['http']))),
           'Sample: up to 100 requests, prioritizing known scan paths; sample counts are not total attack counts.',
           'HTTP 401/403 responses alone are not evidence of abuse or compromise.','',
           'Known requested scan paths and counts within examined rows:']
    for path,count in sorted(summary.get('targets',{}).items(),key=lambda x:(-x[1],x[0])):
        lines.append(path+' : '+str(count))
    lines += ['','Normalized HTTP access-log sample: timestamp | source IP | protocol | method | requested path | response status']
    for row in sorted(evidence['http'],key=lambda r:r['time']):
        lines.append(stamp(row['time'])+' | '+ip+' | HTTP(S) | '+row['method']+' | '+row['path']+' | '+row['status'])
    lines+=['','SSH/SFTP authentication-failure sample (up to 100 per service; bounded log tail, not an exhaustive count):']
    for port in sorted({r['port'] for r in evidence['ssh']}):
        rows=[r for r in evidence['ssh'] if r['port']==port]
        lines.append('TCP '+str(port)+': '+str(len(rows))+' sampled failures; first '+stamp(min((r['time'] for r in rows),default=None))+'; latest '+stamp(max((r['time'] for r in rows),default=None)))
    for row in sorted(evidence['ssh'],key=lambda r:r['time']):
        lines.append(stamp(row['time'])+' | source '+ip+' | '+('SSH/SFTP TCP '+str(row['port']))+' | '+row['event'])
    lines+=['','No successful intrusion or identity/intent of the operator is established by this report.']
    return '\n'.join(lines)+'\n'

def eligible(record, previous, now):
    if previous.get('status') in ('submitting', 'uncertain'):
        return False
    if previous.get('status') == 'submitted' and now - previous['submitted_at'] < int(AUTOMATION.get('cooldown_hours',24))*3600:
        return False
    return max(event['time'] for event in record['bans'].values()) > previous.get('last_episode', 0)
