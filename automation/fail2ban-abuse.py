#!/usr/bin/python3
# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Report repeated real Fail2ban bans to RDAP abuse contacts."""
import hashlib
import argparse
import datetime as dt
import email.utils
from email.message import EmailMessage
import fcntl
import ipaddress
import json
import os
from pathlib import Path
from runtime import load_config, settings_path, ensure_settings
import re
import subprocess
import time
import urllib.request


AUTOMATION_PATH = settings_path()
ensure_settings()
AUTOMATION = json.loads(AUTOMATION_PATH.read_text())

UTC = dt.timezone.utc
EVENT = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*?\[([^]]+)\] (Ban|Found) (\S+)')
ROUTING_FILE = Path(os.environ.get('FCP_ROUTING', '/app/config/abuse-routing.json'))

EMAIL = re.compile(r'[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+')

def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(path)

def collect(raw, allowed, now):
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
            # Duplicate lines and simultaneous jails are one episode; restored bans never match.
            episode = record['bans'].setdefault(stamp, {'time': when.timestamp(), 'jails': []})
            if jail not in episode['jails']:
                episode['jails'].append(jail)
        else:
            record['found'] += 1
            if len(record['detections']) < 50:
                record['detections'].append({'time': when.timestamp(), 'jail': jail})
    return {ip: record for ip, record in result.items() if len(record['bans']) >= int(AUTOMATION.get('min_bans',2))}

def contacts_from(record):
    contacts = set()
    def visit(entities, depth=0):
        if depth > 6 or not isinstance(entities, list):
            return
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            card = entity.get('vcardArray', [])
            if 'abuse' in entity.get('roles', []) and isinstance(card, list) and len(card) == 2 and isinstance(card[1], list):
                for entry in card[1]:
                    if isinstance(entry, list) and len(entry) >= 4 and entry[0] == 'email' and isinstance(entry[3], str) and EMAIL.fullmatch(entry[3]):
                        contacts.add(entry[3])
            visit(entity.get('entities', []), depth + 1)
    visit(record.get('entities', []))
    return sorted(contacts)

def lookup(ip):
    request = urllib.request.Request('https://rdap.org/ip/' + ip, headers={'User-Agent': 'curl/8.14.1', 'Accept': 'application/rdap+json'})
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise ValueError('Réponse RDAP trop volumineuse')
    return contacts_from(json.loads(body))

def route_contacts(contacts, rules):
    blocked = rules.get('blocked_contacts', {})
    allowed, manual = [], []
    for contact in contacts:
        rule = blocked.get(contact.strip().lower())
        if rule:
            manual.append({'contact': contact, **rule})
        else:
            allowed.append(contact)
    return sorted(set(allowed)), manual

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
    lines=['Technical evidence for abuse investigation','Source IP: '+ip,'All timestamps: UTC',
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

def message(cfg, ip, record, contacts, now, evidence=None):
    msg = EmailMessage()
    msg['From'] = cfg['sender']
    if contacts:
        msg['To'] = ', '.join(contacts)
    msg['Reply-To'] = cfg['recipient']
    msg['Date'] = email.utils.format_datetime(dt.datetime.fromtimestamp(now, UTC))
    msg['Message-ID'] = email.utils.make_msgid(domain=cfg.get('message_id_domain','localhost'))
    msg['Subject'] = AUTOMATION.get('subject','Repeated suspicious activity from {ip} — Fail2ban evidence').replace('{ip}',ip)
    lines = [
        'Our services recorded repeated security-filter detections from the following source IP:',
        ip, '',
        f'Fail2ban issued {len(record["bans"])} distinct new bans during the last {AUTOMATION.get("window_hours",24)} hours.',
        f'{record["found"]} matching failure detections were recorded for this IP during that window.',
        'The sshd filter monitors host SSH (TCP 22); the sftp filter monitors Docker SFTP (TCP 2222).',
        'Filter detections alone do not establish malicious intent; review the evidence below.',
        'HTTP 401/403 responses alone do not establish malicious activity.',
        'Filter detections and bans are observations, not proof of compromise or intent.',
        'Restored bans after restarts are excluded. All timestamps below are UTC.', '',
    ]
    for event in sorted(record['bans'].values(), key=lambda e: e['time']):
        stamp = dt.datetime.fromtimestamp(event['time'], UTC).isoformat()
        services = ', '.join(cfg['jails'].get(jail,jail) + ' (jail ' + jail + ')' for jail in sorted(event['jails']))
        lines.append(stamp + ' | source ' + ip + ' | new ban | ' + services)
    lines += ['', 'Detection timeline (up to 50 filter matches; not raw HTTP or SSH request logs):']
    for detection in sorted(record.get('detections', []), key=lambda e: e['time']):
        stamp = dt.datetime.fromtimestamp(detection['time'], UTC).isoformat()
        lines.append(stamp + ' | source ' + ip + ' | filter match | jail ' + detection['jail'])
    lines += ['', 'Please review these observations and investigate if appropriate.',
              'This automated report describes observed events; it does not establish the identity or intent of the operator.',
              'Your abuse contact was obtained from the public RDAP registry.',
              'Sanitized technical evidence is included when available; no passwords, usernames, URL query strings or destination hostnames are included.',
              'For questions, please reply to ' + cfg['recipient'] + '.', '', 'Regards,', 'Service administrator']
    if evidence:
        extract = evidence_text(ip, evidence)
        digest = hashlib.sha256(extract.encode('utf-8')).hexdigest()
        lines += ['', 'Supporting evidence',
                  f"Known scan-path requests in examined recent log rows: {evidence.get('http_summary',{}).get('scan_count',sum(row['scan_path'] for row in evidence['http']))}.",
                  f"SSH/SFTP authentication failure events in the attached sample: {len(evidence['ssh'])}.",
                  'No successful intrusion is established by this report.',
                  'Evidence SHA-256: '+digest, '', extract]
    lines = [AUTOMATION.get('message','Hello Abuse Team,'), '', *lines]
    msg.set_content('\n'.join(lines))
    if evidence:
        msg.add_attachment(extract.encode('utf-8'), maintype='text', subtype='plain', filename='evidence-'+ip.replace(':','_')+'.txt')
    return msg

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--send', action='store_true')
    parser.add_argument('--config', default=os.environ.get('FCP_CONFIG', '/app/config/config.json'))
    args = parser.parse_args()
    cfg = load_config(args.config)
    cfg.update({k: AUTOMATION[k] for k in ('sender','recipient','jails') if k in AUTOMATION})
    if not AUTOMATION.get('email_enabled',False):
        directory=Path(cfg['output'])/'abuse'; directory.mkdir(parents=True,exist_ok=True)
        save(directory/'latest.json',{'checked_at':time.time(),'enabled':False,'submitted':0,'results':[],'errors':[]})
        return
    routing = json.loads(ROUTING_FILE.read_text()) if ROUTING_FILE.exists() else {'blocked_contacts': {}}
    directory = Path(cfg['output']) / 'abuse'
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / 'lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        state_path = directory / 'state.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else {'reports': {}, 'rdap': {}, 'history': []}
        now = time.time()
        logs = subprocess.run(['docker', 'logs', '--timestamps', '--since', str(AUTOMATION.get('window_hours',24))+'h', cfg['container']], capture_output=True, text=True, timeout=90, check=True)
        allowed = cfg['jails']
        if not allowed:
            active = subprocess.run(['docker','exec',cfg['container'],'fail2ban-client','status'],capture_output=True,text=True,check=True,timeout=30).stdout
            match = re.search(r'Jail list:\s*([^\n]*)',active)
            allowed = [j.strip() for j in match[1].split(',') if j.strip()] if match else []
        candidates = collect(logs.stdout + '\n' + logs.stderr, allowed, now)
        status = {'checked_at': now, 'enabled': args.send, 'candidates': len(candidates), 'submitted': 0, 'skipped': 0, 'errors': [], 'results': []}
        if args.send:
            # A process killed after submission must not silently resubmit a possibly sent report.
            for previous in state['reports'].values():
                if previous.get('status') == 'submitting':
                    previous['status'] = 'uncertain'
            save(state_path, state)
        processed = 0
        for ip, record in sorted(candidates.items()):
            previous = state['reports'].get(ip, {})
            if not eligible(record, previous, now):
                status['skipped'] += 1
                status['results'].append({'ip': ip, 'status': previous.get('status', 'cooldown'), 'bans': len(record['bans'])})
                continue
            if processed >= 10:
                status['results'].append({'ip': ip, 'status': 'next_cycle'})
                continue
            processed += 1
            try:
                cache = state['rdap'].get(ip, {})
                if cache.get('expires', 0) < now:
                    contacts = lookup(ip)
                    cache = {'contacts': contacts, 'expires': now + (604800 if contacts else 3600)}
                    if args.send:
                        state['rdap'][ip] = cache
                        save(state_path, state)
                evidence = collect_evidence(ip, now)
                if not evidence['strong_count']:
                    status['results'].append({'ip': ip, 'status': 'insufficient_evidence', 'bans': len(record['bans'])})
                    continue
                contacts, manual = route_contacts(cache['contacts'], routing)
                if not contacts and manual:
                    draft = message(cfg, ip, record, [], now, evidence)
                    (directory / (ip.replace(':', '_') + '.manual.eml')).write_bytes(draft.as_bytes())
                    status['results'].append({'ip': ip, 'status': 'manual_required', 'bans': len(record['bans']), 'routing': manual})
                    continue
                if not contacts:
                    status['results'].append({'ip': ip, 'status': 'no_contact', 'bans': len(record['bans'])})
                    continue
                msg = message(cfg, ip, record, contacts, now, evidence)
                entry = {'ip': ip, 'contacts': contacts, 'bans': len(record['bans']), 'message_id': msg['Message-ID'], 'submitted_at': now, 'last_episode': max(e['time'] for e in record['bans'].values()), 'status': 'preview'}
                if args.send:
                    entry['status'] = 'submitting'
                    state['reports'][ip] = entry
                    save(state_path, state)
                    (directory / (ip.replace(':', '_') + '.eml')).write_bytes(msg.as_bytes())
                    try:
                        subprocess.run(['docker', 'exec', '-i', cfg['postfix'], '/usr/sbin/sendmail', '-i', '-f', cfg['sender'], '--', *contacts], input=msg.as_bytes(), capture_output=True, timeout=60, check=True)
                    except Exception:
                        entry['status'] = 'uncertain'
                        save(state_path, state)
                        raise
                    entry['status'] = 'submitted'
                    state['history'].append(dict(entry))
                    state['history'] = state['history'][-1000:]
                    save(state_path, state)
                    status['submitted'] += 1
                else:
                    (directory / (ip.replace(':', '_') + '.preview.eml')).write_bytes(msg.as_bytes())
                status['results'].append(dict(entry))
            except Exception as exc:
                error = {'ip': ip, 'error': str(exc)[:300]}
                status['errors'].append(error)
                status['results'].append({'ip': ip, 'status': 'error'})
                if args.send and ip not in state['reports']:
                    state['rdap'][ip] = {'contacts': [], 'expires': now + 900}
                    save(state_path, state)
        save(directory / ('latest.json' if args.send else 'preview.json'), status)
        print(json.dumps(status, ensure_ascii=False))
        if status['errors'] or any(p.get('status') == 'uncertain' for p in state['reports'].values()):
            raise SystemExit(1)

if __name__ == '__main__':
    main()
