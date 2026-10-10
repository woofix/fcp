#!/usr/bin/python3
# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Report recurrent SSH authentication failures; never infer web attacks from HTTP status."""
import importlib.util
import json
import os
import time
import subprocess
import fcntl
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from runtime import load_config, settings_path, ensure_settings

spec = importlib.util.spec_from_file_location('collector', Path(__file__).with_name('fail2ban-abuse.py'))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

WEB_LOG = collector.re.compile(r'^\[(?P<time>[^]]+)\]\s+\S+\s+(?P<ip>\S+)\s+\S+\s+"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(?P<path>[^"\s]+)\s+HTTP/[^"\s]+"\s+\d{3}\s+')
WEB_PATH = collector.re.compile(r'(?:^|/)(?:wp-login(?:\.php)?|xmlrpc(?:\.php)?|phpmyadmin|R57\.php|shell\.php|eval-stdin\.php|wp-filemanager\.php)(?:/|$)|(?:^|/)\.(?:env|git)(?:[./]|$)', collector.re.I)

def web_evidence(raw, now):
    result = {}
    for line in raw.splitlines():
        match = WEB_LOG.match(line)
        if not match:
            continue
        path = urllib.parse.unquote(match['path'].split('?', 1)[0])
        if not WEB_PATH.search(path):
            continue
        try:
            stamp = collector.dt.datetime.strptime(match['time'], '%d/%b/%Y:%H:%M:%S %z').timestamp()
            ip = str(collector.ipaddress.ip_address(match['ip']))
        except ValueError:
            continue
        if now - 86460 <= stamp <= now:
            result.setdefault(ip, []).append(stamp)
    return result

def qualified(record, evidence):
    bans = {}
    for stamp, event in record['bans'].items():
        ssh_names = set(load_config().get('ssh_jails', []))
        web_name = load_config().get('web_jail','npmplus')
        ssh = bool(ssh_names & set(event['jails']))
        web = web_name in event['jails'] and sum(event['time'] - 65 <= t <= event['time'] + 2 for t in evidence) >= 3
        jails = ([j for j in event['jails'] if j in ssh_names] if ssh else []) + ([web_name] if web else [])
        if jails:
            bans[stamp] = dict(event, jails=jails)
    return dict(record, bans=bans) if len(bans) >= int(collector.AUTOMATION.get('min_bans',2)) else None

def payload(ip, record):
    events = sorted(record['bans'].values(), key=lambda e: e['time'])
    stamps = ', '.join(collector.dt.datetime.fromtimestamp(e['time'], collector.UTC).isoformat() for e in events)
    jails = {j for e in events for j in e['jails']}
    categories, descriptions = [], []
    if set(load_config().get('ssh_jails',[])) & jails:
        categories.append('18')
        descriptions.append('SSH authentication failures matched by configured SSH filters')
    if load_config().get('web_jail','npmplus') in jails:
        categories.append('21')
        descriptions.append('repeated web requests targeting known sensitive or exploit paths, at least 3 matched requests around each configured web-jail ban; HTTP 401/403 alone excluded')
    return {'ip': ip, 'categories': ','.join(categories), 'comment': f"Fail2ban evidence: {'; '.join(descriptions)}. {len(events)} distinct qualifying new bans in {collector.AUTOMATION.get('window_hours',24)} hours. Ban times UTC: {stamps}. Restored bans excluded."}

def main():
    os.umask(0o077)
    root = Path.home()
    keyfile = Path(os.environ.get('FCP_ABUSEIPDB_KEY_FILE','/app/config/abuseipdb.key'))
    directory = Path(load_config()['output']) / 'abuseipdb'
    directory.mkdir(parents=True, exist_ok=True)
    status = {'checked_at': time.time(), 'submitted': 0, 'errors': [], 'scope': 'configured_ssh_and_verified_web'}
    with (directory / 'lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if not collector.AUTOMATION.get('abuseipdb_enabled',False):
            status.update(status='disabled',enabled=False)
            collector.save(directory/'latest.json',status)
            return
        if not keyfile.exists() or not keyfile.read_text().strip():
            status['status'] = 'awaiting_api_key'
            collector.save(directory / 'latest.json', status)
            print(json.dumps(status))
            return
        if keyfile.stat().st_mode & 0o077:
            raise RuntimeError('API key file must have mode 600')
        key = keyfile.read_text().strip()
        cfg = load_config()
        raw = subprocess.run(['docker', 'logs', '--timestamps', '--since', str(collector.AUTOMATION.get('window_hours',24))+'h', cfg['container']], capture_output=True, text=True, timeout=90, check=True)
        now = time.time()
        collected = collector.collect(raw.stdout + '\n' + raw.stderr, list(cfg.get('ssh_jails',[])) + [cfg.get('web_jail','npmplus')], now)
        evidence = {}
        if cfg.get('http_enabled') and any(cfg.get('web_jail','npmplus') in e['jails'] for r in collected.values() for e in r['bans'].values()):
            web = subprocess.run(['docker', 'exec', cfg['container'], 'tail', '-n', '100000', cfg['web_log']], capture_output=True, text=True, timeout=30)
            if web.returncode:
                status['errors'].append({'error': 'Web evidence log unavailable; web reports skipped'})
            else:
                evidence = web_evidence(web.stdout, now)
        candidates = {}
        for ip, record in collected.items():
            verified = qualified(record, evidence.get(ip, []))
            if verified:
                candidates[ip] = verified
        status['excluded_without_evidence'] = len(collected) - len(candidates)
        statepath = directory / 'state.json'
        state = json.loads(statepath.read_text()) if statepath.exists() else {}
        for entry in state.values():
            if entry.get('status') == 'submitting':
                entry['status'] = 'uncertain'
        collector.save(statepath, state)
        status['candidates'] = len(candidates)
        processed = 0
        for ip, record in sorted(candidates.items()):
            if state.get(ip, {}).get('retry_after', 0) > now or not collector.eligible(record, state.get(ip, {}), now):
                continue
            if processed >= 10:
                break
            processed += 1
            entry = {'status': 'submitting', 'submitted_at': now, 'last_episode': max(e['time'] for e in record['bans'].values())}
            state[ip] = entry
            collector.save(statepath, state)
            request = urllib.request.Request('https://api.abuseipdb.com/api/v2/report', data=urllib.parse.urlencode(payload(ip, record)).encode(), headers={'Key': key, 'Accept': 'application/json'}, method='POST')
            try:
                with urllib.request.urlopen(request, timeout=25) as response:
                    result = json.loads(response.read(65536))
                if result.get('data', {}).get('ipAddress') != ip:
                    raise ValueError('Unexpected API confirmation')
                entry['status'] = 'submitted'
                status['submitted'] += 1
            except urllib.error.HTTPError as exc:
                # Retain rejection and stop this cycle; never expose response bodies or key.
                entry['status'] = 'rejected'
                entry['retry_after'] = now + 86400
                status['errors'].append({'ip': ip, 'http_status': exc.code})
                collector.save(statepath, state)
                break
            except Exception:
                entry['status'] = 'uncertain'
                status['errors'].append({'ip': ip, 'error': 'Submission confirmation unavailable; automatic retry blocked'})
            collector.save(statepath, state)
        status['status'] = 'error' if status['errors'] else 'ready'
        collector.save(directory / 'latest.json', status)
        print(json.dumps(status))

if __name__ == '__main__':
    main()
