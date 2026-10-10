#!/usr/bin/python3
# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Daily Fail2ban report; standard library only, read-only Docker collection."""
import argparse
import collections
import datetime as dt
import html
import ipaddress
import json
import os
from pathlib import Path
from runtime import load_config, settings_path, ensure_settings
import re
import subprocess
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from zoneinfo import ZoneInfo

UTC = dt.timezone.utc
EVENT = re.compile(r'\[([^\]]+)\]\s+(Restore Ban|Ban|Found)\s+(\S+)')

def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if p.returncode:
        raise RuntimeError(' '.join(args[:4]) + ': ' + (p.stderr or p.stdout)[-1200:])
    return p.stdout + p.stderr

def parse_logs(raw, start, end):
    bans, found, restored, errors = [], collections.Counter(), 0, []
    earliest = None
    for line in raw.splitlines():
        stamp, sep, message = line.partition(' ')
        try:
            when = dt.datetime.fromisoformat(re.sub(r'(\.\d{6})\d+', r'\1', stamp).replace('Z', '+00:00'))
        except ValueError:
            continue
        if when.tzinfo is None:
            continue
        earliest = when if earliest is None else min(earliest, when)
        if not start <= when <= end:
            continue
        if re.search(r'\b(WARNING|ERROR|CRITICAL)\b', message):
            errors.append(message[:900])
        match = EVENT.search(message)
        if match:
            jail, action, ip = match.groups()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if action == 'Ban':
                bans.append((jail, ip))
            elif action == 'Found':
                found[jail] += 1
            else:
                restored += 1
    return bans, found, restored, errors, earliest

def collect(cfg):
    end = dt.datetime.now(UTC)
    start = end - dt.timedelta(hours=24)
    warnings, states = [], {}
    logs_ok = True
    try:
        raw = run(['docker', 'logs', '--timestamps', '--until', end.isoformat(), cfg['container']])
        bans, found, restored, errors, earliest = parse_logs(raw, start, end)
        if earliest is None or earliest > start:
            warnings.append('Historique incomplet : les journaux conservés ne couvrent pas toute la période de 24 h. Les chiffres sont partiels.')
    except Exception as exc:
        logs_ok = False
        bans, found, restored, errors = [], {}, 0, []
        warnings.append('Statistiques indisponibles : ' + str(exc))
    active = []
    try:
        status = run(['docker', 'exec', cfg['container'], 'fail2ban-client', 'status'])
        match = re.search(r'Jail list:\s*([^\n]*)', status)
        if not match:
            raise RuntimeError('Liste des jails illisible')
        active = [j.strip() for j in match[1].split(',') if j.strip()]
    except Exception as exc:
        warnings.append('État Fail2ban indisponible : ' + str(exc))
    for jail in sorted(set(active) | set(cfg['jails'])):
        if jail not in active:
            states[jail] = None
            warnings.append('Jail attendue absente ou état indisponible : ' + jail)
            continue
        try:
            status = run(['docker', 'exec', cfg['container'], 'fail2ban-client', 'status', jail])
            match = re.search(r'Banned IP list:\s*([^\n]*)', status)
            if not match:
                raise RuntimeError('Liste des IP illisible')
            states[jail] = match[1].split()
        except Exception as exc:
            states[jail] = None
            warnings.append(jail + ' : ' + str(exc))
    return dict(start=start, end=end, bans=bans, found=found, restored=restored,
                errors=errors, warnings=warnings, states=states, active=active, logs_ok=logs_ok)

def render(cfg, data):
    esc = lambda v: html.escape(str(v))
    zone = ZoneInfo(cfg.get('timezone','UTC'))
    period = 'Du ' + data['start'].astimezone(zone).strftime('%d/%m/%Y à %H:%M') + ' au ' + data['end'].astimezone(zone).strftime('%d/%m/%Y à %H:%M') + ' · '+cfg.get('timezone','UTC')
    counts = collections.Counter(ip for jail, ip in data['bans'])
    jailcounts = collections.Counter(jail for jail, ip in data['bans'])
    current = set(ip for ips in data['states'].values() if ips is not None for ip in ips)
    repeats = [(ip, count) for ip, count in counts.most_common() if count > 1]
    removed_log_events = [
        event for event in data['errors']
        if 'Too many errors. Remove file ' in event and '-json.log' in event
    ]
    other_log_events = [event for event in data['errors'] if event not in removed_log_events]
    def table(headers, rows):
        out = '<table role="table" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:14px"><tr>'
        out += ''.join('<th align="left" style="padding:12px 8px;background:#e8eef5;color:#334155">'+esc(h)+'</th>' for h in headers) + '</tr>'
        for i, row in enumerate(rows):
            out += '<tr>' + ''.join('<td style="padding:12px 8px;border-bottom:1px solid #e2e8f0;background:'+('#f8fafc' if i%2 == 0 else '#ffffff')+';word-break:break-word">'+esc(v)+'</td>' for v in row) + '</tr>'
        return out + '</table>'
    metrics = [('Bans sur 24 h', len(data['bans']) if data['logs_ok'] else 'N/D'), ('IP uniques bannies', len(counts) if data['logs_ok'] else 'N/D'), ('IP bannies maintenant', len(current) if all(x is not None for x in data['states'].values()) and data['states'] else 'N/D'), ('Jails actives', len(data['active']))]
    cards = '<table role="presentation" width="100%" cellspacing="6" cellpadding="0">'
    for i in (0,2):
        cards += '<tr>' + ''.join('<td width="50%" style="padding:18px;background:#eff6ff;border-radius:8px"><div style="font-size:30px;font-weight:bold;color:#1d4ed8">'+esc(v)+'</div><div style="font-size:13px;color:#475569">'+esc(k)+'</div></td>' for k,v in metrics[i:i+2]) + '</tr>'
    cards += '</table>'
    sections = []
    def section(title, body):
        sections.append('<h2 style="font-size:19px;margin:28px 0 12px;color:#0f172a">'+esc(title)+'</h2>'+body)
    if data['warnings']:
        section('Points de vigilance', '<div style="padding:16px;background:#fff7ed;color:#9a3412">'+'<br>'.join(esc(x) for x in data['warnings'])+'</div>')
    if removed_log_events:
        count = len(removed_log_events)
        label = 'fichier de logs Docker a été retiré' if count == 1 else 'fichiers de logs Docker ont été retirés'
        section(
            'Surveillance Docker à contrôler',
            '<div style="padding:18px;background:#fff7ed;border-left:5px solid #f97316;color:#7c2d12">'
            '<div style="font-size:18px;font-weight:bold;margin-bottom:10px">⚠️ '+esc(count)+' '+label+' de la surveillance</div>'
            '<p style="margin:0 0 10px"><strong>Cause probable :</strong> les conteneurs correspondants ont été recréés ou mis à jour et leurs anciens fichiers de logs ont disparu.</p>'
            '<p style="margin:0 0 10px"><strong>Conséquence :</strong> Fail2ban a cessé de lire ces anciens chemins. Ce message ne prouve ni une attaque ni une panne générale de Fail2ban.</p>'
            '<p style="margin:0"><strong>Contrôle conseillé :</strong> vérifier que les jails actives suivent bien les fichiers des conteneurs actuels.</p>'
            '</div>'
        )
    rows = []
    for jail in sorted(set(data['states']) | set(jailcounts)):
        ips = data['states'].get(jail)
        rows.append((jail + ' — ' + cfg['jails'].get(jail, 'Autre service'), 'Active' if ips is not None else 'Absente / inconnue', jailcounts[jail] if data['logs_ok'] else 'N/D', data['found'].get(jail,0) if data['logs_ok'] else 'N/D', len(ips) if ips is not None else 'N/D'))
    section('Services et état des jails', table(['Service / jail','État','Bans 24 h','Détections','Bans actifs'], rows))
    section('Top 10 des IP bannies', table(['IP','Bans 24 h','Jails concernées'], [(ip,n,', '.join(sorted({j for j,p in data['bans'] if p==ip}))) for ip,n in counts.most_common(10)]) if counts else '<p>Aucun bannissement observé dans les journaux disponibles.</p>')
    section('Récidivistes sur 24 h', table(['IP','Nombre de bans'], repeats) if repeats else '<p>Aucune IP bannie plusieurs fois sur la période disponible.</p>')
    section('IP actuellement bannies', table(['Jail','IP'], [(j,ip) for j,ips in data['states'].items() if ips for ip in ips]) if current else '<p>Aucune IP connue actuellement bannie ; consulter les alertes si un état est indisponible.</p>')
    abuse_text = 'Automatisation abuse : état indisponible.'
    try:
        abuse_dir = Path(cfg['output']) / 'abuse'
        abuse = json.loads((abuse_dir / 'latest.json').read_text())
        abuse_state = json.loads((abuse_dir / 'state.json').read_text())
        checked = dt.datetime.fromtimestamp(abuse['checked_at'], UTC)
        recent = [item for item in abuse_state.get('history', []) if data['start'].timestamp() <= item['submitted_at'] <= data['end'].timestamp()]
        stale = (data['end'] - checked).total_seconds() > 900
        label = 'Active' if abuse.get('enabled') and not stale else 'À contrôler'
        abuse_text = f'Automatisation abuse : {label}. Dernier contrôle : {checked.astimezone(zone).strftime("%d/%m/%Y %H:%M")}. {len(recent)} signalement(s) remis à Postfix sur 24 h.'
        rows_abuse = [(item['ip'], ', '.join(item['contacts']), item['bans'], dt.datetime.fromtimestamp(item['submitted_at'], UTC).astimezone(zone).strftime('%d/%m %H:%M')) for item in recent]
        problems = [f"{ip} : soumission incertaine, nouvel envoi bloqué pour éviter un doublon" for ip, item in abuse_state.get('reports', {}).items() if item.get('status') in ('uncertain', 'submitting')]
        problems += [f"{item['ip']} : {item['error']}" for item in abuse.get('errors', [])]
        missing = [item['ip'] for item in abuse.get('results', []) if item.get('status') == 'no_contact']
        if missing:
            problems.append('Contact abuse absent du registre : ' + ', '.join(missing))
        abuse_text += '\n' + '\n'.join(f"{row[0]} → {row[1]} : {row[2]} bans, {row[3]}" for row in rows_abuse)
        abuse_text += '\n' + '\n'.join(problems)
        section('Signalements abuse automatiques', '<p>'+esc(abuse_text.split('\n')[0])+'</p><p>Seuil : 2 bans distincts sur 24 h · Contrôle toutes les 5 min · Un signalement maximum par IP sur 24 h, avec nouveau ban requis. Une remise à Postfix ne prouve pas la réception par le destinataire.</p>' + (table(['IP','Contact abuse','Bans','Envoi · Paris'], rows_abuse) if rows_abuse else '<p>Aucun signalement remis à Postfix sur cette période.</p>') + ('<p>'+ '<br>'.join(esc(p) for p in problems)+'</p>' if problems else ''))
    except (OSError, ValueError, KeyError, TypeError):
        section('Signalements abuse automatiques', '<p>État indisponible : vérifier fail2ban-abuse.service.</p>')
    section('Autres erreurs et avertissements', '<p>'+str(len(other_log_events))+' autre(s) événement(s) sur 24 h.</p>' + (table(['Derniers événements (20 maximum)'], [(x,) for x in other_log_events[-20:]]) if other_log_events else '<p>Aucun autre avertissement ni erreur observé dans les journaux disponibles.</p>'))
    if removed_log_events:
        section('Détails techniques', '<p style="font-size:13px;color:#64748b">Événements bruts liés aux anciens fichiers Docker, conservés pour le diagnostic.</p>'+table(['Événements techniques (20 maximum)'], [(x,) for x in removed_log_events[-20:]]))
    section('Comment lire ce rapport', '<p style="font-size:13px;color:#64748b">Les bans sont les nouveaux événements « Ban », pas les tentatives de connexion. Les détections correspondent aux événements « Found ». Une IP unique est comptée une seule fois, toutes jails confondues. Un récidiviste a au moins deux événements Ban sur ces 24 h, éventuellement dans plusieurs jails. '+str(data['restored'])+' bannissement(s) restauré(s) après redémarrage sont exclus des nouveaux bans. Les services surveillés dépendent des jails configurées. Source : journaux Docker conservés et fail2ban-client au moment de la collecte.</p>')
    document = '<!doctype html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fail2ban</title></head><body style="margin:0;padding:20px 8px;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#334155"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center"><table role="presentation" width="680" cellspacing="0" cellpadding="0" style="width:100%;max-width:680px;background:#ffffff"><tr><td style="padding:28px;background:#0f172a;color:#ffffff"><div style="font-size:12px;letter-spacing:2px;color:#93c5fd">SÉCURITÉ · RAPPORT QUOTIDIEN</div><h1 style="font-size:28px;margin:12px 0">Fail2ban</h1><div style="font-size:13px;color:#cbd5e1">'+esc(period)+'</div></td></tr><tr><td style="padding:20px">'+cards+''.join(sections)+'</td></tr></table></td></tr></table></body></html>'
    plain = 'Fail2ban\n'+period+'\n\n'+'\n'.join(k+': '+str(v) for k,v in metrics)+'\n\n'
    plain += '\n'.join(data['warnings'])+'\n\nJails (état, bans 24h, détections, bans actifs):\n'+'\n'.join(' | '.join(map(str,row)) for row in rows)
    plain += '\n\nTop IP :\n'+'\n'.join(f'{ip}: {n}' for ip,n in counts.most_common(10))+'\n\nRécidivistes :\n'+'\n'.join(f'{ip}: {n}' for ip,n in repeats)
    plain += '\n\nIP actuellement bannies :\n'+'\n'.join(j+': '+(', '.join(ips) if ips is not None else 'indisponible') for j,ips in data['states'].items())
    plain += '\n\n' + abuse_text
    if removed_log_events:
        plain += '\n\nSURVEILLANCE DOCKER À CONTRÔLER\n'+str(len(removed_log_events))+' fichier(s) de logs Docker retiré(s) de la surveillance.\nCause probable : conteneurs recréés ou mis à jour.\nConséquence : Fail2ban a cessé de lire ces anciens chemins ; cela ne prouve ni une attaque ni une panne générale.\nContrôle conseillé : vérifier que les jails actives suivent les conteneurs actuels.'
    plain += '\n\nAutres erreurs / avertissements :\n'+('\n'.join(other_log_events[-20:]) if other_log_events else 'Aucun autre événement.')
    if removed_log_events:
        plain += '\n\nDétails techniques :\n'+'\n'.join(removed_log_events[-20:])
    return document, plain

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument('--send',action='store_true')
    parser.add_argument('--config',default=os.environ.get('FCP_CONFIG', '/app/config/config.json'))
    args=parser.parse_args()
    cfg=load_config(args.config)
    controls=settings_path()
    settings=json.loads(controls.read_text()) if controls.exists() else {}
    cfg.update({k:settings[k] for k in ('sender','recipient','jails') if k in settings})
    if args.send and not settings.get('report_enabled',False): return
    data=collect(cfg)
    document,plain=render(cfg,data)
    out=Path(cfg['output'])
    out.mkdir(parents=True,exist_ok=True)
    (out/'latest.html').write_text(document)
    (out/'latest.txt').write_text(plain)
    if args.send:
        msg=EmailMessage()
        msg['From']=cfg['sender']; msg['To']=cfg['recipient']
        msg['Date']=format_datetime(data['end'])
        msg['Message-ID']=make_msgid(domain=cfg.get('message_id_domain','localhost'))
        msg['Subject']=('[À vérifier] ' if data['warnings'] or data['errors'] else '')+'Fail2ban — '+data['end'].astimezone(ZoneInfo(cfg.get('timezone','UTC'))).strftime('%d/%m/%Y')
        msg.set_content(plain)
        msg.add_alternative(document,subtype='html')
        subprocess.run(['docker','exec','-i',cfg['postfix'],'/usr/sbin/sendmail','-i','-f',cfg['sender'],'--',cfg['recipient']],input=msg.as_bytes(),check=True,timeout=60)
        print('Message remis à Postfix : '+msg['Message-ID'],flush=True)
    print(json.dumps({'bans':len(data['bans']),'unique_ips':len({ip for j,ip in data['bans']}),'warnings':data['warnings'],'log_errors':len(data['errors']),'output':str(out)},ensure_ascii=False))

if __name__ == '__main__':
    main()
