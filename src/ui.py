# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
from flask import Flask, jsonify, request
import subprocess
import re
import ipaddress
from html import escape
from datetime import datetime, timedelta
from functools import lru_cache
import maxminddb
import threading
import urllib.request
import gzip
import os
import tempfile
import json
import time
from concurrent.futures import ThreadPoolExecutor

from runtime import settings_path, ensure_settings, load_config
from security import install_auth
F2B_CONTAINER = load_config()['container']
app = Flask(__name__)
install_auth(app)
ensure_settings()

try:
    geo_reader = maxminddb.open_database('/app/geo/city.mmdb')
except (OSError, ValueError):
    geo_reader = None

try:
    asn_reader = maxminddb.open_database('/app/geo/asn.mmdb')
except (OSError, ValueError):
    asn_reader = None

geo_lock = threading.RLock()
geo_update = {"running": False, "message": ""}

@lru_cache(maxsize=4096)
def geo_label(ip):
    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            return 'Adresse locale ou réservée'
        if geo_reader is None:
            return 'Géolocalisation indisponible'
        with geo_lock:
            record = geo_reader.get(ip) or {}
        def name(part):
            names = record.get(part, {}).get('names', {})
            return names.get('fr') or names.get('en') or ''
        country, city = name('country'), name('city')
        code = record.get('country', {}).get('iso_code', '').upper()
        if len(code) == 2 and code.isascii() and code.isalpha():
            flag = ''.join(chr(127397 + ord(letter)) for letter in code)
            country = flag + ' ' + (country or code)
        return ' · '.join(part for part in (country, city) if part) or 'Localisation inconnue'
    except (ValueError, OSError):
        return 'Localisation inconnue'

@lru_cache(maxsize=4096)
def network_label(ip):
    try:
        if not ipaddress.ip_address(ip).is_global:
            return ''
        if asn_reader is None:
            return 'Opérateur indisponible'
        with geo_lock:
            record = asn_reader.get(ip) or {}
        number = record.get('autonomous_system_number')
        organization = record.get('autonomous_system_organization', '')
        return ' · '.join(part for part in (organization, f'AS{number}' if number else '') if part) or 'Opérateur inconnu'
    except (ValueError, OSError):
        return 'Opérateur inconnu'

abuse_executor = ThreadPoolExecutor(max_workers=2)
abuse_cache = {}
abuse_lock = threading.Lock()


def geo_html(ip):
    label = '<span class="subline">' + escape(geo_label(ip)) + '</span><span class="subline">' + escape(network_label(ip)) + '</span>'
    try:
        if ipaddress.ip_address(ip).is_global:
            label += f'<span class="subline abuse-result" data-ip="{escape(ip, quote=True)}">Contact abuse : recherche automatique…</span>'
    except ValueError:
        pass
    return label


# Short-lived snapshots avoid repeating expensive reads for each browser refresh.
from functools import wraps
snapshot_lock = threading.RLock()
snapshots = {}

def cached_snapshot(key, ttl, loader):
    with snapshot_lock:
        previous = snapshots.get(key)
        if previous and time.monotonic() < previous[0]:
            return previous[1]
        value = loader()
        snapshots[key] = (time.monotonic() + ttl, value)
        return value

dashboard_lock = threading.Lock()
dashboard_ready = threading.Event()
dashboard_state = {'html': None, 'built': 0, 'generation': 0}

def refresh_dashboard():
    with dashboard_lock:
        generation = dashboard_state['generation']
    with app.test_request_context('/'):
        html = dashboard.__wrapped__()
    with dashboard_lock:
        if generation == dashboard_state['generation']:
            dashboard_state.update(html=html, built=time.monotonic())

def dashboard_worker():
    while True:
        dashboard_ready.wait(10)
        dashboard_ready.clear()
        try:
            refresh_dashboard()
        except Exception:
            app.logger.exception('Dashboard background refresh failed')

def cache_dashboard(function):
    @wraps(function)
    def wrapped():
        with dashboard_lock:
            html = dashboard_state['html']
            age = time.monotonic() - dashboard_state['built']
        if html is None:
            return '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta http-equiv="refresh" content="2"><title>Fail2ban</title></head><body style="background:#0a0a0a;color:#e0e0e0;font-family:sans-serif;padding:30px"><h1>Fail2ban</h1><p>Actualisation des données en cours…</p></body></html>'
        if age > 45:
            html = html.replace('<body>', '<body><p role="status">Actualisation retardée : ces données datent de ' + str(int(age)) + ' secondes.</p>', 1)
        return html
    return wrapped

http_pattern = re.compile(r'^\[([^]]+)\]\s+(\S+)\s+(\S+)\s+\S+\s+"(\S+)\s+(.*?)\s+HTTP/[^"]+"\s+(\d{3})')
suspect_pattern = re.compile(r'wp-login|xmlrpc|\.env|\.git|phpmyadmin|/R57\.php|/(?:shell|eval-stdin|wp-filemanager)\.php', re.I)

from collections import deque
from datetime import timezone

class IncrementalHttpLog:
    """Bound each read to an observed file size and keep the latest relevant rows."""
    initial_bytes = 32 * 1024 * 1024
    initial_lines = 50000
    update_bytes = 4 * 1024 * 1024
    max_partial = 256 * 1024

    def __init__(self, path, max_rows=100):
        self.path = path
        self.rows = deque(maxlen=max_rows)
        self.lock = threading.Lock()
        self.identity = None
        self.offset = 0
        self.anchor = b''
        self.partial = b''
        self.last_success = None
        self.error = False
        self.catching_up = False
        self.truncated_line = False
        self.skip_partial = False

    def _initial(self, handle, size):
        end = size
        blocks = []
        lines = 0
        lower = max(0, size - self.initial_bytes)
        while end > lower and lines <= self.initial_lines:
            start = max(lower, end - 65536)
            handle.seek(start)
            block = handle.read(end - start)
            if len(block) != end-start:
                raise OSError('Journal changed during initial read')
            blocks.append(block)
            lines += block.count(b'\n')
            end = start
        data = b''.join(reversed(blocks))
        if end > 0:
            data = data.partition(b'\n')[2]
        parts = data.split(b'\n')
        return b'\n'.join(parts[-(self.initial_lines+1):])

    def _parse(self, data):
        chunks = data.split(b'\n')
        trailing = chunks.pop()
        parsed = []
        for raw in chunks:
            if len(raw) > self.max_partial:
                self.truncated_line = True
                continue
            line = raw.decode('utf-8',errors='replace')
            match = http_pattern.match(line)
            if not match:
                continue
            date, domain, ip, method, path, status = match.groups()
            try:
                if not ipaddress.ip_address(ip).is_global:
                    continue
            except ValueError:
                continue
            if int(status) >= 400 or suspect_pattern.search(path):
                parsed.append((date, ip, domain, method, path, status))
        return parsed, trailing

    def poll(self):
        with self.lock:
            try:
                with open(self.path,'rb') as handle:
                    stat = os.fstat(handle.fileno())
                    identity = (stat.st_dev,stat.st_ino)
                    reset = self.identity != identity or stat.st_size < self.offset
                    if not reset and self.anchor:
                        handle.seek(self.offset-len(self.anchor))
                        reset = handle.read(len(self.anchor)) != self.anchor
                    if reset:
                        data = self._initial(handle, stat.st_size)
                        offset = stat.st_size
                        skipping = False
                        previous = b''
                    else:
                        handle.seek(self.offset)
                        count = min(self.update_bytes, max(0,stat.st_size-self.offset))
                        data = handle.read(count)
                        if len(data) != count:
                            raise OSError('Journal truncated during read')
                        offset = self.offset+len(data)
                        previous = self.partial
                        skipping = self.skip_partial
                    if skipping:
                        boundary = data.find(b'\n')
                        if boundary < 0:
                            data = b''
                        else:
                            data = data[boundary+1:]
                            skipping = False
                    parsed, partial = self._parse(previous+data)
                    if len(partial) > self.max_partial:
                        partial = b''
                        skipping = True
                        self.truncated_line = True
                    handle.seek(max(0,offset-64))
                    anchor = handle.read(min(64,offset))
                    if len(anchor) != min(64,offset):
                        raise OSError('Journal changed during read')
                self._commit_read(parsed,identity,offset,anchor,partial,skipping,offset < stat.st_size)
            except (OSError, sqlite3.Error):
                self.error = True
            return {'rows':list(self.rows),'last_success':self.last_success,
                    'error':self.error,'catching_up':self.catching_up,
                    'truncated_line':self.truncated_line}

import sqlite3
import base64
import math
from contextlib import contextmanager

class SqliteHttpLog(IncrementalHttpLog):
    initial_bytes = 64 * 1024 * 1024
    initial_lines = 200000

    def __init__(self, path, database, max_rows=100, retention_days=30):
        super().__init__(path,max_rows=max_rows)
        self.database = database
        self.retention_days = max(1,min(3650,retention_days))
        os.makedirs(os.path.dirname(os.path.abspath(database)),exist_ok=True)
        with self.connect() as connection:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL, ip TEXT NOT NULL, domain TEXT NOT NULL,
                    method TEXT NOT NULL, path TEXT NOT NULL, status TEXT NOT NULL,
                    occurred_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS requests_occurred_at ON requests(occurred_at);
                CREATE TABLE IF NOT EXISTS reader_state (
                    name TEXT PRIMARY KEY, value TEXT NOT NULL
                );
            ''')
            previous=connection.execute('SELECT value FROM reader_state WHERE name=?',('npmplus',)).fetchone()
            if previous:
                state=json.loads(previous[0])
                self.identity=tuple(state['identity'])
                self.offset=state['offset']
                self.anchor=base64.b64decode(state['anchor'])
                self.partial=base64.b64decode(state['partial'])
                self.skip_partial=state['skip_partial']
                self.last_success=state['last_success']
                self.truncated_line=state['truncated_line']
            self.rows.extend(self._latest(connection))
        os.chmod(self.database,0o600)

    @contextmanager
    def connect(self):
        connection=sqlite3.connect(self.database,timeout=5)
        try:
            connection.execute('PRAGMA synchronous=NORMAL')
            with connection:
                yield connection
        finally:
            connection.close()

    def _latest(self, connection, page=1):
        return list(reversed(connection.execute(
            'SELECT date,ip,domain,method,path,status FROM requests ORDER BY id DESC LIMIT ? OFFSET ?',
            (self.rows.maxlen,(page-1)*self.rows.maxlen)).fetchall()))

    def _commit_read(self, parsed, identity, offset, anchor, partial, skipping, catching_up):
        now=datetime.now(timezone.utc)
        stamp=now.isoformat()
        state={'identity':identity,'offset':offset,
               'anchor':base64.b64encode(anchor).decode(),
               'partial':base64.b64encode(partial).decode(),
               'skip_partial':skipping,'last_success':stamp,
               'truncated_line':self.truncated_line}
        entries=[]
        for row in parsed:
            try: occurred=datetime.strptime(row[0],'%d/%b/%Y:%H:%M:%S %z').timestamp()
            except ValueError: occurred=now.timestamp()
            entries.append((*row,occurred))
        with self.connect() as connection:
            connection.executemany('INSERT INTO requests(date,ip,domain,method,path,status,occurred_at) VALUES(?,?,?,?,?,?,?)',entries)
            connection.execute('DELETE FROM requests WHERE occurred_at < ?', (now.timestamp()-self.retention_days*86400,))
            connection.execute('INSERT INTO reader_state(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value',('npmplus',json.dumps(state)))
            rows=self._latest(connection)
        self.rows.clear()
        self.rows.extend(rows)
        self.identity=identity
        self.offset=offset
        self.anchor=anchor
        self.partial=partial
        self.skip_partial=skipping
        self.last_success=stamp
        self.catching_up=catching_up
        self.error=False

    def history(self,page=1):
        with self.connect() as connection:
            count=connection.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
            rows=self._latest(connection,page)
        return {'rows':rows,'count':count,'page':page,
                'pages':max(1,math.ceil(count/self.rows.maxlen)),
                'retention_days':self.retention_days}

http_reader = SqliteHttpLog(os.environ.get('FCP_HTTP_LOG', '/app/logs/access.log'),
                          os.environ.get('FCP_DATABASE', '/app/data/fcp.sqlite3'),
                          retention_days=int(os.environ.get('FCP_LOG_RETENTION_DAYS','30')))



def read_http_rows():
    return http_reader.poll()['rows']

def render_http_rows(rows):
    html = ""
    suspect = suspect_pattern
    for row in reversed(rows[-100:]):
        raw_date, raw_ip, raw_domain, raw_method, raw_path, raw_status = row
        kind = 'auth' if raw_status in ('401', '403') else 'server' if int(raw_status) >= 500 else 'missing' if raw_status in ('404', '429') else 'other'
        category = 'rate' if raw_status == '429' else kind
        is_suspect = bool(suspect.search(raw_path))
        labels = {'401': 'Authentification refusée', '403': 'Accès interdit', '404': 'Page introuvable', '429': 'Trop de requêtes', '500': 'Erreur interne', '502': 'Service en erreur', '503': 'Service indisponible', '504': 'Délai dépassé'}
        label = labels.get(raw_status, 'Réponse HTTP')
        date, ip, domain, method, path, status = map(escape, row)
        parts = raw_date.split(':', 1)
        date_display = escape(parts[1]) + '<span class="subline">' + escape(parts[0]) + '</span>' if len(parts) == 2 else date
        detail = 'Chemin suspect' if is_suspect else 'Refus d’accès' if kind == 'auth' else 'Erreur HTTP'
        html += f'<tr class="request-row {kind}" data-kind="{category}" data-suspect="{int(is_suspect)}"><td class="date">{date_display}</td><td class="ip">{ip}{geo_html(raw_ip)}</td><td>{domain}</td><td><span class="method">{method}</span></td><td class="path"><code>{path}</code><span class="subline">{detail}</span></td><td><span class="badge {kind}">{status} · {label}</span></td></tr>'
    return html

@app.route('/http/history')
def http_history():
    try:
        page=int(request.args.get('page','1'))
        if page < 1 or page > 100000:
            raise ValueError('Page invalide')
        history=http_reader.history(page)
        history['html']=render_http_rows(history.pop('rows'))
        return jsonify(history)
    except (ValueError,sqlite3.Error) as error:
        return jsonify(error=str(error)),400

BAN_MAP_HTML = '<dialog id="ban-map-dialog" aria-labelledby="ban-map-title"><div class="map-shell"><header class="map-header"><div><span class="map-eyebrow">FCP · SURVEILLANCE</span><h2 id="ban-map-title">Carte mondiale des IP</h2><p>Bannissements actifs et bans levés</p></div><button id="map-close" aria-label="Fermer la carte">✕</button></header><div class="map-toolbar"><label>Afficher<select id="map-state"><option value="banned">IP bannies</option><option value="unbanned">Bans levés</option><option value="all">Toutes les IP</option></select></label><label>Protection<select id="map-jail"><option value="">Toutes les protections</option></select></label><label class="map-search">Rechercher<input id="map-search" type="search" placeholder="IP, pays, ville, opérateur…"></label><button id="map-reload">Actualiser la carte</button></div><div id="map-status" role="status" aria-live="polite"></div><div class="map-layout"><div class="map-visual"><div class="map-canvas"><svg id="ban-world" viewBox="0 0 960 480" role="group" aria-label="Carte du monde : sélectionner un groupe d’IP"><rect x="-960" y="-480" width="2880" height="1440" fill="#e6eefc"/><g id="map-land"><path d="M960.0,282.8L960.0,284.1L958.3,284.8L956.6,285.4L956.3,284.4L957.6,283.8L958.4,283.7L960.0,282.8ZM955.0,286.7L955.7,286.2L956.6,287.0L956.1,288.4L954.5,288.8L953.0,288.4L952.8,287.3L953.8,286.3L955.0,286.7ZM0.6,282.7L0.2,284.0L0.0,284.1L0.0,282.8L0.6,282.7Z" fill-rule="evenodd"/><path d="M570.4,242.5L570.9,242.8L580.5,248.3L580.7,249.8L584.5,252.5L583.3,255.8L583.5,257.3L585.2,258.2L585.3,258.9L584.5,260.5L584.7,261.4L584.5,262.6L585.4,264.3L586.5,266.9L587.5,267.5L587.5,267.5L585.4,269.1L582.5,270.1L580.9,270.1L579.9,270.9L578.1,270.9L577.4,271.3L574.2,270.5L572.2,270.7L571.4,267.1L570.5,265.8L570.0,265.1L567.4,264.6L565.8,263.8L564.2,263.4L563.1,262.9L562.0,262.2L562.0,262.2L560.5,258.9L559.0,257.4L558.5,255.8L558.7,254.5L558.2,252.0L559.3,251.9L560.3,250.9L561.3,249.5L562.0,249.0L562.0,248.1L561.4,247.5L561.3,246.4L561.3,246.4L562.0,246.1L562.2,244.5L561.1,243.0L562.1,242.7L565.0,242.7L570.4,242.5Z" fill-rule="evenodd"/><path d="M456.9,166.2L456.9,166.4L456.8,166.9L456.8,171.0L448.1,170.8L448.2,177.7L445.7,177.9L445.0,179.3L445.5,183.1L435.1,183.1L434.5,184.0L434.6,182.9L434.7,182.9L440.7,182.7L441.0,181.7L442.1,180.5L443.0,176.8L446.7,173.9L447.9,170.6L448.8,170.4L449.6,168.3L451.9,168.0L452.8,168.4L454.0,168.4L454.9,167.8L456.5,167.7L456.5,166.2L456.9,166.2Z" fill-rule="evenodd"/><path d="M152.4,109.3L152.1,109.3L146.9,106.7L145.0,105.6L140.2,104.5L138.7,102.1L139.1,100.5L135.7,99.3L135.2,97.2L132.0,95.2L131.9,93.9L131.9,93.9L133.4,92.6L133.3,90.9L128.8,89.2L126.1,86.2L124.4,84.2L121.9,83.0L120.1,81.9L118.7,80.6L116.1,81.4L113.5,82.9L111.1,81.2L109.2,80.0L106.6,79.3L104.0,79.2L104.0,64.0L104.0,54.1L104.0,54.1L109.0,54.7L113.2,56.0L116.0,56.3L118.3,55.2L121.6,54.3L125.5,54.7L129.5,53.5L133.9,52.8L135.7,53.9L137.7,53.3L138.3,52.0L140.1,52.3L144.6,54.7L148.2,52.9L148.6,54.9L151.8,54.5L152.8,53.7L156.1,53.9L160.2,55.0L166.4,56.0L170.1,56.4L172.7,56.3L176.3,57.6L172.5,58.9L177.3,59.5L184.5,59.2L186.8,58.7L189.7,60.3L192.6,59.0L189.8,57.8L191.6,56.9L194.8,56.8L196.9,56.5L199.1,57.2L201.8,58.6L204.7,58.4L209.5,59.6L213.6,59.2L217.5,59.2L217.2,57.6L219.5,57.1L223.7,58.0L223.7,60.6L225.4,58.4L227.5,58.5L228.7,55.8L225.9,54.2L222.7,53.1L223.0,50.1L226.1,48.2L229.6,48.6L232.3,49.8L235.9,52.8L233.6,54.1L238.5,54.7L238.5,57.4L242.1,55.3L245.3,57.0L244.5,59.0L247.1,60.8L249.9,58.9L251.8,56.6L251.9,53.6L255.7,53.9L259.7,54.2L263.3,55.6L263.4,56.9L261.4,58.3L263.3,59.7L263.0,61.0L257.7,62.9L254.0,63.3L251.3,62.5L250.5,63.8L247.9,66.1L247.1,67.3L244.0,69.1L240.2,69.2L238.1,70.4L237.9,72.1L234.8,72.4L231.6,74.6L228.7,77.6L227.7,79.7L227.5,82.8L231.4,83.2L232.6,85.7L233.9,87.8L237.6,87.2L242.6,88.4L245.2,89.4L247.1,90.7L250.5,91.4L253.3,92.5L257.7,92.7L260.6,92.9L260.2,95.2L261.0,97.9L262.9,100.9L266.9,103.4L269.0,102.6L270.4,99.8L269.0,95.6L267.1,94.2L271.4,93.0L274.4,91.1L275.9,89.2L275.7,87.5L273.9,85.2L270.6,83.2L273.8,80.4L272.6,78.0L271.7,73.8L273.6,73.2L278.1,73.9L280.9,74.2L283.1,73.5L285.6,74.4L288.9,75.9L289.7,77.0L294.4,77.2L294.3,79.4L295.2,82.8L297.7,83.2L299.6,84.8L303.5,83.3L306.0,80.3L307.8,79.1L309.9,81.5L313.3,84.9L316.3,88.1L315.2,89.8L318.8,91.3L321.1,92.8L325.4,93.5L327.1,94.3L328.2,96.6L330.2,96.9L331.3,97.9L331.5,100.9L329.6,101.9L327.7,102.9L323.3,103.8L319.9,106.0L315.4,106.5L309.7,105.9L305.7,105.9L302.9,106.1L300.7,108.0L297.3,109.2L293.5,112.7L290.4,115.1L292.7,114.7L296.9,111.2L302.5,109.0L306.5,108.7L308.9,110.0L306.4,111.8L307.2,114.7L308.1,116.7L311.5,118.0L315.9,117.6L318.6,114.6L318.8,116.6L320.5,117.5L317.2,119.3L311.3,120.9L308.7,122.0L305.7,123.9L303.7,123.7L303.6,121.4L308.2,119.2L303.9,119.3L301.0,119.6L299.2,118.1L299.2,114.5L298.0,113.7L296.3,114.2L295.4,113.5L293.3,115.5L292.5,117.6L291.6,118.8L290.4,119.2L289.6,119.3L289.3,120.0L284.4,120.0L280.4,120.0L279.2,120.5L276.3,122.4L276.0,122.6L275.1,123.7L272.7,123.7L270.1,123.7L268.9,124.1L269.3,124.6L269.5,125.4L269.5,125.7L266.0,127.0L263.3,127.4L260.2,128.9L259.5,128.9L258.6,128.4L258.3,128.1L258.3,127.8L258.9,126.9L260.2,125.4L261.0,123.8L260.4,121.5L259.9,119.1L257.1,117.8L257.4,117.3L257.0,117.0L256.3,117.0L255.8,116.6L255.6,116.0L255.1,116.2L254.4,116.2L254.6,115.9L253.9,115.6L253.7,114.9L251.6,114.1L249.4,113.2L246.8,112.2L244.3,111.2L241.9,111.9L241.1,112.0L237.8,111.3L235.6,111.6L233.0,110.8L230.3,110.4L228.5,110.2L227.6,109.8L227.2,108.3L226.3,108.3L226.2,109.3L220.7,109.3L211.6,109.3L202.5,109.3L194.5,109.3L186.5,109.3L178.7,109.3L170.5,109.3L167.9,109.3L160.0,109.3L152.4,109.3ZM256.0,73.5L258.0,72.2L261.7,72.3L261.6,72.8L258.5,74.2L256.6,74.2L256.0,73.5ZM267.3,45.9L264.3,44.4L264.4,43.5L265.7,43.3L271.8,43.6L276.4,45.1L276.7,45.8L273.8,45.7L271.0,45.7L268.0,46.0L267.3,45.9ZM265.8,74.4L266.9,73.6L267.9,73.7L268.6,74.2L267.6,75.6L266.4,75.4L265.7,74.6L265.8,74.4ZM230.4,40.1L228.9,41.1L225.0,40.9L221.8,40.2L223.2,39.0L227.1,38.3L229.4,39.2L230.4,40.1ZM229.8,33.3L228.5,33.4L223.5,33.2L222.8,32.4L228.2,32.5L230.1,33.0L229.8,33.3ZM222.0,30.0L225.2,30.9L224.5,31.8L220.5,32.4L218.3,31.8L217.2,30.8L217.0,29.7L220.4,29.8L222.0,30.0ZM244.9,41.6L240.6,41.3L233.5,40.4L232.6,39.0L232.3,37.6L229.6,36.5L224.1,36.2L221.0,35.3L222.0,34.2L227.5,34.4L230.5,35.3L235.7,35.3L238.0,36.1L237.4,37.1L240.5,37.7L242.2,38.4L245.8,38.5L249.7,38.7L253.9,38.1L259.3,37.9L263.7,38.1L266.5,39.1L267.1,40.2L265.4,40.9L261.5,41.5L258.1,41.2L250.4,41.6L244.9,41.6ZM183.3,31.6L187.1,32.0L186.2,32.8L181.2,33.6L177.2,32.7L179.4,31.9L183.3,31.6ZM184.1,29.9L187.6,30.4L184.3,30.9L179.9,30.9L179.9,30.5L182.7,29.7L184.1,29.9ZM331.7,103.2L330.3,104.8L328.5,107.2L330.3,106.3L332.1,106.8L331.1,107.8L333.5,108.5L334.7,107.8L337.4,108.7L336.6,110.6L338.4,110.2L338.8,111.6L339.6,113.2L338.5,115.6L337.3,115.7L335.5,115.2L336.1,113.0L335.4,112.7L332.3,115.0L330.7,114.9L332.6,113.6L330.0,113.0L327.1,113.1L322.0,113.1L321.5,112.3L323.2,111.3L322.0,110.6L324.3,109.0L327.0,104.8L328.7,103.2L331.0,102.3L332.2,102.4L331.7,103.2ZM256.3,66.4L259.2,67.3L262.3,68.1L262.5,69.4L264.5,69.2L266.4,70.1L264.0,70.9L259.9,70.3L258.4,69.1L255.7,70.5L251.9,71.9L251.0,70.3L247.4,70.6L249.7,69.2L250.1,67.1L251.0,64.7L252.9,64.9L253.4,66.1L254.8,65.7L256.3,66.4ZM269.9,47.1L272.5,46.0L278.4,47.4L282.1,48.6L282.4,49.8L287.4,49.2L290.1,50.9L296.6,51.9L298.9,53.0L301.4,55.5L296.5,56.7L302.8,58.5L307.0,59.1L310.9,61.5L315.1,61.7L314.2,63.6L309.6,66.7L306.3,65.5L302.1,63.0L298.6,63.3L298.3,64.8L301.1,66.4L304.7,67.6L305.8,68.3L307.5,71.0L306.6,72.9L303.3,72.1L296.6,70.0L300.3,72.3L303.1,73.9L303.6,74.9L296.3,73.8L290.6,72.2L287.4,70.9L288.3,70.2L284.3,68.8L280.4,67.5L280.5,68.3L272.8,68.7L270.5,67.8L272.3,65.8L277.3,65.8L282.8,65.5L281.9,64.5L282.8,63.2L286.3,60.6L285.5,59.4L284.5,58.5L280.4,57.2L275.0,56.3L276.7,55.6L273.9,53.9L271.6,53.8L269.4,52.9L268.0,53.7L263.2,54.0L253.5,53.4L247.8,52.6L243.5,52.2L241.3,51.3L244.1,50.1L240.3,50.1L239.5,47.4L241.5,45.0L244.2,43.9L251.1,43.2L249.2,44.9L251.3,46.6L253.7,44.4L260.5,43.3L265.1,46.1L264.7,47.8L269.9,47.1ZM228.0,42.3L233.5,42.4L238.6,43.0L234.7,45.4L231.5,45.9L228.6,47.9L225.6,47.8L223.9,45.5L224.0,44.2L225.3,43.0L228.0,42.3ZM152.4,37.0L152.4,37.0L156.9,35.0L162.4,33.3L166.5,33.3L170.1,32.9L169.8,35.0L167.7,35.9L165.2,36.1L160.3,37.2L156.0,37.6L152.4,37.0ZM126.1,95.9L128.7,95.7L127.9,98.7L130.2,100.9L129.1,100.8L127.5,99.6L126.5,98.4L125.2,97.6L124.7,96.4L124.9,95.5L126.1,95.9ZM198.7,28.5L203.9,28.9L211.1,29.9L213.2,31.1L214.2,32.2L209.9,31.9L205.5,31.1L199.5,31.0L202.1,30.2L198.9,29.6L198.7,28.5ZM150.6,110.6L149.3,111.0L144.9,109.8L144.1,108.9L141.7,107.9L141.3,107.2L138.5,106.7L137.5,105.2L137.7,104.6L140.5,105.2L142.1,105.6L144.7,105.9L145.6,106.8L146.9,108.1L149.5,109.2L150.6,110.6ZM155.9,41.5L159.7,42.0L166.5,42.2L169.1,42.9L172.0,44.1L168.6,44.7L162.1,46.6L158.8,48.5L158.8,49.6L151.8,50.9L150.3,49.8L144.2,48.4L145.3,47.2L147.2,45.3L149.5,43.5L146.9,41.9L155.9,41.5ZM192.5,37.7L194.9,37.3L197.7,37.4L198.1,38.7L196.5,40.0L187.5,40.4L180.7,41.6L176.7,41.6L176.3,40.7L181.9,39.6L169.8,39.9L166.1,39.4L169.7,36.8L172.3,36.1L179.8,37.0L184.5,38.5L189.2,38.7L185.3,36.2L187.8,35.2L190.5,35.5L191.4,36.8L192.5,37.7ZM195.9,45.1L198.9,46.2L200.6,48.8L201.4,50.7L205.9,52.0L210.7,53.3L210.4,54.4L206.1,54.7L207.8,55.7L206.9,56.7L202.0,56.2L197.4,55.5L194.3,55.7L189.3,56.6L182.6,57.0L177.8,57.2L176.4,56.0L172.7,55.3L170.4,55.6L167.1,53.4L168.9,53.2L173.0,52.7L176.7,52.8L180.2,52.4L175.1,51.7L169.4,51.9L165.6,51.9L164.2,50.9L170.4,49.8L166.3,49.9L161.6,49.2L163.8,47.2L165.7,46.1L172.8,44.5L175.6,45.0L174.2,46.3L180.2,45.5L183.9,46.8L186.9,45.4L189.3,46.3L191.5,48.9L192.8,47.8L190.9,45.1L193.3,44.7L195.9,45.1ZM212.2,46.1L209.2,44.4L212.4,43.1L215.6,43.6L220.3,43.3L221.0,44.1L218.5,45.4L222.6,46.5L222.1,48.9L217.7,49.9L215.1,49.7L213.3,48.7L206.7,46.6L206.7,45.8L212.2,46.1ZM195.7,43.7L199.3,43.6L201.3,44.2L199.0,46.0L194.8,44.1L195.7,43.7ZM217.3,35.4L219.4,36.6L219.5,38.0L218.2,40.0L213.8,40.3L211.0,39.8L211.0,38.3L206.7,38.5L206.5,36.4L209.4,36.5L213.4,35.6L217.1,35.8L217.3,35.4ZM224.0,25.1L225.8,24.2L228.5,24.1L227.4,23.4L233.6,23.3L237.0,24.7L241.5,25.3L245.8,25.8L247.9,27.6L251.2,28.4L247.5,29.2L242.6,31.2L237.9,31.4L232.3,31.1L229.5,30.0L229.5,29.0L231.6,28.3L226.7,28.3L223.8,27.5L222.1,26.2L224.0,25.1ZM235.8,21.6L239.7,21.1L242.8,21.0L248.1,20.6L252.0,19.6L255.3,19.7L258.2,20.5L260.2,19.0L263.7,18.6L268.5,18.3L276.7,18.2L278.1,18.5L285.8,18.0L291.6,18.2L297.3,18.4L304.5,18.6L310.2,18.9L315.1,19.7L314.9,20.4L308.4,21.5L302.0,22.1L299.6,22.7L305.4,22.6L299.1,24.3L294.7,25.0L290.2,27.2L284.7,27.6L283.0,28.2L274.9,28.5L278.6,28.8L276.7,29.3L279.0,30.6L276.4,31.5L272.3,32.3L271.0,33.3L267.3,34.1L267.7,34.7L272.2,34.6L272.3,35.3L265.2,36.9L258.2,36.1L250.4,36.5L246.4,36.2L241.4,36.1L241.0,34.8L246.0,34.2L244.6,32.3L246.3,32.1L253.4,33.2L249.8,31.5L245.4,31.0L247.6,30.0L252.3,29.3L253.1,28.4L249.3,27.4L248.2,26.0L255.5,26.1L257.6,26.4L261.7,25.4L255.7,25.1L246.4,25.3L241.7,24.4L239.5,23.3L236.4,22.5L235.8,21.6ZM279.4,60.1L277.7,60.9L274.7,61.1L274.0,59.8L275.2,58.3L277.6,57.9L279.7,58.6L279.7,59.8L279.4,60.1ZM223.3,54.7L224.9,55.7L223.3,56.6L219.7,55.8L217.5,56.1L213.9,54.9L216.2,54.1L218.1,53.0L220.9,53.7L222.5,54.2L223.3,54.7ZM307.9,107.0L308.9,106.8L312.4,107.4L315.1,108.6L315.2,109.1L313.9,109.1L310.4,108.3L307.9,107.0ZM309.3,114.6L310.2,115.9L312.2,116.2L314.6,116.2L313.3,117.2L312.3,117.4L309.0,116.3L308.3,115.4L309.3,114.6Z" fill-rule="evenodd"/><path d="M152.4,109.3L160.0,109.3L167.9,109.3L170.5,109.3L178.7,109.3L186.5,109.3L194.5,109.3L202.5,109.3L211.6,109.3L220.7,109.3L226.2,109.3L226.3,108.3L227.2,108.3L227.6,109.8L228.5,110.2L230.3,110.4L233.0,110.8L235.6,111.6L237.8,111.3L241.1,112.0L241.9,111.9L244.3,111.2L246.8,112.2L249.4,113.2L251.6,114.1L253.7,114.9L253.9,115.6L254.6,115.9L254.4,116.2L255.1,116.2L255.6,116.0L255.8,116.6L256.3,117.0L257.0,117.0L257.4,117.3L257.1,117.8L259.9,119.1L260.4,121.5L261.0,123.8L260.2,125.4L258.9,126.9L258.3,127.8L258.3,128.1L258.6,128.4L259.5,128.9L260.2,128.9L263.3,127.4L266.0,127.0L269.5,125.7L269.5,125.4L269.3,124.6L268.9,124.1L270.1,123.7L272.7,123.7L275.1,123.7L276.0,122.6L276.3,122.4L279.2,120.5L280.4,120.0L284.4,120.0L289.3,120.0L289.6,119.3L290.4,119.2L291.6,118.8L292.5,117.6L293.3,115.5L295.4,113.5L296.3,114.2L298.0,113.7L299.2,114.5L299.2,118.1L301.0,119.6L301.4,120.5L298.6,121.8L295.8,122.7L293.0,123.5L291.6,125.1L291.2,125.7L291.1,127.1L292.0,128.5L293.1,128.6L292.8,127.6L293.6,128.2L293.4,129.0L291.6,129.4L290.3,129.3L288.4,129.8L287.2,129.9L285.7,130.1L283.4,130.9L287.4,130.3L288.1,130.9L284.4,131.7L282.7,131.7L282.8,131.3L282.0,132.1L282.8,132.2L282.2,134.1L280.3,136.2L280.1,135.5L279.5,135.3L278.6,134.7L279.1,136.1L279.8,136.6L279.8,137.6L279.0,138.6L277.5,140.8L277.2,140.6L278.1,138.8L276.7,137.8L276.4,135.6L275.9,136.8L276.5,138.4L274.7,138.0L276.5,138.9L276.6,141.4L277.4,141.6L277.7,142.5L278.1,145.2L276.4,147.2L273.6,148.0L271.9,149.5L270.5,149.7L269.2,150.7L268.8,151.6L265.9,153.3L264.4,154.6L263.1,156.2L262.7,158.1L263.2,159.9L264.1,162.2L265.2,164.1L265.3,165.2L266.5,168.3L266.4,170.1L266.3,171.2L265.7,172.8L264.9,173.1L263.5,172.8L263.1,171.6L262.1,171.0L260.7,168.7L259.5,166.7L259.1,165.6L259.6,163.9L258.9,162.4L256.8,160.2L255.7,159.8L253.0,161.0L252.6,160.8L251.3,159.6L249.6,158.9L246.6,159.3L244.2,159.0L242.2,159.2L241.1,159.6L241.6,160.3L241.5,161.4L242.1,161.9L241.6,162.2L240.6,161.8L239.6,162.4L237.7,162.3L235.7,160.9L233.3,161.2L231.4,160.6L229.7,160.8L227.5,161.4L225.1,163.4L222.4,164.5L221.0,165.8L220.3,167.0L220.3,168.8L220.5,170.1L221.0,171.0L219.9,171.1L218.0,170.5L215.9,169.7L215.2,168.4L214.6,166.6L213.0,165.0L212.1,163.5L210.8,161.7L208.9,160.6L206.7,160.6L205.0,162.7L202.8,161.9L201.4,161.1L200.8,159.7L199.9,158.3L198.3,157.1L197.0,156.3L196.0,155.3L191.4,155.3L191.4,156.4L189.2,156.4L183.9,156.4L177.9,154.6L173.8,153.3L174.1,152.7L170.7,153.0L167.7,153.2L167.2,151.9L165.5,150.3L164.2,150.0L163.9,149.3L162.5,149.1L161.5,148.4L159.0,148.1L158.3,147.7L158.0,146.2L155.4,143.6L153.2,139.9L153.3,139.2L152.1,138.4L150.1,136.1L149.7,134.0L148.3,132.5L148.9,130.3L148.8,128.0L147.9,126.0L149.0,123.4L149.3,121.0L149.6,118.6L149.1,115.0L148.3,112.7L147.5,111.5L147.8,111.0L151.7,111.9L153.1,114.4L153.8,113.7L153.3,111.5L152.4,109.3ZM65.6,186.5L66.1,186.7L66.5,187.0L67.2,188.0L67.1,188.1L66.1,188.7L65.2,189.1L64.8,189.6L64.2,189.2L64.2,188.4L63.8,187.5L63.9,187.2L64.4,186.7L64.2,186.2L64.4,186.0L64.6,186.0L65.6,186.5ZM64.0,184.6L63.8,184.9L62.9,185.1L62.4,184.6L62.1,184.4L62.1,184.2L62.4,184.0L63.3,184.2L64.0,184.6ZM62.0,183.5L61.9,183.8L60.5,183.7L60.7,183.4L62.0,183.5ZM58.6,182.1L58.8,182.3L59.6,183.1L59.4,183.3L59.3,183.3L58.3,183.2L58.0,182.6L57.9,182.5L58.6,182.1ZM55.0,180.8L55.1,181.4L54.8,181.6L53.9,181.2L54.0,181.0L54.4,180.7L55.0,180.8ZM36.1,79.0L38.2,79.2L38.5,80.2L36.8,80.7L35.1,80.2L33.5,79.4L36.1,79.0ZM71.4,85.4L73.2,85.6L74.3,86.4L72.0,87.7L69.3,88.7L68.0,88.0L67.5,86.8L70.0,85.8L71.4,85.4ZM104.0,54.1L104.0,54.1L104.0,64.0L104.0,79.2L106.6,79.3L109.2,80.0L111.1,81.2L113.5,82.9L116.1,81.4L118.7,80.6L120.1,81.9L121.9,83.0L124.4,84.2L126.1,86.2L128.8,89.2L133.3,90.9L133.4,92.6L131.9,93.9L131.9,93.9L131.9,93.9L130.4,92.9L128.1,92.0L127.3,89.7L123.9,87.5L122.5,85.0L119.9,84.8L115.7,84.8L112.5,84.0L107.0,81.2L104.5,80.7L99.8,79.8L96.1,80.0L90.9,78.8L87.7,77.6L84.7,78.2L85.3,80.1L83.8,80.2L80.7,80.8L78.4,81.7L75.4,82.3L75.0,80.7L76.2,78.1L79.1,77.2L78.3,76.6L74.9,78.1L73.1,79.8L69.3,81.7L71.2,83.0L68.7,84.9L65.8,86.1L63.2,86.9L62.5,88.1L58.4,89.4L57.5,90.7L54.4,91.8L52.6,91.6L50.1,92.4L47.4,93.3L45.1,94.2L40.6,94.9L40.2,94.5L43.1,93.2L45.7,92.4L48.5,90.9L51.8,90.6L53.1,89.6L56.8,88.0L57.4,87.4L59.4,86.5L59.9,84.5L61.2,82.9L58.1,83.7L57.3,83.2L55.8,84.2L54.1,82.8L53.4,83.8L52.4,82.5L49.7,83.5L48.1,83.5L47.9,82.0L48.3,81.0L46.6,80.0L43.2,80.5L40.9,79.3L39.1,78.6L39.1,77.1L37.0,76.0L38.0,74.5L40.2,73.0L41.2,71.6L43.3,71.4L45.2,71.8L47.3,70.6L49.2,70.8L51.3,70.0L50.8,68.7L49.3,68.3L51.3,67.2L49.6,67.3L46.8,67.8L46.0,68.4L43.9,67.8L40.1,68.1L36.2,67.5L35.1,66.4L31.7,64.9L35.5,63.8L41.4,62.5L43.6,62.5L43.2,63.8L48.9,63.7L46.7,62.0L43.4,61.0L41.5,59.7L39.0,58.6L35.3,57.7L36.8,56.3L41.5,56.2L44.9,55.0L45.5,53.7L48.2,52.4L50.8,52.1L55.9,51.0L58.3,51.1L62.5,49.7L66.5,50.3L68.4,51.5L69.6,51.0L74.1,51.1L73.9,51.7L78.0,52.2L80.7,51.9L86.4,52.8L91.5,53.0L93.5,53.4L97.1,52.9L101.1,53.7L104.0,54.1L104.0,54.1ZM22.0,69.9L23.7,70.4L25.4,70.1L27.5,70.9L30.2,71.2L29.9,71.5L27.9,72.1L25.9,71.5L24.9,71.0L22.5,71.2L21.9,70.9L22.0,69.9Z" fill-rule="evenodd"/><path d="M713.0,108.8L710.9,110.5L708.7,110.8L708.6,113.5L707.1,114.7L701.8,113.8L699.9,118.6L698.5,119.2L693.2,120.2L695.6,124.9L693.8,125.5L694.0,127.1L692.4,126.7L691.0,125.7L687.1,125.4L682.7,125.4L681.7,125.7L677.9,124.5L676.4,125.1L676.0,126.7L671.6,125.7L669.8,126.1L669.2,127.3L667.7,127.8L664.2,129.6L663.0,131.6L662.0,131.6L661.3,130.3L657.9,130.2L657.4,128.0L656.1,128.0L656.3,125.3L653.1,123.4L648.5,123.6L645.4,124.0L642.8,121.6L640.6,120.6L636.5,118.7L636.0,118.4L629.1,120.0L629.2,129.8L627.9,130.0L626.0,127.9L624.2,127.1L621.2,127.7L620.0,128.6L619.9,127.9L620.5,126.8L620.0,125.9L616.9,125.0L615.7,122.6L614.2,121.9L614.1,121.0L616.7,121.3L616.8,119.3L619.1,118.9L621.4,119.3L621.9,116.7L621.4,115.1L618.8,115.2L616.5,114.5L613.4,115.7L610.9,116.3L609.6,115.8L609.9,114.5L608.2,112.7L606.2,112.8L603.9,110.9L605.4,108.9L604.7,108.4L606.8,105.5L609.5,107.0L609.9,105.1L615.4,102.2L619.5,102.1L625.4,103.9L628.6,105.0L631.4,103.9L635.6,103.8L639.0,105.2L639.8,104.4L643.6,104.5L644.2,103.3L639.9,101.4L642.5,100.1L642.0,99.4L644.5,98.7L642.6,96.9L643.8,96.0L653.8,95.1L655.1,94.4L661.8,93.4L664.2,92.3L669.0,92.9L669.8,95.6L672.6,95.0L676.0,95.9L675.8,97.4L678.4,97.2L685.0,94.7L684.1,95.5L687.5,97.6L693.4,104.4L694.8,103.0L698.5,104.5L702.4,103.8L703.8,104.3L705.1,105.8L707.0,106.4L708.1,107.5L711.5,107.1L713.0,108.8Z" fill-rule="evenodd"/><path d="M629.2,129.8L629.1,120.0L636.0,118.4L636.5,118.7L640.6,120.6L642.8,121.6L645.4,124.0L648.5,123.6L653.1,123.4L656.3,125.3L656.1,128.0L657.4,128.0L657.9,130.2L661.3,130.3L662.0,131.6L663.0,131.6L664.2,129.6L667.7,127.8L669.2,127.3L670.0,127.6L667.8,129.3L669.8,130.3L671.7,129.6L674.8,131.0L671.4,132.9L669.4,132.7L668.3,132.8L667.9,132.0L668.4,130.8L664.9,131.4L664.0,133.1L662.8,134.6L660.5,134.5L659.8,135.6L661.8,136.3L662.4,138.2L660.9,140.9L658.9,140.4L657.4,140.4L657.5,138.7L653.9,137.6L651.1,136.3L649.4,135.0L646.3,133.2L645.0,130.4L644.1,130.0L641.2,130.1L640.2,129.5L639.9,127.4L636.3,126.0L634.1,127.5L631.8,128.5L632.3,129.8L629.2,129.8Z" fill-rule="evenodd"/><path d="M856.0,246.9L860.6,248.8L865.6,250.3L867.4,251.7L868.9,253.0L869.3,254.6L873.7,256.2L874.4,257.6L871.9,257.9L872.5,259.7L874.9,261.5L876.6,264.3L878.2,264.2L878.0,265.4L880.1,265.8L879.3,266.3L882.1,267.4L881.8,268.2L880.1,268.4L879.4,267.7L877.1,267.4L874.4,267.0L872.4,265.3L870.8,263.8L869.5,261.5L866.0,260.3L863.7,261.1L862.1,262.0L862.4,264.0L860.3,264.9L858.8,264.4L856.1,264.3L856.0,255.6L856.0,246.9ZM887.0,249.8L888.1,250.6L888.4,252.0L887.5,252.7L887.0,251.1L886.4,250.1L885.2,249.2L883.7,248.1L881.8,247.3L882.5,246.7L883.9,247.4L884.9,248.0L886.0,248.6L887.0,249.8ZM883.5,255.6L882.0,256.2L880.6,256.8L879.2,256.8L877.0,256.1L875.5,255.3L875.7,254.5L878.1,254.9L879.6,254.7L880.0,253.4L880.4,253.3L880.6,254.8L882.2,254.5L882.9,253.6L884.4,252.7L884.1,251.1L885.7,251.1L886.2,251.5L886.2,253.0L885.3,254.6L883.9,254.8L883.5,255.6ZM892.7,254.2L893.5,254.8L894.8,256.5L896.1,257.4L895.7,258.2L894.9,258.5L893.8,257.4L892.6,255.7L892.0,253.7L892.4,253.4L892.7,254.2Z" fill-rule="evenodd"/><path d="M856.0,246.9L856.0,255.6L856.1,264.3L853.7,262.1L851.0,261.6L850.4,262.3L847.0,262.4L848.1,260.3L849.8,259.5L849.1,256.6L847.8,254.4L842.6,252.1L840.4,251.9L836.4,249.4L835.6,250.7L834.6,251.0L834.0,250.0L834.0,248.8L832.0,247.5L834.8,246.6L836.7,246.6L836.5,245.9L832.6,245.9L831.6,244.3L829.2,243.8L828.1,242.5L831.6,241.9L833.0,241.0L837.3,242.1L837.7,243.1L838.5,247.4L841.2,249.0L843.4,246.2L846.5,244.5L848.9,244.5L851.2,245.5L853.1,246.4L856.0,246.9ZM813.2,263.7L813.5,264.2L813.6,265.0L811.8,267.0L809.5,267.6L809.2,267.3L809.5,266.4L810.6,264.8L813.2,263.7ZM837.9,258.4L837.6,256.4L838.1,255.4L838.7,254.5L839.3,255.3L839.3,256.6L837.9,258.4ZM794.4,229.0L792.8,231.4L794.8,233.9L794.3,235.1L797.3,237.6L794.2,237.9L793.3,239.7L793.4,242.1L790.8,244.0L790.8,246.6L789.7,250.7L789.3,249.8L786.3,251.0L785.2,249.3L783.3,249.2L782.0,248.3L778.8,249.3L777.9,248.0L776.1,248.1L773.9,247.8L773.5,244.2L772.2,243.5L770.9,241.2L770.5,238.9L770.9,236.4L772.4,234.6L772.9,236.4L774.7,237.9L776.4,237.4L778.1,237.6L779.7,236.2L781.0,236.0L783.5,236.8L785.7,236.2L787.0,232.5L788.1,231.5L789.0,228.5L792.0,228.5L794.4,229.0ZM825.0,247.5L827.9,248.3L828.9,250.3L826.6,249.2L824.4,249.0L822.9,249.1L821.1,249.0L821.7,247.6L825.0,247.5ZM818.3,250.1L816.5,249.6L816.0,248.5L818.7,248.3L819.3,249.2L818.3,250.1ZM821.2,234.2L821.3,235.7L822.9,235.9L823.2,237.0L823.0,239.3L821.7,239.0L821.2,240.7L822.3,242.1L821.6,242.4L820.5,240.7L819.7,237.3L820.3,235.2L821.2,234.2ZM807.8,237.7L810.9,237.6L813.5,235.6L814.0,236.2L811.8,238.9L809.8,239.4L807.3,238.9L802.8,239.0L800.5,239.4L800.1,241.4L802.5,243.8L803.9,242.5L808.9,241.6L808.7,242.9L807.5,242.5L806.4,244.0L804.0,245.1L806.5,248.5L806.1,249.4L808.5,252.5L808.4,254.2L807.0,255.0L806.0,254.1L807.3,251.9L804.6,252.9L804.0,252.2L804.3,251.2L802.4,249.6L802.6,247.0L800.8,247.8L801.0,250.9L801.1,254.7L799.5,255.1L798.3,254.3L799.1,251.9L798.7,249.3L797.5,249.3L796.7,247.5L797.8,245.7L798.2,243.6L799.5,239.6L800.1,238.5L802.4,236.5L804.4,237.3L807.8,237.7ZM800.8,267.4L797.2,265.5L799.7,265.0L801.1,265.8L802.1,266.6L801.9,267.3L800.8,267.4ZM803.6,262.8L805.4,262.6L807.7,261.6L807.4,263.1L803.3,263.8L799.8,263.5L799.8,262.5L801.9,262.0L803.6,262.8ZM795.4,262.3L797.0,262.1L797.7,263.2L794.6,263.8L792.7,264.1L791.3,264.1L792.2,262.6L793.7,262.5L794.4,261.6L795.4,262.3ZM769.3,257.1L769.7,258.1L774.8,258.3L775.4,257.2L780.3,258.5L781.3,260.3L785.3,260.7L788.5,262.3L785.5,263.3L782.6,262.3L780.2,262.3L777.4,262.1L774.9,261.7L771.8,260.6L769.8,260.4L768.7,260.7L763.9,259.6L763.4,258.5L761.0,258.3L762.8,255.7L766.0,255.9L768.2,256.9L769.3,257.1ZM758.3,242.9L758.8,244.8L759.7,246.2L761.7,246.5L763.0,248.2L762.3,251.5L762.2,255.6L759.2,255.7L757.0,253.4L753.6,251.3L752.4,249.6L750.4,247.5L749.1,245.5L747.0,241.7L744.7,239.5L743.9,237.2L742.9,235.1L740.5,233.5L739.1,231.2L737.1,229.7L734.3,226.7L734.1,225.4L735.8,225.5L740.0,226.0L742.3,228.6L744.4,230.4L745.9,231.5L748.4,234.4L751.1,234.4L753.3,236.3L754.9,238.5L756.9,239.7L755.8,241.9L757.4,242.8L758.3,242.9Z" fill-rule="evenodd"/><path d="M297.0,380.4L298.0,381.6L299.3,383.6L302.8,385.2L306.5,385.9L305.3,387.2L302.8,387.3L301.4,386.4L299.8,386.3L297.0,386.3L297.0,380.4ZM326.3,320.6L325.7,322.7L325.0,325.5L325.0,328.1L324.4,328.7L324.2,330.4L324.0,331.8L327.4,334.1L327.0,335.9L328.7,337.1L328.6,338.4L326.0,341.8L322.0,343.3L316.7,343.8L313.8,343.5L314.3,345.1L313.8,347.1L314.3,348.5L312.7,349.4L309.9,349.8L307.4,348.8L306.4,349.5L306.7,352.2L308.5,353.0L310.0,352.1L310.8,353.5L308.3,354.3L306.2,356.0L305.8,358.7L305.2,360.1L302.6,360.1L300.5,361.5L299.8,363.5L302.4,365.4L305.0,366.0L304.0,368.4L300.9,369.9L299.2,373.0L296.7,374.0L295.6,375.3L296.5,378.1L298.3,379.6L297.1,379.5L294.7,379.0L288.2,378.7L287.1,377.1L287.2,375.1L285.4,375.3L284.5,374.3L284.2,371.5L286.3,370.3L287.1,368.7L286.8,367.3L288.2,365.0L289.2,361.5L288.9,359.9L290.1,359.4L289.8,358.4L288.6,357.9L289.4,356.8L288.2,355.8L287.6,352.7L288.7,352.1L288.2,348.9L288.9,346.2L289.6,343.8L291.2,342.8L290.4,340.2L290.3,337.8L292.4,336.0L292.3,333.8L293.8,331.2L293.8,328.7L293.1,328.2L291.9,323.6L293.5,320.9L293.3,318.3L294.3,315.9L296.0,313.4L297.9,311.7L297.1,310.7L297.6,309.8L297.6,305.4L300.5,304.1L301.4,301.3L301.0,300.6L303.3,298.2L306.8,298.9L308.3,300.8L309.4,298.6L312.4,298.8L312.8,299.3L317.7,303.7L319.9,304.1L323.2,306.1L325.9,307.1L326.3,308.3L323.7,312.3L326.4,313.1L329.4,313.5L331.5,313.0L333.9,311.0L334.3,308.6L335.7,308.1L337.0,309.7L336.9,311.8L334.7,313.3L332.9,314.4L329.9,316.9L326.3,320.6Z" fill-rule="evenodd"/><path d="M297.0,380.4L297.0,386.3L299.8,386.3L301.4,386.4L300.6,387.5L298.3,388.3L297.0,388.2L295.4,388.0L293.4,387.2L290.7,386.8L287.3,385.3L284.6,383.9L280.9,380.9L283.1,381.5L286.8,383.2L290.4,384.2L291.8,383.0L292.6,381.1L295.1,380.0L297.0,380.4ZM294.4,286.9L295.7,288.7L296.1,290.6L297.5,291.7L296.6,294.3L298.1,297.3L299.1,301.0L301.0,300.6L301.4,301.3L300.5,304.1L297.6,305.4L297.6,309.8L297.1,310.7L297.9,311.7L296.0,313.4L294.3,315.9L293.3,318.3L293.5,320.9L291.9,323.6L293.1,328.2L293.8,328.7L293.8,331.2L292.3,333.8L292.4,336.0L290.3,337.8L290.4,340.2L291.2,342.8L289.6,343.8L288.9,346.2L288.2,348.9L288.7,352.1L287.6,352.7L288.2,355.8L289.4,356.8L288.6,357.9L289.8,358.4L290.1,359.4L288.9,359.9L289.2,361.5L288.2,365.0L286.8,367.3L287.1,368.7L286.3,370.3L284.2,371.5L284.5,374.3L285.4,375.3L287.2,375.1L287.1,377.1L288.2,378.7L294.7,379.0L297.1,379.5L294.8,379.4L293.5,380.1L291.1,381.1L290.6,383.6L289.5,383.6L286.5,382.8L283.5,380.9L283.5,380.9L280.1,379.4L279.3,377.7L280.1,376.1L278.7,374.3L278.4,369.8L279.5,367.2L282.3,365.2L278.3,364.4L280.8,362.0L281.7,357.6L284.7,358.5L286.1,353.0L284.3,352.3L283.5,355.6L281.8,355.3L282.6,351.5L283.5,346.5L284.8,344.7L284.0,342.1L283.8,339.1L284.9,339.0L286.5,334.7L288.4,330.4L289.5,326.5L288.9,322.5L289.7,320.3L289.4,317.0L290.9,313.7L291.4,308.5L292.3,303.0L293.1,297.0L292.9,292.7L292.3,288.9L293.7,288.2L294.4,286.9Z" fill-rule="evenodd"/><path d="M558.2,252.0L558.7,254.5L558.5,255.8L559.0,257.4L560.5,258.9L562.0,262.2L562.0,262.2L560.9,262.0L557.3,262.4L556.6,262.7L555.9,264.4L556.5,265.6L556.0,268.8L555.7,271.4L556.4,271.9L558.2,273.0L559.0,272.5L559.2,275.4L557.2,275.3L556.1,273.9L555.1,272.7L553.0,272.4L552.4,271.0L550.8,271.8L548.7,271.4L547.8,270.2L546.1,270.0L544.8,270.0L544.7,269.2L543.8,269.1L542.6,269.0L540.9,269.4L539.7,269.3L539.1,269.6L539.2,266.4L538.3,265.4L538.1,263.8L538.5,262.1L538.0,261.1L537.9,259.4L534.7,259.5L534.9,258.5L533.6,258.5L533.4,259.0L531.8,259.1L531.1,260.6L530.7,261.3L529.2,260.9L528.4,261.3L526.6,261.5L525.6,260.1L525.0,259.3L524.2,257.7L523.5,255.7L515.7,255.6L514.7,256.0L514.0,255.9L512.9,256.3L512.5,255.4L513.2,255.2L513.2,254.0L513.7,253.3L514.7,252.7L515.4,253.0L516.3,252.0L517.7,252.0L517.9,252.8L518.9,253.3L520.5,251.6L522.0,250.3L522.7,249.4L522.6,247.2L523.8,244.6L525.0,243.3L526.7,242.0L527.0,241.1L527.1,240.2L527.5,239.2L527.4,237.7L527.7,235.4L528.3,233.7L529.1,232.3L529.2,230.7L529.4,228.8L530.5,227.4L531.9,226.6L534.1,227.5L535.8,228.5L537.8,228.7L539.7,229.3L540.5,227.6L540.9,227.4L542.1,227.7L545.1,226.4L546.1,226.9L547.0,226.9L547.4,226.2L548.4,226.0L550.4,226.3L552.1,226.3L553.0,226.0L554.6,228.2L555.8,228.6L556.5,228.1L557.8,228.3L559.2,227.7L559.9,228.9L562.2,230.6L562.2,230.6L562.1,233.8L563.1,234.1L562.3,235.1L561.2,235.8L560.2,237.2L559.7,238.4L559.5,240.5L558.9,241.6L558.9,243.6L558.1,244.3L558.0,245.9L557.6,246.1L557.4,247.6L558.1,248.8L558.2,252.0Z" fill-rule="evenodd"/><path d="M590.9,244.5L589.3,242.3L589.3,232.6L591.6,229.5L592.3,228.7L594.1,228.7L596.4,226.8L599.9,226.7L607.4,218.7L609.3,216.4L610.5,214.8L610.5,213.4L610.5,210.7L610.5,209.6L610.5,209.6L610.5,209.6L611.4,209.5L612.6,209.1L614.0,208.9L615.3,207.9L616.3,207.9L616.4,208.7L616.1,210.2L616.1,211.6L615.6,212.6L614.8,215.5L613.5,218.4L611.9,221.9L609.6,225.8L607.3,228.7L604.2,232.4L601.5,234.5L597.5,237.2L595.0,239.2L592.1,242.5L591.5,243.9L590.9,244.5Z" fill-rule="evenodd"/><path d="M584.5,252.5L580.7,249.8L580.5,248.3L570.9,242.8L570.4,242.5L570.4,239.7L571.1,238.6L572.5,236.9L573.4,234.9L572.3,231.9L571.9,230.5L570.7,228.7L572.3,227.1L574.1,225.3L575.5,225.8L575.5,227.3L576.4,228.1L578.3,228.1L581.7,230.4L582.5,230.4L583.1,230.4L583.7,230.7L585.5,230.9L586.3,229.8L588.7,228.6L589.8,229.5L591.6,229.5L589.3,232.6L589.3,242.3L590.9,244.5L589.0,245.6L588.4,246.7L587.4,246.9L587.0,248.7L586.1,249.8L585.6,251.6L584.5,252.5Z" fill-rule="evenodd"/><path d="M545.5,218.1L543.5,216.9L542.6,216.1L542.4,215.3L542.8,214.2L542.8,213.1L541.3,211.4L541.0,210.3L541.0,209.6L540.0,208.9L540.0,207.3L539.4,206.3L538.5,206.4L538.8,205.5L539.5,204.3L539.2,203.2L540.0,202.4L539.5,201.8L540.2,200.1L541.4,198.2L543.7,198.4L543.6,187.8L543.6,186.7L546.7,186.7L546.7,181.3L557.4,181.3L567.7,181.3L578.3,181.3L579.2,183.9L578.6,184.4L579.0,187.2L580.0,190.4L581.0,191.0L582.4,192.0L581.1,193.5L579.1,194.0L578.3,194.8L578.0,196.6L576.9,200.5L577.1,201.5L576.7,203.8L575.6,206.5L574.0,207.8L572.9,209.8L572.6,210.9L571.4,211.7L570.6,214.4L570.6,216.8L570.6,214.8L570.2,214.7L570.2,213.4L569.9,212.5L568.6,211.4L568.2,209.5L568.6,207.5L567.3,207.3L567.1,207.9L565.5,208.1L566.2,208.8L566.4,210.5L564.9,211.9L563.6,213.8L562.2,214.1L560.0,212.6L559.0,213.1L558.7,213.9L557.3,214.4L557.2,214.9L554.6,214.9L554.2,214.4L552.3,214.3L551.3,214.8L550.6,214.5L549.2,213.0L548.8,212.2L546.9,212.6L546.1,213.8L545.4,216.2L544.5,216.7L543.7,217.0L545.5,218.1Z" fill-rule="evenodd"/><path d="M543.6,187.8L543.7,198.4L541.4,198.2L540.2,200.1L539.5,201.8L540.0,202.4L539.2,203.2L539.5,204.3L538.8,205.5L538.5,206.4L539.4,206.3L540.0,207.3L540.0,208.9L541.0,209.6L541.0,210.3L539.3,210.7L537.9,211.8L536.0,214.7L533.5,216.0L530.9,215.8L530.2,216.0L530.4,217.0L529.0,217.9L527.9,219.0L524.5,220.0L523.9,219.4L523.4,219.3L522.9,220.0L520.7,220.2L521.2,219.5L520.3,217.6L519.9,216.5L518.8,216.1L517.2,214.5L517.8,213.3L519.0,213.5L519.8,213.4L521.2,213.4L519.8,211.0L519.9,209.2L519.7,207.4L518.7,205.7L518.9,204.5L517.2,204.4L517.2,202.7L516.1,201.7L517.3,198.2L520.7,195.7L520.8,192.2L521.8,186.8L522.4,185.6L521.3,184.7L521.3,183.9L520.3,183.2L519.6,179.0L522.3,177.6L532.9,182.7L543.6,187.8Z" fill-rule="evenodd"/><path d="M288.8,187.4L289.0,188.9L288.8,189.9L288.1,190.4L288.8,191.2L288.8,191.9L287.0,191.4L285.7,191.6L284.1,191.4L282.9,191.9L281.4,191.1L281.7,190.2L284.1,190.6L286.1,190.8L287.1,190.2L285.9,189.1L285.9,188.0L284.2,187.6L284.8,186.9L286.5,187.0L288.8,187.4Z" fill-rule="evenodd"/><path d="M288.8,191.9L288.8,191.2L288.1,190.4L288.8,189.9L289.0,188.9L288.8,187.4L289.1,187.0L291.2,187.0L292.8,187.7L293.5,187.6L293.9,188.6L295.4,188.5L295.3,189.3L296.5,189.4L297.8,190.4L296.8,191.5L295.6,190.9L294.3,191.0L293.5,190.9L293.0,191.3L292.0,191.5L291.5,190.9L290.7,191.2L289.6,193.1L288.9,192.6L288.8,191.9Z" fill-rule="evenodd"/><path d="M956.6,50.4L960.0,49.3L960.0,51.1L957.1,51.3L956.6,50.4ZM610.9,116.3L609.7,117.8L607.1,118.3L604.5,121.0L606.9,123.6L606.6,125.4L609.6,128.5L609.6,128.5L608.0,129.6L607.5,130.3L606.3,130.1L604.5,128.5L603.7,128.4L602.1,127.8L601.3,126.7L598.8,126.1L597.1,126.5L596.7,126.0L593.1,124.7L589.1,124.3L586.9,123.9L586.5,124.2L583.1,121.9L580.1,120.9L577.8,119.3L579.7,118.9L582.0,116.7L580.5,115.6L584.4,114.5L584.3,114.0L581.9,114.4L582.0,113.2L583.4,112.5L586.0,112.3L586.4,111.4L585.8,109.9L586.9,108.5L586.9,107.7L582.9,106.9L581.4,106.9L579.7,105.6L577.7,106.1L574.3,105.1L574.3,104.6L573.4,103.4L571.3,103.3L571.0,102.5L571.7,101.9L570.0,100.4L567.2,100.7L566.4,100.6L565.8,101.2L564.8,101.1L564.8,101.1L564.1,99.4L563.5,98.5L564.0,98.2L566.1,98.3L567.2,97.7L566.4,97.0L564.6,96.5L564.8,96.1L563.7,95.6L562.0,93.8L562.6,93.1L562.3,91.9L559.7,91.2L558.3,91.5L557.9,90.9L555.1,90.2L554.3,88.6L554.1,87.3L552.8,86.7L553.9,85.9L553.1,83.4L555.0,81.9L554.6,81.4L554.6,81.4L557.6,79.9L554.9,78.7L554.9,78.7L560.6,75.3L563.0,73.7L564.0,72.4L560.1,70.5L561.2,68.8L558.8,66.8L560.6,64.5L557.5,61.5L559.9,59.5L555.9,57.7L556.2,55.8L558.4,55.6L562.9,54.5L562.9,54.5L565.7,53.6L570.1,55.2L577.4,55.8L587.4,58.8L589.5,60.1L589.7,61.9L586.7,63.3L582.4,64.0L570.4,62.0L568.5,62.3L572.8,64.3L573.0,65.5L573.2,68.2L576.6,69.0L578.7,69.7L579.0,68.4L577.4,67.3L579.1,66.3L585.6,67.9L587.8,67.3L586.0,65.3L592.2,62.7L594.7,62.9L597.2,63.8L598.8,62.0L596.5,60.4L597.8,58.8L595.9,57.1L603.3,58.0L604.9,59.5L601.5,59.8L601.5,61.3L603.6,62.2L607.7,61.6L608.4,59.9L613.9,58.7L623.2,56.4L625.3,56.5L622.6,58.1L625.9,58.4L627.8,57.5L632.8,57.4L636.8,56.3L639.8,57.9L642.9,56.2L640.1,54.6L641.5,53.7L649.3,54.5L653.0,55.4L662.7,58.4L664.5,57.0L661.8,55.6L661.7,55.0L658.5,54.8L659.4,53.5L657.9,51.4L657.9,50.6L662.8,48.2L664.5,45.8L666.5,45.2L673.6,45.9L674.1,47.4L671.6,49.6L673.3,50.4L674.1,52.3L673.5,55.9L676.4,57.6L675.3,59.4L670.1,63.1L673.1,63.5L674.2,62.6L677.1,61.9L677.8,60.6L680.1,59.3L678.6,57.8L679.8,56.0L676.9,55.8L676.3,54.3L678.4,51.6L674.9,49.5L679.7,47.7L679.1,45.8L680.4,45.7L681.8,47.2L680.8,49.8L683.6,50.3L682.4,48.3L686.9,47.3L692.4,47.1L697.3,48.7L695.0,46.4L694.7,43.6L699.3,43.1L705.7,43.2L711.5,42.8L709.4,41.4L712.4,39.7L715.5,39.6L720.7,38.3L727.7,37.9L728.6,37.2L735.6,37.0L737.8,37.6L743.8,36.1L748.7,36.2L749.4,35.0L752.0,33.9L758.3,32.8L762.8,33.7L759.2,34.3L765.3,34.7L766.0,36.1L768.4,35.4L776.2,35.4L782.2,36.7L784.4,37.7L783.7,39.1L780.7,39.9L773.7,41.4L771.7,42.2L775.0,42.6L779.0,43.2L781.4,42.7L782.7,44.4L783.9,43.7L788.2,43.3L796.7,43.8L797.4,45.0L808.5,45.4L808.7,43.4L814.3,43.8L818.6,43.8L822.9,45.2L824.1,46.9L822.6,48.1L825.9,50.2L830.1,51.2L832.7,48.4L837.0,49.6L841.5,48.9L846.7,49.7L848.6,49.0L853.0,49.4L851.1,46.9L854.6,45.7L878.7,47.5L880.9,49.0L887.9,51.1L898.7,50.6L904.0,51.0L906.2,52.1L905.9,54.1L909.2,54.8L912.7,54.3L917.5,54.2L922.5,54.7L927.6,54.4L932.2,56.8L935.5,56.0L933.4,54.3L934.5,53.1L943.1,53.8L948.6,53.7L956.3,54.9L960.0,56.1L960.0,66.7L960.0,66.7L956.6,67.9L953.1,67.7L955.5,69.1L957.1,71.3L958.3,72.0L958.6,73.1L957.9,73.9L953.0,73.3L945.5,75.3L943.1,75.6L939.1,77.5L935.2,79.1L934.2,80.3L930.4,78.5L923.5,80.6L922.2,79.6L919.7,80.7L916.1,80.4L915.2,82.1L912.0,84.7L912.1,85.8L915.2,86.4L914.8,90.2L912.3,90.3L911.2,92.6L912.3,93.7L907.7,95.1L906.7,98.1L902.7,98.8L901.9,101.5L898.1,104.0L897.1,102.1L896.0,98.2L894.5,92.3L895.8,88.6L898.0,87.0L898.2,85.8L902.3,85.2L907.1,81.8L911.7,79.1L916.5,77.0L918.6,73.2L915.4,73.4L913.8,75.6L907.0,78.5L904.8,75.3L897.9,76.2L891.2,80.6L893.5,82.3L887.5,83.0L883.4,83.3L883.6,81.3L879.4,80.9L876.1,82.2L868.0,81.8L859.2,82.6L850.6,87.8L840.3,94.1L844.5,94.4L845.8,96.1L848.4,96.7L850.1,95.3L853.1,95.5L856.9,98.4L857.0,100.7L854.9,103.4L854.7,106.5L853.5,110.8L849.5,114.7L848.6,116.5L845.0,119.6L841.4,122.7L839.7,124.3L836.1,125.8L834.4,125.9L832.7,124.6L829.2,126.5L828.7,127.4L828.7,127.4L828.7,127.4L828.7,127.4L828.4,126.9L828.4,126.9L828.4,125.6L829.7,125.5L830.1,122.4L829.4,120.1L831.7,119.1L834.9,119.6L836.7,117.0L837.6,114.1L838.7,113.1L840.1,110.7L835.7,111.5L833.4,112.6L829.3,112.6L828.2,110.1L825.1,108.2L820.4,107.3L819.4,104.7L818.5,103.1L817.5,101.9L815.9,99.2L813.5,98.2L809.5,97.4L806.0,97.5L802.7,98.0L800.5,99.3L801.9,100.0L802.0,101.4L800.5,102.3L798.1,105.1L798.1,106.3L794.3,108.0L791.1,107.0L788.0,107.2L786.6,106.3L785.0,106.0L781.1,107.9L777.5,108.3L775.1,109.0L771.7,108.6L769.3,108.6L767.6,107.2L765.0,105.9L762.4,105.6L759.0,105.9L756.5,106.4L752.7,105.3L752.2,103.3L749.0,102.6L746.6,102.3L743.6,101.2L740.9,104.0L742.0,105.5L739.4,107.4L735.5,106.7L732.8,106.6L731.1,105.4L728.3,105.3L726.0,104.5L721.9,105.8L716.8,108.1L714.0,108.5L713.0,108.8L711.5,107.1L708.1,107.5L707.0,106.4L705.1,105.8L703.8,104.3L702.4,103.8L698.5,104.5L694.8,103.0L693.4,104.4L687.5,97.6L684.1,95.5L685.0,94.7L678.4,97.2L675.8,97.4L676.0,95.9L672.6,95.0L669.8,95.6L669.0,92.9L664.2,92.3L661.8,93.4L655.1,94.4L653.8,95.1L643.8,96.0L642.6,96.9L644.5,98.7L642.0,99.4L642.5,100.1L639.9,101.4L644.2,103.3L643.6,104.5L639.8,104.4L639.0,105.2L635.6,103.8L631.4,103.9L628.6,105.0L625.4,103.9L619.5,102.1L615.4,102.2L609.9,105.1L609.5,107.0L606.8,105.5L604.7,108.4L605.4,108.9L603.9,110.9L606.2,112.8L608.2,112.7L609.9,114.5L609.6,115.8L610.9,116.3ZM730.1,23.9L735.8,23.3L741.0,24.7L747.2,27.3L746.5,29.7L740.7,30.0L733.3,29.2L728.8,28.2L726.8,26.3L723.1,25.8L730.1,23.9ZM754.2,28.6L761.0,30.1L760.2,31.2L745.2,32.2L750.0,28.7L752.2,28.4L754.2,28.6ZM850.2,37.0L857.3,37.1L866.9,38.5L864.8,40.5L855.0,40.4L850.5,41.0L845.3,39.3L846.7,37.5L850.2,37.0ZM875.3,39.1L882.0,39.8L878.9,40.8L874.6,40.6L869.7,39.5L870.3,38.7L875.3,39.1ZM853.0,44.3L855.5,43.3L858.8,43.0L862.6,44.1L862.9,44.8L858.9,44.8L853.4,44.5L853.0,44.3ZM599.6,25.1L604.8,24.6L608.8,24.6L609.4,25.3L610.9,24.7L613.4,24.2L617.4,24.8L616.4,25.2L612.8,25.6L610.4,25.8L610.0,26.2L606.9,26.6L604.0,26.0L605.5,25.2L599.6,25.1ZM540.6,95.1L535.7,95.2L532.4,94.9L533.0,93.7L536.7,92.8L539.5,93.3L540.7,93.7L540.4,94.4L540.6,95.1ZM622.7,43.3L629.1,41.0L628.4,39.8L634.3,38.4L643.1,36.7L652.0,36.2L656.6,35.2L661.8,34.8L663.6,35.9L661.8,36.7L652.4,38.0L644.2,39.3L635.9,41.8L632.0,44.4L627.8,47.0L628.3,49.2L633.4,51.4L631.9,51.6L623.1,51.3L622.4,50.1L617.6,49.4L617.2,48.0L619.9,47.4L619.9,45.9L625.1,43.7L622.7,43.3ZM861.1,96.8L862.0,99.4L862.0,102.0L863.1,104.7L865.7,109.4L861.8,108.5L860.2,112.4L862.8,115.1L862.7,117.0L860.7,115.4L858.9,117.4L858.4,115.2L858.7,112.6L858.4,109.7L859.0,107.7L859.1,104.1L857.6,101.5L857.8,97.9L860.3,96.6L859.2,95.4L860.4,95.0L861.1,96.8ZM13.5,60.8L13.3,62.4L15.1,63.1L14.5,61.2L21.7,61.6L26.9,64.1L24.3,65.2L19.9,65.5L19.9,68.1L18.8,68.7L16.3,68.6L14.3,67.7L10.7,66.9L10.1,65.7L7.4,65.3L4.4,65.6L2.9,64.7L3.5,63.7L0.3,64.3L1.5,65.6L0.0,66.7L0.0,56.1L6.5,58.1L13.5,60.8ZM3.5,51.0L0.0,51.1L0.0,49.3L0.3,49.2L2.6,49.2L6.5,49.9L6.2,50.3L3.5,51.0ZM569.2,117.4L569.9,116.7L571.8,117.3L572.6,117.4L573.0,118.0L573.4,118.0L573.4,118.3L574.7,118.9L577.4,118.7L576.9,119.7L574.0,120.2L570.4,121.7L568.9,121.2L569.5,119.9L566.5,119.1L567.0,118.6L569.6,117.7L569.2,117.4Z" fill-rule="evenodd"/><path d="M269.4,168.6L270.6,168.3L272.4,168.4L272.5,169.1L269.6,169.5L269.4,168.6ZM272.6,167.9L274.7,169.1L274.2,171.0L273.7,170.6L273.8,169.3L272.6,168.2L272.6,167.9ZM271.5,172.8L272.3,172.9L273.2,175.1L273.2,176.6L272.6,176.8L271.9,175.2L270.9,174.5L271.5,172.8Z" fill-rule="evenodd"/><path d="M316.8,378.3L320.0,376.7L322.3,377.3L323.9,376.3L326.0,377.5L325.2,378.4L321.6,379.2L320.4,378.3L318.1,379.5L316.8,378.3Z" fill-rule="evenodd"/><path d="M520.4,27.5L521.4,26.6L525.3,26.5L528.7,27.5L537.5,29.5L530.7,30.5L529.3,32.5L526.9,33.0L525.6,35.2L522.4,35.3L516.7,33.7L519.1,32.7L515.1,31.9L509.9,29.7L507.9,27.6L515.1,26.6L516.6,27.6L520.4,27.5ZM562.9,54.5L558.4,55.6L556.2,55.8L557.4,54.0L554.0,52.9L549.8,53.8L548.5,55.8L546.0,56.9L543.1,56.3L539.6,56.4L536.7,55.0L535.1,55.7L533.4,55.8L533.0,57.6L528.0,57.2L527.3,58.6L524.7,58.6L523.0,60.5L520.3,63.5L516.1,67.2L517.1,68.1L516.2,69.2L513.5,69.2L511.8,71.7L512.0,75.2L513.7,76.6L512.8,79.7L510.6,81.5L509.4,83.1L507.6,81.4L502.4,84.5L498.8,85.1L495.1,83.8L494.2,80.9L493.3,74.7L495.8,73.0L502.8,70.8L508.1,68.0L513.0,64.3L519.4,59.2L523.8,57.2L531.2,53.8L537.0,52.7L541.4,52.8L545.5,50.6L550.3,50.7L555.1,50.2L563.4,52.1L560.0,52.8L562.9,54.5ZM553.1,26.5L549.1,28.0L541.4,28.3L533.5,27.8L533.1,27.1L529.2,27.0L526.3,25.8L534.5,25.1L538.4,25.7L541.1,24.9L547.9,25.6L553.1,26.5ZM545.9,32.4L540.0,33.5L535.3,32.9L537.1,32.2L535.5,31.3L541.0,30.8L542.1,31.8L545.9,32.4Z" fill-rule="evenodd"/><path d="M355.3,19.7L364.2,18.1L373.6,18.2L377.0,17.2L386.4,16.9L407.7,17.3L424.4,19.4L419.5,20.4L409.3,20.5L394.9,20.8L396.3,21.3L405.7,21.0L413.7,21.9L418.9,21.1L421.1,22.0L418.2,23.6L425.0,22.6L438.0,21.6L445.9,22.1L447.4,23.2L436.6,25.1L435.1,25.7L426.5,26.2L432.7,26.3L429.6,28.3L427.5,30.0L427.5,33.0L430.7,34.7L426.6,34.8L422.2,35.7L427.1,37.1L427.7,39.3L424.9,39.6L428.3,41.9L422.4,42.1L425.5,43.2L424.6,44.1L420.9,44.5L417.2,44.5L420.5,46.3L420.5,47.5L415.3,46.4L413.9,47.1L417.5,47.8L421.0,49.4L422.0,51.6L417.2,52.1L415.2,51.0L411.9,49.5L412.8,51.3L409.7,52.7L416.7,52.8L420.4,53.0L413.3,55.3L406.0,57.4L398.2,58.3L395.3,58.3L392.5,59.4L388.8,62.2L383.1,64.1L381.2,64.2L377.7,64.8L373.8,65.4L371.5,67.1L371.5,69.0L370.2,70.7L365.8,72.8L366.9,74.9L365.7,77.1L364.3,79.7L360.6,79.9L356.6,77.7L351.3,77.7L348.7,76.2L346.9,73.6L342.3,70.3L341.0,68.6L340.6,66.2L336.9,63.7L337.9,61.8L336.1,60.8L338.7,57.7L342.7,56.7L343.8,55.6L344.3,53.5L341.3,54.5L339.8,54.9L337.4,55.2L334.2,54.4L334.0,52.6L335.0,51.1L337.5,51.1L343.0,51.8L338.4,50.1L336.0,49.2L333.3,49.6L331.1,48.9L334.1,46.4L332.5,45.4L330.3,43.6L327.1,40.8L323.7,39.7L323.8,38.6L316.6,37.1L311.0,36.9L303.8,37.0L297.3,37.2L294.2,36.3L289.6,34.6L296.6,33.8L302.0,33.7L290.6,33.0L284.5,31.9L284.9,30.8L295.0,29.6L304.8,28.3L305.8,27.3L298.6,26.4L300.9,25.3L310.2,23.4L314.0,23.1L312.9,21.9L319.2,21.2L327.4,20.8L335.6,20.8L338.6,21.6L345.6,20.2L352.0,21.2L355.7,21.4L361.3,22.2L354.9,20.8L355.3,19.7Z" fill-rule="evenodd"/><path d="M663.8,369.7L665.5,370.5L668.1,370.8L668.2,371.3L667.4,372.6L663.3,372.7L663.3,371.3L663.6,370.2L663.8,369.7Z" fill-rule="evenodd"/><path d="M813.2,263.7L813.6,263.1L815.9,262.5L817.7,262.4L818.6,262.1L819.6,262.4L818.6,263.1L815.8,264.3L813.6,265.0L813.5,264.2L813.2,263.7Z" fill-rule="evenodd"/><path d="M523.6,316.2L524.9,314.9L525.9,315.6L526.4,316.8L527.6,317.0L529.2,317.5L530.7,317.3L533.1,315.9L533.1,306.0L533.8,306.4L535.4,309.0L535.1,310.6L535.7,311.5L537.6,311.3L538.9,310.1L540.2,309.3L540.9,308.0L542.2,307.4L543.3,307.7L544.6,308.5L546.7,308.6L548.4,308.0L548.7,307.1L549.2,305.9L550.6,305.6L551.4,304.6L552.3,302.9L554.7,300.9L558.5,298.9L559.6,298.9L560.9,299.4L561.8,299.1L563.2,299.3L564.5,303.1L565.1,305.0L564.7,308.0L564.9,308.9L563.6,308.4L562.8,308.6L562.5,309.4L561.8,310.4L561.8,311.3L563.4,312.8L565.0,312.5L565.5,311.3L567.5,311.3L566.9,313.3L566.6,315.5L565.9,316.7L564.1,318.0L563.5,318.4L562.4,319.8L561.7,321.1L560.1,323.0L557.1,325.8L555.3,327.4L553.2,328.6L550.5,329.6L549.1,329.8L548.7,330.5L547.1,330.1L545.8,330.6L542.9,330.1L541.3,330.4L540.2,330.3L537.4,331.4L535.2,331.8L533.5,332.8L532.3,332.9L531.2,331.9L530.3,331.9L529.1,330.7L529.0,331.0L528.7,330.3L528.7,328.8L527.8,327.0L528.7,326.5L528.6,324.4L526.8,321.9L525.5,319.7L525.5,319.7L523.6,316.2ZM557.3,317.2L556.1,316.4L554.9,316.9L553.4,318.0L552.0,319.7L554.0,321.7L555.0,321.5L555.4,320.6L556.9,320.2L557.4,319.3L558.2,318.0L557.3,317.2Z" fill-rule="evenodd"/><path d="M557.3,317.2L558.2,318.0L557.4,319.3L556.9,320.2L555.4,320.6L555.0,321.5L554.0,321.7L552.0,319.7L553.4,318.0L554.9,316.9L556.1,316.4L557.3,317.2Z" fill-rule="evenodd"/><path d="M167.7,153.2L170.7,153.0L174.1,152.7L173.8,153.3L177.9,154.6L183.9,156.4L189.2,156.4L191.4,156.4L191.4,155.3L196.0,155.3L197.0,156.3L198.3,157.1L199.9,158.3L200.8,159.7L201.4,161.1L202.8,161.9L205.0,162.7L206.7,160.6L208.9,160.6L210.8,161.7L212.1,163.5L213.0,165.0L214.6,166.6L215.2,168.4L215.9,169.7L218.0,170.5L219.9,171.1L221.0,171.0L219.9,173.4L219.5,175.3L219.3,178.8L219.0,180.1L219.5,181.6L220.3,182.9L220.8,185.0L222.6,187.0L223.2,188.5L224.3,189.8L227.1,190.5L228.2,191.6L230.5,190.9L232.6,190.6L234.6,190.1L236.2,189.7L237.9,188.6L238.6,187.0L238.8,184.8L239.3,184.0L241.1,183.3L243.9,182.7L246.2,182.8L247.9,182.6L248.5,183.1L248.4,184.4L247.0,186.0L246.3,187.6L246.8,188.1L246.4,189.2L245.8,191.3L245.1,190.6L244.5,190.7L244.0,190.7L243.1,192.3L242.6,192.0L242.3,192.1L242.3,192.5L239.8,192.5L237.3,192.5L237.3,194.0L236.1,194.0L237.1,194.9L238.1,195.5L238.4,196.1L238.8,196.2L238.8,197.1L235.3,197.2L234.1,199.3L234.4,199.8L234.1,200.5L234.1,201.2L231.0,198.4L229.7,197.5L227.5,196.8L226.0,197.0L223.9,198.0L222.5,198.3L220.6,197.6L218.6,197.0L216.1,195.8L214.1,195.5L211.1,194.2L208.9,192.9L208.2,192.2L206.7,192.1L204.0,191.2L202.9,190.0L200.0,188.5L198.7,186.8L198.0,185.5L198.9,185.2L198.7,184.5L199.3,183.8L199.3,182.9L198.4,181.7L198.2,180.6L197.3,179.3L194.9,176.6L192.2,174.5L190.9,172.9L188.6,171.8L188.1,171.1L188.6,169.5L187.2,168.9L185.6,167.6L185.0,165.7L183.5,165.5L182.0,164.1L180.7,162.8L180.6,162.0L179.2,159.9L178.2,157.9L178.3,156.9L176.3,155.8L175.5,155.9L173.9,155.2L173.5,156.3L173.9,157.6L174.2,159.6L175.1,160.7L177.1,162.5L177.5,163.1L177.9,163.3L178.3,164.2L178.8,164.2L179.3,165.9L180.1,166.6L180.7,167.5L182.4,168.9L183.2,171.4L184.0,172.5L184.8,173.8L184.9,175.2L186.2,175.3L187.3,176.5L188.2,177.7L188.2,178.2L187.1,179.2L186.6,179.1L185.9,177.5L184.1,176.0L182.2,174.7L180.8,174.0L180.9,172.1L180.5,170.6L179.3,169.8L177.4,168.6L177.1,169.0L176.4,168.3L174.8,167.6L173.2,166.1L173.4,165.9L174.5,166.0L175.5,165.0L175.6,163.8L173.5,161.9L172.0,161.2L171.0,159.5L170.0,157.8L168.7,155.6L167.7,153.2Z" fill-rule="evenodd"/><path d="M326.3,320.6L328.1,320.3L330.7,322.4L331.7,322.3L334.5,324.0L336.6,325.5L338.1,327.3L336.9,328.5L337.7,330.0L336.5,331.7L333.5,333.2L331.5,332.7L330.1,333.0L327.6,331.8L325.8,331.9L324.2,330.4L324.4,328.7L325.0,328.1L325.0,325.5L325.7,322.7L326.3,320.6Z" fill-rule="evenodd"/><path d="M337.7,330.0L336.9,328.5L338.1,327.3L336.6,325.5L334.5,324.0L331.7,322.3L330.7,322.4L328.1,320.3L326.3,320.6L329.9,316.9L332.9,314.4L334.7,313.3L336.9,311.8L337.0,309.7L335.7,308.1L334.3,308.6L334.9,307.1L335.2,305.5L335.2,304.1L334.3,303.6L333.3,304.0L332.3,303.9L332.0,302.9L331.7,300.4L331.2,299.6L329.4,298.9L328.3,299.4L325.5,298.9L325.7,295.3L324.9,293.8L325.7,293.3L325.5,291.7L326.2,290.6L326.7,288.5L326.0,286.8L324.6,286.1L324.3,285.0L324.7,283.5L319.6,283.4L318.6,280.3L319.3,280.2L319.3,279.1L318.8,278.3L318.7,276.7L317.1,275.9L315.4,276.0L314.3,275.2L312.5,274.7L311.5,273.7L308.5,273.2L305.6,270.8L305.8,269.1L305.5,268.0L305.8,266.0L302.3,266.5L300.9,267.5L298.5,268.6L297.9,269.4L296.6,269.4L294.6,269.2L293.1,269.7L291.9,269.4L292.0,265.3L289.9,266.9L287.5,266.8L286.5,265.4L284.7,265.2L285.3,264.1L283.8,262.5L282.7,260.1L283.4,259.6L283.4,258.4L285.0,257.7L284.7,256.2L285.4,255.3L285.6,254.1L288.7,252.3L290.9,251.7L291.2,251.3L293.6,251.5L294.8,244.2L294.9,243.0L294.5,241.5L293.3,240.5L293.3,238.6L294.8,238.1L295.3,238.4L295.4,237.4L293.9,237.1L293.8,235.4L299.0,235.5L299.9,234.6L300.6,235.4L301.2,237.0L301.7,236.7L303.1,238.1L305.2,237.9L305.7,237.1L307.7,236.5L308.8,236.0L309.1,234.9L311.0,234.1L310.9,233.6L308.6,233.3L308.2,231.7L308.4,229.9L307.2,229.2L307.7,228.9L309.6,229.3L311.8,229.9L312.5,229.3L314.4,228.9L317.4,227.9L318.4,226.9L318.0,226.1L319.4,226.0L320.1,226.6L319.7,227.8L320.6,228.2L321.2,229.4L320.5,230.4L320.1,232.7L320.8,234.0L320.9,235.2L322.6,236.5L323.9,236.6L324.2,236.1L325.0,236.0L326.2,235.5L327.1,234.8L328.6,235.0L329.2,234.9L330.7,235.2L330.9,234.6L330.5,234.1L330.7,233.3L331.8,233.5L333.1,233.3L334.6,233.8L335.8,234.4L336.6,233.7L337.2,233.8L337.6,234.5L338.8,234.3L339.8,233.3L340.7,231.4L342.2,228.9L343.2,228.8L343.8,230.3L345.3,234.9L346.7,235.4L346.8,237.2L344.8,239.4L345.6,240.2L350.3,240.6L350.4,243.3L352.5,241.6L355.8,242.5L360.3,244.1L361.6,245.7L361.1,247.2L364.2,246.4L369.4,247.8L373.4,247.7L377.3,249.9L380.7,252.9L382.8,253.6L385.1,253.7L386.0,254.6L386.9,258.0L387.4,259.6L386.3,264.0L385.0,265.7L381.2,269.4L379.5,272.5L377.5,274.8L376.9,274.8L376.1,276.8L376.3,281.8L375.6,285.9L375.3,287.6L374.4,288.7L374.0,292.3L371.3,295.7L370.8,298.5L368.7,299.7L368.0,301.3L365.1,301.2L360.9,302.3L359.1,303.5L356.1,304.2L352.9,306.4L350.7,309.0L350.3,311.0L350.7,312.5L350.2,315.2L349.6,316.5L347.8,317.9L344.8,322.6L342.5,324.7L340.7,326.0L339.4,328.5L337.7,330.0Z" fill-rule="evenodd"/><path d="M294.6,269.2L296.6,269.4L297.9,269.4L298.5,268.6L300.9,267.5L302.3,266.5L305.8,266.0L305.5,268.0L305.8,269.1L305.6,270.8L308.5,273.2L311.5,273.7L312.5,274.7L314.3,275.2L315.4,276.0L317.1,275.9L318.7,276.7L318.8,278.3L319.3,279.1L319.3,280.2L318.6,280.3L319.6,283.4L324.7,283.5L324.3,285.0L324.6,286.1L326.0,286.8L326.7,288.5L326.2,290.6L325.5,291.7L325.7,293.3L324.9,293.8L324.8,293.0L322.4,291.6L319.9,291.6L315.2,292.4L314.0,294.7L313.9,296.1L312.8,299.3L312.4,298.8L309.4,298.6L308.3,300.8L306.8,298.9L303.3,298.2L301.0,300.6L299.1,301.0L298.1,297.3L296.6,294.3L297.5,291.7L296.1,290.6L295.7,288.7L294.4,286.9L296.1,284.0L295.0,281.8L295.6,280.9L295.1,279.9L296.1,278.5L296.2,276.3L296.3,274.4L296.9,273.5L294.6,269.2Z" fill-rule="evenodd"/><path d="M293.6,251.5L291.2,251.3L290.9,251.7L288.7,252.3L285.6,254.1L285.4,255.3L284.7,256.2L285.0,257.7L283.4,258.4L283.4,259.6L282.7,260.1L283.8,262.5L285.3,264.1L284.7,265.2L286.5,265.4L287.5,266.8L289.9,266.9L292.0,265.3L291.9,269.4L293.1,269.7L294.6,269.2L296.9,273.5L296.3,274.4L296.2,276.3L296.1,278.5L295.1,279.9L295.6,280.9L295.0,281.8L296.1,284.0L294.4,286.9L293.7,288.2L292.3,288.9L289.7,287.4L289.4,286.3L284.1,283.6L279.4,280.7L277.3,279.1L276.2,276.9L276.6,276.1L274.4,272.6L271.8,267.7L269.2,262.4L268.1,261.1L267.3,259.2L265.2,257.4L263.3,256.4L264.2,255.2L262.9,252.6L263.7,250.8L265.9,249.1L266.2,250.2L265.4,250.8L265.5,251.8L266.6,251.6L267.7,251.9L268.8,253.2L270.3,252.1L270.8,250.3L272.4,248.0L275.6,247.0L278.5,244.2L279.4,242.4L279.0,240.4L279.7,240.2L281.5,241.4L282.3,242.7L283.6,243.4L285.1,246.2L287.1,246.5L288.6,245.8L289.6,246.2L291.2,246.0L293.2,247.3L291.5,250.0L292.3,250.0L293.6,251.5Z" fill-rule="evenodd"/><path d="M301.7,236.7L301.2,237.0L300.6,235.4L299.9,234.6L299.0,235.5L293.8,235.4L293.9,237.1L295.4,237.4L295.3,238.4L294.8,238.1L293.3,238.6L293.3,240.5L294.5,241.5L294.9,243.0L294.8,244.2L293.6,251.5L292.3,250.0L291.5,250.0L293.2,247.3L291.2,246.0L289.6,246.2L288.6,245.8L287.1,246.5L285.1,246.2L283.6,243.4L282.3,242.7L281.5,241.4L279.7,240.2L279.0,240.4L277.9,239.8L276.6,238.9L275.8,239.3L273.5,238.9L272.9,237.8L272.4,237.8L269.7,236.3L269.4,235.5L270.4,235.3L270.2,234.0L270.9,233.0L272.2,232.8L273.3,231.1L274.3,229.7L273.3,229.1L273.8,227.6L273.2,225.1L273.8,224.4L273.4,222.2L272.3,220.7L272.7,219.4L273.5,219.6L274.0,218.8L273.4,217.3L273.7,216.9L275.1,217.0L277.1,215.1L278.2,214.8L278.2,213.9L278.7,211.7L280.2,210.4L281.9,210.4L282.1,209.8L284.2,210.1L286.3,208.7L287.4,208.1L288.7,206.8L289.6,207.0L290.3,207.7L289.8,208.6L288.1,209.0L287.4,210.4L286.4,211.1L285.6,212.1L285.3,214.0L284.5,215.6L285.9,215.8L286.2,217.0L286.8,217.6L287.0,218.7L286.7,219.6L286.8,220.2L287.5,220.4L288.1,221.4L291.5,221.1L293.1,221.4L295.0,223.7L296.0,223.4L298.0,223.6L299.5,223.3L300.4,223.7L299.9,225.2L299.3,226.1L299.1,228.0L299.7,229.8L300.4,230.6L300.5,231.2L299.2,232.5L300.1,233.1L300.8,234.0L301.7,236.7Z" fill-rule="evenodd"/><path d="M273.7,216.9L273.4,217.3L274.0,218.8L273.5,219.6L272.7,219.4L272.3,220.7L271.4,220.0L270.9,218.5L271.5,217.8L270.8,217.6L270.3,216.8L269.0,216.0L267.8,216.2L267.3,217.1L266.2,217.8L265.6,217.9L265.4,218.4L266.7,219.9L265.9,220.2L265.5,220.6L264.3,220.7L263.8,219.2L263.5,219.6L262.6,219.4L262.1,218.4L261.0,218.2L260.3,217.9L259.1,217.9L259.1,218.5L258.8,218.1L258.9,217.5L259.1,217.0L259.0,216.5L259.4,216.2L258.9,215.8L258.8,214.7L259.9,214.5L260.8,215.4L260.8,216.0L261.8,216.1L262.1,215.9L262.8,216.6L264.1,216.4L265.3,215.7L266.9,215.2L267.8,214.4L269.3,214.5L269.2,214.8L270.7,214.9L271.9,215.3L272.7,216.1L273.7,216.9Z" fill-rule="evenodd"/><path d="M259.9,214.5L258.8,214.7L258.9,215.8L259.4,216.2L259.0,216.5L259.1,217.0L258.9,217.5L258.8,218.1L257.3,217.5L256.8,216.9L257.1,216.5L257.0,215.9L256.2,215.2L255.2,214.7L254.3,214.4L254.1,213.6L253.4,213.1L253.6,213.9L253.0,214.5L252.4,213.8L251.6,213.5L251.2,213.0L251.2,212.2L251.6,211.3L250.8,210.9L251.4,210.4L251.8,210.1L253.6,210.8L254.2,210.4L255.1,210.7L255.5,211.2L256.3,211.4L256.9,210.8L257.6,212.3L258.6,213.4L259.9,214.5Z" fill-rule="evenodd"/><path d="M256.9,210.8L256.3,211.4L255.5,211.2L255.1,210.7L254.2,210.4L253.6,210.8L251.8,210.1L251.4,210.4L250.5,209.6L249.3,208.5L248.7,207.6L247.6,206.8L246.2,205.6L246.5,205.2L247.0,205.6L247.2,205.4L248.0,205.3L248.3,204.7L248.7,204.6L248.7,203.3L249.3,203.3L249.8,203.3L250.4,202.6L251.2,203.1L251.5,202.8L252.0,202.5L252.9,201.7L252.9,201.2L253.2,201.2L253.5,200.6L253.8,200.5L254.3,200.9L254.8,201.0L255.4,200.7L256.1,200.7L257.0,200.3L257.4,200.0L258.3,200.0L258.0,200.3L257.9,200.9L258.2,201.8L257.6,202.7L257.3,203.8L257.2,205.0L257.3,205.7L257.4,206.9L257.0,207.1L256.7,208.3L256.9,209.0L256.4,209.7L256.5,210.4L256.9,210.8Z" fill-rule="evenodd"/><path d="M258.3,200.0L257.4,200.0L257.0,200.3L256.1,200.7L255.4,200.7L254.8,201.0L254.3,200.9L253.8,200.5L253.5,200.6L253.2,201.2L252.9,201.2L252.9,201.7L252.0,202.5L251.5,202.8L251.2,203.1L250.4,202.6L249.8,203.3L249.3,203.3L248.7,203.3L248.7,204.6L248.3,204.7L248.0,205.3L247.2,205.4L246.7,204.5L245.9,204.3L246.1,203.2L245.7,203.0L245.2,202.8L244.0,203.1L243.9,202.7L243.1,202.3L242.5,201.8L241.7,201.5L242.3,200.9L242.1,200.3L242.3,199.8L243.5,199.1L244.7,198.1L245.0,198.2L245.6,197.7L246.4,197.7L246.6,197.9L247.0,197.7L248.3,198.0L249.5,197.9L250.3,197.6L250.7,197.3L251.5,197.5L252.1,197.6L252.8,197.6L253.4,197.3L254.6,197.7L255.0,197.8L255.8,198.3L256.6,198.9L257.6,199.3L258.3,200.0Z" fill-rule="evenodd"/><path d="M241.7,201.5L242.5,201.8L243.1,202.3L243.9,202.7L244.0,203.1L245.2,202.8L245.7,203.0L246.1,203.2L245.9,204.3L245.6,204.9L244.0,204.9L243.1,204.6L242.0,204.1L240.5,203.9L239.7,203.4L239.8,203.0L240.7,202.3L241.2,202.0L241.1,201.7L241.7,201.5Z" fill-rule="evenodd"/><path d="M234.1,201.2L234.1,200.5L234.4,199.8L234.1,199.3L235.3,197.2L238.8,197.1L238.8,196.2L238.4,196.1L238.1,195.5L237.1,194.9L236.1,194.0L237.3,194.0L237.3,192.5L239.8,192.5L242.3,192.5L242.3,194.6L242.1,197.6L242.9,197.6L243.7,198.1L244.0,197.7L244.7,198.1L243.5,199.1L242.3,199.8L242.1,200.3L242.3,200.9L241.7,201.5L241.1,201.7L241.2,202.0L240.7,202.3L239.8,203.0L239.7,203.4L238.4,202.9L236.7,202.9L235.5,202.3L234.1,201.2Z" fill-rule="evenodd"/><path d="M242.3,192.5L242.3,192.1L242.6,192.0L243.1,192.3L244.0,190.7L244.5,190.7L244.5,191.1L245.0,191.1L245.0,191.8L244.6,192.9L244.8,193.4L244.5,194.3L244.7,194.6L244.4,195.9L243.9,196.6L243.4,196.7L242.9,197.6L242.1,197.6L242.3,194.6L242.3,192.5Z" fill-rule="evenodd"/><path d="M318.0,226.1L318.4,226.9L317.4,227.9L314.4,228.9L312.5,229.3L311.8,229.9L309.6,229.3L307.7,228.9L307.2,229.2L308.4,229.9L308.2,231.7L308.6,233.3L310.9,233.6L311.0,234.1L309.1,234.9L308.8,236.0L307.7,236.5L305.7,237.1L305.2,237.9L303.1,238.1L301.7,236.7L300.8,234.0L300.1,233.1L299.2,232.5L300.5,231.2L300.4,230.6L299.7,229.8L299.1,228.0L299.3,226.1L299.9,225.2L300.4,223.7L299.5,223.3L298.0,223.6L296.0,223.4L295.0,223.7L293.1,221.4L291.5,221.1L288.1,221.4L287.5,220.4L286.8,220.2L286.7,219.6L287.0,218.7L286.8,217.6L286.2,217.0L285.9,215.8L284.5,215.6L285.3,214.0L285.6,212.1L286.4,211.1L287.4,210.4L288.1,209.0L289.8,208.6L289.7,209.2L288.1,209.5L289.0,210.7L289.0,212.1L287.8,213.7L288.8,215.8L290.0,215.6L290.6,213.7L289.7,212.8L289.6,210.7L292.9,209.7L292.5,208.4L293.5,207.6L294.4,209.4L296.3,209.5L298.0,211.0L298.1,211.9L300.5,211.9L303.4,211.6L304.9,212.8L307.0,213.1L308.5,212.3L308.5,211.6L311.8,211.5L315.0,211.4L312.7,212.2L313.6,213.5L315.8,213.7L317.8,215.0L318.2,217.1L319.6,217.1L320.6,217.7L318.5,219.3L318.3,220.2L319.2,221.2L318.5,221.7L316.9,222.1L317.0,223.4L316.2,224.1L318.0,226.1Z" fill-rule="evenodd"/><path d="M329.2,234.9L328.6,235.0L327.1,234.8L326.2,235.5L325.0,236.0L324.2,236.1L323.9,236.6L322.6,236.5L320.9,235.2L320.8,234.0L320.1,232.7L320.5,230.4L321.2,229.4L320.6,228.2L319.7,227.8L320.1,226.6L319.4,226.0L318.0,226.1L316.2,224.1L317.0,223.4L316.9,222.1L318.5,221.7L319.2,221.2L318.3,220.2L318.5,219.3L320.6,217.7L322.4,218.7L324.0,220.4L324.1,221.8L325.1,221.8L326.6,223.1L327.6,224.1L327.2,226.5L325.6,227.2L325.7,227.8L325.2,229.2L326.4,231.1L327.2,231.1L327.6,232.6L329.2,234.9Z" fill-rule="evenodd"/><path d="M334.6,233.8L333.1,233.3L331.8,233.5L330.7,233.3L330.5,234.1L330.9,234.6L330.7,235.2L329.2,234.9L327.6,232.6L327.2,231.1L326.4,231.1L325.2,229.2L325.7,227.8L325.6,227.2L327.2,226.5L327.6,224.1L330.8,224.6L331.1,224.1L333.2,223.9L336.1,224.6L334.7,226.9L334.9,228.8L336.0,230.3L335.5,231.5L335.3,232.7L334.6,233.8Z" fill-rule="evenodd"/><path d="M342.2,228.9L340.7,231.4L339.8,233.3L338.8,234.3L337.6,234.5L337.2,233.8L336.6,233.7L335.8,234.4L334.6,233.8L335.3,232.7L335.5,231.5L336.0,230.3L334.9,228.8L334.7,226.9L336.1,224.6L337.0,224.9L339.0,225.6L341.8,227.8L342.2,228.9ZM496.5,108.1L497.8,108.8L501.6,109.3L500.2,111.1L499.9,113.0L499.2,113.5L498.0,113.2L498.0,113.9L496.1,115.4L496.1,116.6L497.3,116.2L498.2,117.4L498.1,118.1L498.9,119.1L498.0,119.9L498.7,122.0L500.1,122.3L499.8,123.5L497.4,125.0L492.2,124.3L488.3,125.1L488.0,126.7L484.9,127.1L481.9,125.9L480.9,126.5L476.0,125.2L474.9,124.2L476.3,122.6L476.8,117.3L474.1,114.5L472.1,113.1L468.0,112.1L467.8,110.2L471.2,109.6L475.7,110.3L474.8,107.3L477.4,108.4L483.6,106.3L484.4,104.1L486.7,103.6L487.1,104.5L488.3,104.6L489.6,105.7L491.4,106.9L492.8,106.7L495.1,107.9L495.7,108.2L496.5,108.1ZM503.3,126.3L505.0,125.3L505.5,127.6L504.6,129.7L503.4,129.1L502.8,127.3L503.3,126.3Z" fill-rule="evenodd"/><path d="M279.0,240.4L279.4,242.4L278.5,244.2L275.6,247.0L272.4,248.0L270.8,250.3L270.3,252.1L268.8,253.2L267.7,251.9L266.6,251.6L265.5,251.8L265.4,250.8L266.2,250.2L265.9,249.1L267.3,247.1L266.7,245.9L265.7,247.2L264.1,246.0L264.6,245.2L264.2,242.8L265.1,242.4L265.6,240.8L266.6,239.0L266.4,238.0L267.9,237.4L269.7,236.3L272.4,237.8L272.9,237.8L273.5,238.9L275.8,239.3L276.6,238.9L277.9,239.8L279.0,240.4Z" fill-rule="evenodd"/><path d="M303.2,190.6L304.6,190.9L305.1,191.4L304.4,192.1L302.4,192.0L300.8,192.1L300.7,191.0L301.1,190.6L303.2,190.6Z" fill-rule="evenodd"/><path d="M273.1,190.7L274.9,190.9L276.4,191.6L276.8,192.3L274.9,192.4L274.1,192.8L272.6,192.4L271.1,191.4L271.4,190.8L272.5,190.6L273.1,190.7Z" fill-rule="evenodd"/><path d="M260.6,178.2L262.9,178.4L265.0,178.4L267.5,179.3L268.6,180.3L271.1,180.0L272.0,180.6L274.3,182.2L275.9,183.4L276.8,183.4L278.4,184.0L278.2,184.7L280.2,184.8L282.2,185.9L281.9,186.5L280.1,186.9L278.3,187.0L276.5,186.8L272.7,187.1L274.4,185.6L273.4,184.9L271.6,184.7L270.7,183.9L270.1,182.4L268.6,182.5L266.1,181.8L265.3,181.2L261.8,180.8L260.9,180.3L261.9,179.6L259.3,179.5L257.3,180.9L256.2,180.9L255.9,181.6L254.5,181.9L253.4,181.6L254.8,180.8L255.4,179.8L256.6,179.2L258.0,178.7L260.0,178.5L260.6,178.2Z" fill-rule="evenodd"/><path d="M563.2,299.3L561.8,299.1L560.9,299.4L559.6,298.9L558.5,298.9L556.8,297.7L554.7,297.3L553.9,295.6L553.9,294.7L552.8,294.4L549.8,291.4L548.9,289.9L548.4,289.4L547.4,287.3L550.4,287.6L551.2,287.9L552.1,287.8L553.6,286.1L555.9,283.9L556.9,283.7L557.2,282.8L558.7,281.7L560.7,281.4L560.9,282.3L563.1,282.3L564.4,282.9L564.9,283.5L566.2,283.7L567.6,284.6L567.6,287.9L567.1,289.8L567.0,291.8L567.4,292.6L567.1,294.1L566.7,294.4L566.0,296.3L563.2,299.3Z" fill-rule="evenodd"/><path d="M558.5,298.9L554.7,300.9L552.3,302.9L551.4,304.6L550.6,305.6L549.2,305.9L548.7,307.1L548.4,308.0L546.7,308.6L544.6,308.5L543.3,307.7L542.2,307.4L540.9,308.0L540.2,309.3L538.9,310.1L537.6,311.3L535.7,311.5L535.1,310.6L535.4,309.0L533.8,306.4L533.1,306.0L533.1,298.3L535.7,298.2L535.8,288.7L537.7,288.6L541.9,287.7L542.9,288.8L544.6,287.7L545.4,287.7L546.9,287.1L547.4,287.3L548.4,289.4L548.9,289.9L549.8,291.4L552.8,294.4L553.9,294.7L553.9,295.6L554.7,297.3L556.8,297.7L558.5,298.9Z" fill-rule="evenodd"/><path d="M533.1,306.0L533.1,315.9L530.7,317.3L529.2,317.5L527.6,317.0L526.4,316.8L525.9,315.6L524.9,314.9L523.6,316.2L521.6,314.2L520.6,312.2L520.0,309.6L519.3,307.7L518.4,303.6L518.4,300.4L518.0,299.0L517.0,297.9L515.6,295.7L514.2,292.5L513.6,290.8L511.5,288.2L511.3,286.1L512.6,285.6L514.2,285.2L515.9,285.3L517.5,286.5L517.9,286.3L528.7,286.2L530.5,287.4L537.0,287.8L541.9,286.7L544.1,286.1L545.8,286.3L546.9,286.9L546.9,287.1L545.4,287.7L544.6,287.7L542.9,288.8L541.9,287.7L537.7,288.6L535.8,288.7L535.7,298.2L533.1,298.3L533.1,306.0Z" fill-rule="evenodd"/><path d="M435.4,203.7L434.3,201.7L433.0,200.7L434.2,200.2L435.5,198.3L436.1,197.0L437.0,196.1L438.3,196.3L439.6,195.8L441.1,195.7L442.4,196.5L444.2,197.2L445.8,199.2L447.5,201.0L447.7,202.7L448.2,204.2L449.2,205.0L449.4,206.0L449.3,206.8L448.9,207.0L447.5,206.8L447.3,207.1L446.7,207.1L444.8,206.5L443.5,206.4L438.5,206.3L437.8,206.6L436.9,206.5L435.5,207.0L435.1,204.9L437.5,205.0L438.2,204.6L438.6,204.6L439.6,204.0L440.8,204.5L441.9,204.6L443.1,204.0L442.5,203.2L441.7,203.7L440.8,203.7L439.8,203.0L438.9,203.0L438.3,203.7L435.4,203.7Z" fill-rule="evenodd"/><path d="M449.3,206.8L449.4,206.0L449.2,205.0L448.2,204.2L447.7,202.7L447.5,201.0L448.4,200.5L448.9,199.0L449.7,198.9L451.6,199.6L453.1,199.1L454.1,199.3L454.5,198.7L465.2,198.7L465.8,196.8L465.4,196.5L464.1,185.0L462.8,173.4L466.9,173.4L475.9,179.2L484.9,185.0L485.5,186.3L487.2,187.1L488.4,187.5L488.4,189.2L491.4,188.9L491.4,195.1L489.9,196.8L489.7,198.5L487.3,198.9L483.7,199.1L482.7,200.1L481.0,200.2L479.3,200.2L478.6,199.7L477.2,200.1L474.7,201.2L474.2,202.0L472.1,203.2L471.7,203.9L470.6,204.4L469.3,204.1L468.6,204.7L468.2,206.6L466.1,208.8L466.1,209.7L465.4,210.8L465.6,212.3L464.5,212.7L463.9,213.1L463.5,211.9L462.7,212.2L462.2,212.2L461.7,213.0L459.7,212.9L458.9,212.5L458.6,212.8L457.8,212.0L457.9,211.2L457.6,210.9L457.0,211.2L457.1,210.3L457.7,209.6L456.6,208.5L456.3,207.8L455.7,207.2L455.1,207.1L454.5,207.5L453.6,207.8L452.9,208.4L451.8,208.2L451.0,207.5L450.6,207.4L449.9,207.8L449.5,207.8L449.3,206.8Z" fill-rule="evenodd"/><path d="M434.5,184.0L435.1,183.1L445.5,183.1L445.0,179.3L445.7,177.9L448.2,177.7L448.1,170.8L456.8,171.0L456.8,166.9L466.9,173.4L462.8,173.4L464.1,185.0L465.4,196.5L465.8,196.8L465.2,198.7L454.5,198.7L454.1,199.3L453.1,199.1L451.6,199.6L449.7,198.9L448.9,199.0L448.4,200.5L447.5,201.0L445.8,199.2L444.2,197.2L442.4,196.5L441.1,195.7L439.6,195.8L438.3,196.3L437.0,196.1L436.1,197.0L435.9,195.5L436.6,194.2L436.9,191.7L436.6,189.1L436.3,187.7L436.6,186.4L435.9,185.2L434.5,184.0Z" fill-rule="evenodd"/><path d="M487.2,223.3L485.0,223.6L484.3,221.8L484.4,215.7L483.9,215.1L483.8,213.8L482.9,212.9L482.1,212.1L482.4,210.7L483.3,210.4L483.9,209.2L485.2,209.0L485.7,208.2L486.6,207.4L487.6,207.4L489.6,208.9L489.5,209.8L490.1,211.4L489.6,212.4L489.9,213.2L488.6,214.8L487.8,215.6L487.3,217.3L487.3,219.0L487.2,223.3Z" fill-rule="evenodd"/><path d="M519.6,179.0L520.3,183.2L521.3,183.9L521.3,184.7L522.4,185.6L521.8,186.8L520.8,192.2L520.7,195.7L517.3,198.2L516.1,201.7L517.2,202.7L517.2,204.4L518.9,204.5L518.7,205.7L517.9,205.9L517.8,206.7L517.3,206.8L515.5,203.8L514.9,203.7L512.8,205.2L510.7,204.5L509.3,204.3L508.5,204.7L507.0,204.6L505.4,205.7L504.0,205.8L500.8,204.4L499.5,205.1L498.2,205.0L497.2,204.0L494.5,203.0L491.6,203.3L491.0,203.9L490.6,205.5L489.8,206.5L489.6,208.9L487.6,207.4L486.6,207.4L485.7,208.2L485.8,206.3L482.7,205.7L482.6,204.4L481.1,202.7L480.8,201.5L481.0,200.2L482.7,200.1L483.7,199.1L487.3,198.9L489.7,198.5L489.9,196.8L491.4,195.1L491.4,188.9L495.1,187.7L502.9,182.5L512.0,177.4L516.2,178.6L517.7,180.0L519.6,179.0Z" fill-rule="evenodd"/><path d="M487.2,223.3L487.3,219.0L487.3,217.3L487.8,215.6L488.6,214.8L489.9,213.2L489.6,212.4L490.1,211.4L489.5,209.8L489.6,208.9L489.8,206.5L490.6,205.5L491.0,203.9L491.6,203.3L494.5,203.0L497.2,204.0L498.2,205.0L499.5,205.1L500.8,204.4L504.0,205.8L505.4,205.7L507.0,204.6L508.5,204.7L509.3,204.3L510.7,204.5L512.8,205.2L514.9,203.7L515.5,203.8L517.3,206.8L517.8,206.7L518.9,207.8L518.6,208.3L518.4,209.1L516.2,211.2L515.5,212.9L515.1,214.3L514.5,214.9L514.0,216.8L512.6,217.9L512.2,219.2L511.6,220.3L511.3,221.4L509.5,222.3L508.0,221.2L507.0,221.2L505.4,222.8L504.6,222.8L503.4,225.4L502.7,227.3L499.9,228.2L498.9,228.1L497.9,228.7L495.7,228.6L494.3,227.0L493.4,225.0L491.5,223.3L489.5,223.3L487.2,223.3Z" fill-rule="evenodd"/><path d="M518.7,205.7L519.7,207.4L519.9,209.2L519.8,211.0L521.2,213.4L519.8,213.4L519.0,213.5L517.8,213.3L517.2,214.5L518.8,216.1L519.9,216.5L520.3,217.6L521.2,219.5L520.7,220.2L519.4,222.9L518.8,223.4L518.6,225.5L518.8,226.6L518.6,227.4L519.9,228.8L520.1,229.7L521.1,231.1L522.3,232.0L522.4,233.2L522.7,234.0L522.5,235.4L520.4,234.8L518.2,234.1L514.9,234.0L514.5,233.8L513.0,234.2L511.3,233.8L510.1,234.0L505.7,233.9L506.1,231.8L505.1,230.0L503.9,229.6L503.3,228.4L502.6,228.0L502.7,227.3L503.4,225.4L504.6,222.8L505.4,222.8L507.0,221.2L508.0,221.2L509.5,222.3L511.3,221.4L511.6,220.3L512.2,219.2L512.6,217.9L514.0,216.8L514.5,214.9L515.1,214.3L515.5,212.9L516.2,211.2L518.4,209.1L518.6,208.3L518.9,207.8L517.8,206.7L517.9,205.9L518.7,205.7Z" fill-rule="evenodd"/><path d="M482.4,210.7L482.1,212.1L482.9,212.9L483.8,213.8L483.9,215.1L484.4,215.7L484.3,221.8L485.0,223.6L482.8,224.2L482.2,223.3L481.5,221.6L481.3,220.2L481.9,217.8L481.2,216.9L481.0,214.8L481.0,212.8L479.9,211.4L480.1,210.6L482.4,210.7Z" fill-rule="evenodd"/><path d="M480.1,210.6L479.9,211.4L481.0,212.8L481.0,214.8L481.2,216.9L481.9,217.8L481.3,220.2L481.5,221.6L482.2,223.3L482.8,224.2L478.6,225.8L477.2,226.7L474.8,227.4L472.4,226.7L472.5,225.6L471.3,223.3L472.0,220.3L473.2,218.1L472.5,214.3L472.1,212.3L472.2,210.8L476.8,210.6L478.0,210.8L478.8,210.4L480.1,210.6Z" fill-rule="evenodd"/><path d="M458.6,212.8L458.9,212.5L459.7,212.9L461.7,213.0L462.2,212.2L462.7,212.2L463.5,211.9L463.9,213.1L464.5,212.7L465.6,212.3L466.8,212.9L467.3,213.8L468.5,214.4L469.4,213.7L470.6,213.6L472.5,214.3L473.2,218.1L472.0,220.3L471.3,223.3L472.5,225.6L472.4,226.7L471.2,226.7L469.3,226.2L467.6,226.2L464.4,226.7L462.6,227.5L459.9,228.4L459.4,228.4L459.6,226.2L459.9,225.8L459.8,224.8L458.7,223.7L457.8,223.5L457.1,222.8L457.6,221.6L457.4,220.3L457.5,219.5L457.9,219.5L458.1,218.3L457.9,217.8L458.1,217.5L459.1,217.1L458.5,215.0L457.8,213.9L458.1,213.0L458.6,212.8Z" fill-rule="evenodd"/><path d="M443.5,206.4L444.8,206.5L446.7,207.1L447.3,207.1L447.5,206.8L448.9,207.0L449.3,206.8L449.5,207.8L449.9,207.8L450.6,207.4L451.0,207.5L451.8,208.2L452.9,208.4L453.6,207.8L454.5,207.5L455.1,207.1L455.7,207.2L456.3,207.8L456.6,208.5L457.7,209.6L457.1,210.3L457.0,211.2L457.6,210.9L457.9,211.2L457.8,212.0L458.6,212.8L458.1,213.0L457.8,213.9L458.5,215.0L459.1,217.1L458.1,217.5L457.9,217.8L458.1,218.3L457.9,219.5L457.5,219.5L456.7,219.4L456.2,220.5L455.4,220.5L454.9,219.9L455.1,218.9L454.0,217.2L453.3,217.5L452.7,217.6L452.0,217.7L452.0,216.8L451.6,216.1L451.7,215.3L451.1,214.2L450.4,213.2L448.2,213.2L447.6,213.7L446.9,213.8L446.4,214.3L446.1,215.1L444.7,216.3L443.5,214.7L442.5,213.6L441.8,213.3L441.1,212.8L440.8,211.6L440.4,211.0L439.7,210.6L440.8,209.3L441.6,209.3L442.3,208.9L442.9,208.9L443.4,208.5L443.1,207.6L443.4,207.3L443.5,206.4Z" fill-rule="evenodd"/><path d="M435.5,207.0L436.9,206.5L437.8,206.6L438.5,206.3L443.5,206.4L443.4,207.3L443.1,207.6L443.4,208.5L442.9,208.9L442.3,208.9L441.6,209.3L440.8,209.3L439.7,210.6L438.2,209.4L437.1,209.3L436.5,208.5L436.5,208.1L435.7,207.5L435.5,207.0Z" fill-rule="evenodd"/><path d="M457.5,219.5L457.4,220.3L457.6,221.6L457.1,222.8L457.8,223.5L458.7,223.7L459.8,224.8L459.9,225.8L459.6,226.2L459.4,228.4L458.7,228.4L456.0,227.1L453.6,225.1L451.3,223.6L449.5,221.9L450.1,221.1L450.3,220.3L451.5,218.8L452.7,217.6L453.3,217.5L454.0,217.2L455.1,218.9L454.9,219.9L455.4,220.5L456.2,220.5L456.7,219.4L457.5,219.5Z" fill-rule="evenodd"/><path d="M444.7,216.3L446.1,215.1L446.4,214.3L446.9,213.8L447.6,213.7L448.2,213.2L450.4,213.2L451.1,214.2L451.7,215.3L451.6,216.1L452.0,216.8L452.0,217.7L452.7,217.6L451.5,218.8L450.3,220.3L450.1,221.1L449.5,221.9L448.8,221.7L446.9,220.6L445.5,219.2L445.0,218.2L444.7,216.3Z" fill-rule="evenodd"/><path d="M465.6,212.3L465.4,210.8L466.1,209.7L466.1,208.8L468.2,206.6L468.6,204.7L469.3,204.1L470.6,204.4L471.7,203.9L472.1,203.2L474.2,202.0L474.7,201.2L477.2,200.1L478.6,199.7L479.3,200.2L481.0,200.2L480.8,201.5L481.1,202.7L482.6,204.4L482.7,205.7L485.8,206.3L485.7,208.2L485.2,209.0L483.9,209.2L483.3,210.4L482.4,210.7L480.1,210.6L478.8,210.4L478.0,210.8L476.8,210.6L472.2,210.8L472.1,212.3L472.5,214.3L470.6,213.6L469.4,213.7L468.5,214.4L467.3,213.8L466.8,212.9L465.6,212.3Z" fill-rule="evenodd"/><path d="M553.0,226.0L552.1,226.3L550.4,226.3L548.4,226.0L547.4,226.2L547.0,226.9L546.1,226.9L545.1,226.4L542.1,227.7L540.9,227.4L540.5,227.6L539.7,229.3L537.8,228.7L535.8,228.5L534.1,227.5L531.9,226.6L530.5,227.4L529.4,228.8L529.2,230.7L527.5,230.5L525.7,230.1L524.1,231.5L522.7,234.0L522.4,233.2L522.3,232.0L521.1,231.1L520.1,229.7L519.9,228.8L518.6,227.4L518.8,226.6L518.6,225.5L518.8,223.4L519.4,222.9L520.7,220.2L522.9,220.0L523.4,219.3L523.9,219.4L524.5,220.0L527.9,219.0L529.0,217.9L530.4,217.0L530.2,216.0L530.9,215.8L533.5,216.0L536.0,214.7L537.9,211.8L539.3,210.7L541.0,210.3L541.3,211.4L542.8,213.1L542.8,214.2L542.4,215.3L542.6,216.1L543.5,216.9L545.5,218.1L547.0,219.1L547.0,220.0L548.8,221.4L549.9,222.5L550.6,224.1L552.6,225.2L553.0,226.0Z" fill-rule="evenodd"/><path d="M529.2,230.7L529.1,232.3L528.3,233.7L527.7,235.4L527.4,237.7L527.5,239.2L527.1,240.2L527.0,241.1L526.7,242.0L525.0,243.3L523.8,244.6L522.6,247.2L522.7,249.4L522.0,250.3L520.5,251.6L518.9,253.3L517.9,252.8L517.7,252.0L516.3,252.0L515.4,253.0L514.7,252.7L513.7,251.8L512.8,252.3L511.8,253.4L509.6,250.6L511.6,249.1L510.6,247.4L511.5,246.7L513.3,246.4L513.5,245.2L515.0,246.5L517.3,246.6L518.1,245.3L518.5,243.6L518.2,241.5L516.9,239.9L518.1,236.8L517.4,236.3L515.4,236.5L514.7,235.1L514.9,234.0L518.2,234.1L520.4,234.8L522.5,235.4L522.7,234.0L524.1,231.5L525.7,230.1L527.5,230.5L529.2,230.7Z" fill-rule="evenodd"/><path d="M510.1,234.0L511.3,233.8L513.0,234.2L514.5,233.8L514.9,234.0L514.7,235.1L515.4,236.5L517.4,236.3L518.1,236.8L516.9,239.9L518.2,241.5L518.5,243.6L518.1,245.3L517.3,246.6L515.0,246.5L513.5,245.2L513.3,246.4L511.5,246.7L510.6,247.4L511.6,249.1L509.6,250.6L506.8,247.9L505.1,245.7L503.5,243.0L503.5,242.1L504.1,241.2L504.8,239.3L505.3,237.3L506.2,237.2L510.1,237.2L510.1,234.0Z" fill-rule="evenodd"/><path d="M505.7,233.9L510.1,234.0L510.1,237.2L506.2,237.2L505.3,237.3L504.8,236.9L505.7,233.9Z" fill-rule="evenodd"/><path d="M562.0,262.2L563.1,262.9L564.2,263.4L565.8,263.8L567.4,264.6L568.6,265.8L569.3,268.1L568.8,268.8L568.3,271.0L568.8,273.2L568.0,274.1L567.2,276.6L568.6,277.3L560.5,279.5L560.7,281.4L558.7,281.7L557.2,282.8L556.9,283.7L555.9,283.9L553.6,286.1L552.1,287.8L551.2,287.9L550.4,287.6L547.4,287.3L546.9,287.1L546.9,286.9L545.8,286.3L544.1,286.1L541.9,286.7L540.2,285.1L538.4,282.9L538.5,274.4L544.0,274.4L543.8,273.5L544.2,272.5L543.7,271.3L544.0,270.0L543.8,269.1L544.7,269.2L544.8,270.0L546.1,270.0L547.8,270.2L548.7,271.4L550.8,271.8L552.4,271.0L553.0,272.4L555.1,272.7L556.1,273.9L557.2,275.3L559.2,275.4L559.0,272.5L558.2,273.0L556.4,271.9L555.7,271.4L556.0,268.8L556.5,265.6L555.9,264.4L556.6,262.7L557.3,262.4L560.9,262.0L562.0,262.2Z" fill-rule="evenodd"/><path d="M567.4,264.6L570.0,265.1L570.5,265.8L571.4,267.1L572.2,270.7L571.4,272.7L572.2,276.2L573.1,276.2L574.0,277.0L575.2,279.0L575.4,282.4L574.2,283.0L573.4,284.8L571.7,283.2L571.5,281.3L572.0,280.0L571.9,279.0L570.8,278.3L570.1,278.5L568.6,277.3L567.2,276.6L568.0,274.1L568.8,273.2L568.3,271.0L568.8,268.8L569.3,268.1L568.6,265.8L567.4,264.6Z" fill-rule="evenodd"/><path d="M572.2,270.7L574.2,270.5L577.4,271.3L578.1,270.9L579.9,270.9L580.9,270.1L582.5,270.1L585.4,269.1L587.5,267.5L587.5,267.5L587.5,267.5L587.9,268.7L587.8,271.4L588.2,273.7L588.3,277.9L588.7,279.2L587.9,281.1L586.9,282.9L585.2,284.6L582.8,285.6L579.8,286.9L576.8,289.8L575.7,290.2L573.9,292.1L572.8,292.8L572.5,294.7L573.8,296.7L574.3,298.2L574.4,299.0L574.8,298.9L574.8,301.5L574.3,302.8L575.0,303.2L574.6,304.3L573.4,305.3L571.2,306.2L568.0,307.6L566.9,308.6L567.1,309.7L567.8,309.9L567.5,311.3L565.5,311.3L565.3,310.1L564.9,308.9L564.7,308.0L565.1,305.0L564.5,303.1L563.2,299.3L566.0,296.3L566.7,294.4L567.1,294.1L567.4,292.6L567.0,291.8L567.1,289.8L567.6,287.9L567.6,284.6L566.2,283.7L564.9,283.5L564.4,282.9L563.1,282.3L560.9,282.3L560.7,281.4L560.5,279.5L568.6,277.3L570.1,278.5L570.8,278.3L571.9,279.0L572.0,280.0L571.5,281.3L571.7,283.2L573.4,284.8L574.2,283.0L575.4,282.4L575.2,279.0L574.0,277.0L573.1,276.2L572.2,276.2L571.4,272.7L572.2,270.7Z" fill-rule="evenodd"/><path d="M565.5,311.3L565.0,312.5L563.4,312.8L561.8,311.3L561.8,310.4L562.5,309.4L562.8,308.6L563.6,308.4L564.9,308.9L565.3,310.1L565.5,311.3Z" fill-rule="evenodd"/><path d="M514.7,252.7L513.7,253.3L513.2,254.0L513.2,255.2L512.5,255.4L511.8,253.4L512.8,252.3L513.7,251.8L514.7,252.7ZM512.9,256.3L514.0,255.9L514.7,256.0L515.7,255.6L523.5,255.7L524.2,257.7L525.0,259.3L525.6,260.1L526.6,261.5L528.4,261.3L529.2,260.9L530.7,261.3L531.1,260.6L531.8,259.1L533.4,259.0L533.6,258.5L534.9,258.5L534.7,259.5L537.9,259.4L538.0,261.1L538.5,262.1L538.1,263.8L538.3,265.4L539.2,266.4L539.1,269.6L539.7,269.3L540.9,269.4L542.6,269.0L543.8,269.1L544.0,270.0L543.7,271.3L544.2,272.5L543.8,273.5L544.0,274.4L538.5,274.4L538.4,282.9L540.2,285.1L541.9,286.7L537.0,287.8L530.5,287.4L528.7,286.2L517.9,286.3L517.5,286.5L515.9,285.3L514.2,285.2L512.6,285.6L511.3,286.1L511.0,284.5L511.4,282.1L512.3,279.7L512.5,278.5L513.3,276.1L514.0,275.0L515.5,273.3L516.4,272.1L516.6,270.1L516.5,268.6L515.7,267.7L515.0,266.0L514.3,264.4L514.5,263.9L515.3,262.8L514.5,260.3L513.9,258.5L512.6,256.8L512.9,256.3Z" fill-rule="evenodd"/><path d="M561.3,246.4L561.4,247.5L562.0,248.1L562.0,249.0L561.3,249.5L560.3,250.9L559.3,251.9L558.2,252.0L558.1,248.8L557.4,247.6L559.0,247.8L559.8,246.3L561.3,246.4Z" fill-rule="evenodd"/><path d="M575.3,152.8L574.8,153.6L573.8,153.2L573.3,155.0L573.9,155.3L573.3,155.7L573.1,156.4L574.4,156.0L574.5,157.1L573.1,161.3L572.9,160.6L571.4,156.7L571.4,156.7L571.4,156.7L572.2,155.9L572.0,155.7L572.7,154.5L573.2,152.5L573.6,151.8L573.7,151.8L574.6,151.8L574.8,151.3L575.5,151.3L575.6,152.4L575.2,152.8L575.3,152.8Z" fill-rule="evenodd"/><path d="M575.5,151.3L574.8,151.3L574.6,151.8L573.7,151.8L574.6,149.6L575.9,147.7L576.0,147.6L577.2,147.7L577.6,148.8L576.2,149.8L575.5,151.3Z" fill-rule="evenodd"/><path d="M612.1,273.3L612.8,274.4L613.5,276.1L613.9,279.4L614.6,280.6L614.3,281.9L613.9,282.7L613.0,281.1L612.5,281.9L613.0,283.9L612.7,285.0L612.0,285.6L611.8,287.9L610.8,291.0L609.5,294.7L607.8,299.7L606.8,303.4L605.6,306.5L603.4,307.1L601.1,308.3L599.6,307.6L597.4,306.6L596.7,305.2L596.5,302.9L595.6,300.7L595.3,298.8L595.8,296.9L597.0,296.4L597.1,295.5L598.3,293.5L598.6,291.8L598.0,290.6L597.4,288.9L597.2,286.4L598.2,284.9L598.5,283.2L599.9,283.1L601.3,282.6L602.3,282.1L603.5,282.1L605.0,280.6L607.2,278.9L608.0,277.6L607.7,276.4L608.8,276.8L610.3,274.9L610.3,273.3L611.2,272.1L612.1,273.3Z" fill-rule="evenodd"/><path d="M574.4,156.0L573.1,156.4L573.3,155.7L573.9,155.3L573.3,155.0L573.8,153.2L574.8,153.6L574.8,155.2L574.4,156.0Z" fill-rule="evenodd"/><path d="M435.4,203.7L438.3,203.7L438.9,203.0L439.8,203.0L440.8,203.7L441.7,203.7L442.5,203.2L443.1,204.0L441.9,204.6L440.8,204.5L439.6,204.0L438.6,204.6L438.2,204.6L437.5,205.0L435.1,204.9L435.4,203.7Z" fill-rule="evenodd"/><path d="M505.3,159.2L504.1,154.4L502.5,153.3L502.5,152.7L500.3,151.1L500.1,149.1L501.7,147.6L502.3,145.4L501.9,142.8L502.5,141.5L505.4,140.4L507.2,140.7L507.1,142.1L509.4,141.1L509.6,141.6L508.3,142.9L508.2,144.1L509.2,144.8L508.8,147.1L507.1,148.5L507.6,149.9L509.0,150.0L509.6,151.2L510.6,151.6L510.5,153.7L509.2,154.4L508.4,155.3L506.5,156.3L506.8,157.4L506.6,158.6L505.3,159.2Z" fill-rule="evenodd"/><path d="M456.8,166.9L456.9,166.4L456.9,166.2L456.9,163.1L461.2,161.1L463.8,160.7L466.0,160.0L467.0,158.7L470.2,157.6L470.3,155.6L471.8,155.4L473.0,154.4L476.5,154.0L477.0,152.9L476.3,152.4L475.4,149.5L475.2,147.9L474.2,146.2L476.8,144.8L479.7,144.3L481.3,143.2L483.9,142.4L488.4,141.9L492.8,141.7L494.2,142.1L496.7,141.0L499.5,141.0L500.6,141.6L502.5,141.5L501.9,142.8L502.3,145.4L501.7,147.6L500.1,149.1L500.3,151.1L502.5,152.7L502.5,153.3L504.1,154.4L505.3,159.2L506.1,161.5L506.3,162.8L505.8,164.9L506.0,166.2L505.7,167.6L505.9,169.3L504.9,170.4L506.4,172.4L506.5,173.5L507.5,175.0L508.7,174.5L510.8,175.7L512.0,177.4L502.9,182.5L495.1,187.7L491.4,188.9L488.4,189.2L488.4,187.5L487.2,187.1L485.5,186.3L484.9,185.0L475.9,179.2L466.9,173.4L456.8,166.9Z" fill-rule="evenodd"/><path d="M574.8,153.6L575.3,152.8L578.2,153.8L583.4,151.0L584.5,154.2L584.0,154.6L578.7,156.0L581.3,158.6L580.4,159.1L580.0,160.0L578.0,160.4L577.3,161.3L576.2,162.1L573.2,161.7L573.1,161.3L574.5,157.1L574.4,156.0L574.8,155.2L574.8,153.6Z" fill-rule="evenodd"/><path d="M617.5,175.3L618.0,175.2L618.1,175.9L620.2,175.5L622.4,175.6L624.0,175.7L625.8,173.9L627.8,172.2L629.5,170.5L630.0,171.4L630.4,173.5L629.0,173.5L628.8,175.3L629.3,175.7L628.1,176.2L628.1,177.3L627.3,178.4L627.2,179.4L626.7,180.0L618.7,178.7L617.6,176.0L617.5,175.3Z" fill-rule="evenodd"/><path d="M615.5,174.0L615.3,172.0L616.0,170.6L616.8,170.4L617.6,171.2L617.6,172.8L617.0,174.3L616.3,174.5L615.5,174.0Z" fill-rule="evenodd"/><path d="M607.9,160.1L608.5,161.2L608.3,161.8L609.1,163.9L607.2,163.9L606.6,162.7L604.2,162.4L606.1,159.8L607.9,160.1Z" fill-rule="evenodd"/><path d="M584.5,154.2L583.4,151.0L589.3,148.2L590.4,145.0L590.1,143.0L591.6,142.4L592.9,140.7L594.1,140.3L597.2,140.7L598.1,141.3L599.4,140.9L601.1,144.1L602.9,144.9L603.1,146.4L601.7,147.3L601.1,149.4L603.0,152.0L606.2,153.4L607.6,155.4L607.2,157.4L608.0,157.4L608.0,158.8L609.5,160.2L607.9,160.1L606.1,159.8L604.2,162.4L599.2,162.2L591.7,156.8L587.7,155.0L584.5,154.2Z" fill-rule="evenodd"/><path d="M627.2,179.4L627.3,178.4L628.1,177.3L628.1,176.2L629.3,175.7L628.8,175.3L629.0,173.5L630.4,173.5L631.6,175.4L633.1,176.3L635.0,176.7L636.6,177.2L637.8,178.7L638.5,179.6L639.5,179.9L639.5,180.5L638.5,182.1L638.1,182.8L637.0,183.7L636.0,185.5L634.8,185.4L634.2,186.0L633.8,187.4L634.1,189.2L633.9,189.5L632.6,189.5L631.0,190.5L630.7,191.8L630.1,192.3L628.4,192.3L627.4,193.0L627.4,194.1L626.1,194.8L624.6,194.5L622.9,195.4L621.6,195.6L620.8,193.7L618.7,189.3L626.7,186.7L628.4,181.3L627.2,179.4ZM630.0,171.4L629.5,170.5L630.3,169.6L630.6,169.8L630.4,170.9L630.0,171.4Z" fill-rule="evenodd"/><path d="M925.9,282.4L927.6,283.9L926.7,284.3L925.8,283.1L925.9,282.4ZM924.8,281.8L924.4,281.0L924.3,279.0L925.6,279.8L926.1,282.0L925.3,281.6L924.8,281.8Z" fill-rule="evenodd"/><path d="M753.6,207.5L752.9,204.3L754.6,202.1L758.1,201.6L760.6,201.9L762.8,203.0L764.0,201.1L766.4,202.1L767.0,203.9L766.6,207.1L762.2,209.2L763.3,210.8L760.5,211.0L758.2,212.0L756.0,211.6L754.9,210.3L753.6,207.5Z" fill-rule="evenodd"/><path d="M760.6,201.9L758.1,201.6L754.6,202.1L752.9,204.3L753.6,207.5L751.2,206.3L748.9,206.3L749.3,204.2L746.9,204.2L746.7,207.2L745.3,211.1L744.4,213.4L744.6,215.4L746.3,215.4L747.4,217.9L747.9,220.2L749.4,221.7L751.0,222.0L752.4,223.4L751.5,224.5L749.7,224.8L749.5,223.5L747.4,222.3L746.9,222.8L745.8,221.7L745.4,220.4L744.0,218.9L742.7,217.6L742.2,219.2L741.7,217.7L742.0,216.1L742.8,213.5L744.1,210.8L745.6,208.3L744.5,205.9L744.6,204.6L744.3,203.1L742.5,201.0L741.8,199.7L742.8,199.2L743.7,196.9L742.7,195.1L741.0,193.2L739.7,190.8L740.8,190.3L742.0,187.4L743.9,187.3L745.4,186.2L747.0,185.6L748.1,186.4L748.3,188.0L750.1,188.1L749.4,190.9L749.5,193.3L752.3,191.7L753.1,192.2L754.7,192.1L755.2,191.2L757.2,191.4L759.2,193.5L759.4,196.2L761.6,198.5L761.5,200.7L760.6,201.9Z" fill-rule="evenodd"/><path d="M766.4,202.1L764.0,201.1L762.8,203.0L760.6,201.9L761.5,200.7L761.6,198.5L759.4,196.2L759.2,193.5L757.2,191.4L755.2,191.2L754.7,192.1L753.1,192.2L752.3,191.7L749.5,193.3L749.4,190.9L750.1,188.1L748.3,188.0L748.1,186.4L747.0,185.6L747.5,184.6L749.8,182.8L750.1,183.5L751.5,183.5L751.1,180.5L752.5,180.1L754.0,182.2L755.2,184.6L758.5,184.6L759.5,187.0L757.8,187.7L757.1,188.6L760.3,190.2L762.5,193.4L764.1,195.7L766.2,197.6L766.8,199.5L766.4,202.1Z" fill-rule="evenodd"/><path d="M747.0,185.6L745.4,186.2L743.9,187.3L742.0,187.4L740.8,190.3L739.7,190.8L741.0,193.2L742.7,195.1L743.7,196.9L742.8,199.2L741.8,199.7L742.5,201.0L744.3,203.1L744.6,204.6L744.5,205.9L745.6,208.3L744.1,210.8L742.8,213.5L742.6,211.5L743.4,209.5L742.5,207.9L742.7,205.0L741.6,203.6L740.7,200.4L740.3,197.1L739.1,194.9L737.3,196.2L734.3,198.1L732.8,197.9L731.2,197.2L732.1,193.9L731.5,191.4L729.4,188.4L729.8,187.4L728.2,187.1L726.3,184.9L726.1,182.7L727.1,183.1L727.1,181.2L728.4,180.6L728.2,179.5L728.8,178.6L728.9,175.8L731.0,176.4L732.1,174.2L732.3,172.9L733.7,170.7L733.7,169.1L737.1,167.3L739.0,167.8L738.8,166.1L739.7,165.6L739.5,164.6L741.1,164.4L742.0,166.0L743.2,166.6L743.2,168.7L743.1,170.9L740.6,173.1L740.3,176.3L743.1,175.8L743.7,178.3L745.4,178.8L744.6,181.0L746.6,182.0L747.8,182.5L749.7,181.7L749.8,182.8L747.5,184.6L747.0,185.6Z" fill-rule="evenodd"/><path d="M758.2,212.0L760.5,211.0L763.3,210.8L762.2,209.2L766.6,207.1L767.0,203.9L766.4,202.1L766.8,199.5L766.2,197.6L764.1,195.7L762.5,193.4L760.3,190.2L757.1,188.6L757.8,187.7L759.5,187.0L758.5,184.6L755.2,184.6L754.0,182.2L752.5,180.1L753.9,179.4L756.0,179.5L758.6,179.1L760.9,177.7L762.2,178.7L764.6,179.2L764.2,180.8L765.4,181.8L768.1,182.5L764.6,184.8L762.4,187.3L761.8,189.2L763.8,192.0L766.3,195.5L768.7,197.1L770.3,199.3L771.6,204.2L771.2,208.9L769.0,210.6L765.9,212.4L763.7,214.6L760.4,217.1L759.5,215.4L760.2,213.6L758.2,212.0Z" fill-rule="evenodd"/><path d="M828.7,127.4L828.7,127.4L828.7,127.4L828.7,127.4ZM828.4,126.9L828.4,126.9L828.7,127.4L827.7,127.3L826.6,128.2L825.8,129.1L825.9,131.0L824.5,131.6L824.0,132.0L823.0,132.8L821.2,133.3L820.1,134.0L820.0,135.1L819.7,135.4L820.8,135.9L822.3,137.0L821.9,137.7L820.7,137.9L818.9,138.0L817.8,139.2L816.6,139.1L816.5,139.3L815.2,138.8L814.8,139.3L814.1,139.5L814.0,139.0L813.3,138.8L812.6,138.4L813.3,137.2L813.9,136.9L813.7,136.4L814.4,135.0L814.2,134.5L812.6,134.2L811.4,133.5L813.5,131.8L816.5,130.4L818.3,128.5L819.6,129.3L821.9,129.4L821.5,128.0L825.6,126.9L826.7,125.4L828.4,126.9Z" fill-rule="evenodd"/><path d="M816.5,139.3L816.6,139.1L817.8,139.2L818.9,138.0L820.7,137.9L821.9,137.7L822.3,137.0L824.6,140.2L825.2,141.9L825.2,145.0L824.2,146.4L821.8,147.0L819.7,148.1L817.3,148.3L817.0,146.8L817.5,144.8L816.3,142.1L818.3,141.6L816.5,139.3Z" fill-rule="evenodd"/><path d="M714.0,108.5L716.8,108.1L721.9,105.8L726.0,104.5L728.3,105.3L731.1,105.4L732.8,106.6L735.5,106.7L739.4,107.4L742.0,105.5L740.9,104.0L743.6,101.2L746.6,102.3L749.0,102.6L752.2,103.3L752.7,105.3L756.5,106.4L759.0,105.9L762.4,105.6L765.0,105.9L767.6,107.2L769.3,108.6L771.7,108.6L775.1,109.0L777.5,108.3L781.1,107.9L785.0,106.0L786.6,106.3L788.0,107.2L791.1,107.0L789.8,109.0L788.0,111.6L788.6,112.7L790.2,112.4L792.8,112.8L794.8,111.8L797.0,112.7L799.4,114.5L799.1,115.5L797.0,115.2L793.1,115.5L791.2,116.3L789.3,118.1L785.2,119.1L782.6,120.5L779.8,120.0L778.3,119.7L776.9,121.4L777.8,122.5L778.2,123.4L776.3,124.2L774.4,125.7L771.3,126.6L767.3,126.7L763.0,127.6L759.9,129.1L758.7,128.2L755.5,128.2L751.6,126.6L748.9,126.2L745.4,126.6L739.9,126.0L736.9,126.1L735.4,124.5L734.2,122.0L732.5,121.7L729.3,120.1L725.7,119.7L722.5,119.2L721.6,118.1L722.6,115.0L720.7,112.8L716.9,111.8L714.7,110.4L714.0,108.5Z" fill-rule="evenodd"/><path d="M739.5,164.6L739.7,165.6L738.8,166.1L739.0,167.8L737.1,167.3L733.7,169.1L733.7,170.7L732.3,172.9L732.1,174.2L731.0,176.4L728.9,175.8L728.8,178.6L728.2,179.5L728.4,180.6L727.1,181.2L725.7,177.0L725.0,177.0L724.6,178.7L723.1,177.3L723.9,175.8L725.1,175.7L726.3,173.4L724.8,172.9L722.3,173.0L719.8,172.6L719.6,170.8L718.3,170.6L716.2,169.5L715.2,171.3L717.2,172.7L715.5,173.7L714.9,174.7L716.5,175.4L716.1,177.0L717.0,179.0L717.4,181.2L717.0,182.2L715.2,182.1L711.9,182.7L712.1,184.7L710.7,186.3L706.8,188.1L703.8,191.2L701.8,192.9L699.2,194.6L699.2,195.8L697.8,196.5L695.4,197.5L694.2,197.6L693.4,199.6L694.0,203.1L694.1,205.3L693.0,207.9L693.0,212.4L691.6,212.5L690.4,214.5L691.2,215.4L688.7,216.2L687.8,218.0L686.8,218.8L684.2,216.3L683.0,212.5L682.0,209.8L681.1,208.6L679.6,206.0L679.0,202.7L678.5,201.0L676.1,197.4L675.0,192.2L674.2,188.8L674.2,185.5L673.7,183.1L669.8,184.6L667.9,184.3L664.4,181.1L665.7,180.1L664.9,179.1L661.8,176.8L663.6,175.0L669.4,175.0L668.9,172.8L667.4,171.4L667.1,169.4L665.4,168.2L668.3,165.4L671.4,165.6L674.2,162.8L675.9,160.1L678.5,157.4L678.4,155.5L680.7,153.9L678.5,152.6L677.6,150.8L676.7,148.5L678.0,147.3L682.0,148.0L685.0,147.6L687.6,145.3L690.4,148.5L690.2,150.7L691.2,152.0L691.1,153.4L689.2,153.0L690.0,156.0L692.6,157.6L696.3,159.5L694.6,160.7L693.6,163.2L696.2,164.2L698.7,165.5L702.1,167.0L705.8,167.4L707.3,168.7L709.4,169.0L712.6,169.6L714.8,169.6L715.1,168.5L714.8,166.8L715.0,165.7L716.6,165.1L716.8,167.2L716.9,167.7L719.3,168.7L721.0,168.3L723.2,168.5L725.4,168.4L725.6,166.8L724.5,165.9L726.7,165.6L729.1,163.6L732.2,161.9L734.4,162.6L736.3,161.5L737.6,163.1L736.7,164.2L739.5,164.6Z" fill-rule="evenodd"/><path d="M727.1,181.2L727.1,183.1L726.1,182.7L726.3,184.9L725.6,183.5L725.4,182.1L724.9,180.8L723.8,179.3L721.3,179.2L721.6,180.3L720.7,181.8L719.6,181.2L719.2,181.7L718.5,181.4L717.4,181.2L717.0,179.0L716.1,177.0L716.5,175.4L714.9,174.7L715.5,173.7L717.2,172.7L715.2,171.3L716.2,169.5L718.3,170.6L719.6,170.8L719.8,172.6L722.3,173.0L724.8,172.9L726.3,173.4L725.1,175.7L723.9,175.8L723.1,177.3L724.6,178.7L725.0,177.0L725.7,177.0L727.1,181.2Z" fill-rule="evenodd"/><path d="M724.5,165.9L725.6,166.8L725.4,168.4L723.2,168.5L721.0,168.3L719.3,168.7L716.9,167.7L716.8,167.2L718.6,165.2L720.0,164.5L721.9,165.2L723.4,165.2L724.5,165.9Z" fill-rule="evenodd"/><path d="M715.0,165.7L714.8,166.8L715.1,168.5L714.8,169.6L712.6,169.6L709.4,169.0L707.3,168.7L705.8,167.4L702.1,167.0L698.7,165.5L696.2,164.2L693.6,163.2L694.6,160.7L696.3,159.5L697.4,158.9L699.5,159.7L702.2,161.4L703.7,161.8L704.6,163.1L706.7,163.6L708.9,164.8L711.9,165.4L715.0,165.7Z" fill-rule="evenodd"/><path d="M687.6,145.3L685.0,147.6L682.0,148.0L678.0,147.3L676.7,148.5L677.6,150.8L678.5,152.6L680.7,153.9L678.4,155.5L678.5,157.4L675.9,160.1L674.2,162.8L671.4,165.6L668.3,165.4L665.4,168.2L667.1,169.4L667.4,171.4L668.9,172.8L669.4,175.0L663.6,175.0L661.8,176.8L659.8,176.1L659.1,174.2L657.0,172.2L652.1,172.7L647.7,172.8L644.0,173.1L645.0,170.0L648.8,168.6L648.6,167.4L647.3,167.0L647.3,164.6L644.7,163.5L643.7,161.9L642.3,160.5L646.8,161.8L649.5,161.4L651.1,161.8L651.6,161.2L653.5,161.4L656.9,160.3L657.0,158.0L658.5,156.5L660.5,156.5L660.8,155.8L662.8,155.4L663.8,155.7L664.8,154.9L664.7,153.3L665.8,151.7L667.5,151.0L666.5,149.3L669.0,149.4L669.8,148.4L669.6,147.4L671.0,146.3L670.7,144.9L670.0,143.8L671.6,142.6L674.5,142.1L677.5,141.8L678.9,141.3L680.4,141.0L682.4,142.2L683.2,144.3L687.6,145.3Z" fill-rule="evenodd"/><path d="M657.4,140.4L658.9,140.4L660.9,140.9L661.7,141.3L663.6,140.4L664.5,140.9L665.4,139.7L667.0,139.8L667.4,139.4L667.7,138.3L668.8,137.4L670.3,138.0L670.0,138.8L670.8,138.9L670.5,141.2L671.6,142.0L672.5,141.5L673.7,141.2L675.4,140.0L677.2,140.2L679.9,140.2L680.4,141.0L678.9,141.3L677.5,141.8L674.5,142.1L671.6,142.6L670.0,143.8L670.7,144.9L671.0,146.3L669.6,147.4L669.8,148.4L669.0,149.4L666.5,149.3L667.5,151.0L665.8,151.7L664.7,153.3L664.8,154.9L663.8,155.7L662.8,155.4L660.8,155.8L660.5,156.5L658.5,156.5L657.0,158.0L656.9,160.3L653.5,161.4L651.6,161.2L651.1,161.8L649.5,161.4L646.8,161.8L642.3,160.5L644.7,158.0L644.5,156.3L642.5,155.9L642.3,154.2L641.4,152.0L642.6,150.6L641.4,150.2L642.1,148.3L643.2,144.9L645.9,145.9L648.0,145.6L648.5,144.4L650.6,144.0L652.1,143.2L652.7,141.0L654.9,140.5L655.3,139.6L656.6,140.3L657.4,140.4Z" fill-rule="evenodd"/><path d="M660.9,140.9L662.4,138.2L661.8,136.3L659.8,135.6L660.5,134.5L662.8,134.6L664.0,133.1L664.9,131.4L668.4,130.8L667.9,132.0L668.3,132.8L669.4,132.7L668.4,133.5L665.5,133.1L665.2,134.6L668.1,134.4L671.4,135.3L676.5,134.9L677.1,137.3L678.0,137.0L679.6,137.7L679.5,138.7L679.9,140.2L677.2,140.2L675.4,140.0L673.7,141.2L672.5,141.5L671.6,142.0L670.5,141.2L670.8,138.9L670.0,138.8L670.3,138.0L668.8,137.4L667.7,138.3L667.4,139.4L667.0,139.8L665.4,139.7L664.5,140.9L663.6,140.4L661.7,141.3L660.9,140.9Z" fill-rule="evenodd"/><path d="M669.2,127.3L669.8,126.1L671.6,125.7L676.0,126.7L676.4,125.1L677.9,124.5L681.7,125.7L682.7,125.4L687.1,125.4L691.0,125.7L692.4,126.7L694.0,127.1L693.7,127.7L689.4,129.1L688.5,130.2L685.1,130.5L684.1,132.2L681.2,131.8L679.4,132.4L676.9,133.6L677.2,134.2L676.5,134.9L671.4,135.3L668.1,134.4L665.2,134.6L665.5,133.1L668.4,133.5L669.4,132.7L671.4,132.9L674.8,131.0L671.7,129.6L669.8,130.3L667.8,129.3L670.0,127.6L669.2,127.3Z" fill-rule="evenodd"/><path d="M620.0,128.6L621.2,127.7L624.2,127.1L626.0,127.9L627.9,130.0L629.2,129.8L632.3,129.8L631.8,128.5L634.1,127.5L636.3,126.0L639.9,127.4L640.2,129.5L641.2,130.1L644.1,130.0L645.0,130.4L646.3,133.2L649.4,135.0L651.1,136.3L653.9,137.6L657.5,138.7L657.4,140.4L656.6,140.3L655.3,139.6L654.9,140.5L652.7,141.0L652.1,143.2L650.6,144.0L648.5,144.4L648.0,145.6L645.9,145.9L643.2,144.9L643.0,142.7L641.0,142.6L638.0,140.2L635.8,139.9L632.9,138.6L631.0,138.3L629.8,138.8L628.0,138.8L626.1,140.3L623.8,140.8L623.3,138.9L623.7,136.1L621.6,135.2L622.3,133.4L620.5,133.2L621.1,131.0L623.6,131.7L626.0,130.8L624.0,129.2L623.3,127.7L621.1,128.4L620.8,130.3L620.0,128.6Z" fill-rule="evenodd"/><path d="M609.5,160.2L608.0,158.8L608.0,157.4L607.2,157.4L607.6,155.4L606.2,153.4L603.0,152.0L601.1,149.4L601.7,147.3L603.1,146.4L602.9,144.9L601.1,144.1L599.4,140.9L599.4,140.9L597.9,138.7L598.5,137.9L597.6,134.9L599.5,134.1L599.9,135.1L601.2,136.3L603.0,136.7L604.0,136.6L607.2,134.6L608.2,134.4L608.9,135.2L608.0,136.5L609.7,137.9L610.4,137.8L611.2,139.8L613.7,140.3L615.6,141.7L619.4,142.1L623.5,141.4L623.8,140.8L626.1,140.3L628.0,138.8L629.8,138.8L631.0,138.3L632.9,138.6L635.8,139.9L638.0,140.2L641.0,142.6L643.0,142.7L643.2,144.9L642.1,148.3L641.4,150.2L642.6,150.6L641.4,152.0L642.3,154.2L642.5,155.9L644.5,156.3L644.7,158.0L642.3,160.5L643.7,161.9L644.7,163.5L647.3,164.6L647.3,167.0L648.6,167.4L648.8,168.6L645.0,170.0L644.0,173.1L639.0,172.3L636.1,171.7L633.1,171.4L631.9,168.1L630.6,167.6L628.6,168.1L625.9,169.4L622.6,168.5L620.0,166.5L617.4,165.7L615.6,163.2L613.6,159.6L612.2,160.0L610.5,159.2L609.5,160.2Z" fill-rule="evenodd"/><path d="M575.3,152.8L575.2,152.8L575.6,152.4L575.5,151.3L576.2,149.8L577.6,148.8L577.2,147.7L576.0,147.6L575.7,145.6L576.4,144.5L577.1,143.9L577.8,143.3L578.0,141.8L578.8,142.3L581.8,141.6L583.2,142.1L585.4,142.1L588.5,141.1L589.9,141.1L592.9,140.7L591.6,142.4L590.1,143.0L590.4,145.0L589.3,148.2L583.4,151.0L578.2,153.8L575.3,152.8Z" fill-rule="evenodd"/><path d="M604.0,136.6L603.0,136.7L602.0,135.1L602.0,134.7L600.8,134.7L600.0,134.0L599.5,134.1L598.4,133.3L596.4,132.7L596.7,131.4L596.2,130.4L599.9,130.0L600.5,130.7L601.5,131.2L601.0,131.8L602.4,132.8L601.6,133.6L602.8,134.3L604.0,134.8L604.0,136.6Z" fill-rule="evenodd"/><path d="M509.4,83.1L510.6,81.5L512.8,79.7L513.7,76.6L512.0,75.2L511.8,71.7L513.5,69.2L516.2,69.2L517.1,68.1L516.1,67.2L520.3,63.5L523.0,60.5L524.7,58.6L527.3,58.6L528.0,57.2L533.0,57.6L533.4,55.8L535.1,55.7L538.6,57.0L542.8,58.8L542.8,62.9L543.7,64.0L539.2,64.7L536.6,66.6L537.0,68.2L532.7,70.4L527.6,72.7L525.7,76.4L527.6,78.3L530.1,79.8L527.7,82.8L524.9,83.4L523.9,87.9L522.3,90.4L519.1,90.1L517.6,92.2L514.5,92.4L513.7,89.8L511.4,86.8L509.4,83.1Z" fill-rule="evenodd"/><path d="M555.1,90.2L557.9,90.9L558.3,91.5L559.7,91.2L562.3,91.9L562.6,93.1L562.0,93.8L563.7,95.6L564.8,96.1L564.6,96.5L566.4,97.0L567.2,97.7L566.1,98.3L564.0,98.2L563.5,98.5L564.1,99.4L564.8,101.1L564.8,101.1L562.5,101.2L561.7,101.8L561.5,103.1L560.4,102.9L558.0,103.0L557.3,102.4L556.3,102.9L555.3,102.5L553.2,102.4L550.2,101.8L547.5,101.6L545.5,101.6L544.0,102.4L542.7,102.5L542.7,101.3L541.9,100.0L543.5,99.5L543.5,98.4L542.7,97.4L542.6,96.2L545.2,96.3L548.1,95.2L548.7,93.7L550.9,92.9L550.7,91.7L552.3,91.2L555.1,90.2Z" fill-rule="evenodd"/><path d="M564.8,101.1L565.8,101.2L566.4,100.6L567.2,100.7L570.0,100.4L571.7,101.9L571.0,102.5L571.3,103.3L573.4,103.4L574.3,104.6L574.3,105.1L577.7,106.1L579.7,105.6L581.4,106.9L582.9,106.9L586.9,107.7L586.9,108.5L585.8,109.9L586.4,111.4L586.0,112.3L583.4,112.5L582.0,113.2L581.9,114.4L579.8,114.6L578.0,115.5L575.5,115.6L573.2,116.6L573.4,118.0L573.0,118.0L572.6,117.4L571.8,117.3L569.9,116.7L569.2,117.4L568.8,117.1L564.7,116.4L564.5,115.5L562.0,115.8L561.0,117.2L558.9,119.2L557.7,118.8L556.5,119.2L555.3,118.7L556.0,118.4L556.4,117.5L557.2,116.6L557.0,116.2L557.5,116.0L557.8,116.3L559.4,116.4L560.1,116.2L559.6,115.9L559.8,115.5L558.8,114.9L558.4,113.7L557.5,113.3L557.7,112.4L556.5,111.7L555.4,111.6L553.4,110.8L551.6,111.0L551.0,111.4L549.9,111.4L549.2,112.0L547.2,112.3L546.3,112.7L545.1,112.0L543.4,112.0L541.7,111.7L540.6,112.3L540.4,111.6L538.9,110.9L539.4,109.8L540.2,109.1L540.7,109.3L540.0,108.1L542.5,105.8L543.8,105.5L544.1,104.8L542.7,102.5L544.0,102.4L545.5,101.6L547.5,101.6L550.2,101.8L553.2,102.4L555.3,102.5L556.3,102.9L557.3,102.4L558.0,103.0L560.4,102.9L561.5,103.1L561.7,101.8L562.5,101.2L564.8,101.1Z" fill-rule="evenodd"/><path d="M542.6,96.2L542.7,97.4L543.5,98.4L543.5,99.5L541.9,100.0L542.7,101.3L542.7,102.5L544.1,104.8L543.8,105.5L542.5,105.8L540.0,108.1L540.7,109.3L540.2,109.1L537.6,108.1L535.7,108.5L534.4,108.2L532.9,108.8L531.5,107.8L530.4,108.2L530.3,108.0L529.0,106.7L527.1,106.5L526.8,105.7L525.0,105.4L524.6,106.1L523.1,105.5L523.3,104.8L521.3,104.6L520.0,103.7L519.0,102.0L519.2,101.1L518.5,99.7L517.5,98.7L518.3,98.0L517.7,96.6L519.5,95.9L523.6,94.6L527.0,93.7L529.7,94.2L529.9,94.8L532.4,94.9L535.7,95.2L540.6,95.1L542.0,95.4L542.6,96.2Z" fill-rule="evenodd"/><path d="M525.3,111.7L525.1,112.8L523.6,112.8L524.1,113.3L523.2,115.1L522.7,115.5L520.4,115.6L519.0,116.2L516.8,116.0L513.0,115.3L512.4,114.4L509.8,114.8L509.5,115.3L507.8,115.0L506.5,114.9L505.3,114.4L505.7,113.7L505.6,113.3L506.4,113.1L507.7,113.9L508.1,113.2L510.5,113.3L512.4,112.8L513.7,112.9L514.5,113.4L514.7,113.0L514.4,111.2L515.3,110.9L516.3,109.7L518.2,110.5L519.7,109.4L520.7,109.2L522.7,110.0L524.0,109.9L525.2,110.4L525.0,110.7L525.3,111.7Z" fill-rule="evenodd"/><path d="M538.9,110.9L540.4,111.6L540.6,112.3L538.9,112.9L537.7,114.7L536.1,116.5L533.9,117.0L532.3,116.9L530.2,117.6L530.2,117.6L529.2,118.0L527.0,117.5L525.0,116.3L524.2,116.0L523.7,115.1L523.2,115.1L524.1,113.3L523.6,112.8L525.1,112.8L525.3,111.7L526.6,112.4L527.6,112.6L529.9,112.3L530.1,111.8L531.1,111.7L532.4,111.3L532.7,111.5L534.0,111.1L534.6,110.5L535.5,110.3L538.3,111.1L538.9,110.9Z" fill-rule="evenodd"/><path d="M551.0,111.4L551.6,111.0L553.4,110.8L555.4,111.6L556.5,111.7L557.7,112.4L557.5,113.3L558.4,113.7L558.8,114.9L559.8,115.5L559.6,115.9L560.1,116.2L559.4,116.4L557.8,116.3L557.5,116.0L557.0,116.2L557.2,116.6L556.4,117.5L556.0,118.4L555.3,118.7L554.8,117.5L555.1,116.3L555.0,115.2L553.5,113.6L552.6,112.5L551.8,111.7L551.0,111.4Z" fill-rule="evenodd"/><path d="M555.3,118.7L556.5,119.2L557.7,118.8L558.9,119.2L559.0,119.9L557.7,120.5L556.9,120.2L556.2,123.4L554.6,123.2L552.6,122.2L549.5,122.8L548.2,123.5L544.3,123.4L542.2,122.9L541.2,123.1L540.4,122.0L539.9,121.6L540.5,121.1L539.9,120.8L539.1,121.4L537.5,120.6L537.3,119.5L535.7,118.9L535.4,118.0L533.9,117.0L536.1,116.5L537.7,114.7L538.9,112.9L540.6,112.3L541.7,111.7L543.4,112.0L545.1,112.0L546.3,112.7L547.2,112.3L549.2,112.0L549.9,111.4L551.0,111.4L551.8,111.7L552.6,112.5L553.5,113.6L555.0,115.2L555.1,116.3L554.8,117.5L555.3,118.7Z" fill-rule="evenodd"/><path d="M550.7,91.7L550.9,92.9L548.7,93.7L548.1,95.2L545.2,96.3L542.6,96.2L542.0,95.4L540.6,95.1L540.4,94.4L540.7,93.7L539.5,93.3L536.7,92.8L536.1,90.6L539.2,89.8L543.7,89.9L546.3,89.7L546.7,90.2L548.1,90.4L550.7,91.7Z" fill-rule="evenodd"/><path d="M552.8,86.7L554.1,87.3L554.3,88.6L555.1,90.2L552.3,91.2L550.7,91.7L548.1,90.4L546.7,90.2L546.3,89.7L543.7,89.9L539.2,89.8L536.1,90.6L536.2,88.6L537.6,86.9L540.1,86.0L542.2,88.0L544.3,87.9L544.8,85.9L547.1,85.4L548.3,85.7L550.6,86.7L552.8,86.7Z" fill-rule="evenodd"/><path d="M554.6,81.4L554.6,81.4L555.0,81.9L553.1,83.4L553.9,85.9L552.8,86.7L550.6,86.7L548.3,85.7L547.1,85.4L544.8,85.9L545.1,84.3L544.2,84.6L542.5,83.7L542.2,82.2L545.6,81.4L549.0,81.0L551.9,81.5L554.6,81.4L554.6,81.4Z" fill-rule="evenodd"/><path d="M517.7,96.6L518.3,98.0L517.5,98.7L518.5,99.7L519.2,101.1L519.0,102.0L520.0,103.7L518.9,104.0L518.2,103.7L517.5,104.2L515.6,104.7L514.6,105.4L512.6,106.0L513.1,106.7L513.4,107.9L514.8,108.5L516.3,109.7L515.3,110.9L514.4,111.2L514.7,113.0L514.5,113.4L513.7,112.9L512.4,112.8L510.5,113.3L508.1,113.2L507.7,113.9L506.4,113.1L505.6,113.3L502.7,112.5L502.2,113.0L499.9,113.0L500.2,111.1L501.6,109.3L497.8,108.8L496.5,108.1L496.6,106.9L496.1,106.3L496.4,104.5L496.0,101.7L497.6,101.7L498.2,100.7L498.9,98.3L498.4,97.4L498.9,96.8L501.2,96.7L501.7,97.3L503.5,95.9L502.9,94.9L502.7,93.4L504.8,93.8L506.5,93.4L506.5,94.4L509.2,95.0L509.2,96.0L511.9,95.5L513.4,94.7L516.4,95.8L517.7,96.6Z" fill-rule="evenodd"/><path d="M540.4,122.0L541.2,123.1L542.2,122.9L544.3,123.4L548.2,123.5L549.5,122.8L552.6,122.2L554.6,123.2L556.2,123.4L554.8,124.6L553.8,126.5L554.7,128.0L552.4,127.6L549.6,128.5L549.6,129.8L547.2,130.0L545.3,129.1L543.2,129.8L541.2,129.8L541.0,128.0L539.7,127.1L540.1,126.8L539.8,126.5L540.3,125.6L541.3,124.8L540.0,123.6L539.8,122.6L540.4,122.0Z" fill-rule="evenodd"/><path d="M550.1,145.9L549.8,146.7L545.9,146.9L546.0,146.4L542.7,145.9L543.2,144.8L544.7,145.7L546.7,145.5L548.7,145.7L548.7,146.2L550.1,145.9ZM541.2,129.8L543.2,129.8L545.3,129.1L547.2,130.0L549.6,129.8L549.6,128.5L550.9,129.2L550.1,130.8L549.5,131.1L547.9,131.1L546.5,130.8L543.2,131.5L545.1,133.0L543.7,133.4L542.2,133.4L540.8,132.1L540.3,132.6L540.9,134.2L542.3,135.5L541.3,136.1L542.7,137.3L544.1,138.1L544.1,139.6L541.6,138.9L542.4,140.2L540.7,140.5L541.7,142.9L540.0,142.9L537.8,141.7L536.8,139.6L536.3,137.8L535.3,136.6L533.9,135.1L533.7,134.3L535.0,133.0L535.1,132.2L536.0,131.8L536.1,131.1L537.8,130.8L538.8,130.3L540.3,130.3L540.7,129.9L541.2,129.8Z" fill-rule="evenodd"/><path d="M599.4,140.9L598.1,141.3L597.2,140.7L594.1,140.3L592.9,140.7L589.9,141.1L588.5,141.1L585.4,142.1L583.2,142.1L581.8,141.6L578.8,142.3L578.0,141.8L577.8,143.3L577.1,143.9L576.4,144.5L575.4,143.3L576.4,142.3L574.8,142.5L572.6,141.9L570.7,143.4L566.7,143.7L564.5,142.3L561.7,142.2L561.0,143.3L559.2,143.6L556.6,142.2L553.7,142.2L552.1,139.6L550.2,138.1L551.5,136.0L549.8,134.8L552.7,132.2L556.9,132.1L558.0,130.1L563.1,130.4L566.3,128.7L569.4,127.9L573.8,127.9L578.4,129.8L582.3,130.8L585.4,130.4L587.7,130.6L590.8,129.2L593.7,129.1L596.2,130.4L596.7,131.4L596.4,132.7L598.4,133.3L599.5,134.1L597.6,134.9L598.5,137.9L597.9,138.7L599.4,140.9L599.4,140.9ZM549.6,128.5L552.4,127.6L554.7,128.0L555.0,129.0L557.3,129.9L556.8,130.5L553.7,130.7L552.5,131.5L550.3,132.9L549.4,131.7L549.5,131.1L550.1,130.8L550.9,129.2L549.6,128.5Z" fill-rule="evenodd"/><path d="M536.1,131.1L536.0,131.8L535.1,132.2L535.0,133.0L533.7,134.3L533.3,134.1L533.2,133.6L531.7,132.7L531.5,131.4L531.7,129.6L532.1,128.7L531.7,128.3L531.7,128.3L531.5,127.5L532.6,126.2L532.8,126.7L533.5,126.4L534.1,127.1L534.7,127.4L534.9,128.4L534.9,128.4L534.6,129.3L534.9,130.4L536.1,131.1Z" fill-rule="evenodd"/><path d="M524.2,116.0L525.0,116.3L527.0,117.5L529.2,118.0L530.2,117.6L530.9,118.6L531.7,119.4L530.7,120.4L529.5,119.8L527.6,119.8L525.3,119.4L524.1,119.4L523.5,120.0L522.6,119.4L522.0,120.5L523.3,121.7L523.9,122.6L525.1,123.6L526.1,124.1L527.1,125.3L529.5,126.3L529.2,126.7L529.2,126.7L526.7,125.7L525.1,124.8L522.7,124.0L520.5,122.0L521.0,121.8L519.8,120.7L519.7,119.8L518.0,119.4L517.2,120.5L516.4,119.6L516.5,118.7L516.6,118.7L518.4,118.8L518.9,118.3L519.8,118.7L520.9,118.8L520.9,118.0L521.8,117.8L522.0,116.7L524.2,116.0Z" fill-rule="evenodd"/><path d="M505.6,113.3L505.7,113.7L505.3,114.4L506.5,114.9L507.8,115.0L507.6,116.0L506.5,116.5L504.5,116.2L503.9,117.2L502.6,117.3L502.2,116.9L500.7,117.8L499.4,117.9L498.2,117.4L497.3,116.2L496.1,116.6L496.1,115.4L498.0,113.9L498.0,113.2L499.2,113.5L499.9,113.0L502.2,113.0L502.7,112.5L505.6,113.3Z" fill-rule="evenodd"/><path d="M496.1,106.3L496.6,106.9L496.5,108.1L495.7,108.2L495.1,107.9L495.4,106.4L496.1,106.3Z" fill-rule="evenodd"/><path d="M496.4,104.5L496.1,106.3L495.4,106.4L495.1,107.9L492.8,106.7L491.4,106.9L489.6,105.7L488.3,104.6L487.1,104.5L486.7,103.6L488.8,103.1L488.8,103.1L488.8,103.1L490.8,103.3L493.3,102.7L495.0,103.9L496.4,104.5Z" fill-rule="evenodd"/><path d="M498.4,97.4L498.9,98.3L498.2,100.7L497.6,101.7L496.0,101.7L496.4,104.5L495.0,103.9L493.3,102.7L490.8,103.3L488.8,103.1L488.8,103.1L490.2,102.3L492.5,98.4L496.2,97.3L498.4,97.4Z" fill-rule="evenodd"/><path d="M455.9,128.3L456.9,127.6L458.0,127.3L458.6,128.6L460.2,128.6L460.7,128.2L462.2,128.3L463.0,129.6L461.7,130.4L461.7,132.5L461.3,132.8L461.2,134.1L460.0,134.3L461.1,135.9L460.3,137.7L461.3,138.5L460.9,139.2L459.9,140.2L460.1,141.1L459.1,141.8L457.6,141.4L456.3,141.7L456.7,139.6L456.4,138.0L455.2,137.7L454.6,136.7L454.8,135.0L455.9,134.0L456.1,132.9L456.6,131.3L456.6,130.2L456.0,129.2L455.9,128.3Z" fill-rule="evenodd"/><path d="M460.1,141.1L459.9,140.2L460.9,139.2L461.3,138.5L460.3,137.7L461.1,135.9L460.0,134.3L461.2,134.1L461.3,132.8L461.7,132.5L461.7,130.4L463.0,129.6L462.2,128.3L460.7,128.2L460.2,128.6L458.6,128.6L458.0,127.3L456.9,127.6L455.9,128.3L456.0,126.4L455.0,125.3L458.7,123.3L462.0,123.8L465.6,123.8L468.4,124.3L470.6,124.1L474.9,124.2L476.0,125.2L480.9,126.5L481.9,125.9L484.9,127.1L488.0,126.7L488.1,128.3L485.6,130.1L482.2,130.6L481.9,131.5L480.3,133.0L479.3,135.2L480.3,136.7L478.8,137.9L478.2,139.6L476.2,140.2L474.3,142.2L470.9,142.2L468.3,142.2L466.7,143.1L465.7,144.1L464.4,143.9L463.4,143.0L462.6,141.5L460.1,141.1Z" fill-rule="evenodd"/><path d="M463.5,96.4L463.9,98.3L461.9,100.6L457.2,102.2L453.4,101.8L455.6,99.0L454.2,96.3L457.8,94.2L459.8,93.0L460.4,94.4L459.8,95.8L461.5,95.8L463.5,96.4Z" fill-rule="evenodd"/><path d="M922.1,296.2L924.3,297.9L925.7,299.1L924.6,299.7L923.2,299.0L921.3,297.8L919.5,296.4L917.8,294.5L917.4,293.6L918.6,293.7L920.1,294.6L921.2,295.5L922.1,296.2Z" fill-rule="evenodd"/><path d="M912.3,268.0L913.1,268.9L911.2,268.9L910.2,267.2L911.8,267.9L912.3,268.0ZM911.1,265.6L910.7,266.1L908.8,263.8L908.2,262.2L909.1,262.2L910.1,264.3L911.1,265.6ZM908.9,266.3L907.9,266.4L906.3,266.1L905.7,265.7L905.9,264.6L907.6,265.1L908.5,265.6L908.9,266.3ZM905.7,261.4L906.3,262.2L906.4,262.8L904.4,261.6L902.9,260.7L901.9,259.8L902.3,259.5L903.5,260.2L905.7,261.4ZM899.0,258.7L900.1,259.6L899.6,259.7L898.4,259.1L897.3,258.0L897.4,257.6L899.0,258.7Z" fill-rule="evenodd"/><path d="M951.7,346.8L950.7,348.3L949.4,350.1L947.3,351.2L946.8,350.5L945.7,350.1L947.3,347.9L946.4,346.4L943.5,345.4L943.6,344.4L945.5,343.5L946.0,341.4L945.9,339.7L944.8,337.9L944.9,337.4L943.6,336.3L941.5,334.0L940.4,332.1L941.4,331.9L942.8,333.3L944.9,334.0L945.6,336.4L947.6,339.2L947.6,337.4L948.8,338.1L949.2,340.1L951.4,341.0L953.2,341.2L954.7,340.2L956.0,340.5L955.4,342.9L954.6,344.4L952.6,344.4L951.8,345.2L952.1,346.3L951.7,346.8ZM932.4,356.1L934.7,354.8L936.3,353.4L937.5,351.4L938.5,350.7L938.9,349.2L940.8,348.0L941.4,349.1L942.0,350.2L943.9,349.1L944.7,350.3L944.7,351.4L943.7,352.6L941.9,354.6L940.6,355.7L941.5,356.9L939.5,357.0L937.2,358.0L936.5,359.7L935.0,362.4L932.9,363.6L931.6,364.4L929.1,364.3L927.4,363.4L924.5,363.3L924.0,362.3L925.5,360.3L928.8,357.7L930.5,357.2L932.4,356.1Z" fill-rule="evenodd"/><path d="M873.8,348.8L875.4,349.0L875.6,352.2L874.7,353.1L874.4,355.2L873.5,354.5L871.7,356.4L871.1,356.2L869.5,356.1L867.8,353.9L867.5,352.1L865.9,349.8L866.0,348.5L867.7,348.8L870.3,349.7L871.8,349.3L873.8,348.8ZM816.4,325.9L813.6,327.3L811.3,327.9L810.7,329.3L809.8,330.4L807.5,330.4L805.8,330.7L803.5,330.2L801.5,330.5L799.7,330.6L798.1,332.0L797.4,331.9L796.0,332.7L794.7,333.5L792.8,333.4L791.0,333.4L788.2,331.7L786.7,331.2L786.8,329.7L788.1,329.3L788.6,328.7L788.5,327.7L788.8,325.9L788.5,324.3L787.1,321.6L786.7,320.1L786.8,318.6L785.7,316.8L785.6,316.0L784.5,315.0L784.1,312.9L782.6,310.8L782.2,309.6L783.4,310.8L782.5,308.3L783.8,309.1L784.6,310.1L784.6,308.8L783.3,306.7L783.0,305.8L782.4,305.0L782.7,303.5L783.2,302.8L783.6,301.5L783.3,299.9L784.4,298.0L784.6,300.0L785.7,298.2L787.9,297.3L789.2,296.2L791.2,295.2L792.4,295.0L793.2,295.3L795.3,294.3L796.9,294.0L797.3,293.5L798.0,293.2L799.5,293.3L802.3,292.5L803.7,291.3L804.4,289.9L806.0,288.5L806.1,287.5L806.2,286.0L808.0,283.7L809.2,286.0L810.3,285.5L809.3,284.3L810.2,283.0L811.4,283.5L811.7,281.5L813.1,280.2L813.8,279.1L815.1,278.7L815.2,277.9L816.3,278.3L816.4,277.6L817.6,277.2L818.8,276.8L820.8,278.1L822.3,279.7L824.0,279.7L825.7,279.9L825.1,278.5L826.4,276.3L827.6,275.6L827.2,275.0L828.3,273.4L829.9,272.5L831.3,272.8L833.5,272.3L833.5,270.9L831.5,270.1L833.0,269.7L834.7,270.3L836.1,271.4L838.4,272.1L839.1,271.8L840.8,272.7L842.4,271.9L843.4,272.1L844.0,271.6L845.2,272.9L844.5,274.4L843.5,275.4L842.6,275.5L842.9,276.6L842.1,277.9L841.1,279.2L841.3,280.0L843.5,281.5L845.5,282.3L846.9,283.2L848.8,284.8L849.6,284.8L851.0,285.5L851.4,286.3L853.9,287.2L855.7,286.3L856.2,284.9L856.7,283.7L857.1,282.2L857.9,280.1L857.5,278.8L857.7,278.1L857.4,276.5L857.7,274.5L858.2,274.0L857.8,273.1L858.5,271.7L859.0,270.2L859.0,269.4L860.0,268.4L860.8,269.8L861.0,271.4L861.6,271.7L861.8,272.9L862.7,274.2L862.9,275.7L862.8,276.7L863.8,278.8L865.5,277.8L866.4,278.9L867.7,280.0L867.4,281.1L868.0,283.4L868.4,284.8L869.0,285.1L869.8,287.4L869.5,288.7L870.4,290.6L873.3,291.9L875.1,293.2L876.9,294.4L876.6,295.0L878.1,296.7L879.1,299.6L880.2,299.0L881.3,300.1L881.9,299.7L882.4,302.6L884.3,304.2L885.5,305.2L887.6,307.4L888.4,309.5L888.4,311.0L888.2,312.7L889.5,315.0L889.4,317.3L888.9,318.6L888.2,320.9L888.2,322.5L887.7,324.4L886.5,326.8L884.6,328.1L883.6,330.2L882.7,331.5L881.9,333.8L880.9,335.1L880.2,337.1L879.9,339.0L880.0,339.8L878.5,340.7L875.5,340.8L873.0,341.9L871.8,343.0L870.2,344.1L868.0,342.9L866.3,342.4L866.8,341.1L865.3,341.6L863.0,343.5L860.7,342.8L859.1,342.3L857.6,342.2L855.0,341.4L853.3,339.7L852.8,337.7L852.2,336.4L850.9,335.3L848.3,335.0L849.2,333.7L848.6,331.7L847.3,333.5L844.9,334.0L846.3,332.6L846.7,331.0L847.7,329.7L847.5,327.7L845.3,330.0L843.7,330.9L842.6,333.0L840.6,331.9L840.6,330.5L839.0,328.6L837.6,327.6L838.1,327.0L834.6,325.4L832.8,325.3L830.2,324.0L825.4,324.2L822.0,325.2L818.9,326.1L816.4,325.9Z" fill-rule="evenodd"/><path d="M698.1,219.9L697.7,222.7L696.6,223.5L694.3,224.1L693.0,222.0L692.5,218.1L693.7,213.8L695.6,215.3L696.8,217.2L698.1,219.9Z" fill-rule="evenodd"/><path d="M771.9,191.5L769.7,190.6L769.7,188.4L771.0,187.1L773.9,186.4L775.4,186.5L776.0,187.5L774.9,188.7L774.2,190.2L771.9,191.5ZM694.0,127.1L693.8,125.5L695.6,124.9L693.2,120.2L698.5,119.2L699.9,118.6L701.8,113.8L707.1,114.7L708.6,113.5L708.7,110.8L710.9,110.5L713.0,108.8L714.0,108.5L714.7,110.4L716.9,111.8L720.7,112.8L722.6,115.0L721.6,118.1L722.5,119.2L725.7,119.7L729.3,120.1L732.5,121.7L734.2,122.0L735.4,124.5L736.9,126.1L739.9,126.0L745.4,126.6L748.9,126.2L751.6,126.6L755.5,128.2L758.7,128.2L759.9,129.1L763.0,127.6L767.3,126.7L771.3,126.6L774.4,125.7L776.3,124.2L778.2,123.4L777.8,122.5L776.9,121.4L778.3,119.7L779.8,120.0L782.6,120.5L785.2,119.1L789.3,118.1L791.2,116.3L793.1,115.5L797.0,115.2L799.1,115.5L799.4,114.5L797.0,112.7L794.8,111.8L792.8,112.8L790.2,112.4L788.6,112.7L788.0,111.6L789.8,109.0L791.1,107.0L794.3,108.0L798.1,106.3L798.1,105.1L800.5,102.3L802.0,101.4L801.9,100.0L800.5,99.3L802.7,98.0L806.0,97.5L809.5,97.4L813.5,98.2L815.9,99.2L817.5,101.9L818.5,103.1L819.4,104.7L820.4,107.3L825.1,108.2L828.2,110.1L829.3,112.6L833.4,112.6L835.7,111.5L840.1,110.7L838.7,113.1L837.6,114.1L836.7,117.0L834.9,119.6L831.7,119.1L829.4,120.1L830.1,122.4L829.7,125.5L828.4,125.6L828.4,126.9L826.7,125.4L825.6,126.9L821.5,128.0L821.9,129.4L819.6,129.3L818.3,128.5L816.5,130.4L813.5,131.8L811.4,133.5L807.6,134.3L805.7,135.5L802.8,136.3L804.2,135.0L803.7,134.0L805.8,132.2L804.4,130.8L802.0,131.8L799.0,133.6L797.4,135.3L794.8,135.5L793.4,136.7L794.8,138.5L797.0,138.9L797.1,140.1L799.2,140.9L802.2,139.0L804.6,140.1L806.3,140.1L806.7,141.5L802.9,142.3L801.7,143.7L799.1,145.0L797.7,146.9L800.6,148.4L801.7,151.0L803.3,153.4L805.1,155.5L805.0,157.5L803.4,158.2L804.0,159.6L805.6,160.4L805.2,162.6L804.5,164.7L803.0,165.0L801.1,167.9L798.9,171.4L796.4,174.5L792.8,177.0L789.0,179.2L786.0,179.6L784.4,180.7L783.5,179.9L782.0,181.2L778.2,182.5L775.4,182.9L774.5,185.8L773.0,185.9L772.3,184.0L773.0,182.9L769.4,182.1L768.1,182.5L765.4,181.8L764.2,180.8L764.6,179.2L762.2,178.7L760.9,177.7L758.6,179.1L756.0,179.5L753.9,179.4L752.5,180.1L751.1,180.5L751.5,183.5L750.1,183.5L749.8,182.8L749.7,181.7L747.8,182.5L746.6,182.0L744.6,181.0L745.4,178.8L743.7,178.3L743.1,175.8L740.3,176.3L740.6,173.1L743.1,170.9L743.2,168.7L743.2,166.6L742.0,166.0L741.1,164.4L739.5,164.6L736.7,164.2L737.6,163.1L736.3,161.5L734.4,162.6L732.2,161.9L729.1,163.6L726.7,165.6L724.5,165.9L723.4,165.2L721.9,165.2L720.0,164.5L718.6,165.2L716.8,167.2L716.6,165.1L715.0,165.7L711.9,165.4L708.9,164.8L706.7,163.6L704.6,163.1L703.7,161.8L702.2,161.4L699.5,159.7L697.4,158.9L696.3,159.5L692.6,157.6L690.0,156.0L689.2,153.0L691.1,153.4L691.2,152.0L690.2,150.7L690.4,148.5L687.6,145.3L683.2,144.3L682.4,142.2L680.4,141.0L679.9,140.2L679.5,138.7L679.6,137.7L678.0,137.0L677.1,137.3L676.5,134.9L677.2,134.2L676.9,133.6L679.4,132.4L681.2,131.8L684.1,132.2L685.1,130.5L688.5,130.2L689.4,129.1L693.7,127.7L694.0,127.1Z" fill-rule="evenodd"/><path d="M804.7,174.9L803.1,179.2L802.0,181.4L800.6,179.2L800.3,177.2L801.9,174.6L804.0,172.5L805.2,173.3L804.7,174.9Z" fill-rule="evenodd"/><path d="M507.8,115.0L509.5,115.3L509.8,114.8L512.4,114.4L513.0,115.3L516.8,116.0L516.5,117.3L517.2,118.4L515.0,118.0L512.9,119.0L513.0,120.3L512.7,121.1L513.6,122.4L516.1,123.8L517.4,126.0L520.4,128.1L522.5,128.1L523.1,128.7L522.4,129.2L524.8,130.2L526.7,131.0L529.0,132.4L529.3,132.9L528.8,133.8L527.3,132.6L525.0,132.2L523.9,133.9L525.8,134.9L525.5,136.3L524.4,136.4L522.9,138.7L521.8,138.9L521.8,138.1L522.4,136.7L523.0,136.1L521.9,134.5L521.1,133.2L520.0,132.9L519.2,131.7L517.5,131.2L516.3,130.2L514.4,130.0L512.3,128.8L509.8,127.1L508.0,125.5L507.2,122.9L505.9,122.6L503.7,121.7L502.5,122.1L500.9,123.3L499.8,123.5L500.1,122.3L498.7,122.0L498.0,119.9L498.9,119.1L498.1,118.1L498.2,117.4L499.4,117.9L500.7,117.8L502.2,116.9L502.6,117.3L503.9,117.2L504.5,116.2L506.5,116.5L507.6,116.0L507.8,115.0ZM519.4,138.3L521.4,138.1L520.4,140.1L520.8,141.0L520.3,142.3L518.2,141.3L516.9,141.1L513.1,139.7L513.5,138.3L516.6,138.6L519.4,138.3ZM503.2,130.9L504.6,130.1L506.2,132.0L505.8,135.5L504.6,135.4L503.5,136.2L502.5,135.5L502.4,132.3L501.8,130.8L503.2,130.9Z" fill-rule="evenodd"/><path d="M506.5,93.4L504.8,93.8L502.7,93.4L501.7,92.0L501.6,89.2L502.0,88.5L502.8,87.7L505.1,87.5L506.1,86.8L508.2,86.1L508.1,87.4L507.3,88.3L507.7,89.0L509.1,89.4L508.4,90.4L507.7,90.2L505.7,92.1L506.5,93.4ZM513.0,90.4L513.8,91.7L512.2,93.9L509.4,92.4L509.1,91.3L513.0,90.4Z" fill-rule="evenodd"/><path d="M463.5,96.4L461.5,95.8L459.8,95.8L460.4,94.4L459.8,93.0L462.0,92.9L464.9,94.5L463.5,96.4ZM471.7,97.6L471.8,97.6L472.1,96.0L470.4,94.4L470.3,94.4L467.1,93.9L466.4,93.2L467.4,92.0L466.5,91.2L465.1,92.5L464.9,89.9L463.6,88.6L464.6,85.8L466.6,83.7L468.8,83.9L472.0,83.6L469.1,86.5L471.9,86.2L474.8,86.2L474.1,88.3L471.7,90.7L474.4,90.9L474.7,91.2L477.0,94.3L478.9,94.8L480.5,97.8L481.3,98.9L484.5,99.4L484.2,101.1L482.8,101.8L483.9,103.2L481.5,104.6L477.9,104.6L473.4,105.3L472.1,104.8L470.4,106.1L467.9,105.8L466.0,106.8L464.6,106.2L468.5,103.4L470.9,102.9L470.9,102.9L466.7,102.4L466.0,101.4L468.7,100.5L467.3,99.1L467.8,97.3L471.7,97.6Z" fill-rule="evenodd"/><path d="M441.3,62.8L440.7,64.5L443.7,66.3L440.2,68.4L432.5,70.2L430.3,70.7L426.7,70.3L419.3,69.4L421.9,68.3L416.1,67.0L420.8,66.4L420.7,65.7L415.1,65.0L416.9,63.3L421.0,62.9L425.1,64.7L429.2,63.3L432.5,64.0L436.9,62.6L441.3,62.8Z" fill-rule="evenodd"/><path d="M603.7,128.4L604.5,128.5L606.3,130.1L607.5,130.3L608.0,129.6L609.6,128.5L611.0,129.9L612.3,131.8L613.6,131.9L614.4,132.6L612.2,132.9L611.7,134.9L611.3,135.9L610.3,136.5L610.4,137.8L609.7,137.9L608.0,136.5L608.9,135.2L608.2,134.4L607.2,134.6L604.0,136.6L604.0,134.8L602.8,134.3L601.6,133.6L602.4,132.8L601.0,131.8L601.5,131.2L600.5,130.7L599.9,130.0L600.6,129.6L602.6,130.3L604.0,130.5L604.4,130.2L603.1,128.7L603.7,128.4ZM603.0,136.7L601.2,136.3L599.9,135.1L599.5,134.1L600.0,134.0L600.8,134.7L602.0,134.7L602.0,135.1L603.0,136.7Z" fill-rule="evenodd"/><path d="M586.5,124.2L586.9,123.9L589.1,124.3L593.1,124.7L596.7,126.0L597.1,126.5L598.8,126.1L601.3,126.7L602.1,127.8L603.7,128.4L603.1,128.7L604.4,130.2L604.0,130.5L602.6,130.3L600.6,129.6L599.9,130.0L596.2,130.4L593.7,129.1L590.8,129.2L591.2,128.1L590.5,126.3L589.0,125.3L587.5,125.0L586.5,124.2Z" fill-rule="evenodd"/><path d="M802.2,206.1L800.9,204.1L803.1,204.2L804.1,205.1L803.4,207.5L802.2,206.1ZM806.9,213.4L807.6,212.6L807.9,211.0L809.3,210.8L808.9,212.6L810.9,210.0L810.6,212.6L809.7,213.5L808.8,215.2L808.0,215.9L806.3,214.1L806.9,213.4ZM817.0,217.6L817.3,219.3L817.4,220.8L816.5,223.3L815.6,220.6L814.3,221.9L815.2,223.9L814.4,225.1L811.3,223.6L810.5,221.6L811.3,220.4L809.6,219.1L808.8,220.2L807.5,220.1L805.6,221.6L805.1,220.8L806.2,218.6L807.8,217.8L809.3,216.8L810.2,218.0L812.3,217.3L812.7,216.1L814.6,216.0L814.4,214.0L816.6,215.2L816.8,216.6L817.0,217.6ZM796.0,215.2L792.5,217.7L793.8,215.8L795.7,214.2L797.3,212.3L798.7,209.7L799.2,211.9L797.4,213.3L796.0,215.2ZM806.2,191.4L805.8,192.5L806.7,194.4L806.0,196.6L804.4,197.5L804.0,199.7L804.6,201.8L806.0,202.1L807.2,201.8L810.5,203.2L810.3,204.7L811.2,205.3L810.9,206.6L808.8,205.3L807.8,203.9L807.1,204.8L805.4,203.2L803.0,203.6L801.7,203.0L801.8,201.9L802.6,201.3L801.8,200.6L801.5,201.6L800.2,200.1L799.8,198.9L799.7,196.4L800.8,197.2L801.0,193.1L801.9,190.7L803.5,190.7L805.2,191.4L806.0,190.7L806.2,191.4ZM805.4,209.6L805.0,208.3L806.6,209.1L808.3,209.1L808.3,210.2L807.0,211.4L805.3,212.2L805.2,210.9L805.4,209.6ZM814.7,207.6L815.4,210.5L813.4,209.8L813.4,210.7L814.1,212.4L812.8,213.0L812.7,211.1L811.9,211.0L811.5,209.3L813.0,209.6L813.0,208.5L811.4,206.5L813.9,206.6L814.7,207.6Z" fill-rule="evenodd"/><path d="M746.9,222.8L747.4,222.3L749.5,223.5L749.7,224.8L751.5,224.5L752.4,223.4L753.0,223.7L754.6,225.3L755.7,227.1L755.8,228.8L755.6,230.1L755.8,231.0L756.0,232.6L756.9,233.3L758.0,235.7L757.9,236.6L756.1,236.7L753.5,234.8L750.4,232.6L750.1,231.3L748.5,229.5L748.2,227.3L747.2,225.8L747.5,223.9L746.9,222.8ZM794.4,229.0L792.0,228.5L789.0,228.5L788.1,231.5L787.0,232.5L785.7,236.2L783.5,236.8L781.0,236.0L779.7,236.2L778.1,237.6L776.4,237.4L774.7,237.9L772.9,236.4L772.4,234.6L774.4,235.6L776.5,235.1L777.0,232.8L778.1,232.3L781.3,231.7L783.2,229.6L784.5,227.9L785.8,229.3L786.3,228.4L787.6,228.5L787.7,226.8L787.9,225.5L789.9,223.6L791.3,221.5L792.3,221.5L793.7,222.9L793.8,224.0L795.6,224.8L797.8,225.6L797.6,226.6L795.8,226.8L796.3,228.1L794.4,229.0Z" fill-rule="evenodd"/><path d="M787.9,225.5L787.7,226.8L787.6,228.5L786.3,228.4L785.8,229.3L784.5,227.9L785.6,226.9L787.9,225.5Z" fill-rule="evenodd"/><path d="M516.8,116.0L519.0,116.2L520.4,115.6L522.7,115.5L523.2,115.1L523.7,115.1L524.2,116.0L522.0,116.7L521.8,117.8L520.9,118.0L520.9,118.8L519.8,118.7L518.9,118.3L518.4,118.8L516.6,118.7L517.2,118.4L516.5,117.3L516.8,116.0Z" fill-rule="evenodd"/><path d="M556.2,55.8L555.9,57.7L559.9,59.5L557.5,61.5L560.6,64.5L558.8,66.8L561.2,68.8L560.1,70.5L564.0,72.4L563.0,73.7L560.6,75.3L554.9,78.7L554.9,78.7L554.9,78.7L550.0,78.9L545.3,79.8L541.0,80.4L539.4,79.0L536.9,78.1L537.5,75.5L536.2,73.0L537.4,71.5L539.8,69.8L545.9,66.9L547.7,66.4L547.5,65.2L543.7,64.0L542.8,62.9L542.8,58.8L538.6,57.0L535.1,55.7L536.7,55.0L539.6,56.4L543.1,56.3L546.0,56.9L548.5,55.8L549.8,53.8L554.0,52.9L557.4,54.0L556.2,55.8Z" fill-rule="evenodd"/><path d="M540.2,109.1L539.4,109.8L538.9,110.9L538.3,111.1L535.5,110.3L534.6,110.5L534.0,111.1L532.7,111.5L532.4,111.3L531.1,111.7L530.1,111.8L529.9,112.3L527.6,112.6L526.6,112.4L525.3,111.7L525.0,110.7L525.2,110.4L525.6,109.8L526.8,109.9L527.7,109.6L527.8,109.3L528.3,109.2L528.5,108.6L529.1,108.5L529.5,108.0L530.3,108.0L530.4,108.2L531.5,107.8L532.9,108.8L534.4,108.2L535.7,108.5L537.6,108.1L540.2,109.1Z" fill-rule="evenodd"/><path d="M520.0,103.7L521.3,104.6L523.3,104.8L523.1,105.5L524.6,106.1L525.0,105.4L526.8,105.7L527.1,106.5L529.0,106.7L530.3,108.0L529.5,108.0L529.1,108.5L528.5,108.6L528.3,109.2L527.8,109.3L527.7,109.6L526.8,109.9L525.6,109.8L525.2,110.4L524.0,109.9L522.7,110.0L520.7,109.2L519.7,109.4L518.2,110.5L516.3,109.7L514.8,108.5L513.4,107.9L513.1,106.7L512.6,106.0L514.6,105.4L515.6,104.7L517.5,104.2L518.2,103.7L518.9,104.0L520.0,103.7Z" fill-rule="evenodd"/><path d="M577.1,201.5L576.9,200.5L578.0,196.6L578.3,194.8L579.1,194.0L581.1,193.5L582.4,192.0L584.0,195.1L584.7,197.5L586.2,198.8L589.8,201.4L591.3,202.9L592.7,204.4L593.6,205.3L594.9,206.1L594.1,206.8L592.9,206.6L592.0,205.7L590.9,204.1L589.7,203.3L589.1,202.4L586.7,201.3L584.9,201.2L584.3,200.7L582.7,201.3L581.1,200.1L580.3,202.1L577.1,201.5Z" fill-rule="evenodd"/><path d="M858.4,135.5L855.9,138.2L855.9,141.0L854.9,143.1L855.4,144.4L854.0,146.3L850.6,147.6L845.9,147.7L842.1,150.8L840.3,149.7L840.2,147.7L835.6,148.3L832.4,149.6L829.3,149.6L832.0,151.6L830.2,156.1L828.5,157.3L827.2,156.2L827.9,153.8L826.2,153.0L825.1,151.2L827.6,150.4L829.0,148.7L831.7,147.3L833.6,145.5L839.0,144.7L841.8,145.3L844.6,140.5L846.4,141.8L850.3,139.1L851.8,138.1L853.5,134.8L853.0,131.8L854.1,130.1L857.0,129.7L858.4,133.4L858.4,135.5ZM865.6,122.8L867.5,121.6L868.1,124.6L864.2,125.4L861.8,128.0L857.6,126.2L856.2,129.1L853.2,129.1L852.8,126.5L854.2,124.4L857.0,124.3L857.8,120.6L858.6,118.5L861.7,121.3L863.8,122.2L865.6,122.8ZM833.0,150.8L834.5,149.2L836.0,149.5L837.1,148.4L839.0,148.9L839.4,149.8L837.9,151.5L836.8,150.6L835.4,151.2L834.7,152.8L833.0,152.0L833.0,150.8Z" fill-rule="evenodd"/><path d="M324.9,293.8L325.7,295.3L325.5,298.9L328.3,299.4L329.4,298.9L331.2,299.6L331.7,300.4L332.0,302.9L332.3,303.9L333.3,304.0L334.3,303.6L335.2,304.1L335.2,305.5L334.9,307.1L334.3,308.6L333.9,311.0L331.5,313.0L329.4,313.5L326.4,313.1L323.7,312.3L326.3,308.3L325.9,307.1L323.2,306.1L319.9,304.1L317.7,303.7L312.8,299.3L313.9,296.1L314.0,294.7L315.2,292.4L319.9,291.6L322.4,291.6L324.8,293.0L324.9,293.8Z" fill-rule="evenodd"/><path d="M618.7,189.3L620.8,193.7L621.6,195.6L619.7,196.3L619.2,197.5L619.1,198.4L616.5,199.5L612.2,200.8L609.8,202.7L608.6,202.8L607.8,202.6L606.3,203.8L604.6,204.3L602.3,204.4L601.7,204.6L601.1,205.3L600.4,205.5L600.0,206.1L598.7,206.1L597.8,206.4L596.0,206.3L595.3,204.7L595.3,203.3L594.9,202.5L594.4,200.5L593.6,199.4L594.1,199.3L593.9,198.1L594.2,197.6L594.1,196.4L595.2,195.6L595.0,194.4L595.7,193.1L596.8,193.8L597.5,193.6L600.6,193.5L601.1,193.8L603.6,194.0L604.7,193.9L605.3,194.8L606.6,194.4L608.5,191.6L611.0,190.4L618.7,189.3Z" fill-rule="evenodd"/><path d="M573.2,161.7L576.2,162.1L577.3,161.3L578.0,160.4L580.0,160.0L580.4,159.1L581.3,158.6L578.7,156.0L584.0,154.6L584.5,154.2L587.7,155.0L591.7,156.8L599.2,162.2L604.2,162.4L606.6,162.7L607.2,163.9L609.1,163.9L610.2,166.2L611.5,166.8L611.9,167.7L613.7,168.8L613.9,169.9L613.6,170.8L614.0,171.7L614.7,172.5L615.1,173.3L615.5,174.0L616.3,174.5L617.0,174.3L617.5,175.3L617.6,176.0L618.7,178.7L626.7,180.0L627.2,179.4L628.4,181.3L626.7,186.7L618.7,189.3L611.0,190.4L608.5,191.6L606.6,194.4L605.3,194.8L604.7,193.9L603.6,194.0L601.1,193.8L600.6,193.5L597.5,193.6L596.8,193.8L595.7,193.1L595.0,194.4L595.2,195.6L594.1,196.4L593.7,195.3L592.9,194.5L592.7,193.4L591.3,192.4L589.9,190.2L589.2,188.0L587.3,186.2L586.1,185.8L584.4,183.2L584.1,181.4L584.2,179.8L582.6,176.8L581.4,175.8L580.0,175.2L579.1,173.7L579.2,173.1L578.5,171.7L577.7,171.1L576.7,169.1L575.0,167.0L573.7,165.2L572.4,165.2L572.8,163.7L572.9,162.8L573.2,161.7Z" fill-rule="evenodd"/><path d="M350.2,448.1L351.6,448.1L355.6,447.6L359.6,448.1L362.9,449.3L364.0,450.9L364.3,452.0L364.4,453.4L360.3,454.2L356.0,454.9L351.0,455.5L345.4,456.1L339.1,455.9L335.6,455.0L336.0,453.9L341.7,453.2L344.0,452.3L345.7,451.2L346.9,450.2L348.5,449.2L350.2,448.1L350.2,448.1ZM303.2,454.0L309.2,454.1L315.0,454.4L317.0,453.3L318.4,452.3L321.1,453.4L320.4,454.8L319.6,456.0L314.0,455.6L308.0,455.8L304.7,454.9L304.7,454.8L303.2,454.0ZM282.9,430.1L282.9,430.1L284.7,429.7L287.8,429.8L288.6,428.5L288.7,427.5L288.7,425.3L290.2,424.1L292.7,423.7L294.1,424.7L294.7,425.7L295.8,426.9L296.7,428.0L297.5,429.2L297.8,430.4L297.3,431.5L296.6,432.5L293.4,432.8L290.5,433.3L287.0,433.3L288.3,432.2L285.1,432.6L282.2,433.0L280.1,432.2L280.0,431.1L282.9,430.1ZM207.1,431.7L207.1,431.7L208.8,431.2L212.2,431.6L216.0,431.8L219.0,432.2L221.9,431.9L223.5,433.4L221.4,433.2L218.1,433.3L214.8,433.2L211.2,433.3L208.5,432.8L207.1,431.7ZM153.0,436.4L153.0,436.4L153.6,435.5L156.8,436.0L160.2,436.4L163.4,436.0L161.9,436.9L159.4,437.6L155.7,437.4L153.0,436.4ZM140.6,435.9L140.6,435.9L142.5,435.3L145.2,436.0L149.2,437.0L147.7,436.9L144.2,436.6L140.6,435.9ZM43.4,449.6L43.4,449.6L45.1,448.6L50.0,449.0L52.7,449.8L54.7,450.8L55.4,452.0L50.3,452.4L46.8,451.4L45.3,450.5L45.2,450.3L43.4,449.6ZM960.0,465.9L960.0,480.0L0.0,480.0L0.0,465.9L0.2,465.9L2.5,464.4L7.3,465.2L7.6,465.1L10.4,464.3L10.8,464.3L11.1,464.3L15.0,465.4L18.4,464.3L19.0,464.2L26.8,463.7L29.3,464.3L30.6,464.6L34.6,465.5L42.2,466.2L48.2,467.0L58.5,467.7L66.2,466.9L77.5,467.5L83.9,468.3L91.0,467.5L98.4,466.8L99.0,465.5L88.5,465.4L79.8,464.8L77.6,463.7L70.4,463.2L70.9,462.0L71.9,460.9L72.9,459.9L72.4,458.8L67.9,458.0L65.9,457.1L61.8,456.3L68.2,456.4L74.4,456.0L78.3,456.9L83.0,456.1L87.4,455.1L89.6,454.2L88.6,453.1L85.2,452.4L81.2,451.6L75.8,451.5L71.0,451.1L65.8,450.8L64.1,449.8L60.6,449.0L58.5,448.1L57.7,445.0L59.0,445.3L61.4,446.1L65.8,445.9L70.0,445.5L72.2,446.7L76.4,446.4L80.0,445.8L83.3,445.1L86.4,444.2L90.4,443.9L90.3,442.9L89.3,442.0L90.1,441.0L93.6,440.5L95.1,441.4L99.2,440.9L102.3,440.2L106.1,440.2L109.7,439.9L113.3,439.3L116.2,438.7L119.4,438.1L121.5,438.3L123.3,438.5L127.3,438.1L130.9,438.6L134.5,438.6L138.0,438.2L141.6,438.5L145.6,438.7L149.3,438.6L153.2,438.7L157.1,438.7L160.8,438.6L163.5,437.8L166.7,437.4L170.1,438.0L173.3,437.5L176.1,436.6L177.9,437.4L178.8,438.3L180.5,439.2L183.3,438.5L186.5,439.4L190.1,439.8L193.2,440.5L196.9,440.3L200.3,439.9L204.4,440.0L208.0,440.3L211.6,440.8L213.0,439.7L211.3,438.8L210.0,437.8L206.5,437.6L205.0,436.6L204.5,435.6L203.5,433.6L205.6,434.0L209.1,434.2L212.5,434.0L215.6,434.4L218.3,435.2L219.5,436.2L223.1,436.3L226.5,435.9L230.2,435.4L233.5,435.1L236.2,435.7L239.8,435.5L242.1,433.5L244.2,434.7L247.3,435.2L250.6,434.9L252.8,435.9L256.3,436.1L259.6,436.4L262.7,436.9L264.8,435.9L265.9,435.0L268.5,436.1L272.2,435.8L274.9,436.4L276.7,437.3L280.3,437.0L283.1,436.4L285.8,435.7L289.0,435.4L292.8,435.1L296.2,434.7L298.8,434.1L300.3,433.3L301.0,432.1L300.7,431.0L299.8,430.0L298.9,428.9L298.1,427.9L297.4,427.0L297.2,425.9L297.5,424.9L298.7,423.9L299.8,422.8L300.2,421.7L299.7,420.6L299.4,419.5L300.7,418.3L302.1,417.6L303.8,416.6L305.7,415.7L307.8,414.9L308.9,413.8L310.3,413.1L312.0,412.4L314.6,412.2L316.2,411.4L318.1,410.9L320.3,410.6L322.2,409.9L323.7,409.0L325.8,408.7L327.4,409.4L326.4,410.3L323.7,411.1L322.5,411.6L320.6,411.2L318.4,411.5L316.5,412.1L314.6,412.8L313.3,413.6L312.9,414.6L313.1,415.6L314.3,416.5L312.5,417.1L310.0,417.3L308.5,418.2L307.0,419.1L305.3,420.2L304.9,421.2L305.8,422.3L307.2,423.1L309.4,423.8L311.5,424.6L312.6,425.7L313.1,426.6L313.9,427.7L315.2,428.6L316.0,429.6L316.3,432.0L317.1,433.0L317.3,434.1L318.2,435.1L317.8,436.5L316.3,437.6L314.8,438.5L311.2,438.9L310.0,439.8L308.4,440.7L304.4,441.7L300.8,442.1L297.5,442.7L293.9,443.3L291.7,444.4L287.4,444.5L282.7,444.4L278.5,444.6L274.0,444.6L274.9,445.6L278.9,446.1L281.9,446.8L283.6,447.8L280.6,448.6L276.0,448.3L272.2,449.0L272.0,450.1L271.9,451.2L275.1,452.0L275.6,453.0L279.0,454.0L284.7,454.4L289.5,455.2L293.3,456.0L298.2,456.8L304.8,457.3L311.3,458.0L315.9,458.8L320.8,459.7L323.4,460.9L324.7,461.9L328.0,461.0L332.4,460.2L337.0,459.4L342.6,458.7L347.3,457.9L353.9,457.9L360.5,458.3L365.8,458.9L367.6,457.7L371.3,457.0L378.0,456.9L383.3,456.3L388.3,455.7L393.8,455.4L399.7,454.9L403.9,454.2L402.0,453.3L400.8,452.4L400.8,451.4L395.7,451.5L390.2,451.9L385.0,451.9L384.2,450.9L384.6,448.9L385.8,448.3L389.6,447.7L394.1,447.1L397.3,446.3L400.6,445.5L403.0,444.5L406.6,444.0L410.2,443.6L412.1,443.4L416.2,443.3L420.1,442.9L423.4,442.4L426.6,441.8L429.6,441.2L433.3,440.3L435.6,439.4L438.1,438.7L438.9,437.6L436.1,437.0L437.0,435.9L438.8,435.1L441.6,434.5L444.5,433.9L447.2,433.1L449.3,432.0L450.6,430.8L452.5,430.0L455.7,430.2L457.0,431.1L460.2,431.2L460.3,430.2L461.7,429.2L464.6,429.4L465.2,430.4L468.4,430.6L471.9,430.1L475.2,429.8L478.2,429.9L479.4,431.0L482.3,430.1L485.0,429.7L488.1,429.3L491.0,428.9L493.8,428.3L496.7,427.9L499.0,427.3L500.6,426.4L502.6,427.1L505.4,426.7L507.3,428.0L508.8,428.9L511.9,428.4L513.1,427.3L515.8,426.6L519.3,426.7L520.3,427.7L522.5,426.7L525.4,426.4L528.5,426.3L531.4,426.4L534.3,426.7L537.2,426.9L538.5,427.7L540.2,428.5L543.1,428.1L546.2,428.0L549.3,428.0L552.2,427.9L554.9,427.5L557.7,427.2L560.1,426.5L562.6,426.0L565.3,425.8L567.3,425.0L568.8,423.6L570.3,422.7L573.1,423.1L574.1,424.0L576.4,424.7L579.2,424.4L581.1,425.4L583.1,426.1L585.8,425.4L586.7,424.3L589.1,423.8L591.9,422.9L594.5,422.6L597.6,422.0L599.7,421.5L601.9,420.8L604.0,420.3L606.5,420.6L608.9,419.6L610.6,418.9L613.1,419.0L615.3,418.3L615.9,417.4L618.1,416.7L620.3,416.1L623.0,415.7L625.4,415.5L627.8,415.7L630.3,415.9L632.4,416.7L632.7,417.8L635.0,418.7L636.7,419.4L639.8,419.7L641.6,420.5L643.8,421.2L646.4,421.4L648.5,420.8L650.8,419.7L653.3,420.3L655.9,420.6L658.4,420.9L661.0,421.2L663.7,421.2L665.9,423.9L665.8,424.6L665.5,425.8L662.9,426.5L660.8,427.5L661.2,428.5L664.2,428.5L663.8,429.5L662.5,430.5L661.2,431.6L663.2,432.4L666.3,432.7L669.4,432.2L670.9,431.2L671.8,430.2L673.2,429.4L674.9,428.6L675.6,427.6L677.0,426.3L678.6,426.1L681.7,426.0L684.3,425.7L687.1,425.2L688.4,424.2L689.1,423.2L691.0,422.2L693.6,421.5L695.8,421.0L697.3,420.1L698.8,419.6L700.7,419.2L703.4,419.5L705.8,419.2L708.4,418.9L711.3,419.1L713.3,418.3L714.6,416.6L715.6,417.3L716.9,418.5L719.1,419.1L721.7,419.3L724.2,419.0L727.0,419.2L729.5,419.2L731.1,419.0L733.4,419.1L735.4,419.7L737.8,419.3L740.7,419.3L743.1,419.0L745.9,419.3L747.7,418.4L749.0,417.6L750.9,416.8L754.2,414.8L755.9,415.2L758.0,415.9L759.8,416.9L763.2,418.5L765.8,418.5L768.2,418.5L771.1,418.2L774.0,417.9L776.2,417.1L778.0,416.4L781.0,416.2L782.9,415.7L785.0,416.2L786.4,417.0L788.3,417.9L791.2,417.8L793.0,418.4L796.2,419.1L799.6,419.4L802.3,419.2L804.4,418.3L806.2,417.5L808.6,417.3L811.0,417.7L813.8,417.9L816.3,417.5L818.7,417.5L821.0,417.8L823.5,418.0L825.9,417.6L828.8,417.1L831.5,417.0L834.5,417.0L837.0,416.8L839.4,416.6L840.1,415.3L840.2,414.2L841.9,414.9L842.3,416.1L843.2,417.2L844.3,418.1L846.6,418.5L849.6,418.4L853.1,418.3L855.5,418.2L859.0,418.2L861.5,418.1L865.0,418.2L868.0,418.4L869.9,419.3L869.3,420.3L871.1,421.1L873.9,421.7L876.9,422.4L880.4,422.8L884.0,423.2L886.7,423.7L889.7,423.7L891.4,422.8L893.8,423.6L895.8,424.4L898.2,425.0L901.4,425.3L904.5,425.6L905.8,426.6L908.8,427.3L910.9,428.2L913.8,428.6L916.9,428.6L919.8,428.7L923.0,428.7L926.2,428.9L929.1,429.3L931.9,429.9L934.7,430.4L936.6,431.2L936.2,432.2L934.8,433.2L933.6,434.4L932.7,435.3L931.4,436.4L927.9,436.8L926.4,437.8L922.9,438.3L921.7,439.4L919.9,440.4L918.0,441.2L916.9,442.3L916.2,443.3L915.9,444.5L916.0,445.5L917.5,446.6L918.1,447.5L919.3,448.5L924.3,448.9L925.3,450.0L920.5,450.4L916.4,451.0L911.4,451.1L909.1,452.6L908.7,453.9L907.5,454.9L906.1,455.9L909.7,456.7L911.0,457.8L913.3,458.8L916.5,459.7L920.3,460.6L924.3,461.4L930.4,462.2L931.7,463.5L939.4,464.1L939.9,464.3L941.9,465.1L949.3,464.4L955.4,465.3L960.0,465.9Z" fill-rule="evenodd"/><path d="M567.3,146.3L567.5,146.3L567.9,145.6L569.8,145.7L572.2,144.9L570.4,146.0L570.6,146.5L570.3,146.4L569.8,146.6L569.4,146.6L569.3,146.7L569.2,146.4L569.0,146.2L568.5,146.2L567.8,146.4L567.3,146.3Z" fill-rule="evenodd"/><path d="M567.3,146.3L567.8,146.4L568.5,146.2L569.0,146.2L569.2,146.4L569.3,146.7L569.4,146.6L569.8,146.6L570.3,146.4L570.6,146.5L570.7,146.7L567.9,147.8L566.6,147.5L566.0,146.4L567.3,146.3Z" fill-rule="evenodd"/><path d="M474.2,146.2L475.2,147.9L475.4,149.5L476.3,152.4L477.0,152.9L476.5,154.0L473.0,154.4L471.8,155.4L470.3,155.6L470.2,157.6L467.0,158.7L466.0,160.0L463.8,160.7L461.2,161.1L456.9,163.1L456.9,166.2L456.5,166.2L456.5,167.7L454.9,167.8L454.0,168.4L452.8,168.4L451.9,168.0L449.6,168.3L448.8,170.4L447.9,170.6L446.7,173.9L443.0,176.8L442.1,180.5L441.0,181.7L440.7,182.7L434.7,182.9L434.6,182.9L434.7,181.6L435.8,180.9L436.6,179.5L436.5,178.6L437.4,176.7L438.9,175.0L439.8,174.6L440.5,173.1L440.5,171.6L441.5,170.0L443.3,169.0L445.0,166.3L445.0,166.3L446.3,165.2L448.8,164.9L450.9,163.1L452.3,162.4L454.5,160.2L453.8,156.9L454.8,154.6L455.2,153.2L456.9,151.4L459.6,150.1L461.6,149.0L463.3,146.3L464.2,144.6L466.1,144.7L467.8,145.8L470.3,145.6L473.1,146.2L474.2,146.2Z" fill-rule="evenodd"/><path d="M578.3,181.3L567.7,181.3L557.4,181.3L546.7,181.3L546.7,171.5L546.7,162.0L545.9,159.9L546.6,158.2L546.1,157.1L547.1,155.8L550.7,155.8L553.2,156.5L555.9,157.3L557.1,157.7L559.2,156.8L560.3,156.1L562.6,155.9L564.5,156.2L565.2,157.5L565.8,156.6L568.0,157.3L570.1,157.4L571.4,156.7L571.4,156.7L572.9,160.6L573.1,161.3L572.4,162.4L571.8,164.4L571.1,165.8L570.5,166.3L569.6,165.4L568.4,164.2L566.5,160.4L566.2,160.6L567.3,163.5L568.9,166.1L570.9,170.3L571.9,171.7L572.8,173.2L575.2,176.2L574.6,176.7L574.7,178.4L577.8,180.8L578.3,181.3Z" fill-rule="evenodd"/><path d="M546.7,181.3L546.7,186.7L543.6,186.7L543.6,187.8L532.9,182.7L522.3,177.6L519.6,179.0L517.7,180.0L516.2,178.6L512.0,177.4L510.8,175.7L508.7,174.5L507.5,175.0L506.5,173.5L506.4,172.4L504.9,170.4L505.9,169.3L505.7,167.6L506.0,166.2L505.8,164.9L506.3,162.8L506.1,161.5L505.3,159.2L506.6,158.6L506.8,157.4L506.5,156.3L508.4,155.3L509.2,154.4L510.5,153.7L510.6,151.6L513.8,152.6L514.9,152.3L517.1,152.8L520.7,154.0L521.9,156.3L524.3,156.8L528.1,158.0L530.9,159.3L532.2,158.6L533.5,157.4L532.9,155.3L533.7,154.0L535.6,152.8L537.4,152.4L541.1,153.0L542.0,154.2L543.0,154.2L543.8,154.6L546.5,154.9L547.1,155.8L546.1,157.1L546.6,158.2L545.9,159.9L546.7,162.0L546.7,171.5L546.7,181.3Z" fill-rule="evenodd"/><path d="M607.4,218.7L599.9,226.7L596.4,226.8L594.1,228.7L592.3,228.7L591.6,229.5L589.8,229.5L588.7,228.6L586.3,229.8L585.5,230.9L583.7,230.7L583.1,230.4L582.5,230.4L581.7,230.4L578.3,228.1L576.4,228.1L575.5,227.3L575.5,225.8L574.1,225.3L572.6,222.4L571.3,221.8L570.9,220.7L569.5,219.4L567.9,219.2L568.8,217.7L570.2,217.7L570.6,216.8L570.6,214.4L571.4,211.7L572.6,210.9L572.9,209.8L574.0,207.8L575.6,206.5L576.7,203.8L577.1,201.5L580.3,202.1L581.1,200.1L582.7,201.3L584.3,200.7L584.9,201.2L586.7,201.3L589.1,202.4L589.7,203.3L590.9,204.1L592.0,205.7L592.9,206.6L592.0,207.7L591.1,209.0L591.3,209.7L591.3,210.5L592.8,210.6L593.5,210.4L594.1,210.9L593.5,211.8L594.5,213.3L595.5,214.6L596.5,215.5L605.2,218.7L607.4,218.7Z" fill-rule="evenodd"/><path d="M592.9,206.6L594.1,206.8L594.9,206.1L595.5,207.0L595.4,208.1L593.9,208.7L595.1,209.4L594.1,210.9L593.5,210.4L592.8,210.6L591.3,210.5L591.3,209.7L591.1,209.0L592.0,207.7L592.9,206.6Z" fill-rule="evenodd"/><path d="M610.5,209.6L610.5,209.6L610.5,209.6L610.5,210.7L610.5,213.4L610.5,214.8L609.3,216.4L607.4,218.7L605.2,218.7L596.5,215.5L595.5,214.6L594.5,213.3L593.5,211.8L594.1,210.9L595.1,209.4L595.9,209.9L596.4,211.0L597.6,212.1L599.0,212.2L601.5,211.5L604.4,211.2L606.7,210.3L608.1,210.2L609.0,209.7L610.5,209.6L610.5,209.6Z" fill-rule="evenodd"/><path d="M570.4,242.5L565.0,242.7L562.1,242.7L561.1,243.0L559.5,243.8L558.9,243.6L558.9,241.6L559.5,240.5L559.7,238.4L560.2,237.2L561.2,235.8L562.3,235.1L563.1,234.1L562.1,233.8L562.2,230.6L562.2,230.6L563.3,229.9L565.0,230.5L567.2,229.9L569.0,229.9L570.7,228.7L571.9,230.5L572.3,231.9L573.4,234.9L572.5,236.9L571.1,238.6L570.4,239.7L570.4,242.5Z" fill-rule="evenodd"/><path d="M561.1,243.0L562.2,244.5L562.0,246.1L561.3,246.4L561.3,246.4L559.8,246.3L559.0,247.8L557.4,247.6L557.6,246.1L558.0,245.9L558.1,244.3L558.9,243.6L559.5,243.8L561.1,243.0Z" fill-rule="evenodd"/><path d="M529.5,126.3L527.1,125.3L526.1,124.1L525.1,123.6L523.9,122.6L523.3,121.7L522.0,120.5L522.6,119.4L523.5,120.0L524.1,119.4L525.3,119.4L527.6,119.8L529.5,119.8L530.7,120.4L530.7,120.4L531.6,120.4L531.0,121.5L532.3,122.6L531.9,123.8L531.2,123.9L530.8,124.2L529.9,124.8L529.5,126.3Z" fill-rule="evenodd"/><path d="M539.7,127.1L541.0,128.0L541.2,129.8L540.7,129.9L540.3,130.3L538.8,130.3L537.8,130.8L536.1,131.1L534.9,130.4L534.6,129.3L534.9,128.4L534.9,128.4L535.2,128.4L535.4,127.9L536.9,127.4L537.5,127.3L538.4,127.2L539.7,127.1Z" fill-rule="evenodd"/><path d="M530.2,117.6L530.2,117.6L532.3,116.9L533.9,117.0L535.4,118.0L535.7,118.9L537.3,119.5L537.5,120.6L539.1,121.4L539.9,120.8L540.5,121.1L539.9,121.6L540.4,122.0L539.8,122.6L540.0,123.6L541.3,124.8L540.3,125.6L539.8,126.5L540.1,126.8L539.7,127.1L538.4,127.2L537.5,127.3L537.4,127.1L537.8,126.8L538.1,126.2L537.7,126.2L537.2,125.7L536.7,125.6L536.4,125.2L535.9,125.0L535.5,124.6L535.0,124.8L534.7,125.6L534.0,125.8L534.2,125.6L533.2,125.1L532.3,124.8L532.0,124.4L531.2,123.9L531.9,123.8L532.3,122.6L531.0,121.5L531.6,120.4L530.7,120.4L530.7,120.4L531.7,119.4L530.9,118.6L530.2,117.6Z" fill-rule="evenodd"/><path d="M533.5,126.4L532.8,126.7L532.6,126.2L531.5,127.5L531.7,128.3L531.1,128.1L530.4,127.2L529.2,126.7L529.5,126.3L529.9,124.8L530.8,124.2L531.2,123.9L532.0,124.4L532.3,124.8L533.2,125.1L534.2,125.6L534.0,125.8L533.5,126.4Z" fill-rule="evenodd"/><path d="M534.9,128.4L534.7,127.4L534.1,127.1L533.5,126.4L534.0,125.8L534.7,125.6L535.0,124.8L535.5,124.6L535.9,125.0L536.4,125.2L536.7,125.6L537.2,125.7L537.7,126.2L538.1,126.2L537.8,126.8L537.4,127.1L537.5,127.3L536.9,127.4L535.4,127.9L535.2,128.4L534.9,128.4Z" fill-rule="evenodd"/><path d="M315.5,211.3L317.1,211.0L317.6,211.1L317.5,213.0L315.3,213.3L314.8,213.1L315.6,212.4L315.5,211.3Z" fill-rule="evenodd"/><path d="M562.2,230.6L559.9,228.9L559.2,227.7L557.8,228.3L556.5,228.1L555.8,228.6L554.6,228.2L553.0,226.0L552.6,225.2L550.6,224.1L549.9,222.5L548.8,221.4L547.0,220.0L547.0,219.1L545.5,218.1L543.7,217.0L544.5,216.7L545.4,216.2L546.1,213.8L546.9,212.6L548.8,212.2L549.2,213.0L550.6,214.5L551.3,214.8L552.3,214.3L554.2,214.4L554.6,214.9L557.2,214.9L557.3,214.4L558.7,213.9L559.0,213.1L560.0,212.6L562.2,214.1L563.6,213.8L564.9,211.9L566.4,210.5L566.2,208.8L565.5,208.1L567.1,207.9L567.3,207.3L568.6,207.5L568.2,209.5L568.6,211.4L569.9,212.5L570.2,213.4L570.2,214.7L570.6,214.8L570.6,216.8L570.2,217.7L568.8,217.7L567.9,219.2L569.5,219.4L570.9,220.7L571.3,221.8L572.6,222.4L574.1,225.3L572.3,227.1L570.7,228.7L569.0,229.9L567.2,229.9L565.0,230.5L563.3,229.9L562.2,230.6Z" fill-rule="evenodd"/></g><g id="map-points"></g></svg><div class="map-zoom"><button id="map-zoom-in" aria-label="Agrandir la carte">+</button><button id="map-zoom-out" aria-label="Réduire la carte">−</button><button id="map-reset">Monde</button></div></div><div class="map-legend"><span><i class="map-dot banned"></i>Bannie</span><span><i class="map-dot unbanned"></i>Ban levé</span><span><i class="map-dot history"></i>Historique</span><span id="map-count"></span></div><p class="map-caption">Positions approximatives issues de la base locale DB-IP. Plusieurs IP au même endroit sont regroupées. Les IP sans coordonnées restent dans la liste. Fond de carte : Natural Earth (domaine public).</p><div id="map-list" aria-label="Liste des IP de la carte"></div></div><aside id="map-detail" aria-label="IP sélectionnée"><h3>Sélectionner une IP</h3><p>Choisis un point sur la carte ou une adresse dans la liste pour consulter ses informations et ses actions.</p></aside></div></div></dialog>\n'

@app.route("/")
@cache_dashboard
def dashboard():
    html = """
<!DOCTYPE html>
<html>
<head>

<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#0a0a0a;--card:#1a1a1a;--accent:#3498db;--danger:#ff4757;--text:#e0e0e0;--border:#333;}
* {margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:20px;line-height:1.5;}
.container{max-width:1400px;margin:0 auto;background:var(--card);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.5);overflow:hidden;}
.header{background:linear-gradient(135deg,#132034,#203c4b);padding:30px;text-align:center;}
.header h1{font-size:2.2em;margin:0;font-weight:300;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;padding:30px;}
.card{background:var(--bg);border-radius:12px;padding:25px;border:1px solid var(--border);}
.card h3{color:var(--accent);margin-bottom:15px;}
pre{background:var(--card);padding:20px;border-radius:8px;font-family:monospace;font-size:12px;max-height:300px;overflow:auto;}
.ip-container{display:flex;flex-wrap:wrap;gap:12px;margin-top:15px;}
.ip-btn{background:var(--danger);color:white;border:none;padding:10px 18px;border-radius:25px;cursor:pointer;}
.empty-state{color:#888;text-align:center;padding:30px;}
.refresh{position:fixed;top:20px;right:20px;background:var(--accent);color:white;padding:12px 20px;border-radius:25px;cursor:pointer;}

.suspect-card{grid-column:1/-1}.table-wrap{overflow:auto;max-height:620px}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:#9dcfff;background:#1a1a1a;position:sticky;top:0}th,td{padding:12px;border-bottom:1px solid #333;vertical-align:top}td.path{word-break:break-all;min-width:240px}td.date,td.ip{white-space:nowrap}.badge{color:#ffb7be;background:#3a1c24;padding:3px 8px;border-radius:6px}.note{color:#aaa;margin-bottom:15px}

.summary-strip{display:grid;grid-template-columns:repeat(4,minmax(110px,1fr));gap:12px;margin:18px 0}.metric{background:#151e2b;border:1px solid #2a3a50;border-radius:12px;padding:16px}.metric strong{display:block;font-size:28px;color:#fff}.metric small{color:#b6c4d6}.metric.red{border-color:#71363f}.metric.amber{border-color:#725d31}.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:18px 0}.toolbar input,.toolbar select{background:#141c28;color:#e9f0fa;border:1px solid #3a4a61;border-radius:8px;padding:10px}.toolbar input{flex:1;min-width:220px}tbody tr:nth-child(even){background:#121720}tbody tr:hover{background:#1c293b}tbody tr.auth td:first-child{border-left:4px solid #ff6579}tbody tr.server td:first-child{border-left:4px solid #b79aff}tbody tr.missing td:first-child{border-left:4px solid #f4c264}.badge{display:inline-block;font-weight:700;white-space:nowrap}.badge.auth{background:#49242e;color:#ffb3bf}.badge.server{background:#342549;color:#d3bdff}.badge.missing{background:#493b20;color:#ffda8d}.badge.other{background:#203c4b;color:#a6def5}.subline{display:block;font-size:11px;color:#a3adbc;margin-top:4px}.path code{color:#d1e4fa;font-size:12px}.method{color:#8ab9eb;font-size:11px;font-weight:700}.ip{font-family:monospace}.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:#b6c4d6;margin-bottom:12px}@media(max-width:700px){.summary-strip{grid-template-columns:repeat(2,1fr)}.stats-grid{padding:12px}.card{padding:16px}}

/* Keep wide tables and technical logs inside their own cards. */
.stats-grid{grid-template-columns:repeat(2,minmax(0,1fr));align-items:start}
.card{min-width:0;max-width:100%;overflow-wrap:anywhere}
.summary-strip{grid-template-columns:repeat(auto-fit,minmax(min(140px,100%),1fr))}
.metric{min-width:0}
.table-wrap{width:100%;max-width:100%;position:relative;isolation:isolate}
th{z-index:1}
details{min-width:0;max-width:100%}
pre{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:760px){.stats-grid{grid-template-columns:minmax(0,1fr)}.header h1{font-size:1.7em}.refresh{position:static;display:block;width:max-content;margin:16px auto}}

#administration-panel[hidden],.stats-grid[hidden]{display:none}
.display-controls{display:flex;gap:10px;flex-wrap:wrap;justify-content:center;padding:14px 20px;border-bottom:1px solid var(--border)}
.display-controls button{background:#203c4b;color:#e9f0fa;border:1px solid #3a4a61;padding:8px 14px;border-radius:8px;cursor:pointer}
.section-title{display:flex;align-items:center;justify-content:space-between;gap:12px;cursor:pointer;list-style:none;color:var(--accent);font-weight:700;margin-bottom:15px}
.section-title::-webkit-details-marker{display:none}
.section-title::after{content:'−';font-size:22px;flex-shrink:0}
.card:not([open])>.section-title::after{content:'+'}
.card:not([open])>.section-title{margin-bottom:0}
body.compact .stats-grid{gap:10px;padding:14px}
body.compact .card{padding:14px;border-radius:8px}
body.compact .header{padding:14px}
body.compact .header h1{font-size:1.5em}
body.compact .metric{padding:8px}
body.compact .metric strong{font-size:22px}
body.compact .summary-strip{gap:8px;margin:10px 0}
body.compact th,body.compact td{padding:6px 8px;font-size:12px}
body.compact .note{font-size:12px;margin-bottom:8px}
body.compact .empty-state{padding:12px}
body.compact .table-wrap{max-height:350px}
.tabs{display:flex;gap:8px;flex-wrap:wrap;justify-content:center}.tabs button[aria-selected="true"]{background:#3498db;color:#fff;border-color:#3498db}.card[hidden]{display:none}
.abuse-result{white-space:normal;overflow-wrap:anywhere;max-width:280px}.abuse-result a{color:#9dcfff}
/* FCP — thème adapté de Visio Display, Eric TOMAS; Apache-2.0 avec autorisation du détenteur des droits. */
:root{color-scheme:light;--bg:#edf2ff;--card:rgba(255,255,255,.62);--accent:#4f46e5;--danger:#dc2626;--text:#132032;--border:#d8e1f2;--muted:#42506b;--radius:22px;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--text);background:var(--bg)}
body{font-family:inherit;color:var(--text);background:radial-gradient(ellipse at 15% 0%,rgba(79,70,229,.18),transparent 55%),radial-gradient(ellipse at 95% 20%,rgba(14,165,233,.13),transparent 55%),var(--bg);padding:28px 28px 28px 264px;min-height:100vh;line-height:1.55}
.container{max-width:1600px;margin:auto;background:transparent;box-shadow:none;overflow:visible;border-radius:0}
.header,header{background:linear-gradient(135deg,#172554,#312e81 45%,#0f766e);border:1px solid rgba(255,255,255,.35);border-radius:24px;color:#fff;padding:30px 32px;text-align:left;box-shadow:0 18px 42px rgba(15,23,42,.12)}
.header h1,header h1{font-weight:750;letter-spacing:-.04em;font-size:34px;margin:0 0 6px}.header p,header p{color:#dbe4ff}header a{color:#fff}
.display-controls{position:fixed;inset:0 auto 0 0;width:236px;background:#081222;border-right:1px solid rgba(255,255,255,.08);padding:30px 16px;display:block;z-index:10;overflow:auto}
.display-controls:before{content:'FCP';display:block;color:#eef2ff;font-size:27px;font-weight:750;letter-spacing:-.04em;padding:0 12px 4px}
.tabs{display:flex;flex-direction:column;align-items:stretch;gap:8px;margin-top:26px}.display-controls button{background:transparent;border:1px solid transparent;color:#95a4c7;text-align:left;padding:12px 14px;border-radius:12px;font:inherit;font-size:14px}.display-controls button:hover{background:rgba(129,140,248,.12);color:#dbe4ff}.tabs button[aria-selected="true"]{background:rgba(99,102,241,.22);border-color:rgba(129,140,248,.24);color:#fff}
.stats-grid{padding:24px 0;gap:22px}.card{background:var(--card);border:1px solid rgba(255,255,255,.82);border-radius:var(--radius);padding:26px;box-shadow:0 14px 38px rgba(15,23,42,.09),inset 0 1px 0 rgba(255,255,255,.96);backdrop-filter:blur(30px) saturate(1.35)}
.card h3,.section-title{color:#312e81}.note,.muted,small,.subline,.legend,.empty-state,label{color:var(--muted)}.note{font-size:13px}.subline{font-size:11px}.path code{color:#42506b}.method{color:#4f46e5}
.metric{background:rgba(255,255,255,.56);border:1px solid var(--border);border-radius:16px;box-shadow:0 4px 15px rgba(15,23,42,.04)}.metric strong{color:#312e81;font-weight:750}.metric small{color:var(--muted)}.metric.red{border-color:#f0bfc5}.metric.amber{border-color:#f4d8b5}
button,a.button,.toolbar button,#geo-update{font:inherit;font-size:13px;background:rgba(255,255,255,.78);color:#312e81;border:1px solid #c5d2ea;border-radius:12px;padding:10px 16px;cursor:pointer;transition:background .18s,box-shadow .18s}
button:hover,a.button:hover{background:#e7e9ff;box-shadow:0 4px 14px rgba(79,70,229,.12)}button:disabled{opacity:.5;cursor:default}button.danger,.ip-btn{background:#fff1f2;color:#b91c1c;border:1px solid #fecdd3}.ip-btn:hover,button.danger:hover{background:#ffe4e6}
input,select,textarea,.toolbar input,.toolbar select{font:inherit;background:rgba(255,255,255,.78);color:var(--text);border:1px solid #c5d2ea;border-radius:12px;padding:10px 12px}input:focus,select:focus,textarea:focus{outline:3px solid rgba(79,70,229,.14);border-color:#8b8cff}button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #8b8cff;outline-offset:3px}
pre{background:#f4f7ff;color:#132032;border:1px solid var(--border);border-radius:14px}.table-wrap{border:1px solid var(--border);border-radius:14px}th{background:#e7e9ff;color:#312e81;font-weight:650}th,td{border-bottom:1px solid var(--border);padding:13px 14px}tbody tr:nth-child(even){background:rgba(244,247,255,.68)}tbody tr:hover{background:#e7e9ff}
.badge{background:#e7e9ff;color:#312e81;border-radius:8px}.badge.auth{background:#ffe4e6;color:#9f1239}.badge.server{background:#ede9fe;color:#5b21b6}.badge.missing{background:#fef3c7;color:#92400e}.badge.other{background:#e0f2fe;color:#075985}.abuse-result a,#geo-note a{color:#4f46e5!important}
#geo-note{padding:20px 12px!important;margin:8px 0 0}.refresh{position:static;margin:0 0 20px auto;display:block;width:max-content;background:#4f46e5;color:#fff;border-radius:12px;box-shadow:0 8px 24px rgba(79,70,229,.2);font-size:12px;font-weight:650}
#administration-panel{margin-top:24px}main{max-width:1600px;padding:24px 0;margin:auto}nav{gap:8px}nav button.active{background:#4f46e5;color:#fff;border-color:#4f46e5}#message{background:#e7e9ff;color:#312e81;border:1px solid #c5d2ea;border-radius:12px}body:has(main){padding:28px}body:has(main):has(header[hidden]){padding:12px}
@media(max-width:900px){body{padding:18px}.display-controls{position:static;width:auto;border-radius:18px;margin-top:18px;padding:14px}.display-controls:before,.display-controls:after{display:none}.tabs{flex-direction:row;margin:0;gap:6px}.display-controls button{flex:1;text-align:center;padding:10px;font-size:12px}.stats-grid{gap:16px}.header,header{padding:24px}.refresh{margin-left:auto}}
@media(max-width:600px){body,body:has(main){padding:12px}.header h1{font-size:28px}.stats-grid{grid-template-columns:minmax(0,1fr)}.card{padding:18px;border-radius:18px}.tabs button{flex:1 1 40%}.toolbar input{min-width:0;width:100%}.header p{font-size:13px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}

/* World map, isolated from both dashboard and administration styles. */
.metric.map-trigger{display:block;text-align:left;width:100%;color:var(--text);cursor:pointer;font:inherit}.metric.map-trigger:hover{border-color:#8b8cff;box-shadow:0 0 0 3px rgba(79,70,229,.1)}.metric.map-trigger small:after{content:' ↗';color:#4f46e5}.ip-btn.map-ip{color:#312e81;background:#e7e9ff;border-color:#c5d2ea}.map-history-link{padding:4px 8px;font-size:12px}
#ban-map-dialog{border:1px solid #c5d2ea;border-radius:24px;padding:0;width:min(1440px,96vw);max-width:96vw;height:min(940px,94dvh);max-height:94dvh;margin:auto;background:#f4f7ff;color:#132032;box-shadow:0 38px 110px rgba(15,23,42,.35);overflow:auto}#ban-map-dialog::backdrop{background:rgba(8,18,34,.6);backdrop-filter:blur(8px)}body:has(#ban-map-dialog[open]){overflow:hidden}.map-shell{padding:22px}.map-header{background:linear-gradient(135deg,#172554,#312e81 55%,#0f766e);padding:22px 26px;display:flex;align-items:center;justify-content:space-between;margin:0;border-radius:18px;color:#fff}.map-header h2{font-size:27px;letter-spacing:-.03em}.map-header p{font-size:13px;margin-top:4px;color:#dbe4ff}.map-eyebrow{font-size:10px;letter-spacing:.14em;color:#c7d2fe}.map-header button{color:#fff;background:rgba(255,255,255,.14);border-color:rgba(255,255,255,.4);font-size:20px}.map-toolbar{display:flex;align-items:end;gap:12px;flex-wrap:wrap;margin:18px 0 8px}.map-toolbar label{display:flex;flex-direction:column;gap:5px;color:#42506b;font-size:12px;margin:0}.map-toolbar select,.map-toolbar input{width:100%;font-size:13px}.map-search{flex:1;min-width:190px}#map-status{font-size:13px;min-height:25px;color:#42506b;margin-bottom:8px}.map-layout{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:20px;align-items:start}.map-visual{min-width:0}.map-canvas{position:relative;border:1px solid #c5d2ea;border-radius:18px;overflow:hidden;background:#e6eefc}#ban-world{display:block;width:100%;aspect-ratio:2/1;touch-action:none;cursor:grab}#ban-world:active{cursor:grabbing}#map-land path{fill:#fafcff;stroke:#b9c7df;stroke-width:.65;vector-effect:non-scaling-stroke}.map-point{cursor:pointer;outline:none}.map-point .halo{fill:#dc2626;opacity:.15}.map-point .pin{fill:#dc2626;stroke:white;stroke-width:2;vector-effect:non-scaling-stroke}.map-point.unbanned .halo,.map-point.unbanned .pin{fill:#0f766e}.map-point.history .halo,.map-point.history .pin{fill:#64748b}.map-point:focus .halo,.map-point:hover .halo{opacity:.4}.map-point text{font-size:10px;fill:white;font-weight:750;pointer-events:none;text-anchor:middle;dominant-baseline:central}.map-zoom{position:absolute;right:10px;bottom:10px;display:flex;gap:4px}.map-zoom button{padding:6px 12px;background:rgba(255,255,255,.92)}.map-legend{display:flex;gap:14px;align-items:center;flex-wrap:wrap;font-size:12px;margin:12px 0}.map-legend span{display:flex;align-items:center;gap:5px}.map-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#64748b}.map-dot.banned{background:#dc2626}.map-dot.unbanned{background:#0f766e}#map-count{margin-left:auto;color:#42506b}.map-caption{font-size:11px;color:#64748b;line-height:1.5;margin-bottom:12px}#map-list{max-height:265px;overflow:auto;display:grid;gap:8px}.map-row{display:flex;align-items:center;justify-content:space-between;gap:10px;background:#fff;border:1px solid #d8e1f2;border-radius:12px;padding:11px 14px;text-align:left;width:100%;color:#132032}.map-row:hover,.map-row[aria-pressed="true"]{background:#e7e9ff;border-color:#8b8cff}.map-row strong{font-family:ui-monospace,monospace;font-size:13px}.map-row small{display:block;font-size:11px;color:#42506b;margin-top:2px}.map-state-badge{font-size:10px;font-weight:650;border-radius:7px;padding:4px 7px;white-space:nowrap;background:#f1f5f9;color:#475569}.map-state-badge.banned{background:#ffe4e6;color:#9f1239}.map-state-badge.unbanned{background:#ccfbf1;color:#115e59}#map-detail{padding:22px;background:rgba(255,255,255,.8);border:1px solid white;border-radius:18px;box-shadow:0 12px 36px rgba(15,23,42,.06);overflow-wrap:anywhere}#map-detail h3{font-size:19px;color:#312e81;margin:0 0 14px}#map-detail dl{font-size:13px}#map-detail dt{color:#64748b;font-size:11px;margin-top:14px}#map-detail dd{margin:3px 0 0}#map-detail .map-actions{display:grid;gap:9px;margin-top:22px}#map-detail p{font-size:13px;color:#42506b}.map-empty{padding:22px;text-align:center;color:#64748b;font-size:13px}.map-header h2:focus{outline:none}
@media(max-width:950px){.map-layout{grid-template-columns:minmax(0,1fr)}#map-detail{min-height:0}.map-shell{padding:14px}#ban-map-dialog{width:96vw;height:94dvh}.map-toolbar label{flex:1;min-width:130px}.map-toolbar button{width:100%}.map-header{padding:18px}.map-header h2{font-size:23px}.map-zoom button{padding:5px 9px}#map-list{max-height:210px}}

#map-panel{background:rgba(255,255,255,.8);border:1px solid #d8e1f2;border-radius:18px;color:#132032}#map-panel .map-header{background:none;color:inherit;padding:0 0 16px}#map-panel .map-header h2{color:#312e81}#map-panel .map-header p{color:#64748b}#map-panel .map-eyebrow,#map-panel #map-close{display:none}

.configuration-menu{display:flex;flex-direction:column;gap:4px;padding:2px 0 8px 12px;border-left:1px solid #34405c;margin-left:14px}.configuration-menu[hidden]{display:none!important}.display-controls .configuration-menu button{font-size:12px;padding:9px 10px;line-height:1.4;white-space:normal}.configuration-menu button[aria-current="page"]{background:rgba(99,102,241,.22);color:#fff;border-color:rgba(129,140,248,.24)}
@media(max-width:900px){.tabs{flex-wrap:wrap}.configuration-menu{flex:1 1 100%;flex-direction:row;flex-wrap:wrap;margin:0;padding:8px;border-left:0}.configuration-menu button{flex:1 1 150px}}
</style>
<title>FCP</title>
</head>
<body>
<div class="container">
<div class="header">
<h1>FCP</h1>
<p>Actualisation toutes les 30 secondes · Protection des sites, du SSH et du SFTP</p>
</div>
<div class="display-controls" aria-label="Options d’affichage">
<div class="tabs" role="tablist" aria-label="Sections">
<button type="button" role="tab" id="tab-overview" data-tab="overview" aria-selected="true">Vue d’ensemble</button>
<button type="button" role="tab" id="administration-button" data-tab="administration" aria-selected="false" aria-controls="administration-panel">Configuration</button><div id="configuration-menu" class="configuration-menu" aria-label="Rubriques de configuration" hidden><button type="button" data-admin-section="overview" aria-current="false">État du service</button><button type="button" data-admin-section="jails" aria-current="false">Jails</button><button type="button" data-admin-section="files" aria-current="false">Filtres et actions</button><button type="button" data-admin-section="logs" aria-current="false">Journaux</button><button type="button" data-admin-section="backups" aria-current="false">Sauvegardes</button><button type="button" data-admin-section="abuse-settings" aria-current="false">Automatisations et e-mails</button><button type="button" data-admin-section="advanced" aria-current="false">Fonctions avancées</button></div>
<button type="button" role="tab" id="tab-detections" data-tab="detections" aria-selected="false">Détections</button>
<button type="button" role="tab" id="tab-history" data-tab="history" aria-selected="false">Historique</button>
<button type="button" role="tab" id="tab-requests" data-tab="requests" aria-selected="false">Requêtes HTTP</button>
<button type="button" role="tab" id="tab-map" data-tab="map" aria-selected="false" aria-controls="map-panel">🌐 Map Monde</button>
</div>
</div>
<p id="geo-note" class="note" style="padding:10px 20px;text-align:center">Pays et ville approximatifs · Opérateur et ASN : base locale facultative · DB-IP Lite, <span id="geo-version">version en cours de lecture</span> · <a href="https://db-ip.com" style="color:#9dcfff" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a> · Contact abuse : recherche RDAP selon les réglages de Configuration → Automatisations et e-mails ; seule l’IP est transmise<br><button type="button" id="geo-update" style="margin-top:8px;padding:6px 12px;border-radius:6px;cursor:pointer">Mettre à jour la base</button> <span id="geo-update-status" role="status"></span></p>
<section id="administration-panel" role="tabpanel" aria-labelledby="administration-button" hidden><iframe id="administration-frame" title="Administration Fail2ban" style="width:100%;height:750px;border:0;display:block" loading="lazy"></iframe></section>
<section id="map-panel" role="tabpanel" aria-labelledby="tab-map" hidden></section>
<div class="stats-grid">
"""

    def query_client(args):
        return subprocess.run(["docker", "exec", F2B_CONTAINER, "fail2ban-client", *args], capture_output=True, text=True, timeout=10, check=True).stdout

    # Four bounded readers; repeated values reuse the same future.
    try:
        server_status = query_client(("status",))
        jail_line = re.search(r"Jail list:\s*(.*)", server_status)
        jail_names = [name.strip() for name in jail_line.group(1).split(',') if name.strip()] if jail_line else []
    except (OSError, subprocess.SubprocessError):
        jail_names = []
    queries = [("ping",)]
    for jail in jail_names:
        queries.append(("status", jail))
        queries.extend(("get", jail, field) for field in ("maxretry", "findtime", "bantime", "banip"))
    with ThreadPoolExecutor(max_workers=4) as readers:
        client_results = {args: readers.submit(query_client, args) for args in queries}
    def client(*args):
        return client_results[args].result()

    def duration(value):
        seconds = int(re.search(r"\d+", value).group())
        if seconds % 3600 == 0:
            return f"{seconds // 3600} h"
        if seconds % 60 == 0:
            return f"{seconds // 60} min"
        return f"{seconds} s"

    # One bounded journal snapshot shared by activity and history.
    log_text = None
    clock_now = None
    try:
        logs = subprocess.run(["docker", "logs", "--tail", "5000", F2B_CONTAINER], capture_output=True, text=True, timeout=10, check=True)
        log_text = logs.stdout + "\n" + logs.stderr
        clock_result = subprocess.run(["docker", "exec", F2B_CONTAINER, "date", "+%Y-%m-%dT%H:%M:%S%z"], capture_output=True, text=True, timeout=10, check=True)
        clock_now = datetime.strptime(clock_result.stdout.strip(), "%Y-%m-%dT%H:%M:%S%z")
    except (subprocess.SubprocessError, OSError, ValueError):
        pass

    def age(moment):
        seconds = max(0, int((clock_now - moment).total_seconds()))
        if seconds < 60:
            return "il y a moins d’une minute"
        if seconds < 3600:
            return f"il y a {seconds // 60} min"
        if seconds < 86400:
            return f"il y a {seconds // 3600} h"
        return f"il y a {seconds // 86400} jours"

    def test_ip(ip):
        try:
            address = ipaddress.ip_address(ip)
            return any(address in ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32") if address.version == ipaddress.ip_network(net).version)
        except ValueError:
            return False

    detections = []
    bans = []
    if log_text is not None and clock_now is not None:
        pattern_activity = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*?\[([^]]+)\] (Found|Ban) (\S+)")
        for line in log_text.splitlines():
            match = pattern_activity.search(line)
            if match:
                stamp, jail, action, ip = match.groups()
                moment = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=clock_now.tzinfo)
                (detections if action == "Found" else bans).append((moment, jail, ip))
        html += '<div class="card suspect-card"><h3>Dernière activité observée</h3><p class="note">Événements présents dans les 5 000 dernières lignes du journal. Les adresses réservées aux tests sont exclues de ce résumé.</p>'
        for title, records in (("Dernière détection", detections), ("Dernier ban", bans)):
            real_records = [item for item in records if not test_ip(item[2])]
            if real_records:
                moment, jail, ip = max(real_records)
                html += f'<p><strong>{title} :</strong> {escape(ip)} · {escape(geo_label(ip))} · {escape(jail)} · {age(moment)} <span class="subline">{moment:%d/%m/%Y %H:%M:%S %z}</span></p>'
            else:
                html += f'<p><strong>{title} :</strong> aucun événement réel dans les lignes consultées.</p>'
        html += '</div>'
    else:
        html += '<div class="card suspect-card"><h3>⚠️ Activité indisponible</h3><p>Lecture du journal ou de l’heure de Fail2ban impossible.</p></div>'

    try:
        client("ping")
        html += '<div class="card suspect-card"><h3>✅ Fail2ban répond</h3><p>Le service est actif. Une liste vide signifie qu’aucun bannissement n’est en cours. Les bans levés restent visibles dans l’historique ci-dessous.</p></div>'
    except (subprocess.SubprocessError, OSError):
        html += '<div class="card suspect-card"><h3>⚠️ État du service indisponible</h3><p>Impossible de confirmer que Fail2ban répond.</p></div>'

    for jail in jail_names:
        title = escape({"npmplus": "🔒 Sites — NPMplus", "sshd": "🔐 SSH", "sftp": "🔐 SFTP"}.get(jail, "🔒 " + jail))
        html += f'<div class="card"><h3>{title}</h3>'
        try:
            status = client("status", jail)
            def count(label):
                match = re.search(re.escape(label) + r":\s*(\d+)", status)
                if not match:
                    raise ValueError("Compteur absent")
                return int(match.group(1))
            active = count("Currently banned")
            total = count("Total banned")
            detected = count("Total failed")
            retries = escape(client("get", jail, "maxretry").strip())
            window = duration(client("get", jail, "findtime"))
            ban = duration(client("get", jail, "bantime"))
            html += f'<p><strong>Protection active</strong> · Ban après {retries} détections de la même IP en {window}, pour {ban} (durée de base).</p>'
            if jail == "npmplus":
                html += '<p class="note">Détections : réponses 401 / 403 ou chemins suspects. Les réseaux locaux sont exclus. Les autres erreurs HTTP du tableau ne déclenchent pas forcément un ban.</p>'
            html += f'<div class="summary-strip"><button type="button" class="metric map-trigger" data-map-jail="{escape(jail, quote=True)}" data-map-state="banned" aria-label="Voir les IP bannies sur la carte : {escape(jail, quote=True)}"><strong>{active}</strong><small>IP bannies actuellement</small></button><button type="button" class="metric map-trigger" data-map-jail="{escape(jail, quote=True)}" data-map-state="all"><strong>{total}</strong><small>Bans depuis le démarrage</small></button><div class="metric"><strong>{detected}</strong><small>Détections depuis le démarrage</small></div></div>'
            ips = client("get", jail, "banip").split()
            valid_ips = []
            for ip in ips:
                try:
                    valid_ips.append(str(ipaddress.ip_address(ip)))
                except ValueError:
                    pass
            if valid_ips:
                html += '<div class="ip-container">'
                for ip in valid_ips:
                    html += f'<button type="button" class="ip-btn map-ip" data-map-jail="{escape(jail, quote=True)}" data-map-ip="{ip}" data-map-state="banned">IP bannie : {ip} · {escape(geo_label(ip))} ↗</button>'
                html += '</div>'
            else:
                html += '<div class="empty-state">Aucun ban en cours. La surveillance reste active.</div>'
            html += f'<details><summary>Détails techniques</summary><pre>{escape(status)}</pre></details>'
        except (subprocess.SubprocessError, OSError, ValueError, AttributeError):
            html += '<p>⚠️ État de cette protection indisponible.</p>'
        html += '</div>'

    html += '<div class="card suspect-card"><h3>Progression des détections par IP</h3><p class="note">Le seuil concerne une même IP dans la fenêtre indiquée. Estimation à partir du journal ; les compteurs internes de Fail2ban restent la référence. Les détections anciennes sortent de la fenêtre. Actualisation toutes les 30 secondes.</p>'
    if log_text is not None and clock_now is not None:
        try:
            html += '<div class="table-wrap"><table><thead><tr><th>IP</th><th>Protection</th><th>Dans la fenêtre actuelle</th><th>Dernière détection</th><th>Situation</th></tr></thead><tbody>'
            for jail in jail_names:
                retries = int(client("get", jail, "maxretry").strip())
                seconds = int(re.search(r"\d+", client("get", jail, "findtime")).group())
                banned = set(client("get", jail, "banip").split())
                grouped = {}
                for moment, record_jail, ip in detections:
                    if record_jail == jail and not test_ip(ip):
                        grouped.setdefault(ip, []).append(moment)
                for ip, moments in sorted(grouped.items(), key=lambda item: max(item[1]), reverse=True)[:20]:
                    last = max(moments)
                    recent = sum(clock_now - timedelta(seconds=seconds) <= moment <= clock_now for moment in moments)
                    situation = "Bannie actuellement" if ip in banned else "Fenêtre écoulée" if recent == 0 else "Seuil non atteint" if recent < retries else "Seuil atteint dans le journal ; aucun ban actif"
                    html += f'<tr><td class="ip">{escape(ip)}{geo_html(ip)}</td><td>{escape(jail)}</td><td><strong>{recent} / {retries}</strong><span class="subline">sur {duration(str(seconds))}</span></td><td>{age(last)}<span class="subline">{last:%d/%m %H:%M:%S}</span></td><td>{situation}</td></tr>'
                if not grouped:
                    html += f'<tr><td colspan="5">{escape(jail)} : aucune détection réelle dans les lignes consultées.</td></tr>'
            html += '</tbody></table></div>'
        except (subprocess.SubprocessError, OSError, ValueError, AttributeError):
            html += '</tbody></table></div><p>⚠️ Progression indisponible : lecture des paramètres impossible.</p>'
    else:
        html += '<p>⚠️ Journal indisponible : progression non calculée.</p>'
    html += '</div>'

    html += '<div class="card suspect-card"><h3>Historique récent des bannissements</h3><p class="note">Les 50 derniers événements présents dans les 5 000 dernières lignes du journal du conteneur. Un ban levé n’apparaît plus dans les IP bannies actuellement. Heures telles qu’enregistrées par Fail2ban.</p>'
    try:
        if log_text is None:
            raise OSError("Journal indisponible")
        events = []
        for line in log_text.splitlines():
            match = re.search(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*?\[([^]]+)\] (Ban|Unban) (\S+)", line)
            if match:
                events.append(match.groups())
        events.sort(key=lambda event: event[0], reverse=True)
        if events:
            html += '<div class="table-wrap"><table><thead><tr><th>Date et heure</th><th>Protection</th><th>IP</th><th>Événement</th></tr></thead><tbody>'
            for date, jail, action, ip in events[:50]:
                label = "IP bannie" if action == "Ban" else "Ban levé"
                if test_ip(ip):
                    label += " · adresse de test"
                html += f'<tr><td>{escape(date)}</td><td>{escape(jail)}</td><td class="ip">{escape(ip)}{geo_html(ip)}</td><td><button type="button" class="map-history-link" data-map-jail="{escape(jail, quote=True)}" data-map-ip="{escape(ip, quote=True)}" data-map-state="all">{label} ↗</button></td></tr>'
            html += '</tbody></table></div>'
        else:
            html += '<p>Aucun événement de bannissement dans les lignes consultées.</p>'
    except (subprocess.SubprocessError, OSError):
        html += '<p>⚠️ Historique indisponible.</p>'
    html += '</div>'

    # Requêtes suspectes : lecture bornée du journal, contenu échappé.
    html += '<div class="card suspect-card"><h3>Requêtes suspectes et erreurs HTTP — npmplus</h3>'
    try:
        log_snapshot = http_reader.poll()
        rows = log_snapshot['rows']
        suspect = suspect_pattern
        ips = len({row[1] for row in rows})
        html += f'<p class="note">{len(rows)} requêtes suspectes ou en erreur retenues · {ips} IP publiques distinctes. Les 100 plus récentes sont affichées, de la plus récente à la plus ancienne. Historique enregistré en base et suivi des nouvelles lignes toutes les 10 secondes.</p>'
        if log_snapshot['last_success']:
            stamp = escape(log_snapshot['last_success'], quote=True)
            html += f'<p class="note">Dernière lecture réussie : <time class="http-read-time" datetime="{stamp}">{stamp}</time></p>'
        if log_snapshot['error']:
            html += '<p class="note" role="status">Lecture du journal momentanément indisponible. Les dernières données connues sont conservées.</p>'
        if log_snapshot['catching_up']:
            html += '<p class="note" role="status">Rattrapage des nouvelles lignes en cours.</p>'
        if log_snapshot['truncated_line']:
            html += '<p class="note" role="status">Certaines lignes trop volumineuses ont été ignorées.</p>'
        html += '<p class="note">Ban de 6 heures après 3 détections en 1 minute (401, 403 ou chemin suspect), hors réseaux locaux. Une requête suspecte ne signifie pas une intrusion réussie. Le code indique la réponse du proxy ; les compteurs Fail2ban repartent au redémarrage.</p>'
        auth_count = sum(r[5] in ('401', '403') for r in rows)
        server_count = sum(int(r[5]) >= 500 for r in rows)
        html += f'<div class="summary-strip"><div class="metric"><strong>{len(rows)}</strong><small>Requêtes à examiner</small></div><div class="metric"><strong>{ips}</strong><small>IP publiques distinctes</small></div><div class="metric red"><strong>{auth_count}</strong><small>Refus 401 / 403</small></div><div class="metric amber"><strong>{server_count}</strong><small>Erreurs serveur 5xx</small></div></div>'
        html += '<div class="toolbar"><input id="request-search" type="search" placeholder="Rechercher une IP, un domaine, un chemin…" aria-label="Rechercher dans les requêtes"><select id="request-filter" aria-label="Filtrer les réponses"><option value="all">Toutes les réponses</option><option value="auth">401 / 403 — accès refusé</option><option value="missing">404 — page introuvable</option><option value="rate">429 — trop de requêtes</option><option value="server">5xx — erreur serveur</option><option value="suspect">Chemins suspects</option></select><span id="visible-count" class="note"></span></div>'
        history_state = http_reader.history()
        html += f'<div class="toolbar"><button type="button" id="http-previous" disabled>← Plus récentes</button><span id="http-page">Page 1 / {history_state["pages"]} · {history_state["count"]} requêtes enregistrées · conservation {history_state["retention_days"]} jours</span><button type="button" id="http-next" {"disabled" if history_state["pages"] <= 1 else ""}>Plus anciennes →</button></div>'
        html += '<div class="legend"><span>🔴 Accès refusé</span><span>🟡 Page introuvable / limite</span><span>🟣 Erreur serveur</span><span>🔵 Autre réponse</span></div>'
        if rows:
            html += '<div class="table-wrap"><table id="http-history-table"><thead><tr><th>Date et heure</th><th>IP source</th><th>Domaine</th><th>Méthode</th><th>Chemin demandé</th><th>Réponse HTTP</th></tr></thead><tbody>'
            html += render_http_rows(rows)
            html += '</tbody></table></div>'
        else:
            html += '<div class="empty-state">' + ('En attente de la première lecture réussie du journal.' if log_snapshot['error'] else 'Aucune requête suspecte ou en erreur provenant d’Internet dans les lignes consultées.') + '</div>'
    except (subprocess.SubprocessError, OSError):
        html += '<p class="note">Lecture du journal npmplus indisponible. Réessayez après actualisation.</p>'
    html += '</div>'


    html += "</div></div>" + BAN_MAP_HTML
    html += """
<div class="refresh" onclick="location.reload()">🔄 REFRESH</div>
<script>
const mapDialog=document.getElementById('ban-map-dialog'), mapSvg=document.getElementById('ban-world');
const mapEl=id=>document.getElementById(id);
let mapItems=[],mapSelected=null,mapLocation=null,mapBusy=false,mapBox=[0,0,960,480],mapDrag=null;
const mapNames={npmplus:'Sites — NPMplus',sshd:'SSH',sftp:'SFTP'},mapStates={banned:'Bannie',unbanned:'Ban levé',history:'Historique'};
const mapKey=r=>r.jail+'|'+r.ip, mapHasLocation=r=>Number.isFinite(r.latitude)&&Number.isFinite(r.longitude);
const mapXY=r=>[(r.longitude+180)*960/360,(90-r.latitude)*480/180];
async function mapApi(payload){const response=await fetch('/admin/api',{method:'POST',headers:{'Content-Type':'application/json','X-Fail2ban-Token':'__ADMINTOKEN__'},body:JSON.stringify(payload)});const data=await response.json();if(!response.ok||data.error)throw Error(data.error||'Carte indisponible');return data;}
function mapText(tag,text,cls){const el=document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el;}
function mapView(){mapSvg.setAttribute('viewBox',mapBox.join(' '));}
function mapZoom(factor){const [x,y,w,h]=mapBox,nw=Math.max(120,Math.min(960,w*factor)),nh=nw/2;mapBox=[Math.max(0,Math.min(960-nw,x+w/2-nw/2)),Math.max(0,Math.min(480-nh,y+h/2-nh/2)),nw,nh];mapView();}
function mapRows(){const state=mapEl('map-state').value,jail=mapEl('map-jail').value,query=mapEl('map-search').value.toLowerCase();return mapItems.filter(r=>(state==='all'||r.state===state)&&(!jail||r.jail===jail)&&(!query||(r.ip+' '+r.location+' '+r.network).toLowerCase().includes(query)));}
function mapSelect(record,center=false){mapSelected=mapKey(record);renderMapDetail(record);renderMap();if(center&&mapHasLocation(record)){const [x,y]=mapXY(record);mapBox=[Math.max(0,Math.min(720,x-120)),Math.max(0,Math.min(360,y-60)),240,120];mapView();}}
function renderMapDetail(record){const panel=mapEl('map-detail');panel.replaceChildren();panel.append(mapText('h3',record.ip));panel.append(mapText('span',mapStates[record.state],'map-state-badge '+record.state));const dl=document.createElement('dl');const fields=[['Protection',mapNames[record.jail]||record.jail],['Localisation approximative',record.location],['Opérateur / réseau',record.network||'Non renseigné'],['Coordonnées',mapHasLocation(record)?record.latitude.toFixed(4)+'°, '+record.longitude.toFixed(4)+'°':'Coordonnées indisponibles — aucun point placé'],['Dernier événement dans le journal',record.last_event||'Non présent dans les lignes consultées']];for(const [label,value]of fields){dl.append(mapText('dt',label),mapText('dd',value));}panel.append(dl);const actions=mapText('div','','map-actions');const action=mapText('button',record.state==='banned'?'Débannir cette IP':'Bannir cette IP');action.className=record.state==='banned'?'danger':'';action.addEventListener('click',()=>mapAction(record));actions.append(action);if(record.state==='banned'){const keep=mapText('button','Conserver le bannissement');keep.onclick=()=>{mapEl('map-status').textContent='Bannissement conservé pour '+record.ip+'.';};actions.append(keep);}const copy=mapText('button','Copier l’adresse IP');copy.onclick=async()=>{try{await navigator.clipboard.writeText(record.ip);mapEl('map-status').textContent='Adresse IP copiée.';}catch{mapEl('map-status').textContent='Adresse à copier : '+record.ip;}};actions.append(copy);panel.append(actions);}
async function mapAction(record){if(mapBusy)return;const unban=record.state==='banned';if(!confirm((unban?'Débannir ':'Bannir ')+record.ip+' dans '+(mapNames[record.jail]||record.jail)+' ?'+(unban?' Cette action lève sa protection dans cette jail.':'')))return;mapBusy=true;mapEl('map-detail').querySelectorAll('button').forEach(b=>b.disabled=true);mapEl('map-status').textContent='Action en cours…';try{await mapApi({op:unban?'unban':'ban',jail:record.jail,ip:record.ip});await loadMap();mapEl('map-status').textContent=(unban?'Ban levé pour ':'IP bannie : ')+record.ip+'.';}catch(error){mapEl('map-status').textContent=error.message;}finally{mapBusy=false;mapEl('map-detail').querySelectorAll('button').forEach(b=>b.disabled=false);}}
function renderMap(){const rows=mapRows(),list=mapEl('map-list'),points=mapEl('map-points');list.replaceChildren();points.replaceChildren();const groups=new Map();let located=0;for(const record of rows){if(mapHasLocation(record)){located++;const key=record.latitude+','+record.longitude;const group=groups.get(key)||[];group.push(record);groups.set(key,group);}}
for(const group of groups.values()){const [x,y]=mapXY(group[0]),ns='http://www.w3.org/2000/svg',g=document.createElementNS(ns,'g');const state=group.some(r=>r.state==='banned')?'banned':group.some(r=>r.state==='unbanned')?'unbanned':'history';g.setAttribute('class','map-point '+state);g.setAttribute('transform',`translate(${x},${y})`);g.setAttribute('role','button');g.setAttribute('tabindex','0');g.setAttribute('aria-label',group.length+' IP · '+group[0].location);for(const [radius,cls]of [[13,'halo'],[7,'pin']]){const circle=document.createElementNS(ns,'circle');circle.setAttribute('r',radius);circle.setAttribute('class',cls);g.append(circle);}if(group.length>1){const t=document.createElementNS(ns,'text');t.textContent=group.length;g.append(t);}const select=()=>{mapLocation=group.map(mapKey);mapSelect(group[0]);mapEl('map-status').textContent=group.length+' IP à cet emplacement. Choisis une adresse dans la liste.';};g.onclick=select;g.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();select();}};points.append(g);}
const shown=mapLocation?rows.filter(r=>mapLocation.includes(mapKey(r))):rows;if(mapLocation){const all=mapText('button','← Afficher toute la liste');all.onclick=()=>{mapLocation=null;renderMap();};list.append(all);}for(const record of shown){const button=mapText('button','','map-row');button.setAttribute('aria-pressed',String(mapKey(record)===mapSelected));const info=document.createElement('span');info.append(mapText('strong',record.ip),mapText('small',(mapNames[record.jail]||record.jail)+' · '+record.location+(mapHasLocation(record)?'':' · sans coordonnées')));button.append(info,mapText('span',mapStates[record.state],'map-state-badge '+record.state));button.onclick=()=>mapSelect(record,true);list.append(button);}if(!shown.length)list.append(mapText('p','Aucune IP ne correspond à cette sélection.','map-empty'));mapEl('map-count').textContent=rows.length+' IP / protection · '+located+' géolocalisées';}
async function loadMap(){mapEl('map-status').textContent='Lecture des bannissements…';mapEl('map-reload').disabled=true;try{const d=await mapApi({op:'ban_map_data'});mapItems=d.items;const select=mapEl('map-jail'),previous=select.value;select.replaceChildren(new Option('Toutes les protections',''));for(const jail of d.jails)select.append(new Option(mapNames[jail]||jail,jail));select.value=d.jails.includes(previous)?previous:'';mapLocation=null;renderMap();const current=mapItems.find(r=>mapKey(r)===mapSelected);if(current)renderMapDetail(current);mapEl('map-status').textContent='État actuel vérifié auprès de Fail2ban. Historique limité aux 5 000 dernières lignes'+(d.history_limited?' et 300 anciennes IP.':'.');}catch(error){mapItems=[];mapLocation=null;renderMap();mapEl('map-detail').replaceChildren(mapText('h3','État indisponible'),mapText('p','Actualise la carte avant de choisir une action.'));mapEl('map-status').textContent=error.message;throw error;}finally{mapEl('map-reload').disabled=false;}}
async function openBanMap(jail='',ip='',state='banned',inline=false){const shell=document.querySelector('.map-shell');if(inline){if(mapDialog.open)mapDialog.close();mapEl('map-panel').append(shell);}else{mapDialog.append(shell);}mapEl('map-state').value=state;mapEl('map-search').value='';mapLocation=null;mapSelected=null;mapBox=[0,0,960,480];mapView();if(!inline&&!mapDialog.open)mapDialog.showModal();mapEl('map-detail').replaceChildren(mapText('h3','Sélectionner une IP'),mapText('p','Choisis un point ou une adresse dans la liste.'));try{await loadMap();mapEl('map-jail').value=jail;renderMap();if(ip){const r=mapItems.find(r=>r.ip===ip&&r.jail===jail);if(r){mapEl('map-state').value=r.state==='history'?'all':r.state;mapSelect(r,true);}}}catch{}}
mapEl('map-close').onclick=()=>mapDialog.close();mapDialog.addEventListener('click',e=>{if(e.target===mapDialog){const box=mapDialog.getBoundingClientRect();if(e.clientX<box.left||e.clientX>box.right||e.clientY<box.top||e.clientY>box.bottom)mapDialog.close();}});
mapEl('map-reload').onclick=()=>loadMap().catch(()=>{});for(const name of ['map-state','map-jail','map-search'])mapEl(name).addEventListener(name==='map-search'?'input':'change',()=>{mapLocation=null;renderMap();});mapEl('map-zoom-in').onclick=()=>mapZoom(.5);mapEl('map-zoom-out').onclick=()=>mapZoom(2);mapEl('map-reset').onclick=()=>{mapBox=[0,0,960,480];mapView();mapLocation=null;renderMap();};
mapSvg.addEventListener('wheel',e=>{e.preventDefault();mapZoom(e.deltaY<0?.8:1.25);},{passive:false});mapSvg.addEventListener('pointerdown',e=>{if(e.target.closest('.map-point'))return;mapDrag={x:e.clientX,y:e.clientY,box:[...mapBox]};mapSvg.setPointerCapture(e.pointerId);});mapSvg.addEventListener('pointermove',e=>{if(!mapDrag)return;const rect=mapSvg.getBoundingClientRect(),[x,y,w,h]=mapDrag.box;mapBox=[Math.max(0,Math.min(960-w,x-(e.clientX-mapDrag.x)*w/rect.width)),Math.max(0,Math.min(480-h,y-(e.clientY-mapDrag.y)*h/rect.height)),w,h];mapView();});mapSvg.addEventListener('pointerup',()=>mapDrag=null);mapSvg.addEventListener('pointercancel',()=>mapDrag=null);
document.addEventListener('click',e=>{const button=e.target.closest('[data-map-jail]');if(!button)return;openBanMap(button.dataset.mapJail||'',button.dataset.mapIp||'',button.dataset.mapState||'banned');});

let abuseBusy=false;
async function refreshAbuse(){if(abuseBusy)return;abuseBusy=true;try{const addresses=[...new Set([...document.querySelectorAll('.card:not([hidden]) .abuse-result')].map(node=>node.dataset.ip))];for(let offset=0;offset<addresses.length;offset+=20){const response=await fetch('/abuse/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips:addresses.slice(offset,offset+20)})});if(!response.ok)throw new Error();const records=await response.json();document.querySelectorAll('.abuse-result').forEach(node=>{const data=records[node.dataset.ip];if(!data)return;node.replaceChildren();if(data.contacts&&data.contacts.length){node.append(document.createTextNode('Abuse : '));data.contacts.forEach((email,index)=>{if(index)node.append(document.createTextNode(', '));const link=document.createElement('a');link.href='mailto:'+email;link.textContent=email;node.append(link);});}else node.textContent=data.message;});}}catch(e){document.querySelectorAll('.card:not([hidden]) .abuse-result').forEach(node=>{if(node.textContent.includes('recherche automatique'))node.textContent='Contact abuse : recherche indisponible';});}finally{abuseBusy=false;}}
setTimeout(refreshAbuse,0);setInterval(refreshAbuse,5000);
const geoUpdateButton=document.getElementById('geo-update');
async function geoStatus(){try{const response=await fetch('/geo/status');if(!response.ok)throw new Error();const data=await response.json();document.getElementById('geo-version').textContent=data.version;document.getElementById('geo-update-status').textContent=data.message;geoUpdateButton.disabled=data.running;geoUpdateButton.textContent=data.running?'Mise à jour en cours…':'Mettre à jour la base';}catch(e){document.getElementById('geo-update-status').textContent='État de la base indisponible';}}
geoUpdateButton.addEventListener('click',async()=>{geoUpdateButton.disabled=true;try{const response=await fetch('/geo/update',{method:'POST',headers:{'X-Requested-With':'Fail2ban-UI'}});if(!response.ok)throw new Error();await geoStatus();}catch(e){document.getElementById('geo-update-status').textContent='Impossible de démarrer la mise à jour';geoUpdateButton.disabled=false;}});
geoStatus();setInterval(geoStatus,3000);
document.querySelectorAll('.http-read-time').forEach(node=>{node.textContent=new Date(node.dateTime).toLocaleString('fr-FR');});
const displayKey='fail2ban-tabs-v1';
let displayPrefs={compact:false,tab:'overview'};
try{displayPrefs=JSON.parse(localStorage.getItem(displayKey))||displayPrefs;}catch(e){}
const cards=[...document.querySelectorAll('.stats-grid > .card')];
const groups=cards.map((card,index)=>index<__OVERVIEWCOUNT__?'overview':['detections','history','requests'][index-__OVERVIEWCOUNT__]);
const tabButtons=[...document.querySelectorAll('[role="tab"]')];
function saveDisplay(){try{localStorage.setItem(displayKey,JSON.stringify(displayPrefs));}catch(e){}}
function applyCompact(){document.body.classList.remove('compact');displayPrefs.compact=false;}
const adminSections=['overview','jails','files','logs','backups','abuse-settings','advanced'];
let selectedAdminSection='overview';try{const saved=localStorage.getItem('fcp-admin-section');if(adminSections.includes(saved))selectedAdminSection=saved;}catch(e){}
function syncAdminMenu(){document.querySelectorAll('[data-admin-section]').forEach(b=>b.setAttribute('aria-current',b.dataset.adminSection===selectedAdminSection?'page':'false'));}
function sendAdminSection(){const f=document.getElementById('administration-frame');if(f.contentWindow)f.contentWindow.postMessage({type:'fcp-admin-navigate',section:selectedAdminSection},location.origin);}
document.querySelectorAll('[data-admin-section]').forEach(b=>b.addEventListener('click',()=>{selectedAdminSection=b.dataset.adminSection;try{localStorage.setItem('fcp-admin-section',selectedAdminSection);}catch(e){}selectTab('administration');syncAdminMenu();sendAdminSection();document.getElementById('administration-panel').scrollIntoView({block:'start'});}));
function selectTab(name){if(!groups.includes(name)&&name!=='administration'&&name!=='map')name='overview';const admin=name==='administration',world=name==='map';document.getElementById('configuration-menu').hidden=!admin;syncAdminMenu();document.getElementById('map-panel').hidden=!world;if(world)openBanMap('','','all',true);document.getElementById('administration-panel').hidden=!admin;document.querySelector('.stats-grid').hidden=admin||world;document.getElementById('geo-note').hidden=admin||world;const frame=document.getElementById('administration-frame');if(admin&&!frame.getAttribute('src'))frame.src='/manage?embedded=1';displayPrefs.tab=name;cards.forEach((card,i)=>{card.hidden=groups[i]!==name;card.setAttribute('role','tabpanel');card.setAttribute('aria-labelledby','tab-'+groups[i]);});tabButtons.forEach(button=>{const selected=button.dataset.tab===name;button.setAttribute('aria-selected',String(selected));button.tabIndex=selected?0:-1;});saveDisplay();setTimeout(refreshAbuse,0);}
window.addEventListener('message',event=>{const frame=document.getElementById('administration-frame');if(event.origin!==location.origin||event.source!==frame.contentWindow)return;if(event.data?.type==='fcp-admin-ready')sendAdminSection();if(event.data?.type==='fcp-admin-section'&&adminSections.includes(event.data.section)){selectedAdminSection=event.data.section;syncAdminMenu();}if(event.data?.type==='fail2ban-admin-height'&&Number.isFinite(event.data.height))frame.style.height=Math.max(500,Math.min(6000,event.data.height))+'px';});
setInterval(()=>{if(!['administration','map'].includes(displayPrefs.tab)&&!mapDialog.open)location.reload();},30000);
applyCompact();selectTab(displayPrefs.tab);
tabButtons.forEach((button,index)=>{button.addEventListener('click',()=>selectTab(button.dataset.tab));button.addEventListener('keydown',event=>{let next=index;if(event.key==='ArrowRight')next=(index+1)%tabButtons.length;else if(event.key==='ArrowLeft')next=(index+tabButtons.length-1)%tabButtons.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=tabButtons.length-1;else return;event.preventDefault();tabButtons[next].focus();selectTab(tabButtons[next].dataset.tab);});});
const searchBox=document.getElementById('request-search'), filterBox=document.getElementById('request-filter');
function filterRequests(){const query=searchBox.value.toLowerCase(), category=filterBox.value;let count=0;document.querySelectorAll('.request-row').forEach(row=>{const match=(category==='all'||(category==='suspect'?row.dataset.suspect==='1':row.dataset.kind===category))&&row.textContent.toLowerCase().includes(query);row.hidden=!match;if(match)count++;});document.getElementById('visible-count').textContent=count+' lignes affichées';}
if(searchBox&&filterBox){searchBox.addEventListener('input',filterRequests);filterBox.addEventListener('change',filterRequests);filterRequests();}
let httpPage=1;
async function loadHttpPage(page){const prev=document.getElementById('http-previous'),next=document.getElementById('http-next');prev.disabled=next.disabled=true;try{const response=await fetch('/http/history?page='+page);const data=await response.json();if(!response.ok)throw Error(data.error||'Historique indisponible');document.querySelector('#http-history-table tbody').innerHTML=data.html;httpPage=data.page;document.getElementById('http-page').textContent='Page '+data.page+' / '+data.pages+' · '+data.count+' requêtes enregistrées · conservation '+data.retention_days+' jours';prev.disabled=data.page<=1;next.disabled=data.page>=data.pages;filterRequests();refreshAbuse();}catch(error){document.getElementById('http-page').textContent=error.message;prev.disabled=httpPage<=1;next.disabled=false;}}
document.getElementById('http-previous')?.addEventListener('click',()=>loadHttpPage(httpPage-1));
document.getElementById('http-next')?.addEventListener('click',()=>loadHttpPage(httpPage+1));


function unban(ip,jail){
  if(!confirm('Débannir '+ip+' dans '+jail+' ?'))return;
  fetch('/admin/api',{method:'POST',headers:{'Content-Type':'application/json','X-Fail2ban-Token':'__ADMINTOKEN__'},body:JSON.stringify({op:'unban',ip,jail})})
    .then(async response=>{const data=await response.json();if(!response.ok||data.error)throw Error(data.error||'Échec');setTimeout(()=>location.reload(),1500);}).catch(error=>alert(error.message));
}
</script>
</body></html>
"""
    return html.replace("__OVERVIEWCOUNT__", str(2 + len(jail_names))).replace("__ADMINTOKEN__", admin_token)



def fetch_abuse(ip, settings=None, revision=0):
    settings = settings or abuse_settings_read()[0]
    result = {'contacts': [], 'message': 'Contact abuse non renseigné dans le registre', 'expires': time.time() + settings['cache_hours'] * 3600, 'revision': revision}
    try:
        query = urllib.request.Request('https://rdap.org/ip/' + ip, headers={'User-Agent': 'curl/8.14.1', 'Accept': 'application/rdap+json'})
        with urllib.request.urlopen(query, timeout=15) as response:
            body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise ValueError('Réponse trop volumineuse')
        record = json.loads(body)
        emails = set()
        def visit(entities, depth=0):
            if depth > 6 or not isinstance(entities, list):
                return
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                if 'abuse' in entity.get('roles', []):
                    card = entity.get('vcardArray', [])
                    if len(card) == 2 and isinstance(card[1], list):
                        for entry in card[1]:
                            if isinstance(entry, list) and len(entry) >= 4 and entry[0] == 'email' and isinstance(entry[3], str) and re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", entry[3]):
                                emails.add(entry[3])
                visit(entity.get('entities', []), depth + 1)
        visit(record.get('entities', []))
        result['contacts'] = sorted(emails)
    except Exception:
        result.update(message=f"Contact abuse : registre indisponible, nouvelle tentative dans {settings['retry_minutes']} min", expires=time.time() + settings['retry_minutes'] * 60)
    with abuse_lock:
        abuse_cache[ip] = result

repeat_snapshot = {'expires': 0, 'counts': {}}
repeat_lock = threading.Lock()

def repeated_bans():
    settings, revision = abuse_settings_read()
    with repeat_lock:
        if repeat_snapshot['expires'] > time.time() and repeat_snapshot.get('revision') == revision:
            return repeat_snapshot['counts']
        logs = subprocess.run(['docker', 'logs', '--since', str(settings['window_hours']) + 'h', '--tail', '10000', F2B_CONTAINER], capture_output=True, text=True, timeout=10, check=True)
        episodes = {}
        pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*?\[([^]]+)\] Ban (\S+)')
        for line in (logs.stdout + '\n' + logs.stderr).splitlines():
            match = pattern.search(line)
            if not match:
                continue
            stamp, jail, ip = match.groups()
            try:
                address = ipaddress.ip_address(ip)
                if not address.is_global:
                    continue
            except ValueError:
                continue
            # Distinct ban times; duplicate lines or simultaneous jails count once.
            episodes.setdefault(str(address), set()).add(stamp)
        counts = {ip: len(stamps) for ip, stamps in episodes.items()}
        repeat_snapshot.update(expires=time.time() + 30, counts=counts, revision=revision)
        return counts

@app.route('/abuse/status', methods=['POST'])
def abuse_status():
    payload = request.get_json(silent=True) or {}
    ips = payload.get('ips', [])
    if not isinstance(ips, list) or len(ips) > 20:
        return jsonify(error='Liste incorrecte'), 400
    settings, revision = abuse_settings_read()
    if not settings['lookup_enabled']:
        return jsonify({str(ip): {'contacts': [], 'message': 'Recherche des contacts abuse désactivée.'} for ip in ips if isinstance(ip, str)})
    try:
        repeats = repeated_bans()
    except (OSError, subprocess.SubprocessError):
        return jsonify(error='Impossible de vérifier la récidive'), 503
    output = {}
    with abuse_lock:
        for raw_ip in ips:
            try:
                address = ipaddress.ip_address(raw_ip)
                if not address.is_global:
                    continue
                ip = str(address)
            except (ValueError, TypeError):
                continue
            count = repeats.get(ip, 0)
            if count < settings['min_bans']:
                output[ip] = {'contacts': [], 'message': f"Abuse non recherché : {count} ban sur {settings['window_hours']} h, seuil = {settings['min_bans']} bans distincts"}
                continue
            previous = abuse_cache.get(ip)
            if previous is None or previous['expires'] < time.time() or previous.get('revision') != revision:
                if len(abuse_cache) >= 512:
                    expired = [key for key, value in abuse_cache.items() if value['expires'] < time.time()]
                    for key in expired:
                        abuse_cache.pop(key, None)
                    if len(abuse_cache) >= 512:
                        output[ip] = {'contacts': [], 'message': 'Contact abuse : limite de recherches atteinte'}
                        continue
                abuse_cache[ip] = {'contacts': [], 'message': 'Contact abuse : recherche en cours…', 'expires': time.time() + 120, 'revision': revision}
                abuse_executor.submit(fetch_abuse, ip, settings, revision)
            output[ip] = {key: value for key, value in abuse_cache[ip].items() if key not in ('expires', 'revision')}
    return jsonify(output)

@app.route('/geo/status')
def geo_status():
    with geo_lock:
        try:
            stamp = datetime.fromtimestamp(geo_reader.metadata().build_epoch)
            version = 'base du ' + stamp.strftime('%d/%m/%Y')
        except (AttributeError, ValueError, OSError):
            version = 'base indisponible'
        return jsonify(version=version, **geo_update)

@app.route('/geo/update', methods=['POST'])
def update_geo():
    if request.headers.get('X-Requested-With') != 'Fail2ban-UI':
        return jsonify(error='Requête non autorisée'), 403
    with geo_lock:
        if geo_update['running']:
            return jsonify(**geo_update), 202
        geo_update.update(running=True, message='Téléchargement et vérification de la base…')
    def download():
        global geo_reader
        compressed = candidate = None
        try:
            release = datetime.now().strftime('%Y-%m')
            url = f'https://download.db-ip.com/free/dbip-city-lite-{release}.mmdb.gz'
            with tempfile.NamedTemporaryFile(dir='/app/geo', delete=False) as target:
                compressed = target.name
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "curl/8.14.1"}), timeout=30) as source:
                    size = 0
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > 250 * 1024 * 1024:
                            raise ValueError('Téléchargement trop volumineux')
                        target.write(chunk)
            with tempfile.NamedTemporaryFile(dir='/app/geo', delete=False) as target:
                candidate = target.name
                with gzip.open(compressed, 'rb') as source:
                    size = 0
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > 512 * 1024 * 1024:
                            raise ValueError('Base trop volumineuse')
                        target.write(chunk)
            with maxminddb.open_database(candidate) as checked:
                if 'City' not in checked.metadata().database_type:
                    raise ValueError('Format de base incorrect')
                if not checked.get('8.8.8.8'):
                    raise ValueError('Base incomplète')
            replacement = maxminddb.open_database(candidate)
            try:
                with geo_lock:
                    os.replace(candidate, '/app/geo/city.mmdb')
                    candidate = None
                    previous = geo_reader
                    geo_reader = replacement
                    geo_label.cache_clear()
                    if previous is not None:
                        previous.close()
                    geo_update.update(running=False, message='Base mise à jour. Actualise la page pour afficher les nouvelles localisations.')
            except Exception:
                replacement.close()
                raise
        except Exception:
            with geo_lock:
                geo_update.update(running=False, message='Mise à jour impossible. La base précédente est conservée ; réessaie plus tard.')
        finally:
            for path in (compressed, candidate):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
    threading.Thread(target=download, daemon=True).start()
    return jsonify(**geo_update), 202


# Administrative operations use structured arguments, never a shell command.
import secrets
import hashlib
from urllib.parse import urlsplit
admin_token = secrets.token_urlsafe(32)
admin_mutation_lock = threading.Lock()

CONFIG_TOOL = r'''
import sys,json,pathlib,hashlib,configparser,tempfile,shutil,subprocess,datetime,os
q=json.load(sys.stdin)
root=pathlib.Path('/data'); effective=pathlib.Path('/etc/fail2ban')
kind=q.get('kind','jail'); name=q.get('name','')
dirs={'jail':'jail.d','filter':'filter.d','action':'action.d'}
def digest(b): return hashlib.sha256(b).hexdigest()
def parse(b):
 c=configparser.RawConfigParser(strict=True); c.read_string(b.decode()); return c
op=q['op']
if op=='inventory':
 out={}
 for k,d in dirs.items():
  out[k]=[{'name':p.name,'custom':(root/d/p.name).is_file()} for p in sorted((effective/d).iterdir()) if p.is_file() and p.suffix in ('.conf','.local')]
 print(json.dumps(out)); sys.exit()
if kind not in dirs or not __import__('re').fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.(conf|local)',name): raise ValueError('Nom de fichier invalide')
p=root/dirs[kind]/name; e=effective/dirs[kind]/name
builtin=root/'backups'/'ui-original'/dirs[kind]/name
if op=='read':
 b=e.read_bytes() if e.is_file() else b''
 print(json.dumps({'content':b.decode(),'hash':digest(b),'custom':p.is_file()})); sys.exit()
if op not in ('validate','save','delete','restore'): raise ValueError('Operation invalide')
old=e.read_bytes() if e.is_file() else b''
if q.get('hash') != digest(old): raise ValueError('Le fichier a change depuis son ouverture. Rechargez-le.')
if op=='restore':
 backup=q.get('backup','')
 if not __import__('re').fullmatch(r'[A-Za-z0-9_.-]+',backup): raise ValueError('Sauvegarde invalide')
 manifest=json.loads((root/'backups'/'ui'/backup/'manifest.json').read_text())
 if manifest['kind']!=kind or manifest['name']!=name: raise ValueError('Sauvegarde incompatible')
 content=(root/'backups'/'ui'/backup/'previous').read_bytes() if manifest['existed'] else None
elif op=='delete':
 if not p.is_file(): raise ValueError('Seuls les fichiers personnalises peuvent etre supprimes')
 content=None
else: content=q['content'].encode()
if content is not None:
 if len(content)>131072: raise ValueError('Fichier trop volumineux')
 parse(content)
with tempfile.TemporaryDirectory(prefix='f2b-ui-') as tmp:
 staged=pathlib.Path(tmp)/'config'; shutil.copytree(effective,staged,symlinks=False)
 candidate=staged/dirs[kind]/name
 if content is None:
  if kind!='jail' and builtin.is_file(): candidate.write_bytes(builtin.read_bytes())
  else: candidate.unlink(missing_ok=True)
 else: candidate.write_bytes(content)
 test=subprocess.run(['fail2ban-client','-c',str(staged),'-t'],capture_output=True,text=True,timeout=25)
 if test.returncode==0 and kind=='filter' and content is not None:
  test=subprocess.run(['fail2ban-regex','-c',str(staged),'/dev/null',str(candidate)],capture_output=True,text=True,timeout=20)
 output=(test.stdout+'\n'+test.stderr)[-12000:]
 if test.returncode: print(json.dumps({'ok':False,'output':output})); sys.exit()
 if op=='validate': print(json.dumps({'ok':True,'output':output})); sys.exit()
 custom_old=p.read_bytes() if p.is_file() else None
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')+'-'+kind+'-'+name
 backup=root/'backups'/'ui'/stamp; backup.mkdir(parents=True,mode=0o700)
 (backup/'manifest.json').write_text(json.dumps({'kind':kind,'name':name,'existed':custom_old is not None}))
 if custom_old is not None: (backup/'previous').write_bytes(custom_old)
 link_old=os.readlink(e) if e.is_symlink() else None
 effective_old=e.read_bytes() if e.is_file() and not e.is_symlink() else None
 if kind!='jail' and effective_old is not None and not builtin.exists():
  builtin.parent.mkdir(parents=True,exist_ok=True); builtin.write_bytes(effective_old)
 def install(b):
  if b is None:
   p.unlink(missing_ok=True)
   if kind!='jail':
    e.unlink(missing_ok=True)
    if builtin.is_file(): e.write_bytes(builtin.read_bytes())
  else:
   p.parent.mkdir(parents=True,exist_ok=True)
   temp=p.with_name(p.name+'.ui-tmp'); temp.write_bytes(b); temp.chmod(0o600); os.replace(temp,p)
   if kind!='jail':
    e.unlink(missing_ok=True); e.symlink_to(p)
 try:
  install(content)
  loaded=subprocess.run(['fail2ban-client','reload'],capture_output=True,text=True,timeout=30)
  if loaded.returncode: raise RuntimeError(loaded.stdout+'\n'+loaded.stderr)
 except Exception as error:
  install(custom_old)
  if kind!='jail':
   e.unlink(missing_ok=True)
   if link_old is not None: e.symlink_to(link_old)
   elif builtin.is_file(): e.write_bytes(builtin.read_bytes())
  rollback=subprocess.run(['fail2ban-client','reload'],capture_output=True,text=True,timeout=30)
  print(json.dumps({'ok':False,'output':'Application refusee; fichier restaure. '+str(error),'rollback_ok':rollback.returncode==0,'backup':stamp})); sys.exit()
 print(json.dumps({'ok':True,'output':loaded.stdout+'\n'+loaded.stderr,'backup':stamp}))
'''

def admin_exec(arguments, timeout=35):
    result = subprocess.run(['docker','exec',F2B_CONTAINER,*arguments], capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        raise ValueError((result.stderr+'\n'+result.stdout)[-12000:])
    return result.stdout

def admin_config(payload):
    result = subprocess.run(['docker','exec','-i',F2B_CONTAINER,'python3','-c',CONFIG_TOOL],input=json.dumps(payload),capture_output=True,text=True,timeout=90)
    if result.returncode:
        raise ValueError((result.stderr+'\n'+result.stdout)[-12000:])
    return json.loads(result.stdout)

def invalidate_dashboard():
    with dashboard_lock:
        dashboard_state['generation'] += 1
    dashboard_ready.set()

def admin_jail(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',value):
        raise ValueError('Nom de jail invalide')
    return value

# Persistent contact lookup and mail settings; managed by the existing admin API.
ABUSE_SETTINGS_PATH = os.environ.get('FCP_ABUSE_SETTINGS', '/app/data/abuse-settings.sqlite3')
ABUSE_DEFAULTS = {'webhook_url': '', 'webhook_token': '', 'webhook_events': 'all', 'lookup_enabled': True, 'min_bans': 2, 'window_hours': 24, 'cache_hours': 24, 'retry_minutes': 15, 'smtp_host': '', 'smtp_port': 587, 'smtp_security': 'starttls', 'smtp_username': '', 'smtp_password': '', 'sender': '', 'reply_to': '', 'test_recipient': '', 'subject': 'Abuse report — {ip}', 'message': 'Hello,\n\nWe have observed suspicious activity originating from {ip}.\nAffected protection: {jail}\nDate: {date}\n\nPlease investigate this activity and take appropriate action.\n\nThank you.\n'}

def abuse_settings_read():
    result = dict(ABUSE_DEFAULTS)
    if not os.path.exists(ABUSE_SETTINGS_PATH):
        return result, 0
    with sqlite3.connect(ABUSE_SETTINGS_PATH, timeout=5) as db:
        row = db.execute('SELECT payload, revision FROM settings WHERE id=1').fetchone()
    if row:
        result.update(json.loads(row[0]))
        return result, row[1]
    return result, 0


def abuse_settings_public():
    settings, revision = abuse_settings_read()
    configured = bool(settings.pop('smtp_password'))
    webhook_configured = bool(settings.pop('webhook_token'))
    return {'settings': settings, 'password_configured': configured, 'webhook_token_configured': webhook_configured, 'revision': revision}


def abuse_settings_validate(payload, previous):
    data = dict(previous)
    values = payload.get('settings')
    if not isinstance(values, dict):
        raise ValueError('Paramètres invalides.')
    if set(values) - set(ABUSE_DEFAULTS):
        raise ValueError('Paramètre inconnu.')
    for key, value in values.items():
        if key == 'lookup_enabled':
            if type(value) is not bool: raise ValueError('Activation invalide.')
        elif key in ('min_bans', 'window_hours', 'cache_hours', 'retry_minutes', 'smtp_port'):
            bounds = {'min_bans': (1, 100), 'window_hours': (1, 168), 'cache_hours': (1, 168), 'retry_minutes': (1, 1440), 'smtp_port': (1, 65535)}
            low, high = bounds[key]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{key} doit être compris entre {low} et {high}.')
        else:
            if not isinstance(value, str) or len(value) > (10000 if key == 'message' else 500):
                raise ValueError('Texte invalide ou trop long : ' + key)
            if key not in ('message', 'smtp_password') and any(c in value for c in '\r\n\x00'):
                raise ValueError('Caractère interdit : ' + key)
            if key == 'smtp_security' and value not in ('starttls', 'ssl'):
                raise ValueError('Choisissez STARTTLS ou TLS direct.')
            if key in ('sender', 'reply_to', 'test_recipient') and value and not re.fullmatch(r'[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+', value):
                raise ValueError('Adresse e-mail invalide : ' + key)
            if key == 'smtp_host' and value and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', value):
                raise ValueError('Nom du serveur SMTP invalide.')
            if key == 'webhook_url' and value:
                webhook_validate_url(value)
            if key == 'webhook_events' and value not in ('all', 'bans', 'abuse'):
                raise ValueError('Événements webhook invalides.')
            if key in ('smtp_password', 'webhook_token') and value == '':
                continue  # Empty means preserve; explicit removal is a separate flag.
        data[key] = value
    if payload.get('clear_password') is True:
        data['smtp_password'] = ''
    if payload.get('clear_webhook_token') is True:
        data['webhook_token'] = ''
    import string
    for key in ('subject', 'message'):
        try:
            for _, field, spec, conversion in string.Formatter().parse(data[key]):
                if field is not None and (field not in ('ip', 'jail', 'date') or spec or conversion):
                    raise ValueError('Variables autorisées : {ip}, {jail}, {date}.')
        except ValueError:
            raise ValueError('Modèle invalide. Variables autorisées : {ip}, {jail}, {date}.')
    return data


def abuse_settings_save(payload):
    # Private file, transaction and revision guard also work across Gunicorn workers.
    fd = os.open(ABUSE_SETTINGS_PATH, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    os.chmod(ABUSE_SETTINGS_PATH, 0o600)
    with sqlite3.connect(ABUSE_SETTINGS_PATH, timeout=5) as db:
        db.execute('CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, payload TEXT NOT NULL, revision INTEGER NOT NULL)')
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT payload, revision FROM settings WHERE id=1').fetchone()
        previous = dict(ABUSE_DEFAULTS)
        revision = 0
        if row:
            previous.update(json.loads(row[0])); revision = row[1]
        if payload.get('revision') != revision:
            raise ValueError('Réglages modifiés ailleurs. Rechargez cet onglet avant de réessayer.')
        settings = abuse_settings_validate(payload, previous)
        db.execute('INSERT OR REPLACE INTO settings VALUES (1, ?, ?)', (json.dumps(settings), revision + 1))
    with repeat_lock:
        repeat_snapshot['expires'] = 0
    return {'output': 'Réglages abuse et e-mail enregistrés.', **abuse_settings_public()}



def webhook_validate_url(value):
    from urllib.parse import urlsplit
    parsed = urlsplit(value)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('URL webhook invalide. Utilisez HTTP ou HTTPS sans identifiants ni fragment.')
    try:
        parsed.port
    except ValueError:
        raise ValueError('Port webhook invalide.')


def webhook_send_test():
    from datetime import datetime, timezone
    settings, _ = abuse_settings_read()
    if not settings['webhook_url']:
        raise ValueError('Enregistrez une URL webhook avant le test.')
    webhook_validate_url(settings['webhook_url'])
    payload = {'event': 'test', 'source': 'FCP', 'message': 'FCP webhook configuration test. No ban or abuse report has been sent.', 'timestamp': datetime.now(timezone.utc).isoformat()}
    headers = {'Content-Type': 'application/json', 'User-Agent': 'FCP-Webhook/1.0'}
    if settings['webhook_token']:
        headers['Authorization'] = 'Bearer ' + settings['webhook_token']
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        req = urllib.request.Request(settings['webhook_url'], data=json.dumps(payload).encode(), headers=headers, method='POST')
        with urllib.request.build_opener(NoRedirect).open(req, timeout=10) as response:
            status = response.status
        return {'output': 'Webhook de test accepté (HTTP %s).' % status}
    except urllib.error.HTTPError as error:
        raise ValueError('Webhook refusé (HTTP %s). Vérifiez le destinataire et son authentification.' % error.code)
    except (OSError, ValueError):
        raise ValueError('Connexion webhook impossible. Vérifiez l’URL et le certificat TLS.')

def abuse_smtp_test(send=False):
    import smtplib, ssl
    from email.message import EmailMessage
    settings, _ = abuse_settings_read()
    if not settings['smtp_host']:
        raise ValueError('Enregistrez le serveur SMTP avant le test.')
    if send and (not settings['sender'] or not settings['test_recipient']):
        raise ValueError('Renseignez un expéditeur et un destinataire de test.')
    context = ssl.create_default_context()
    try:
        if settings['smtp_security'] == 'ssl':
            server = smtplib.SMTP_SSL(settings['smtp_host'], settings['smtp_port'], timeout=10, context=context)
        else:
            server = smtplib.SMTP(settings['smtp_host'], settings['smtp_port'], timeout=10)
        with server:
            server.ehlo()
            if settings['smtp_security'] == 'starttls':
                server.starttls(context=context); server.ehlo()
            if settings['smtp_username']:
                server.login(settings['smtp_username'], settings['smtp_password'])
            if send:
                message = EmailMessage()
                message['From'] = settings['sender']; message['To'] = settings['test_recipient']
                message['Subject'] = 'FCP — test de configuration e-mail'
                if settings['reply_to']: message['Reply-To'] = settings['reply_to']
                message.set_content('Ce message confirme le test manuel de la configuration SMTP de FCP. Aucun signalement abuse ne figure dans cet e-mail.')
                server.send_message(message)
    except smtplib.SMTPAuthenticationError:
        raise ValueError('Authentification SMTP refusée. Vérifiez le compte et le mot de passe.')
    except (OSError, smtplib.SMTPException):
        raise ValueError('Connexion SMTP impossible. Vérifiez le serveur, le port et la sécurité TLS.')
    return {'output': 'E-mail de test accepté par le serveur SMTP.' if send else 'Connexion TLS et authentification SMTP réussies. Aucun e-mail envoyé.'}


def ban_map_data():
    """Current bans are authoritative; lifted bans require an explicit Unban event."""
    raw = admin_exec(['fail2ban-client', 'status'])
    match = re.search(r'Jail list:\s*([^\n]+)', raw)
    jails = [x.strip() for x in match.group(1).split(',')] if match else []
    records = {}
    active = set()
    for jail in jails:
        admin_jail(jail)
        for raw_ip in admin_exec(['fail2ban-client', 'get', jail, 'banip']).split():
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue
            active.add((jail, ip))
            records[(jail, ip)] = {'ip': ip, 'jail': jail, 'state': 'banned', 'last_event': ''}
    logs = subprocess.run(['docker', 'logs', '--tail', '5000', F2B_CONTAINER], capture_output=True, text=True, timeout=10, check=True)
    pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*?\[([^]]+)\] (Ban|Unban) (\S+)')
    events = []
    for line in (logs.stdout + '\n' + logs.stderr).splitlines():
        m = pattern.search(line)
        if not m: continue
        date, jail, action, raw_ip = m.groups()
        if jail not in jails: continue
        try: ip = str(ipaddress.ip_address(raw_ip))
        except ValueError: continue
        events.append((date, jail, action, ip))
    for date, jail, action, ip in sorted(events):
        key = (jail, ip)
        records[key] = {'ip': ip, 'jail': jail, 'state': 'banned' if key in active else ('unbanned' if action == 'Unban' else 'history'), 'last_event': date}
    items = []
    ordered = sorted(records.values(), key=lambda r: (r['state'] != 'banned', -int(r['last_event'].replace('-', '').replace(':', '').replace(' ', '') or '0')))
    # Keep every current ban and at most 300 historical records.
    history_count = 0
    for item in ordered:
        if item['state'] != 'banned':
            history_count += 1
            if history_count > 300: continue
        item.update(location=geo_label(item['ip']), network=network_label(item['ip']), latitude=None, longitude=None)
        if ipaddress.ip_address(item['ip']).is_global and geo_reader is not None:
            try:
                with geo_lock:
                    geo = geo_reader.get(item['ip']) or {}
                location = geo.get('location') or {}
                lat, lon = location.get('latitude'), location.get('longitude')
                import math
                if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and math.isfinite(lat) and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180:
                    item.update(latitude=lat, longitude=lon)
            except (OSError, ValueError):
                pass
        items.append(item)
    return {'items': items, 'jails': jails, 'history_limited': history_count > 300, 'output': 'Carte actualisée.'}


AUTOMATION_FILE = str(settings_path())
AUTOMATION_STATE = '/app/automation-state'

def automation_read():
    import hashlib
    with open(AUTOMATION_FILE,'rb') as handle:
        raw = handle.read()
    settings=json.loads(raw)
    states={}
    history=[]
    for kind in ('abuse','abuseipdb'):
        try:
            with open(AUTOMATION_STATE+'/'+kind+'/latest.json') as f: states[kind]=json.load(f)
            with open(AUTOMATION_STATE+'/'+kind+'/state.json') as f: state=json.load(f)
            if kind=='abuse': history=state.get('history',[])[-50:][::-1]
            else: states[kind]['history']=sorted([dict(v,ip=k) for k,v in state.items()],key=lambda x:x.get('submitted_at',0),reverse=True)[:50]
        except (OSError,ValueError): states.setdefault(kind,{'status':'indisponible'})
    try:
        with open(AUTOMATION_STATE+'/latest.txt') as f: report=f.read(100000)
        report_time=os.path.getmtime(AUTOMATION_STATE+'/latest.txt')
    except OSError: report='Rapport indisponible'; report_time=None
    return {'settings':settings,'revision':hashlib.sha256(raw).hexdigest(),'states':states,'history':history,'report':report,'report_time':report_time,'output':'Automatisations actualisées.'}

def automation_save(q):
    import hashlib, fcntl, tempfile
    with open(AUTOMATION_FILE+'.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        current=automation_read()
        if q.get('revision')!=current['revision']: raise ValueError('Réglages modifiés ailleurs : rechargez la page.')
        values=q.get('settings')
        allowed={'email_enabled','abuseipdb_enabled','report_enabled','min_bans','window_hours','cooldown_hours','sender','recipient','subject','message'}
        if not isinstance(values,dict) or set(values)!=allowed: raise ValueError('Réglages incomplets ou inconnus.')
        for key in ('email_enabled','abuseipdb_enabled','report_enabled'):
            if type(values[key]) is not bool: raise ValueError('Activation invalide.')
        for key,lo,hi in [('min_bans',2,100),('window_hours',1,24),('cooldown_hours',24,168)]:
            if type(values[key]) is not int or not lo<=values[key]<=hi: raise ValueError('Seuil hors limites : '+key)
        for key in ('sender','recipient','subject','message'):
            value=values[key]
            optional_address = key in ('sender','recipient') and not (values['email_enabled'] or values['report_enabled'])
            if not isinstance(value,str) or (not value.strip() and not optional_address) or len(value)>5000 or '\x00' in value: raise ValueError('Champ invalide : '+key)
            if key!='message' and ('\n' in value or '\r' in value): raise ValueError('En-tête invalide.')
        for key in ('sender','recipient'):
            if values[key] and not re.fullmatch(r'[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+',values[key]): raise ValueError('Adresse invalide.')
        settings=current['settings'];settings.update(values)
        fd,name=tempfile.mkstemp(prefix='.automation-',dir=os.path.dirname(AUTOMATION_FILE))
        try:
            with os.fdopen(fd,'w') as f:
                json.dump(settings,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
            owner=os.stat(AUTOMATION_FILE);os.chown(name,owner.st_uid,owner.st_gid)
            os.chmod(name,0o600);os.replace(name,AUTOMATION_FILE)
        finally:
            if os.path.exists(name): os.unlink(name)
    result=automation_read();result['output']='Réglages appliqués aux prochaines exécutions planifiées.';return result

@app.route('/manage')
def management_page():
    html = ADMIN_HTML.replace('__TOKEN__',admin_token)
    if request.args.get('embedded') == '1':
        html = html.replace('</head>', '<style>header,main>nav{display:none!important}body:has(main){padding:0!important;min-height:0}main{padding:0!important;max-width:none}.card{margin:14px 0}#message{position:static}</style></head>', 1)
        html = html.replace('</body>', '<script>function sendHeight(){parent.postMessage({type:"fail2ban-admin-height",height:Math.ceil(document.body.getBoundingClientRect().height)+24},location.origin);}new ResizeObserver(sendHeight).observe(document.body);window.addEventListener("load",()=>{sendHeight();parent.postMessage({type:"fcp-admin-ready"},location.origin);});</script></body>', 1)
    return html

@app.route('/admin/api',methods=['POST'])
def administration():
    if request.headers.get('X-Fail2ban-Token') != admin_token:
        return jsonify(error='Rechargez la page de gestion.'),403
    origin=request.headers.get('Origin')
    if origin and urlsplit(origin).netloc != request.host:
        return jsonify(error='Origine refusee.'),403
    q=request.get_json(silent=True)
    if not isinstance(q,dict):
        return jsonify(error='Requete invalide'),400
    try:
        op=q.get('op')
        if op=='automation_read': return jsonify(automation_read())
        if op=='automation_save': return jsonify(automation_save(q))
        if op=='abuse_settings_read': return jsonify(abuse_settings_public())
        if op=='abuse_settings_save': return jsonify(abuse_settings_save(q))
        if op=='webhook_test':
            if q.get('confirm') is not True: raise ValueError('Confirmation requise.')
            return jsonify(webhook_send_test())
        if op=='abuse_smtp_test': return jsonify(abuse_smtp_test())
        if op=='abuse_smtp_send_test':
            if q.get('confirm') is not True: raise ValueError('Confirmation requise.')
            return jsonify(abuse_smtp_test(send=True))
        if op=='ban_map_data': return jsonify(ban_map_data())
        if op=='overview':
            return jsonify(status=admin_exec(['fail2ban-client','status','--all']),version=admin_exec(['fail2ban-client','version']).strip(),files=admin_config({'op':'inventory'}))
        if op=='read': return jsonify(admin_config(q))
        if op=='logs':
            result=subprocess.run(['docker','logs','--tail','300',F2B_CONTAINER],capture_output=True,text=True,timeout=10)
            return jsonify(output=(result.stdout+'\n'+result.stderr)[-100000:])
        if op=='backups':
            code="import pathlib,json; p=pathlib.Path('/data/backups/ui'); print(json.dumps([{'id':x.name,**json.loads((x/'manifest.json').read_text())} for x in sorted(p.iterdir(),reverse=True) if (x/'manifest.json').is_file()][:100] if p.exists() else []))"
            return jsonify(items=json.loads(admin_exec(['python3','-c',code])))
        if op=='jail':
            jail=admin_jail(q.get('jail'))
            fields=('maxretry','findtime','bantime','ignoreip','banip','actions','logpath','failregex','ignoreregex')
            def field(name):
                try: return admin_exec(['fail2ban-client','get',jail,name])
                except ValueError as error: return str(error)
            with ThreadPoolExecutor(max_workers=4) as pool:
                values=dict(zip(fields,pool.map(field,fields)))
            return jsonify(values=values,status=admin_exec(['fail2ban-client','status',jail]))
        with admin_mutation_lock:
            if op=='help': return jsonify(output=admin_exec(['fail2ban-client','--help']))
            if op=='client_command':
                import shlex
                command=q.get('command','')
                if not isinstance(command,str) or len(command)>2000 or q.get('confirm')!='COMMANDE': raise ValueError('Commande ou confirmation invalide')
                args=shlex.split(command)
                allowed={'start','restart','reload','stop','unban','banned','status','stats','statistic','statistics','ping','version','echo','set','get','add','flushlogs','-t','-d','--dp'}
                if not args or args[0] not in allowed or len(args)>64: raise ValueError('Commande Fail2ban non prise en charge')
                result=admin_exec(['fail2ban-client',*args],timeout=45)
                invalidate_dashboard()
                return jsonify(ok=True,output=result)
            if op=='service':
                command=q.get('command')
                if command not in ('start','stop','restart') or q.get('confirm')!='SERVICE': raise ValueError('Commande ou confirmation invalide')
                r=subprocess.run(['docker',command,F2B_CONTAINER],capture_output=True,text=True,timeout=45)
                if r.returncode: raise ValueError(r.stderr)
                invalidate_dashboard()
                return jsonify(ok=True,output=r.stdout)
            if op in ('validate','save','delete','restore'):
                result=admin_config(q)
                if result.get('ok') and op!='validate': invalidate_dashboard()
                return jsonify(result)
            if op=='test': return jsonify(ok=True,output=admin_exec(['fail2ban-client','-t']))
            if op=='reload':
                admin_exec(['fail2ban-client','-t'])
                result=admin_exec(['fail2ban-client','reload'])
            elif op in ('ban','unban'):
                jail=admin_jail(q.get('jail')); ip=str(ipaddress.ip_address(q.get('ip','')))
                result=admin_exec(['fail2ban-client','set',jail,'banip' if op=='ban' else 'unbanip',ip])
            elif op=='unban_all':
                if q.get('confirm')!='DEBANNIR': raise ValueError('Confirmation requise')
                result=admin_exec(['fail2ban-client','unban','--all'])
            elif op=='restart_jail':
                jail=admin_jail(q.get('jail'))
                admin_exec(['fail2ban-client','-t'])
                result=admin_exec(['fail2ban-client','reload','--restart',jail])
            elif op=='regex':
                kind=q.get('kind'); name=q.get('name')
                if kind!='filter' or not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.(conf|local)',name): raise ValueError('Filtre invalide')
                sample=q.get('sample','')
                if not isinstance(sample,str) or len(sample)>50000: raise ValueError('Echantillon trop volumineux')
                code="import sys,tempfile,subprocess; sample=sys.stdin.read(); f=tempfile.NamedTemporaryFile(mode='w',suffix='.log'); f.write(sample); f.flush(); r=subprocess.run(['fail2ban-regex',f.name,sys.argv[1]],capture_output=True,text=True,timeout=15); print(r.stdout+r.stderr); sys.exit(r.returncode)"
                r=subprocess.run(['docker','exec','-i',F2B_CONTAINER,'python3','-c',code,'/etc/fail2ban/filter.d/'+name],input=sample,capture_output=True,text=True,timeout=20)
                return jsonify(ok=r.returncode==0,output=(r.stdout+r.stderr)[-15000:])
            else: raise ValueError('Operation inconnue')
            invalidate_dashboard()
            return jsonify(ok=True,output=result)
    except (ValueError,TypeError,OSError,subprocess.SubprocessError) as error:
        return jsonify(error=str(error)[-12000:]),400

ADMIN_HTML = r'''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Administration Fail2ban</title><style>
:root{color-scheme:dark;font-family:system-ui;background:#0b111b;color:#e6edf6}body{margin:0}header{padding:26px max(24px,calc((100vw - 1200px)/2));background:#132034;border-bottom:1px solid #30415a}header a{color:#92caff}h1{margin:10px 0;font-size:28px}main{max-width:1200px;margin:auto;padding:24px}nav{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px}button,a.button{background:#23476d;color:#fff;border:1px solid #466888;border-radius:8px;padding:10px 16px;cursor:pointer;text-decoration:none}button:hover{background:#315d89}button.danger{background:#6d2835}button:disabled{opacity:.5;cursor:wait}.card{background:#131e2d;border:1px solid #30415a;padding:22px;border-radius:12px;margin:14px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}label{display:block;color:#b6c7db;margin:12px 0 6px}input,select,textarea{box-sizing:border-box;background:#0b1420;color:#e6edf6;border:1px solid #425673;border-radius:7px;padding:10px;width:100%;font:inherit}textarea.code{font-family:ui-monospace,monospace;min-height:340px;white-space:pre;tab-size:4}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1420;padding:16px;border-radius:8px;max-height:480px;overflow:auto}small,.muted{color:#a2b5cb}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row select,.row input{width:auto;flex:1;min-width:150px}#message{position:sticky;top:0;z-index:1;border-radius:8px;background:#1c3750;padding:12px;white-space:pre-wrap;max-height:260px;overflow:auto}#message:empty{display:none}.active{background:#3877b0}section[hidden]{display:none}.badge{background:#20445d;padding:4px 9px;border-radius:20px}h2{font-size:20px;margin-top:0}/* FCP — thème adapté de Visio Display, Eric TOMAS; Apache-2.0 avec autorisation du détenteur des droits. */
:root{color-scheme:light;--bg:#edf2ff;--card:rgba(255,255,255,.62);--accent:#4f46e5;--danger:#dc2626;--text:#132032;--border:#d8e1f2;--muted:#42506b;--radius:22px;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--text);background:var(--bg)}
body{font-family:inherit;color:var(--text);background:radial-gradient(ellipse at 15% 0%,rgba(79,70,229,.18),transparent 55%),radial-gradient(ellipse at 95% 20%,rgba(14,165,233,.13),transparent 55%),var(--bg);padding:28px 28px 28px 264px;min-height:100vh;line-height:1.55}
.container{max-width:1600px;margin:auto;background:transparent;box-shadow:none;overflow:visible;border-radius:0}
.header,header{background:linear-gradient(135deg,#172554,#312e81 45%,#0f766e);border:1px solid rgba(255,255,255,.35);border-radius:24px;color:#fff;padding:30px 32px;text-align:left;box-shadow:0 18px 42px rgba(15,23,42,.12)}
.header h1,header h1{font-weight:750;letter-spacing:-.04em;font-size:34px;margin:0 0 6px}.header p,header p{color:#dbe4ff}header a{color:#fff}
.display-controls{position:fixed;inset:0 auto 0 0;width:236px;background:#081222;border-right:1px solid rgba(255,255,255,.08);padding:30px 16px;display:block;z-index:10;overflow:auto}
.display-controls:before{content:'FCP';display:block;color:#eef2ff;font-size:27px;font-weight:750;letter-spacing:-.04em;padding:0 12px 4px}
.tabs{display:flex;flex-direction:column;align-items:stretch;gap:8px;margin-top:26px}.display-controls button{background:transparent;border:1px solid transparent;color:#95a4c7;text-align:left;padding:12px 14px;border-radius:12px;font:inherit;font-size:14px}.display-controls button:hover{background:rgba(129,140,248,.12);color:#dbe4ff}.tabs button[aria-selected="true"]{background:rgba(99,102,241,.22);border-color:rgba(129,140,248,.24);color:#fff}
.stats-grid{padding:24px 0;gap:22px}.card{background:var(--card);border:1px solid rgba(255,255,255,.82);border-radius:var(--radius);padding:26px;box-shadow:0 14px 38px rgba(15,23,42,.09),inset 0 1px 0 rgba(255,255,255,.96);backdrop-filter:blur(30px) saturate(1.35)}
.card h3,.section-title{color:#312e81}.note,.muted,small,.subline,.legend,.empty-state,label{color:var(--muted)}.note{font-size:13px}.subline{font-size:11px}.path code{color:#42506b}.method{color:#4f46e5}
.metric{background:rgba(255,255,255,.56);border:1px solid var(--border);border-radius:16px;box-shadow:0 4px 15px rgba(15,23,42,.04)}.metric strong{color:#312e81;font-weight:750}.metric small{color:var(--muted)}.metric.red{border-color:#f0bfc5}.metric.amber{border-color:#f4d8b5}
button,a.button,.toolbar button,#geo-update{font:inherit;font-size:13px;background:rgba(255,255,255,.78);color:#312e81;border:1px solid #c5d2ea;border-radius:12px;padding:10px 16px;cursor:pointer;transition:background .18s,box-shadow .18s}
button:hover,a.button:hover{background:#e7e9ff;box-shadow:0 4px 14px rgba(79,70,229,.12)}button:disabled{opacity:.5;cursor:default}button.danger,.ip-btn{background:#fff1f2;color:#b91c1c;border:1px solid #fecdd3}.ip-btn:hover,button.danger:hover{background:#ffe4e6}
input,select,textarea,.toolbar input,.toolbar select{font:inherit;background:rgba(255,255,255,.78);color:var(--text);border:1px solid #c5d2ea;border-radius:12px;padding:10px 12px}input:focus,select:focus,textarea:focus{outline:3px solid rgba(79,70,229,.14);border-color:#8b8cff}button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #8b8cff;outline-offset:3px}
pre{background:#f4f7ff;color:#132032;border:1px solid var(--border);border-radius:14px}.table-wrap{border:1px solid var(--border);border-radius:14px}th{background:#e7e9ff;color:#312e81;font-weight:650}th,td{border-bottom:1px solid var(--border);padding:13px 14px}tbody tr:nth-child(even){background:rgba(244,247,255,.68)}tbody tr:hover{background:#e7e9ff}
.badge{background:#e7e9ff;color:#312e81;border-radius:8px}.badge.auth{background:#ffe4e6;color:#9f1239}.badge.server{background:#ede9fe;color:#5b21b6}.badge.missing{background:#fef3c7;color:#92400e}.badge.other{background:#e0f2fe;color:#075985}.abuse-result a,#geo-note a{color:#4f46e5!important}
#geo-note{padding:20px 12px!important;margin:8px 0 0}.refresh{position:static;margin:0 0 20px auto;display:block;width:max-content;background:#4f46e5;color:#fff;border-radius:12px;box-shadow:0 8px 24px rgba(79,70,229,.2);font-size:12px;font-weight:650}
#administration-panel{margin-top:24px}main{max-width:1600px;padding:24px 0;margin:auto}nav{gap:8px}nav button.active{background:#4f46e5;color:#fff;border-color:#4f46e5}#message{background:#e7e9ff;color:#312e81;border:1px solid #c5d2ea;border-radius:12px}body:has(main){padding:28px}body:has(main):has(header[hidden]){padding:12px}
@media(max-width:900px){body{padding:18px}.display-controls{position:static;width:auto;border-radius:18px;margin-top:18px;padding:14px}.display-controls:before,.display-controls:after{display:none}.tabs{flex-direction:row;margin:0;gap:6px}.display-controls button{flex:1;text-align:center;padding:10px;font-size:12px}.stats-grid{gap:16px}.header,header{padding:24px}.refresh{margin-left:auto}}
@media(max-width:600px){body,body:has(main){padding:12px}.header h1{font-size:28px}.stats-grid{grid-template-columns:minmax(0,1fr)}.card{padding:18px;border-radius:18px}.tabs button{flex:1 1 40%}.toolbar input{min-width:0;width:100%}.header p{font-size:13px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}


.grid{grid-template-columns:repeat(3,minmax(0,1fr));gap:22px 20px;align-items:start}.grid>div{min-width:0}.grid>div>label:first-child{min-height:3.1em;margin:0 0 8px;display:flex;align-items:flex-end;line-height:1.5}.grid input:not([type=checkbox]),.grid select{width:100%;height:46px;min-height:46px;box-sizing:border-box}.grid select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='m4 6 4 4 4-4' fill='none' stroke='%2342506b' stroke-width='1.5'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:36px}.grid small{display:block;margin-top:7px;line-height:1.45}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:600px){.grid{grid-template-columns:minmax(0,1fr)}.grid>div>label:first-child{min-height:0}}
</style></head><body><header><a href="/">← Tableau de bord</a><h1>Administration Fail2ban</h1><p>Gestion persistante des protections, filtres et actions.</p></header><main><div id="message" role="status" aria-live="polite"></div><nav><button data-tab="overview">État du service</button><button data-tab="jails">Jails</button><button data-tab="files">Filtres et actions</button><button data-tab="logs">Journaux</button><button data-tab="backups">Sauvegardes</button><button data-tab="abuse-settings">Automatisations et e-mails</button><button data-tab="advanced">Fonctions avancées</button></nav>
<section id="overview"><div class="card"><h2>Fail2ban — version <span id="version" class="badge"></span></h2><div class="row"><button id="refresh">Actualiser</button><button id="test">Tester la configuration</button><button id="reload">Appliquer la configuration</button><button id="all" class="danger">Débannir toutes les IP</button></div><p id="servicesummary">Chargement…</p><details><summary>Détails techniques du service</summary><div class="row" style="margin-top:12px"><button data-service="start">Démarrer Fail2ban</button><button class="danger" data-service="restart">Redémarrer Fail2ban</button><button class="danger" data-service="stop">Arrêter Fail2ban</button></div><pre id="service"></pre></details><p class="muted">L’application recharge les protections sans redémarrer le conteneur. Les bans manuels suivent la durée définie par chaque jail.</p></div></section>
<section id="jails" hidden><div class="card"><h2>Gérer les jails</h2><div class="row"><select id="jailfile"></select><button id="openjail">Ouvrir</button><button id="newjail">Créer une jail</button></div><p class="muted">Les changements sont sauvegardés, testés puis appliqués. Désactiver une jail retire sa protection et peut lever ses bans.</p></div><div class="card" id="jailpanel" hidden><h2 id="jailtitle"></h2><div class="grid"><div><label for="jailname">Nom de la jail</label><input id="jailname"></div><div><label for="enabled">Protection</label><select id="enabled"><option value="true">Activée</option><option value="false">Désactivée</option></select></div><div><label for="filter">Filtre</label><input id="filter" list="filterlist"><datalist id="filterlist"></datalist></div><div><label for="backend">Lecture des journaux</label><select id="backend"><option>polling</option><option>auto</option><option>systemd</option></select></div><div><label for="maxretry">Échecs avant ban</label><input id="maxretry" type="number" min="1"></div><div><label for="findtime">Fenêtre de détection</label><input id="findtime" placeholder="10m"></div><div><label for="bantime">Durée du ban</label><input id="bantime" placeholder="1h"></div><div><label for="port">Ports</label><input id="port"></div></div><label for="logpath">Journaux surveillés (un chemin par ligne)</label><textarea id="logpath" rows="3"></textarea><label for="ignoreip">Adresses et réseaux exclus</label><input id="ignoreip"><label for="action">Actions exécutées lors du ban</label><textarea id="action" rows="3"></textarea><div class="row" style="margin-top:16px"><button id="savejail">Enregistrer et appliquer</button><button id="validatejail">Tester sans enregistrer</button><button id="restartjail">Recharger cette jail</button><button id="deletejail" class="danger">Supprimer ce fichier</button></div><details><summary style="margin-top:16px">Configuration complète et options avancées</summary><p class="muted">Durées progressives, DNS, regex, paramètres d’action et autres options Fail2ban. L’éditeur conserve les options non présentes dans le formulaire.</p><textarea id="jailraw" class="code"></textarea><button id="saveraw">Enregistrer l’éditeur complet</button></details><h3>État et paramètres actifs</h3><p id="jailsummary"></p><details><summary>Détails techniques et paramètres actifs</summary><pre id="jailstatus"></pre></details><div class="row"><input id="ip" placeholder="Adresse IPv4 ou IPv6"><button id="ban">Bannir</button><button id="unban">Débannir</button><button id="jailrefresh">Actualiser l’état</button></div></div></section>
<section id="files" hidden><div class="card"><h2>Filtres et actions</h2><div class="row"><select id="kind"><option value="filter">Filtres</option><option value="action">Actions</option></select><select id="filename"></select><button id="openfile">Ouvrir</button><button id="newfile">Créer</button></div><label for="editname">Nom du fichier</label><input id="editname" placeholder="mon-filtre.conf"><p class="muted">Les actions exécutent des commandes sur le serveur : vérifiez leur contenu avant application.</p><textarea id="content" class="code"></textarea><div class="row"><button id="validatefile">Tester la configuration</button><button id="savefile">Enregistrer et appliquer</button><button id="deletefile" class="danger">Supprimer la personnalisation</button></div><div id="regexbox"><label for="sample">Tester ce filtre sur un extrait de journal</label><textarea id="sample" rows="5" placeholder="Collez quelques lignes de journal ici"></textarea><button id="regex">Tester les correspondances</button><pre id="regexresult"></pre></div></div></section>
<section id="logs" hidden><div class="card"><h2>Journal Fail2ban</h2><button id="logrefresh">Actualiser</button><pre id="logtext"></pre></div></section>
<section id="backups" hidden><div class="card"><h2>Sauvegardes de configuration</h2><p class="muted">Chaque modification conserve la version précédente. Restaurer teste puis applique cette version.</p><button id="backuprefresh">Actualiser</button><div id="backuplist"></div></div></section>
<section id="abuse-settings" hidden><div class="card"><h2>Envois automatiques existants</h2><p>Les signalements utilisent Postfix directement, sans webhook. Contrôle toutes les 5 minutes ; rapport quotidien à 08 h, heure configurée. Les historiques et les protections contre les doublons sont conservés.</p><div class="grid">
<div><label>Signalements par e-mail</label><select id="auto-email_enabled"><option value="true">Activés</option><option value="false">Désactivés</option></select></div>
<div><label>Signalements AbuseIPDB</label><select id="auto-abuseipdb_enabled"><option value="true">Activés</option><option value="false">Désactivés</option></select><small>La clé reste dans le fichier privé de configuration et n’est pas exposée ici.</small></div>
<div><label>Rapport quotidien par e-mail</label><select id="auto-report_enabled"><option value="true">Activé</option><option value="false">Désactivé</option></select></div>
<div><label>Bannissements distincts avant signalement</label><input id="auto-min_bans" type="number" min="2" max="100"></div>
<div><label>Fenêtre de récidive (heures)</label><input id="auto-window_hours" type="number" min="1" max="24"></div>
<div><label>Délai entre signalements d’une IP (heures)</label><input id="auto-cooldown_hours" type="number" min="24" max="168"></div>
<div><label>Expéditeur Postfix</label><input id="auto-sender" type="email"></div><div><label>Destinataire du rapport et adresse de réponse</label><input id="auto-recipient" type="email"></div></div>
<label>Objet du signalement en anglais · variable {ip}</label><input id="auto-subject"><label>Introduction du signalement en anglais</label><textarea id="auto-message" rows="4"></textarea><p class="muted">Les preuves techniques filtrées et leur pièce jointe sont ajoutées automatiquement. Les réponses HTTP 401/403 seules ne suffisent pas. Aucun renvoi d’ancien signalement lors d’une sauvegarde.</p><button id="auto-save">Enregistrer les automatisations</button> <button id="auto-refresh">Actualiser l’état</button><h3>État des derniers contrôles</h3><pre id="auto-status"></pre><h3>Derniers signalements par e-mail</h3><div id="auto-history"></div><h3>Derniers signalements AbuseIPDB</h3><div id="auto-ipdb"></div><details><summary>Dernier rapport quotidien</summary><pre id="auto-report" style="white-space:pre-wrap"></pre></details></div>
<details><summary>Réglages auxiliaires et tests (facultatif)</summary><div class="card"><h2>Réglages auxiliaires</h2><p class="muted">Réglages auxiliaires : recherche RDAP de l’interface et tests SMTP. Les envois réels sont pilotés par les automatisations ci-dessus.</p><h3>Recherche des contacts</h3><div class="grid"><div><label for="ab-lookup_enabled">Recherche RDAP</label><select id="ab-lookup_enabled"><option value="true">Activée</option><option value="false">Désactivée</option></select></div><div><label for="ab-min_bans">Bans distincts avant recherche</label><input id="ab-min_bans" type="number" min="1" max="100"></div><div><label for="ab-window_hours">Fenêtre de récidive (heures)</label><input id="ab-window_hours" type="number" min="1" max="168"></div><div><label for="ab-cache_hours">Conservation du résultat (heures)</label><input id="ab-cache_hours" type="number" min="1" max="168"></div><div><label for="ab-retry_minutes">Nouvel essai après erreur (minutes)</label><input id="ab-retry_minutes" type="number" min="1" max="1440"></div></div><p class="muted">Seules les IP publiques sont recherchées. La fenêtre dépend des journaux disponibles, dans la limite des 10 000 dernières lignes. Seule l’IP est transmise au service RDAP.</p><h3>SMTP de test (distinct de Postfix)</h3><div class="grid"><div><label for="ab-smtp_host">Serveur SMTP</label><input id="ab-smtp_host" autocomplete="off" placeholder="smtp.exemple.fr"></div><div><label for="ab-smtp_port">Port</label><input id="ab-smtp_port" type="number" min="1" max="65535"></div><div><label for="ab-smtp_security">Sécurité</label><select id="ab-smtp_security"><option value="starttls">STARTTLS (souvent 587)</option><option value="ssl">TLS direct (souvent 465)</option></select></div><div><label for="ab-smtp_username">Identifiant SMTP</label><input id="ab-smtp_username" autocomplete="off"></div><div><label for="ab-smtp_password">Mot de passe SMTP</label><input id="ab-smtp_password" type="password" autocomplete="new-password" placeholder="Laisser vide pour conserver"><small id="ab-password-status"></small><label><input id="ab-clear-password" type="checkbox" style="width:auto"> Supprimer le mot de passe enregistré</label></div><div><label for="ab-sender">Adresse expéditrice</label><input id="ab-sender" type="email"></div><div><label for="ab-reply_to">Adresse de réponse (facultative)</label><input id="ab-reply_to" type="email"></div><div><label for="ab-test_recipient">Destinataire de test</label><input id="ab-test_recipient" type="email"></div></div><h3>Webhook facultatif — test uniquement</h3><p class="muted">Destination des événements de bannissement, débannissement et des signalements abuse. La configuration est enregistrée ici ; la diffusion automatique reste à raccorder. Le test envoie uniquement un événement fictif en anglais.</p><div class="grid"><div><label for="ab-webhook_url">URL du webhook</label><input id="ab-webhook_url" type="url" autocomplete="off" placeholder="https://exemple.fr/webhook"></div><div><label for="ab-webhook_events">Événements à transmettre</label><select id="ab-webhook_events"><option value="all">Tout : bans, débannissements et abuse</option><option value="bans">Bannissements et débannissements</option><option value="abuse">Signalements abuse</option></select></div><div><label for="ab-webhook_token">Jeton Bearer (facultatif)</label><input id="ab-webhook_token" type="password" autocomplete="new-password" placeholder="Laisser vide pour conserver"><small id="ab-webhook-token-status"></small><label><input id="ab-clear-webhook-token" type="checkbox" style="width:auto"> Supprimer le jeton enregistré</label></div></div><p class="muted">Format : POST JSON. Le jeton reste masqué après sauvegarde. Les redirections sont refusées.</p><button id="ab-webhook-test">Envoyer un événement de test</button><h3>Ancien modèle auxiliaire (non utilisé par les automatismes)</h3><p class="muted">Variables disponibles : {ip}, {jail}, {date}. Le modèle est enregistré pour préparer les signalements ; aucun envoi automatique n’est activé.</p><label for="ab-subject">Objet</label><input id="ab-subject"><label for="ab-message">Message</label><textarea id="ab-message" rows="8"></textarea><div class="row" style="margin-top:18px"><button id="ab-save">Enregistrer les réglages</button><button id="ab-reload">Recharger</button><button id="ab-test">Tester la connexion SMTP</button><button id="ab-send-test">Envoyer un e-mail de test</button></div><p class="muted">Les tests utilisent les réglages enregistrés. Le mot de passe reste masqué après sauvegarde. Utilisez l’accès HTTPS habituel pour saisir vos identifiants.</p></div></details></section>
<section id="advanced" hidden><div class="card"><h2>Toutes les commandes Fail2ban</h2><p>Accès aux réglages du service, de la base, des actions et aux autres fonctions disponibles dans cette version.</p><p class="muted">Les changements effectués ici agissent sur le service en cours et peuvent être temporaires. Pour conserver les réglages des jails, utilisez les onglets de configuration. Une commande peut interrompre la protection ou lever des bans.</p><button id="clienthelp">Afficher les commandes disponibles</button><pre id="helptext" hidden></pre><label for="command">Commande Fail2ban, sans le préfixe fail2ban-client</label><input id="command" placeholder="Exemple : get dbpurgeage"><button id="clientrun" style="margin-top:12px">Exécuter</button><pre id="commandresult"></pre></div></section></main><script>
const token='__TOKEN__', el=id=>document.getElementById(id);let inventory={}, jf=null,ff=null;
async function api(q){const r=await fetch('/admin/api',{method:'POST',headers:{'Content-Type':'application/json','X-Fail2ban-Token':token},body:JSON.stringify(q)});const d=await r.json();if(!r.ok||d.error||d.ok===false)throw Error(d.error||d.output||'Opération refusée');return d;}
let adminNavigationPending=null;
function flushAdminNavigation(){if(!adminNavigationPending)return;const b=document.querySelector('nav button[data-tab="'+adminNavigationPending+'"]');if(b&&!b.disabled){adminNavigationPending=null;b.click();}}
window.addEventListener('message',event=>{if(event.origin!==location.origin||event.source!==parent||event.data?.type!=='fcp-admin-navigate')return;if(!['overview','jails','files','logs','backups','abuse-settings','advanced'].includes(event.data.section))return;adminNavigationPending=event.data.section;flushAdminNavigation();});
async function run(fn){document.querySelectorAll('button').forEach(b=>b.disabled=true);try{el('message').textContent='Opération en cours…';let d=await fn();el('message').textContent=d?.output||'Terminé.';if(d?.backup)el('message').textContent+='\nSauvegarde : '+d.backup;return d;}catch(e){el('message').textContent=e.message;}finally{document.querySelectorAll('button').forEach(b=>b.disabled=false);flushAdminNavigation();}}
let abuseRevision=0;
const autoFields=['email_enabled','abuseipdb_enabled','report_enabled','min_bans','window_hours','cooldown_hours','sender','recipient','subject','message'];let autoRevision=null;
function autoDate(v){return v?new Date(v*1000).toLocaleString('fr-FR',{timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone}):'indisponible';}
const autoLabels={submitted:'Remis au service d’envoi',uncertain:'Confirmation incertaine : renvoi bloqué',rejected:'Refusé',disabled:'Désactivé',ready:'Prêt',insufficient_evidence:'Preuves insuffisantes',manual_required:'Traitement manuel requis',no_contact:'Contact absent'};
function autoRows(id,rows){const target=el(id);target.replaceChildren();if(!rows.length){target.textContent='Aucun signalement enregistré.';return;}for(const r of rows){const p=document.createElement('p');p.textContent=[r.ip,autoLabels[r.status]||r.status,autoDate(r.submitted_at),(r.contacts||[]).join(', ')].filter(Boolean).join(' · ');target.append(p);}}
async function loadAutomation(){const d=await api({op:'automation_read'});autoRevision=d.revision;for(const k of autoFields)el('auto-'+k).value=String(d.settings[k]);let lines=[];for(const [k,label] of [['abuse','E-mails abuse'],['abuseipdb','AbuseIPDB']]){const s=d.states[k]||{};lines.push(label+' : dernier contrôle '+autoDate(s.checked_at)+' · '+(autoLabels[s.status]||((s.enabled===false)?'Désactivé':'Contrôle effectué'))+' · '+(s.submitted||0)+' remis lors du dernier contrôle'+((s.errors||[]).length?' · '+s.errors.length+' erreur(s)':''));if(s.checked_at&&Date.now()/1000-s.checked_at>900)lines.push('Attention : ce contrôle date de plus de 15 minutes.');}lines.push('Rapport généré : '+autoDate(d.report_time));el('auto-status').textContent=lines.join('\n');autoRows('auto-history',d.history);autoRows('auto-ipdb',d.states.abuseipdb?.history||[]);el('auto-report').textContent=d.report;return {output:d.output};}
el('auto-refresh').onclick=()=>run(loadAutomation);el('auto-save').onclick=()=>run(async()=>{const settings={};for(const k of autoFields){let v=el('auto-'+k).value;if(k.endsWith('_enabled'))v=v==='true';else if(['min_bans','window_hours','cooldown_hours'].includes(k))v=Number(v);settings[k]=v;}const d=await api({op:'automation_save',revision:autoRevision,settings});await loadAutomation();return d;});

const abuseFields=['webhook_url','webhook_events','lookup_enabled','min_bans','window_hours','cache_hours','retry_minutes','smtp_host','smtp_port','smtp_security','smtp_username','sender','reply_to','test_recipient','subject','message'];
function applyAbuse(d){abuseRevision=d.revision;for(const key of abuseFields)el('ab-'+key).value=String(d.settings[key]);el('ab-webhook_token').value='';el('ab-clear-webhook-token').checked=false;el('ab-webhook-token-status').textContent=d.webhook_token_configured?'Jeton enregistré.':'Aucun jeton enregistré.';el('ab-smtp_password').value='';el('ab-clear-password').checked=false;el('ab-password-status').textContent=d.password_configured?'Mot de passe enregistré.':'Aucun mot de passe enregistré.';}
async function loadAbuse(){const d=await api({op:'abuse_settings_read'});applyAbuse(d);return {output:'Réglages abuse et e-mail chargés.'};}
el('ab-reload').onclick=()=>run(loadAbuse);
el('ab-save').onclick=()=>run(async()=>{const settings={};for(const key of abuseFields){let value=el('ab-'+key).value;if(key==='lookup_enabled')value=value==='true';else if(['min_bans','window_hours','cache_hours','retry_minutes','smtp_port'].includes(key))value=Number(value);settings[key]=value;}settings.webhook_token=el('ab-webhook_token').value;settings.smtp_password=el('ab-smtp_password').value;const d=await api({op:'abuse_settings_save',revision:abuseRevision,settings,clear_webhook_token:el('ab-clear-webhook-token').checked,clear_password:el('ab-clear-password').checked});applyAbuse(d);return d;});
el('ab-webhook-test').onclick=()=>run(async()=>{const d=await api({op:'abuse_settings_read'});if(!d.settings.webhook_url)throw Error('Enregistrez une URL webhook.');if(!confirm('Envoyer un événement de test à '+d.settings.webhook_url+' ?'))return {output:'Test annulé.'};return api({op:'webhook_test',confirm:true});});
el('ab-test').onclick=()=>run(()=>api({op:'abuse_smtp_test'}));
el('ab-send-test').onclick=()=>run(async()=>{const d=await api({op:'abuse_settings_read'});if(!d.settings.test_recipient)throw Error('Enregistrez un destinataire de test.');if(!confirm('Envoyer un e-mail de test à '+d.settings.test_recipient+' avec les réglages enregistrés ?'))return {output:'Envoi annulé.'};return api({op:'abuse_smtp_send_test',confirm:true});});

function options(id,files){let s=el(id),previous=s.value;s.replaceChildren();for(const f of files){let o=document.createElement('option');o.value=f.name;o.textContent=f.name+(f.custom?' · personnalisé':' · fourni par Fail2ban');s.append(o);}if([...s.options].some(o=>o.value===previous))s.value=previous;}
async function overview(){el('servicesummary').textContent='État du service : vérification en cours…';let d;try{d=await api({op:'overview'});}catch(e){el('servicesummary').textContent='État du service : indisponible (arrêté ou inaccessible).';throw e;}inventory=d.files;el('service').textContent=d.status;let jailMatch=d.status.match(/Jail list:\s*([^\n]+)/);el('servicesummary').textContent='État du service : actif. Protections actives : '+(jailMatch?jailMatch[1].trim():'aucune')+'.';el('version').textContent=d.version;options('jailfile',inventory.jail);fileOptions();el('filterlist').replaceChildren();for(let f of inventory.filter){let o=document.createElement('option');o.value=f.name.replace(/\.(conf|local)$/,'');el('filterlist').append(o);}return {output:'État actualisé.'};}
function fileOptions(){options('filename',inventory[el('kind').value]||[]);el('regexbox').hidden=el('kind').value!=='filter';}
const fields=['enabled','filter','backend','maxretry','findtime','bantime','port','logpath','ignoreip','action'];
function readSection(text,name){let result={},section='';let lines=text.split('\n');for(let i=0;i<lines.length;i++){let line=lines[i],m=line.match(/^\s*\[([^\]]+)\]/);if(m){section=m[1];continue;}if(section!==name)continue;m=line.match(/^([\w.-]+)\s*=\s*(.*)$/);if(m){let value=m[2];while(i+1<lines.length&&/^\s+\S/.test(lines[i+1])&&!/^\s*[#;]/.test(lines[i+1]))value+='\n'+lines[++i].trim();result[m[1]]=value;}}return result;}
function setFields(text,name){let values=readSection(text,name);for(let f of fields){el(f).value=values[f]||({enabled:'false',backend:'auto',maxretry:'5',findtime:'10m',bantime:'1h'}[f]||'');}if(![...el('backend').options].some(x=>x.value===values.backend)&&values.backend){let o=document.createElement('option');o.value=o.textContent=values.backend;el('backend').append(o);el('backend').value=values.backend;}}
function formText(){let text=el('jailraw').value,name=el('jailname').value.trim();if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name))throw Error('Nom de jail invalide');let lines=text.split('\n'),out=[],section='',seen=false;for(let i=0;i<lines.length;i++){let line=lines[i],m=line.match(/^\s*\[([^\]]+)\]/);if(m){section=m[1];if(section===name)seen=true;}let kv=line.match(/^([\w.-]+)\s*=/);if(section===name&&kv&&fields.includes(kv[1])){while(i+1<lines.length&&/^\s+\S/.test(lines[i+1])&&!/^\s*[#;]/.test(lines[i+1]))i++;continue;}out.push(line);}if(!seen)out.push('['+name+']');else {let start=out.findIndex(x=>new RegExp('^\\s*\\['+name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\]').test(x));let end=out.findIndex((x,i)=>i>start&&/^\s*\[/.test(x));if(end<0)end=out.length;let additions=fields.filter(f=>el(f).value.trim()).map(f=>f+' = '+el(f).value.trim().replace(/\n/g,'\n    '));out.splice(end,0,...additions);return out.join('\n')+'\n';}for(let f of fields)if(el(f).value.trim())out.push(f+' = '+el(f).value.trim().replace(/\n/g,'\n    '));return out.join('\n')+'\n';}
async function jailState(){let jail=el('jailname').value;try{let d=await api({op:'jail',jail});let count=d.status.match(/Currently banned:\s*(\d+)/);el('jailsummary').textContent='Protection active · '+(count?count[1]:'?')+' IP bannie(s).';el('jailstatus').textContent=d.status+'\n'+Object.entries(d.values).map(([k,v])=>k+' : '+v.trim()).join('\n');}catch(e){el('jailsummary').textContent='Protection inactive ou indisponible.';el('jailstatus').textContent=e.message;}}
async function openJail(){let name=el('jailfile').value;if(!name)throw Error('Aucun fichier');let d=await api({op:'read',kind:'jail',name});jf={name,hash:d.hash,custom:d.custom};let sections=[...d.content.matchAll(/^\s*\[([^\]]+)\]/gm)].map(m=>m[1]).filter(x=>x!=='DEFAULT'&&x!=='INCLUDES');el('jailname').value=sections[0]||name.replace(/\.(conf|local)$/,'');el('jailname').readOnly=true;el('jailtitle').textContent=name;el('jailraw').value=d.content;setFields(d.content,el('jailname').value);el('jailpanel').hidden=false;await jailState();return {output:'Configuration chargée.'};}
async function saveJail(op,raw=false){if(!jf)throw Error('Ouvrez une jail');let content=raw?el('jailraw').value:formText();if(op==='save'&&!confirm('Appliquer cette configuration ? Désactiver une jail retire sa protection.'))return {output:'Annulé.'};let d=await api({op,kind:'jail',name:jf.name,hash:jf.hash,content});if(op==='save'){await overview();el('jailfile').value=jf.name;await openJail();}return d;}
async function openFile(){let kind=el('kind').value,name=el('filename').value;if(!name)throw Error('Aucun fichier');let d=await api({op:'read',kind,name});ff={kind,name,hash:d.hash,custom:d.custom};el('editname').value=name;el('editname').readOnly=true;el('content').value=d.content;return {output:'Fichier chargé.'};}
async function saveFile(op){if(!ff)throw Error('Ouvrez ou créez un fichier');let name=el('editname').value.trim();if(op==='save'&&!confirm('Tester puis appliquer ce fichier ? Les actions peuvent modifier le pare-feu.'))return {output:'Annulé.'};let d=await api({op,kind:ff.kind,name,hash:ff.hash,content:el('content').value});if(op==='save'){await overview();el('filename').value=name;await openFile();}return d;}
async function removeFile(file){if(!file)throw Error('Ouvrez un fichier');if(!confirm('Supprimer '+file.name+' et appliquer ? La protection correspondante peut être retirée.'))return {output:'Annulé.'};let d=await api({op:'delete',kind:file.kind||'jail',name:file.name,hash:file.hash});await overview();el('jailpanel').hidden=true;return d;}
async function backups(){let d=await api({op:'backups'});el('backuplist').replaceChildren();for(let x of d.items){let p=document.createElement('div');p.className='card';let label=document.createElement('p');label.textContent=x.id;let b=document.createElement('button');b.textContent='Restaurer';b.onclick=()=>run(async()=>{if(!confirm('Restaurer la version précédente de '+x.name+' ?'))return {output:'Annulé.'};let current=await api({op:'read',kind:x.kind,name:x.name});let result=await api({op:'restore',kind:x.kind,name:x.name,hash:current.hash,backup:x.id});await overview();await backups();return result;});p.append(label,b);el('backuplist').append(p);}if(!d.items.length)el('backuplist').textContent='Aucune modification enregistrée depuis cette interface.';return {output:'Sauvegardes actualisées.'};}
async function logs(){let d=await api({op:'logs'});el('logtext').textContent=d.output;return {output:'Journal actualisé.'};}
for(let b of document.querySelectorAll('[data-tab]'))b.onclick=()=>{if(parent!==window)parent.postMessage({type:'fcp-admin-section',section:b.dataset.tab},location.origin);for(let s of document.querySelectorAll('main>section'))s.hidden=s.id!==b.dataset.tab;for(let x of document.querySelectorAll('[data-tab]'))x.classList.toggle('active',x===b);if(b.dataset.tab==='abuse-settings')run(async()=>{await loadAutomation();return loadAbuse();});if(b.dataset.tab==='logs')run(logs);if(b.dataset.tab==='backups')run(backups);};
el('refresh').onclick=()=>run(overview);el('test').onclick=()=>run(()=>api({op:'test'}));el('reload').onclick=()=>run(async()=>{if(!confirm('Tester puis recharger toutes les jails ?'))return {output:'Annulé.'};let d=await api({op:'reload'});await overview();return d;});el('all').onclick=()=>run(async()=>{if(prompt('Cette opération lève tous les bans. Tapez DEBANNIR pour confirmer.')!=='DEBANNIR')return {output:'Annulé.'};let d=await api({op:'unban_all',confirm:'DEBANNIR'});await overview();return d;});
el('openjail').onclick=()=>run(openJail);el('newjail').onclick=()=>run(async()=>{let jail=prompt('Nom de la nouvelle jail (lettres, chiffres, tirets)');if(!jail)return {output:'Annulé.'};if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(jail))throw Error('Nom invalide');let name=jail+'.local';let d=await api({op:'read',kind:'jail',name});if(d.content)throw Error('Ce fichier existe déjà.');jf={name,hash:d.hash,custom:false};el('jailname').value=jail;el('jailname').readOnly=true;el('jailtitle').textContent=name;el('jailraw').value='['+jail+']\nenabled = false\n';setFields(el('jailraw').value,jail);el('jailpanel').hidden=false;el('jailstatus').textContent='Nouvelle jail, pas encore enregistrée.';return {output:'Complétez les paramètres avant activation.'};});
el('savejail').onclick=()=>run(()=>saveJail('save'));el('validatejail').onclick=()=>run(()=>saveJail('validate'));el('saveraw').onclick=()=>run(()=>saveJail('save',true));el('deletejail').onclick=()=>run(()=>removeFile(jf));el('jailrefresh').onclick=()=>run(async()=>{await jailState();return {output:'État actualisé.'};});el('restartjail').onclick=()=>run(async()=>{if(!confirm('Recharger cette jail ? Sa protection peut être brièvement interrompue.'))return {output:'Annulé.'};let d=await api({op:'restart_jail',jail:el('jailname').value});await jailState();return d;});
for(let op of ['ban','unban'])el(op).onclick=()=>run(async()=>{if(!confirm((op==='ban'?'Bannir ':'Débannir ')+el('ip').value+' dans '+el('jailname').value+' ?'))return {output:'Annulé.'};let d=await api({op,jail:el('jailname').value,ip:el('ip').value.trim()});await jailState();return d;});
el('kind').onchange=()=>{ff=null;el('content').value='';fileOptions();};el('openfile').onclick=()=>run(openFile);el('newfile').onclick=()=>run(async()=>{let name=prompt('Nom du fichier, avec .conf ou .local');if(!name)return {output:'Annulé.'};let kind=el('kind').value;let d=await api({op:'read',kind,name});if(d.content)throw Error('Ce fichier existe déjà.');ff={kind,name,hash:d.hash,custom:false};el('editname').value=name;el('editname').readOnly=true;el('content').value=kind==='filter'?'[Definition]\nfailregex = \nignoreregex = \n':'[Definition]\nactionstart = \nactionstop = \nactioncheck = \nactionban = \nactionunban = \n';return {output:'Complétez le fichier.'};});el('validatefile').onclick=()=>run(()=>saveFile('validate'));el('savefile').onclick=()=>run(()=>saveFile('save'));el('deletefile').onclick=()=>run(()=>removeFile(ff));el('regex').onclick=()=>run(async()=>{if(!ff)throw Error('Ouvrez un filtre');let d=await api({op:'regex',kind:'filter',name:ff.name,sample:el('sample').value});el('regexresult').textContent=d.output;return d;});el('logrefresh').onclick=()=>run(logs);el('backuprefresh').onclick=()=>run(backups);for(let b of document.querySelectorAll('[data-service]'))b.onclick=()=>run(async()=>{if(prompt('Cette opération peut interrompre toutes les protections. Tapez SERVICE pour confirmer.')!=='SERVICE')return {output:'Annulé.'};let d=await api({op:'service',command:b.dataset.service,confirm:'SERVICE'});return d;});run(overview);
</script></body></html>'''

background_start_lock = threading.Lock()
background_started = False

def start_background_services():
    global background_started
    with background_start_lock:
        if background_started:
            return
        # Initialize only inside the serving process, never before a WSGI fork.
        try:
            refresh_dashboard()
        except Exception:
            app.logger.exception('Initial dashboard refresh failed')
        threading.Thread(target=dashboard_worker, name='fcp-dashboard-refresh', daemon=True).start()
        background_started = True

if __name__ == "__main__":
    start_background_services()
    app.run(host="0.0.0.0", port=9191)
