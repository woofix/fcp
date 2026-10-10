# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Shared installation settings; secrets and local state never belong in Git."""
import json
import os
from pathlib import Path


def settings_path():
    return Path(os.environ.get('FCP_AUTOMATION_FILE', '/app/data/automation.json'))


def load_config(path=None):
    path = Path(path or os.environ.get('FCP_CONFIG', '/app/config/config.json'))
    cfg = {
        'container': os.environ.get('FCP_FAIL2BAN_CONTAINER', 'fail2ban'),
        'fcp_container': os.environ.get('FCP_CONTAINER', 'fcp'),
        'postfix': '', 'output': '/app/automation-state', 'jails': {},
        'sender': '', 'recipient': '', 'timezone': os.environ.get('TZ','UTC'),
        'http_enabled': False, 'web_jail': 'npmplus',
        'web_log': '/var/log/npmplus/fail2ban_access.log',
        'ssh_jails': ['sshd'], 'ssh_log': '/data/host-logs/sshd.log',
        'ssh_port': 22, 'sftp_port': 22, 'sftp_container': '',
        'service_description': 'See the jail names and observed service ports below.',
        'message_id_domain': 'localhost',
    }
    if path.exists():
        cfg.update(json.loads(path.read_text()))
    for key, env in (('container','FCP_FAIL2BAN_CONTAINER'),('fcp_container','FCP_CONTAINER'),('timezone','TZ')):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    return cfg


def ensure_settings():
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = load_config()
    defaults = {
        'email_enabled': False, 'abuseipdb_enabled': False, 'report_enabled': False,
        'min_bans': 2, 'window_hours': 24, 'cooldown_hours': 24,
        'sender': cfg['sender'], 'recipient': cfg['recipient'],
        'subject': 'Repeated suspicious activity from {ip} — Fail2ban evidence',
        'message': 'Hello Abuse Team,\n\nPlease review the observations and supporting evidence below.',
    }
    # Exclusive creation preserves saved settings when workers start together.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, 'w') as handle:
        json.dump(defaults, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
