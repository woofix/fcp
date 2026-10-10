#!/usr/bin/env python3
# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Prepare an installation without starting services or overwriting settings."""
import json
from pathlib import Path
import secrets


def main():
    root = Path(__file__).resolve().parent
    for name in ('config','data','state','geo','logs'):
        (root/name).mkdir(exist_ok=True, mode=0o700)
    config = root/'config/config.json'
    if not config.exists():
        config.write_text(json.dumps({
            'postfix':'',
            'sender':'', 'recipient':'', 'output':'/app/automation-state',
            'jails':{}, 'ssh_jails':['sshd'], 'web_jail':'npmplus',
            'http_enabled':False, 'web_log':'/var/log/npmplus/fail2ban_access.log',
            'ssh_log':'/data/host-logs/sshd.log', 'ssh_port':22,
            'sftp_container':'', 'sftp_port':22, 'timezone':'UTC',
            'service_description':'Specify your protected services and public destination ports here.',
        }, indent=2)+'\n')
        config.chmod(0o600)
    env = root/'.env'
    if not env.exists():
        env.write_text('FCP_ADMIN_USER=admin\nFCP_ADMIN_PASSWORD='+secrets.token_urlsafe(32)+'\nFCP_BIND_ADDRESS=127.0.0.1\nFCP_PORT=9191\nFCP_FAIL2BAN_CONTAINER=fail2ban\nFCP_CONTAINER=fcp\nTZ=UTC\n')
        env.chmod(0o600)
    print('Installation prepared. Review .env and config/config.json, then run: docker compose up -d --build')
    print('Administrator: admin. Password stored only in .env.')


if __name__ == '__main__':
    main()
