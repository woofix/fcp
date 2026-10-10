# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Single scheduler process. Reports run once a day; controls default to off."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import time
from zoneinfo import ZoneInfo
from runtime import ensure_settings, load_config


def run(name, *args):
    result = subprocess.run(['python', '/app/automation/'+name, *args], timeout=300)
    if result.returncode:
        print(json.dumps({'job':name,'exit_code':result.returncode}), flush=True)


def main():
    os.umask(0o077)
    ensure_settings()
    cfg = load_config()
    state = Path(cfg['output']); state.mkdir(parents=True,exist_ok=True)
    marker = state / 'daily-attempt.json'
    zone = ZoneInfo(cfg['timezone'])
    while True:
        run('fail2ban-abuse.py', '--send')
        run('fail2ban-abuseipdb.py')
        now = dt.datetime.now(zone)
        previous = json.loads(marker.read_text()) if marker.exists() else {}
        # Persist before attempting submission: a restart must not duplicate a report.
        if now.hour >= int(os.environ.get('FCP_REPORT_HOUR','8')) and previous.get('date') != now.date().isoformat():
            marker.write_text(json.dumps({'date':now.date().isoformat(),'attempted_at':now.isoformat()}))
            run('fail2ban-report.py', '--send')
        time.sleep(300)


if __name__ == '__main__':
    main()
