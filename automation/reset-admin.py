#!/usr/bin/env python3
"""Local-console recovery only. Never expose this operation through HTTP."""
import argparse
import getpass
import os
import sqlite3
import time
from argon2 import PasswordHasher
parser=argparse.ArgumentParser(description='Reset FCP administrator password from the trusted host console.')
args=parser.parse_args()
password=getpass.getpass('New password (20–256 characters): ')
if not 20<=len(password)<=256 or password!=getpass.getpass('Confirm password: '):
    raise SystemExit('Invalid length or confirmation.')
path=os.environ.get('FCP_AUTH_DATABASE','/app/data/auth.sqlite3')
if not os.path.isfile(path):raise SystemExit('No initialized authentication database.')
with sqlite3.connect(path,timeout=15) as db:
    db.execute('BEGIN IMMEDIATE')
    db.execute('UPDATE administrator SET password=? WHERE id=1',(PasswordHasher().hash(password),))
    db.execute('DELETE FROM sessions');db.execute('DELETE FROM failures')
    db.execute('INSERT INTO audit VALUES(?,?,?)',(time.time(),'local_admin_recovery','local-console'))
print('Administrator password updated. All sessions revoked.')
