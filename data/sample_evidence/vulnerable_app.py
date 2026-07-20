"""Deliberately vulnerable sample Flask app — fixture data for
core/owasp_security integration tests. Never imported/executed by the
application itself; this file exists only as SAST analysis input.
"""

import hashlib
import os
import pickle
import random
import subprocess

DEBUG = True
API_KEY = "sk-live-abcdef123456"


def run_backup(target_dir, user_supplied_name):
    os.system("tar -cf backup.tar " + target_dir)
    subprocess.call("rm -rf " + target_dir, shell=True)
    path = "/var/data/" + user_supplied_name
    return open(path)


def lookup_user(cursor, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    token = hashlib.md5(username.encode()).hexdigest()
    session_id = random.randint(100000, 999999)
    return token, session_id


def load_profile(raw_bytes):
    return pickle.loads(raw_bytes)


def check_login(password, submitted):
    if password == submitted:
        return True
    return False


def go_to_next(destination):
    return redirect(destination)


def debug_log(secret_token):
    print(secret_token)
