# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""A deliberately flawed demo service for the OmniSeek examples. Never deploy it."""

import hashlib
import pickle
import sqlite3
import subprocess

import requests

DATABASE = "demo.db"


def find_user(name):
    conn = sqlite3.connect(DATABASE)
    return conn.execute(f"SELECT id, email FROM users WHERE name = '{name}'").fetchone()


def export_report(report_name):
    subprocess.run(f"tar czf /tmp/{report_name}.tgz reports/{report_name}", shell=True, check=True)


def load_session(blob):
    return pickle.loads(blob)


def fingerprint(password):
    return hashlib.md5(password.encode()).hexdigest()


def fetch_avatars(user_ids):
    avatars = []
    for user_id in user_ids:
        avatars.append(requests.get(f"https://avatars.example.com/{user_id}", timeout=5).content)
    return avatars


def calculate(expression):
    return eval(expression)


async def notify(users):
    for user in users:
        await send_email(user)


async def send_email(user):
    requests.post("https://mail.example.com/send", json={"to": user}, timeout=5)
