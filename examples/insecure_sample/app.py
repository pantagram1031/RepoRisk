import hashlib
import pickle
import subprocess

import requests
import yaml

DEBUG = True
SECRET_KEY = "sample-secret-for-demo-only"
password = "changeme123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

subprocess.run("echo demo", shell=True)
eval("1 + 1")
exec("print('demo')")
yaml.load("name: demo")
pickle.loads(b"not-a-real-pickle")
requests.get("https://example.invalid", verify=False)
hashlib.md5(b"demo").hexdigest()
query = "SELECT * FROM users WHERE name = '" + username + "'"
