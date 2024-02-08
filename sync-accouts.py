import os
import re
from hashlib import sha256

## User Initial Run Command
# :/usr/sbin/nologin
groups = os.popen("cat /etc/group | awk -F: '{ print $1 }'").read().split('\n')
users = os.popen("cat /etc/passwd | awk -F: '{ print $1 }'").read().split('\n')

## Clear Commnets in the output
def clean_comments(groups):
    data = list(groups)
    for line in data:
        match = re.match("^[\s]*#", line)
        if match or line == '':
            groups.remove(line)
    return sorted(groups)

groups_list = clean_comments(groups)
users_list = clean_comments(users)

users_str = ''.join(users).encode('UTF-8')
groups_str = ''.join(groups).encode('UTF-8')

users_hash = sha256(users_str).hexdigest()
groups_hash = sha256(groups_str).hexdigest()

for i in groups_list:
    print(i)

for i in users_list:
    print(i)