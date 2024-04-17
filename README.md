# xz-utils demo
This will create two vms within google cloud (admin-vm and developer-vm), both running on Ubuntu. The developer vm will get 
and updated liblzma that is vulnerable to the xz-utils vulnerability. On both hosts the Lacework agent will be installed

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
