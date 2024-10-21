##################################################################
# DESCRIPTION:
# This will create two VMs (developer-vpm and admin-vm) on GCP
# ssh will be enabled on the developer-vm but limited to pub-key
# ssh will be enabled but blocked via firewall on admin-vm
# auto-updates will be disabled on developer-vm
# metadata script will run to replace the liblzmao to a vulnerable
#   version on developer-vm to allow xz-util hack
# lacework-agent will be installed on both machines
#
# YOU NEED THE FOLLOWING API ENABLED: Cloud billing API
#
# CHANGE SECTION:
# Change to your billing account
data "google_billing_account" "acct" {
  display_name = "Mein Rechnungskonto"
}

# adjust if you want to use another project name and id
resource "random_id" "bucket_prefix" {
  byte_length = 8
}
resource "google_project" "my_project" {
  name            = "xz-hack"
  project_id      = "xz-hack-${random_id.bucket_prefix.hex}"
  billing_account = data.google_billing_account.acct.id
}

# Update to you lacework agent install link from the token
variable "lacework-agent" {
  type    = string
  default = "AGENTURL/install.sh"
}
##################################################################




variable "region" {
  type    = string
  default = "us-west1"
}

provider "google" {
  region = var.region
}

# enable APIs
variable "gcp_service_list" {
  description = "Projectof apis"
  type        = list(string)
  default = [
    "compute.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudbilling.googleapis.com",
    "iam.googleapis.com",
    "appenginereporting.googleapis.com",
    "pubsub.googleapis.com",
    "cloudscheduler.googleapis.com",
    "serviceusage.googleapis.com"
  ]
}
resource "google_project_service" "gcp-serv" {
  for_each = toset(var.gcp_service_list)
  project  = google_project.my_project.project_id
  service  = each.key
}

# create VPC
resource "google_compute_network" "vpc" {
  name                    = "vm-vpc"
  auto_create_subnetworks = "true"
  routing_mode            = "GLOBAL"
  project                 = google_project.my_project.project_id
  depends_on = [
    google_project_service.gcp-serv
  ]
}

# allow ssh firewall policy
resource "google_compute_firewall" "allow-ssh" {
  name    = "vm-fw-allow-ssh"
  network = google_compute_network.vpc.name
  project = google_project.my_project.project_id
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ssh"]
}

variable "ubuntu_2204_sku" {
  type        = string
  description = "SKU for Ubuntu 22.04 LTS"
  default     = "ubuntu-os-cloud/ubuntu-2204-lts"
}

variable "linux_instance_type" {
  type        = string
  description = "VM instance type for Linux Server"
  default     = "e2-micro"
}

# prepare environment for development-vm
# download xzbot demo with vulnerable liblzmao library and link to installed one
# disable auto-updates
data "template_file" "linux-metadata" {
  template = <<EOF
#!/bin/bash
sudo apt-get update > /tmp/terraform.log 2>&1
sudo apt-get install golang-go pip git >> /tmp/terraform.log 2>&1
cat /etc/apt/apt.conf.d/20auto-upgrades | sed s/'APT::Periodic::Unattended-Upgrade "1"'/'APT::Periodic::Unattended-Upgrade "0"'/g | sed s/'APT::Periodic::Update-Package-Lists "1"'/'APT::Periodic::Update-Package-Lists "0"'/g >> /tmp/confd
cp /tmp/confd /etc/apt/apt.conf.d/20auto-upgrades >> /tmp/terraform.log 2>&1
rm -f /tmp/confd >> /tmp/terraform.log 2>&1 
git clone https://github.com/amlweems/xzbot.git /tmp/xzbot >> /tmp/terraform.log 2>&1
cp /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1 /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1.original >> /tmp/terraform.log 2>&1
sudo cp /tmp/xzbot/assets/liblzma.so.5.6.1.patch /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1 >> /tmp/terraform.log 2>&1
ln -sf /lib/x86_64-linux-gnu/liblzma.so.5.6.1 /lib/x86_64-linux-gnu/liblzma.so.5 >> /tmp/terraform.log 2>&1
systemctl restart sshd >> /tmp/terraform.log 2>&1
cd /tmp
wget ${var.lacework-agent} >> /tmp/terraform.log 2>&1
sh /tmp/install.sh >> /tmp/terraform.log 2>&1
rm -f /tmp/install.sh >> /tmp/terraform.log 2>&1
EOF
}

data "google_compute_default_service_account" "default" {
  project = google_project.my_project.project_id
  depends_on = [
    google_project_service.gcp-serv
  ]
}

# allow ssh for developer-vm
resource "google_compute_instance" "vm_instance_public" {
  name         = "developer-vm"
  machine_type = var.linux_instance_type
  project      = google_project.my_project.project_id
  zone         = "us-west1-c"
  tags         = ["ssh"]
  boot_disk {
    initialize_params {
      image = var.ubuntu_2204_sku
    }
  }
  metadata_startup_script = data.template_file.linux-metadata.rendered
  network_interface {
    network = google_compute_network.vpc.name
    access_config {}
  }
  service_account {
    email  = data.google_compute_default_service_account.default.email
    scopes = ["compute-rw", "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
  depends_on = [
    google_project_service.gcp-serv
  ]
}

resource "google_service_account" "sa" {
  account_id   = "admin-service-account"
  project      = google_project.my_project.project_id
  display_name = "A service account for admin"
}

resource "google_project_iam_member" "owner_binding" {
  project = google_project.my_project.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.sa.email}"
}

data "template_file" "lacework-agent" {
  template = <<EOF
#!/bin/bash
cd /tmp
wget ${var.lacework-agent} 
sh /tmp/install.sh
rm -f /tmp/install.sh
EOF
}

# create admin-vm without ssh access allowed
resource "google_compute_instance" "vm_instance_admin" {
  name         = "admin-vm"
  machine_type = var.linux_instance_type
  project      = google_project.my_project.project_id
  zone         = "us-west1-c"
  boot_disk {
    initialize_params {
      image = var.ubuntu_2204_sku
    }
  }
  metadata_startup_script = data.template_file.lacework-agent.rendered
  network_interface {
    network = google_compute_network.vpc.name
    access_config {}
  }
  service_account {
    email  = google_service_account.sa.email
    scopes = ["cloud-platform"]
  }
  depends_on = [
    google_project_service.gcp-serv,
    google_service_account.sa
  ]
}
