# Integrating Wazuh and MISP for Proactive Threat Detection

## Objective
The goal of this simulation is to integrate MISP threat intelligence with Wazuh and demonstrate how malicious file hashes can be detected through real time monitoring. This includes deploying MISP with Docker, configuring Wazuh agents to watch file system changes, and using a custom integration script and rules that generate alerts when a monitored file matches known indicators stored in MISP.

---

**key Goals:**

  - Deploy a working MISP instance using Docker
  - Enable threat intelligence ingestion and IOC management in MISP
  - Configure Wazuh agents for real time file integrity monitoring
  - Build and install a custom integration script for MISP hash lookups
  - Create Wazuh rules to trigger alerts when file hashes match MISP data
  - Test the setup using the EICAR standard antivirus test file
  - Validate alert visibility in the Wazuh Dashboard and integration logs

---
	
## Background Theory
The **Malware Information Sharing Platform (MISP)** operates on the fundamental theory that collaborative, structured, and timely sharing of Threat Intelligence (TI) significantly enhances the global defense against cyber threats. It transforms fragmented, raw threat data into actionable intelligence, moving organizations from reactive to proactive security postures.

**Core Principles of MISP**
MISP's functionality is built upon the following three theoretical pillars:

**Standardization**:
	- Converts raw Indicators of Compromise (IOCs) into a machine-readable format.
	- Organizes data as Attributes within contextual Events for automation and analysis.

**Contextualization**:
	- Automatically correlates IOCs across all events to reveal complex threat patterns.
	- Enriches raw data by linking it to threat actors, campaigns, and historical attacks.

**Collective Sharing**:
	- Facilitates secure, controlled exchange of TI among trusted partners.
	- Uses standards like STIX/TAXII and granular access controls for collaborative defense.

---

## Lab Setup
Network Settings for All VMs

**Select Adapter 1**:

  - Check Enable Network Adapter
  - Attached to: NAT Network
  - Adapter Type: Intel PRO/1000 MT Desktop (default is fine)
  - Cable Connected: Checked

Repeat the same for **Windows VM**.
Repeat the same for **Ubuntu VM**.

## Ubuntu(MISP) Network Config
<img width="720" height="562" alt="image" src="https://github.com/user-attachments/assets/f55334b7-e52b-461f-ab13-0cd19c29fa7e" />

## Ubuntu(Wazuh Agent) Network Config
<img width="716" height="559" alt="image" src="https://github.com/user-attachments/assets/e2fa2c85-9658-47c1-98f8-e0e8fb3802a2" />

## Windows 10(Wazuh Agent) Network Config
<img width="714" height="566" alt="image" src="https://github.com/user-attachments/assets/ef3bdc2d-7eb5-4824-bf4b-cb103e6cff07" />


## Virtual Machines (VirtualBox)
| **VM NAME**  | **Network Adapter** | **Purpose** | **Tools Used** |
|---------------|-------------|---------------|---------------|
| **Ubuntu Server (Wazuh Manager)**    | **Adapter 1: NAT Network**  | Internet access for updates and MISP API connectivity  | Wazuh Manager, custom MISP integration script, Linux CLI, Syscheck alerts, log review |                
| **Ubuntu Server (MISP Instance)**    | **Adapter 1: NAT Network**   | Docker image pulls and external feed sync |MISP (Docker), MySQL,MISP REST API access |               
| **Windows 10 (Wazuh Agent)**        | **Adapter 1: NAT Network**   | Simulates real workstation with internet  | Wazuh Agent, PowerShell, file creation,EICAR test file |
            
---

## Install MISP with Docker(Ubuntu Server for Misp instance):

### Step 1: Update and install prerequisites-

Open your terminal and run:

```bash
sudo apt update
sudo apt install git -y
```
This ensures your system is up-to-date and installs git (needed to clone the MISP Docker repository).

### Step 2: Clone the official MISP Docker repository
```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
```
This pulls down the official Docker configuration maintained by MISP and enters the folder.

### Step 4: Copy the environment configuration template

Inside the misp-docker directory, you’ll find a template environment file. Copy it to create your working .env file:
```bash
cp template.env .env 
```
Change the **MISP_BASEURL** variable to reflect the IP address of the machine you are running MISP on.

In Terminal: 
```bash
nano .env
```
<img width="975" height="524" alt="image" src="https://github.com/user-attachments/assets/5b5abde2-d2b0-4e45-878e-7416e2a6840a" />


### Step 5: Install Docker and Docker Compose
If Docker or Docker Compose aren’t installed, install them:

```bash
apt install docker-compose-v2
```
Enable and start Docker:

```bash
sudo systemctl enable docker
sudo systemctl start docker
```

### Step 6: Next, build the MISP Docker containers with the command:
```bash
Docker compose build
```

<img width="975" height="41" alt="image" src="https://github.com/user-attachments/assets/83f749b6-9efd-4879-86d3-120fa76c39fe" />

This will fetch MISP, MySQL, Redis, and other service images defined in the Docker configuration.

### Step 7: Run MISP using Docker Compose

Start the containers:
```bash
sudo docker compose up
```
<img width="975" height="46" alt="image" src="https://github.com/user-attachments/assets/571738c0-fba2-4e80-9b3a-9cf0852475c8" />
(You can also run it in detached mode using -d:
**sudo docker compose up -d**

### Step 8: Access MISP Web Interface
  - Open  browser and go to:
      - https://YOUR_SERVER_IP
  - you’ll see a warning about SSL — click Advanced → Accept the Risk.
  - The MISP login page will appear.

<img width="975" height="375" alt="image" src="https://github.com/user-attachments/assets/469c23e3-1b10-433d-b5cd-b27009f1d292" />

### Step 9: Log in to MISP
Use the default credentials:
  - Username: admin@admin.test
  - Password: admin
After logging in, you can explore the dashboard, create events, and use the MISP interface.

<img width="1852" height="846" alt="image" src="https://github.com/user-attachments/assets/0e5db4fb-531b-401c-b122-0075aeb10f38" />

## MISP Auth key :

  1. Login to your MISP account 
  2. Click "Administration" and then click "List Auth Keys"

<img width="975" height="434" alt="image" src="https://github.com/user-attachments/assets/12779e5a-1d1b-4c81-ad37-d0f797329cc5" />
<img width="975" height="448" alt="image" src="https://github.com/user-attachments/assets/f222e24b-a51d-48b3-8b36-52e109417955" />
<img width="904" height="773" alt="image" src="https://github.com/user-attachments/assets/acfd9fe4-9334-423d-a6ae-89897127d59d" />
<img width="894" height="393" alt="image" src="https://github.com/user-attachments/assets/d241e7d1-fb7b-4908-92bc-6147bad13e79" />



## Wazuh and MISP integration
**Wazuh Host Monitoring**

**Goal: Detect suspicious activity from the Windows endpoint.**

Steps:
  - Install the Wazuh Agent on the Windows 10 machine
  - Configure the agent to communicate with the Wazuh Manager on Ubuntu
  - Enable file integrity monitoring for the selected directories
  - Start and verify the agent service
  - Confirm alerts in the Wazuh Dashboard (Threat Hunting → Events) or by checking log files on the manager



	
