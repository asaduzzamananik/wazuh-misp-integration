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


## Add RestApi :

What the MISP REST API Does?
The MISP REST API (Representational State Transfer API) allows external systems, scripts, and tools to interact with your MISP instance programmatically — without needing to manually use the web interface.
You can use it to search, add, modify, or export data such as:
  - Events
  - Attributes (indicators of compromise)
  - Objects
  - Tags
  - Sightings
  - Correlations
Essentially, it gives you a way to automate threat intelligence exchange between MISP and other systems (like Wazuh, Suricata, or SIEMs).

**/attributes/restSearch** — the endpoint **/attributes/restSearch** is one of the most used MISP API routes.
It lets you search for attributes (IOCs) based on various filters — like event IDs, types, values, categories, timeframes, or tags.
Think of it as a “search engine” for all your indicators stored in MISP.

<img width="975" height="416" alt="image" src="https://github.com/user-attachments/assets/fe785ac4-d785-4e6e-b85c-985b5a65aa80" />


---

## MISP integration script(Wazuh Manager):

Based on the VirusTotal integration script, we wrote a new script called custom-misp-file-hashes.py. This file must be placed in the **/var/ossec/integrations** directory in the Wazuh Server.
Download the [custom-misp-file-hashes.py](https://github.com/MISP/wazuh-integration/blob/main/scripts/custom-misp_file_hashes.py) script. After creating the custom-misp_file_hashes.py file in the **/var/ossec/integrations** directory, we have to adjust the file permissions:
  - chown root:wazuh /var/ossec/integrations/custom-misp_file_hashes.py
  - chmod 750 /var/ossec/integrations/custom-misp_file_hashes.py
  - systemctl restart wazuh-manager 
**configure Wazuh server to use this integration by adding the <integration> block to the **/var/ossec/etc/ossec.conf** file.**

```bash

<ossec_config>
    <integration>
        <name>custom-misp_file_hashes.py</name>
        <hook_url>https://YOUR_MISP_INSTANCE</hook_url>
        <api_key>YOUR_API_KEY</api_key>
        <group>syscheck</group>
        <rule_id>554</rule_id>
        <alert_format>json</alert_format>
        <options>{
              "timeout": 10,
              "retries": 3,
              "debug": false,
              "tags": ["tlp:white", "tlp:clear", "malware"],
              "push_sightings": true,
              "sightings_source": "wazuh"
          }
        </options>
    </integration>
</ossec_config>

```

<img width="975" height="323" alt="image" src="https://github.com/user-attachments/assets/606147d1-16e5-4e60-bc8f-e06f43d911cf" />

## Wazuh rules
Once we are receiving file creation alerts from our agent and these are being processed by our MISP integration, we need to define some rules in Wazuh.
In the Wazuh UI, navigate to Server Management → Rules, then click (+) Add new rules file.
Name the file misp_file_hashes.xml
Add the following content to the rules file:

```bash
<group name="misp,malware,">
    <rule id="100800" level="0">
        <decoded_as>json</decoded_as>
        <description>MISP: file hash check</description>
        <field name="integration">misp_file_hashes</field>
        <options>no_full_log</options>
    </rule>
    <rule id="100801" level="0">
        <if_sid>100800</if_sid>
        <field name="misp_file_hashes.found">0</field>
        <description>MISP: file hash not found</description>
    </rule>
    <rule id="100802" level="12">
        <if_sid>100800</if_sid>
        <field name="misp_file_hashes.found">1</field>
        <description>MISP: file hash matched</description>
    </rule>
    <rule id="100803" level="10">
        <if_sid>100800</if_sid>
        <field name="misp_file_hashes.error">403</field>
        <description>MISP ERROR: Invalid MISP credentials, check your the api_key setting configured
            in the MISP integration is valid MISP AuthKey</description>
    </rule>
    <rule id="100803" level="10">
        <if_sid>100800</if_sid>
        <field name="misp_file_hashes.error">429</field>
        <description>MISP ERROR: Rate limit exceeded, too many requests</description>
    </rule>
    <rule id="100804" level="10">
        <if_sid>100800</if_sid>
        <field name="misp_file_hashes.error">500</field>
        <description>MISP ERROR: $(misp_file_hashes.description)</description>
    </rule>
</group>
```

After saving the rules, restart the Wazuh Manager.
```bash
systemctl restart wazuh-manager
```

<img width="1841" height="864" alt="image" src="https://github.com/user-attachments/assets/c16ba35c-f901-4269-b12a-959a218a352b" />
<img width="1907" height="826" alt="image" src="https://github.com/user-attachments/assets/cdcb5dbe-9498-4c11-9ab1-1d9b530b0367" />
<img width="1852" height="874" alt="image" src="https://github.com/user-attachments/assets/71ab6ac3-7e66-461d-8d5d-40b45aa9d0dc" />

---

## Wazuh and MISP integration
**Wazuh Host Monitoring**

**Goal: Detect suspicious activity from the Windows endpoint.**

Steps:
  - Install the Wazuh Agent on the Windows 10 machine
  - Configure the agent to communicate with the Wazuh Manager on Ubuntu
  - Enable file integrity monitoring for the selected directories
  - Start and verify the agent service
  - Confirm alerts in the Wazuh Dashboard (Threat Hunting → Events) or by checking log files on the manager

<img width="1918" height="910" alt="image" src="https://github.com/user-attachments/assets/9df0140b-5b4b-4e16-aa40-566deb01fab8" />

### Configuring directory monitoring (In Wazuh Agent)

First we need to configure our Wazuh agents(Windows) to enable filesystem monitoring on the directories we are interested in.
On Ubuntu the agent configuration file is usually located in **/var/ossec/etc/ossec.conf**.
We can instruct the Wazuh agent to monitor a directory using the <directories> configuration block as follows:

```bash
<ossec_config>
  <syscheck>
    <disabled>no</disabled>
    <directories check_all="yes" realtime="yes">MONITORED_DIRECTORY_PATH</directories>
  </syscheck>
</ossec_config>
```

<img width="975" height="453" alt="image" src="https://github.com/user-attachments/assets/dd626beb-c5e9-4bc0-9684-2eb10e33c930" />



## Add Event in Misp Instance
To trigger a positive match in MISP, add any of the **eicar.com hashes to your MISP instance.

  - MD5: 44d88612fea8a8f36de82e1278abb02f
  - SHA1: 3395856ce81f2b7382dee72602f798b642f14140
  - SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

<img width="975" height="325" alt="image" src="https://github.com/user-attachments/assets/e0dc8f82-0e4c-4aca-b35d-018009f12201" />
<img width="975" height="412" alt="image" src="https://github.com/user-attachments/assets/a8b98449-b457-46a0-9d45-43cb066f6649" />
<img width="975" height="415" alt="image" src="https://github.com/user-attachments/assets/c47d25c2-aa82-47ad-a70a-4708a9a0ed94" />
<img width="889" height="957" alt="image" src="https://github.com/user-attachments/assets/24bc670e-3677-45a7-80f1-84e7d74ba1d9" />

## Test

Download [Eicar.com](https://www.eicar.org/) file to the monitored directory. 

<img width="975" height="448" alt="image" src="https://github.com/user-attachments/assets/b298613b-4f1f-4d0d-af9c-92594cdd8def" />
<img width="975" height="404" alt="image" src="https://github.com/user-attachments/assets/a6d90c84-c771-4f07-859e-710ae79e6c03" />
<img width="975" height="310" alt="image" src="https://github.com/user-attachments/assets/a37dab72-10c1-4550-a928-65e2f69d42f1" />

Now:-
  1. Open Notepad
    - Press Windows + R, type notepad, and press Enter.
     
    <img width="608" height="332" alt="image" src="https://github.com/user-attachments/assets/19af8c92-5ba4-40e0-b93c-9d971d5e7cbb" />

  3. Paste the EICAR test string
    - In Notepad paste the single line exactly as shown above. Do not add extra spaces, line breaks, or characters.

  4. Save the file with the correct name and encoding
    - Click File → Save As.
    - In the Save As dialog:
    - Navigate to the target monitored directory (if you want it saved directly into the monitored folder).
    - In File name enter: eicar.com
    - Set Save as type to All Files (*.*).
    - Set Encoding to ANSI (this is the same as ASCII for this content).
	- Click Save.

<img width="975" height="408" alt="image" src="https://github.com/user-attachments/assets/4b79511e-259b-44be-a8ea-d3f72fe0a1a2" />

**Alternative: create the file using PowerShell**
If you want a command-line method instead of Notepad, run PowerShell and execute:
	- Start Windows Powershel As Admin: Then paste:

```bash
Set-Content -Path "C:\path\to\monitored\folder\eicar.com" -Value "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" -Encoding ASCII
```

Set-Content -Path "C:\path\to\monitored\folder\eicar.com" -Value "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" -Encoding ASCII

**Note : Replace C:\path\to\monitored\folder\ with the actual path to your monitored directory**

<img width="975" height="145" alt="image" src="https://github.com/user-attachments/assets/6bb41e6f-4b28-4a2a-9e56-3fac77af685c" />

**The EICAR test file was successfully created and saved in the monitored directory.**

## Verify Alert Generation in Wazuh:

After downloading the file:

  - Open the Wazuh Dashboard → Threat Intelligence → Threat Hunting → Events.
  - Wait for a few moments while the agent scans the directory.
  - Confirm that alerts are generated for the detected hash indicators.

<img width="975" height="682" alt="image" src="https://github.com/user-attachments/assets/f395ec85-f33e-4a0e-a034-b31cc30d27d1" />

Check the integration script logs in **Wazuh Manager**:
In terminal –

```bash
tail -f   /var/ossec/logs/integrations.log
```

<img width="975" height="319" alt="image" src="https://github.com/user-attachments/assets/b03a0b0c-d742-45b3-a1ff-ae44532a837a" />




	
