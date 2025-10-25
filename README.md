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
