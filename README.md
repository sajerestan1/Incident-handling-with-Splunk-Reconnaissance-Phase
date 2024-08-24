# Incident-handling-with-Splunk-Reconnaissance-Phase

![image](https://github.com/user-attachments/assets/780abca8-c2e5-448b-a663-dbdb8bfe0dc0)


## Project Report: Investigating a Cyber-Attack on Wayne Enterprises

### 1. Overview

This project involved investigating a cyber-attack on Wayne Enterprises, where attackers successfully defaced the company's website, http://www.imreallynotbatman.com. As a Security Analyst, I was tasked with identifying the root cause of the attack and tracing all activities carried out by the attackers within the network. The investigation was conducted using Splunk as the Security Information and Event Management (SIEM) solution, which provided access to logs from various sources, including web servers, firewalls, Suricata, and Sysmon. The focus was on analyzing the logs to understand how the attackers breached the network and defaced the website.

![image](https://github.com/user-attachments/assets/46549d47-e76f-4ad0-9476-55991d69f5a3)


### 2. Scenario — Investigating the Cyber-Attack

The investigation began with an understanding of the network environment and the available log sources within Splunk. The primary goal was to trace the attack's origin, identify the tools used, and determine the actions performed by the attackers. This investigation was part of the Detection and Analysis phase of incident response.

### 2.1 Task 4: Reconnaissance Phase

### 2.1.1 Reconnaissance Overview

Reconnaissance is the phase where attackers gather information about their target, such as the systems in use, web applications, employees, or locations. In this task, the focus was on identifying any reconnaissance attempts against the web server, imreallynotbatman.com.

### 2.1.2 Log Source Identification

To start the investigation, I searched for the domain imreallynotbatman.com within the index=botsv1, which contained logs related to the incident. The search results indicated that the following log sources contained traces of the domain:

Search Query: index=botsv1 imreallynotbatman.com

![image](https://github.com/user-attachments/assets/64fd29f7-1f93-4ab6-8e5d-9e49791c58ee)


    Suricata
    stream
    fortigate_utm
    iis

These log sources provided visibility into both network and host-centric activities, which were critical for identifying the reconnaissance activities.

2.1.3 IP Address Identification

I focused on the stream:http log source, which contained HTTP traffic logs. By examining the src_ip field, I identified two IP addresses, 40.80.148.42 and 23.22.63.114. The IP address 40.80.148.42 was of particular interest due to its high presence in the logs, suggesting it was likely responsible for the reconnaissance activity.

Search Query: index=botsv1 imreallynotbatman.com sourcetype=stream:http

![image](https://github.com/user-attachments/assets/f867987a-4ca6-4f92-abb9-fe0baf054375)


    Identified IP: 40.80.148.42

### 2.2 Validation of Scanning Attempts

#### 2.2.1 Further Analysis of the IP Address

To confirm the suspicious activity associated with the IP address 40.80.148.42, I further analyzed the logs by focusing on specific fields such as User-Agent, Post request, and URIs. This analysis revealed that the IP address was indeed probing the domain imreallynotbatman.com, validating the reconnaissance attempt.
2.2.2 Suricata Log Analysis.

Search Query: index=botsv1 imreallynotbatman.com sourcetype=stream:http

![image](https://github.com/user-attachments/assets/a71a758e-cc7a-4415-95e6-ddb5028ab5b3)


Next, I examined the Suricata logs to identify any triggered alerts associated with the source IP 40.80.148.42. The search query was refined to focus on logs from the suricata log source, which detected communication from this IP. The analysis revealed a Suricata alert that highlighted a specific CVE value associated with the attack attempt.

![image](https://github.com/user-attachments/assets/2adddd2c-0f6e-4183-9435-4200b4323a8f)


    CVE Value: CVE-2014-6271

### 2.3 Additional Findings

#### 2.3.1 Content Management System (CMS) Identification

By examining the http.http_refer and http.url fields within the logs, I identified that the web server was using Joomla as its CMS. This information was crucial for understanding the potential vulnerabilities that the attackers may have exploited.

![image](https://github.com/user-attachments/assets/eef329f1-359c-4fad-987f-cce5bfaa0b3f)


![image](https://github.com/user-attachments/assets/8608246e-49ae-4867-8b73-d6f577da48a5)

    CMS: Joomla

2.3.2 Web Scanner Identification

Further analysis of the logs, particularly the user-agent field, indicated that the attacker used Acunetix, a well-known web vulnerability scanner, to perform the scanning attempts against the web server.


![image](https://github.com/user-attachments/assets/8a4ff887-42d3-46de-b3ad-09a6bc66ac2e)

    Web Scanner: Acunetix

2.3.3 Web Server IP Address

Finally, I identified the IP address of the web server imreallynotbatman.com, which was the target of the attack.

![image](https://github.com/user-attachments/assets/b118ae84-f3f8-42ea-a558-3a311b40e05a)

    Web Server IP: 192.168.250.70

3. Thoughts

This investigation provided valuable insights into the methods used by attackers to compromise a network and deface a website. The process of analyzing logs using Splunk reinforced my understanding of the importance of log analysis in detecting and responding to security incidents. Each step of the investigation, from identifying reconnaissance attempts to validating scanning activities, demonstrated the critical role of a Security Analyst in protecting organizational assets. The findings from this investigation will inform future security measures and enhance my capabilities in threat detection and incident response.
4. Conclusion

The investigation into the cyber-attack on Wayne Enterprises successfully identified the key elements of the attack, including the reconnaissance activities, the tools used by the attackers, and the vulnerabilities exploited. By leveraging Splunk's powerful log analysis capabilities, I was able to trace the attack from its inception to its execution, providing a comprehensive understanding of the attack vector. This experience underscores the importance of continuous monitoring and analysis of network traffic and logs to detect and mitigate potential threats before they cause significant damage. The knowledge gained from this project will be instrumental as I continue to develop my expertise in cybersecurity and prepare for more complex challenges in the field.

