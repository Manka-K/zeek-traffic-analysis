# zeek-traffic-analysis
Collection of network forensic investigations using Zeek. Includes analysis of Log4Shell exploitation attempts, anomalous DNS traffic, and phishing campaigns, with extracted IoCs and conclusions.
# Reference
This write-up is based on the TryHackMe room: Zeek Exercises (https://tryhackme.com/room/zeekbroexercises).
# Anomalous DNS
## Objective
The main goal of this exercise was to inspect the provided `.pcap` file, extract and analyze artifacts using Zeek, and confirm whether the triggered alert “Anomalous DNS Activity” represents a true positive.
## Tools Used
- TryHackMe Virtual Machine
- Zeek
- dns-tunneling.pcap - Packet Capture (PCAP) provided by TryHackMe
## Step-by-Step Approach
First, I ran Zeek against the capture file:
`zeek -Cr dns-tunneling.pcap`

<img width="2824" height="480" alt="image" src="https://github.com/user-attachments/assets/9a895bf0-4db2-4860-ab74-52d07663e618" />

This produced multiple logs: `conn.log`, `dns.log`, `http.log`, and `ntp.log`.
### Q1: Investigate the **dns.log** file. What is the number of DNS records linked to the IPv6 address?
For this exercise, I focused on `dns.log`.
I opened the DNS log to examine the available fields:
`head dns.log`

<img width="2824" height="764" alt="image" src="https://github.com/user-attachments/assets/40f9203f-3637-49c9-a04c-f330183a22a1" />

The fields `qtype` and `qtype_name` appear to be the most relevant for answering the question. 
I retrieved the `qtype` and `qtype_name` fields from `dns.log` to confirm whether they contain the necessary information:
`cat dns.log | zeek-cut qtype qtype_name`

<img width="2824" height="1298" alt="image" src="https://github.com/user-attachments/assets/005d566a-24ed-4c60-8920-726606b77598" />

Indeed, `qtype` represents the numeric code of the DNS query type, and `qtype_name` provides the human-readable label. For example, IPv6 address records are identified by a `qtype` value of 28, corresponding to the `qtype_name` ”AAAA”.
Then, I extracted the number of DNS records linked to IPv6 addresses:
Option 1 (using numeric code):
`cat dns.log | zeek-cut qtype | grep 28 | wc -l`
Option 2 (using descriptive label):
`cat dns.log | zeek-cut qtype_name | grep “AAAA” | wc -l`
### Q2: Investigate the **conn.log** file. What is the longest connection duration?
I opened the DNS log to examine the available fields:
`head conn.log`

<img width="2824" height="688" alt="image" src="https://github.com/user-attachments/assets/38521fdf-4c5a-424a-8dc8-a2b291e4309f" />

There is a field called `duration` that I am interested in.
I extracted the connection durations and sorted them so the longest one appears at the end:
`cat conn.log | zeek-cut duration | sort`
or:
`cat conn.log | zeek-cut duration | sort -n | tail -1`
### Q3: Investigate the **dns.log** file. Filter all unique DNS queries. What is the number of unique domain queries?
Looking at the fields available in `dns.log`, there is one called `query`.
To examine the unique DNS queries:
`cat dns.log | zeek-cut query | sort | uniq`

<img width="2824" height="1302" alt="image" src="https://github.com/user-attachments/assets/3d491833-5c30-482f-a4ee-a57001dfd654" />

There are many `*.cisco-update.com` queries, where `*` is 32 characters long and consists only of hexadecimal characters. This pattern resembles the output of a Domain Generation Algorithm (DGA), which produces numerous pseudo-random domain names that malware can use to contact its Command-and-Control (C2) servers.
These queries have the structure `sub-domain.SLD.TLD`. To filter them and display only unique domain entries, I first tried the following command:
`cat dns.log | zeek-cut query | cut -d ‘.’ -f 2-3 | sort | uniq`

<img width="2000" height="416" alt="image" src="https://github.com/user-attachments/assets/4993f37c-3445-4849-9297-6966785a82c9" />

As shown in the screenshot, the command successfully extracted some domains (e.g., `cisco-update.com`, `rhodes.edu`, `ubuntu.com`, and `_tcp.local`). However, some of the resulting entries do not appear meaningful.
Therefore, I had to take a different approach: first reverse the string so that the TLD and SLD appear first, extract those two fields, and then reverse the string back:
`cat dns.log | zeek-cut query | rev | cut -d ‘.’ -f 1-2 | rev | sort | uniq`

<img width="2824" height="306" alt="image" src="https://github.com/user-attachments/assets/81093318-d9f8-46ed-9691-3f2b13394210" />

This makes much more sense!
### Q4: There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let's find out which hosts are involved in this activity. Investigate the **conn.log** file. What is the IP address of the source host?
We have already observed that many DNS queries were sent to the `cisco-update.com` domain. To determine which hosts (`id.orig_h` in `conn.log`) were involved, I used the following command:
`cat conn.log | zeek-cut id.orig_h | sort | uniq -c`

<img width="2000" height="216" alt="image" src="https://github.com/user-attachments/assets/1d251d35-2f69-489f-9a96-6d73d3144099" />

As seen in the screenshot, most of the queries originated from a single IP address, which could indicate a potentially compromised host!
### Indicators of Compromise (IoCs)
**Suspicious Domain Names**
- `.cisco-update.com` with 32-character hexadecimal subdomains.
- Pattern resembles a Domain Generation Algorithm (DGA).
**Compromised Host**
- IP 10.20.57.3 originated most of the DNS queries to the same domain. This host may be compromised and attempting to contact a Command-and-Control (C2) server.
### Conclusion
The Zeek analysis confirmed that the DNS traffic was anomalous and the alert was valid.  Further investigation into the infected host is required.
# Phishing
## Objective
The objective of this exercise was to analyze the provided `.pcap` file, extract and investigate the relevant artifacts, and determine whether the triggered “Phishing Attempt” alert represents a true positive.
## Tools Used
- TryHackMe Virtual Machine
- Zeek
- CyberChef
- VirusTotal
- `phishing.pcap`, `hash-demo.zeek`, `file-extract-demo.zeek` files provided by TryHackMe
## Step-by-Step Approach
The initial step was to execute Zeek on the capture file with the `file-extract-demo.zeek` script:
`zeek -Cr phishing.pcap file-extract-demo.zeek`
The following logs were generated: `dhcp.log`, `files.log`, `pe.log`, `conn.log`, `dns.log`, `packet_filter.log`, along with a folder containing the extracted files.
### Q1: Investigate the logs. What is the suspicious source address? Enter your answer in **defanged format**.
I assumed that the phishing attempt involved a compromised host downloading a malicious attachment. Therefore, I began the analysis with `http.log`. Among the available fields, I focused on:
- `id.orig_h` – Source IP address of the client
- `host` – HTTP host or domain name being accessed
- `uri` – Requested resource path on the server
- `resp_filenames` – Names of files returned by the server
- `resp_mime_types` – MIME types of the server’s response

<img width="2824" height="876" alt="image" src="https://github.com/user-attachments/assets/3f53247d-7c5a-42cc-b17e-d6a594e90a07" />

As observed from the collected entries, there was only one client source IP. To present the results in a defanged format, I processed it using CyberChef:

<img width="2820" height="1360" alt="image" src="https://github.com/user-attachments/assets/d68824fb-ef51-40cf-9068-df86fedefcb9" />

### Q2: Investigate the **http.log** file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.
The domain address in question was identified within the same entries collected from `http.log`. Then, I let CyberChef to perform a baking session and convert the domain address into a defanged format.

<img width="2820" height="1360" alt="image" src="https://github.com/user-attachments/assets/cb875ed3-aa79-42ba-8efc-2082cbd05ea6" />

### Q3: Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?
The entries collected from `http.log` showed that the client downloaded three files: a text file, a Microsoft Word document, and an executable. To investigate the files in VirusTotal, I re-ran Zeek on the capture file, this time using the `hash-demo.zeek` script.

<img width="2820" height="1098" alt="image" src="https://github.com/user-attachments/assets/8ce8c3a2-f2fc-43e4-8069-1924ec0be625" />

By examining `files.log`, the respective MD5 and SHA1 hashes of the files can be observed.
I used the following command to extract the filenames, MIME types, and their corresponding MD5 hashes from `files.log`:
`cat files.log | zeek-cut filename mime_type md5`

<img width="2820" height="204" alt="image" src="https://github.com/user-attachments/assets/2b730a7d-9868-4238-9f5d-5f53e93e877e" />

I began the analysis with the Microsoft Word document and found that (1) the file is clearly malicious, and (2) it is associated with a VBA file type. VBA (Visual Basic for Applications) is a scripting language commonly embedded in Microsoft Office documents. It is frequently abused by attackers to deliver malware, as a malicious Word document may contain an embedded VBA macro that executes automatically when the file is opened—an approach often used in phishing campaigns.

<img width="2820" height="704" alt="image" src="https://github.com/user-attachments/assets/cbba4417-3e66-470f-9017-64150e6e634e" />
<img width="2820" height="730" alt="image" src="https://github.com/user-attachments/assets/359ba849-4fd5-4c09-a092-19b47801a09a" />

### Q4: Investigate the extracted malicious **.exe** file. What is the given file name in Virustotal?
### Q5: Investigate the malicious **.exe** file in VirusTotal. What is the contacted domain name? Enter your answer in **defanged format**.
The executable file downloaded by the client also appeared malicious in VirusTotal. It was associated with the name `PleaseWaitWindow.exe` and communicated with the domain `hopto[.]org`. The domain is registered to No-IP (Vitalwerks Internet Solutions, LLC), which is a DDNS provider (according to Cisco Talos).

<img width="2820" height="522" alt="image" src="https://github.com/user-attachments/assets/4156d005-9362-4c89-b60e-87df251b2df9" />
<img width="2820" height="522" alt="image" src="https://github.com/user-attachments/assets/3fa011fd-4029-4c74-b8f2-4dfeed06a7e1" />
<img width="2820" height="1128" alt="image" src="https://github.com/user-attachments/assets/55b7e585-ea4a-44bf-9339-13e1ee53f0c2" />

The domain is registered to No-IP (Vitalwerks Internet Solutions, LLC), which is a DDNS provider (according to Cisco Talos).

<img width="1286" height="490" alt="image" src="https://github.com/user-attachments/assets/793a4a00-90c4-4602-a7ce-8230ac36a1fd" />

### Q6: Investigate the http.log file. What is the request name of the downloaded malicious **.exe** file?
From the entries collected from `http.log`, I found that the request name of the downloaded .exe file was `/knr.exe`.
### Indicators of Compromise (IoCs)
**Malicious Executable and Microsoft Word Document**
- VirusTotal Verdict: Malicious.
- Microsoft Word Document is associated with a VBA file type.
### Conclusion
The investigation into the provided `.pcap` file revealed a targeted phishing attempt involving a compromised host. First, a Microsoft Word document was downloaded, containing a VBA macro intended to execute malicious code upon opening. The macro initiated the download of an executable file named `PleaseWaitWindow.exe`, which was flagged as malicious by VirusTotal. The executable established communication with the domain `hopto[.]org`, a Dynamic DNS service provider, indicating potential Command-and-Control (C2) activity.
# Log4J
## Objective
The main goal of this exercise was to analyze the provided `.pcap` file, extract and investigate the relevant artifacts, and determine whether the triggered “Log4J Exploitation Attempt” alert represents a true positive.
## Tools Used
- TryHackMe Virtual Machine
- Zeek
- `log4shell.pcapng`, `detection-log4j.zeek` script files provided by TryHackMe
## Step-by-Step Approach
### Q1: Investigate the log4shell.pcapng file with detection-log4j.zeek script. Investigate the signature.log file. What is the number of signature hits?
First, I executed Zeek on the capture file with the `detection-log4j.zeek` script.

<img width="2820" height="348" alt="image" src="https://github.com/user-attachments/assets/691057a1-08d3-4aa6-a80a-e4d99a152bae" />

To determine the number of signature hits, I extracted the `event_msg` field from `signatures.log`:
`cat signatures.log | zeek-cut event_msg`

<img width="2820" height="742" alt="image" src="https://github.com/user-attachments/assets/782a435a-b54e-4940-884d-a23c9e64c8ed" />

### Q2: Investigate the **http.log** file. Which tool is used for scanning?
Looking at the fields available in `http.log`, there is one called `user_agent`.

<img width="2820" height="852" alt="image" src="https://github.com/user-attachments/assets/e5612a9b-6c8c-4f14-9e8f-867a4a99ba6b" />

To examine and count the unique `user_agent` values:
`cat http.log | zeek-cut user_agent | sort | uniq -c`

<img width="2820" height="442" alt="image" src="https://github.com/user-attachments/assets/faac2585-7c15-4d8c-b098-893a466b00c6" />

Analysis revealed that 593 `user_agent` entries were associated with *Mozilla/5.0 (Nmap Scripting Engine).*
### Q3: Investigate the **http.log** file. What is the extension of the exploit file?
To examine and count the unique `uri` values:
`cat http.log | zeek-cut uri | sort | uniq -c`

<img width="2820" height="332" alt="image" src="https://github.com/user-attachments/assets/364e31dd-a894-4203-84f7-21d44b911616" />

Upon analysis of the output, I observed several exploit files with the `.class` extension. In malicious contexts, attackers often use them to deliver Java-based exploits or payloads.
### Q4: Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?
To extract the base64 commands from the `log4j.log` file, I used the following command:
`cat log4j.log | zeek-cut uri | sort | uniq -c`

<img width="2820" height="332" alt="image" src="https://github.com/user-attachments/assets/e0389b0a-19aa-4ab8-92eb-d59e4b7fd045" />

Then, I decoded the extracted commands using CyberChef:

<img width="2820" height="1348" alt="image" src="https://github.com/user-attachments/assets/334800f3-b29d-4cbb-aa20-522f6d63276d" />

I observed that the `touch` command was used to create an empty file named `/tmp/pwned`.
### Indicators of Compromise (IoCs)
**User-Agent:**
- `Mozilla/5.0 (Nmap Scripting Engine)` – indicates automated scanning activity.
**Exploit Artifacts:**
- Malicious requests attempting to load files with `.class` extension (common for Java exploit payloads).
**Commands Observed:**
- Base64-encoded payload decoding to `touch /tmp/pwned` – confirms attacker gained code execution.
**File Created:**
- `/tmp/pwned`
### Conclusion
The analysis confirms that the observed traffic corresponds to a true positive Log4Shell exploitation attempt. Evidence includes automated scanning via Nmap scripting engine, retrieval of `.class` exploit files, and successful execution of attacker-supplied commands on the target system. The creation of the `/tmp/pwned` file demonstrates that the exploit worked and remote code execution was achieved.
