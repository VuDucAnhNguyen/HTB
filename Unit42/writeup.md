# Unit42
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

To answer the questions in this lab, you will only need the Event Viewer, with VirusTotal as an optional supplement. Below are some important Sysmon Event IDs that can be utilized in your analysis:

Event ID 1: Process Creation/Execution. Includes process path, parent process path, and command-line arguments. <br>
Event ID 2: File Creation Time Changed. Includes the file making the change, the file to which the change is being made, tampered timestamp, and original timestamp.
<br>
Event ID 3: Network Connection. Includes the process making the connection, destination IP Address, and port.
<br>
Event ID 5: Process Termination. Includes the name of the process that was killed or terminated itself.
<br>
Event ID 11: File Created. Includes the process creating the file, the file being created, and its full path.
<br>
Event ID 22: DNS Query. Includes the process querying the domain, the target domain name, and the IP Addresses they resolve to.

Artifacts Provided

unit42.zip: A ZIP file with SHA1 hash: 1D8AC45395551187EAF23793CE525056C4136D6E.

## Attachments
- `unit42.zip`

## Solve
After downloading and extracting the attachment, I obtained the file: `Microsoft-Windows-Sysmon-Operational.evtx`. I used `EvtxECmd` to parse the event log to `.csv` to analyze the artifacts.

<br>

### Task 1
#### Question:
How many Event logs are there with Event ID 11?

#### Answer:
Opening the Sysmon log and filtering for Event ID 11 reveals 56 records.

Answer: **56**

<br>

### Task 2
#### Question:
Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?

#### Answer:
Filtering for Event ID 1 shows a suspicious entry at Record Number 47. The Image path contains a double extension (`.exe.exe`), and VirusTotal flags this file as malicious.
```json
{"EventData":{"Data":[{"@Name":"RuleName","#text":"technique_id=T1204,technique_name=User Execution"},{"@Name":"UtcTime","#text":"2024-02-14 03:41:56.538"},{"@Name":"ProcessGuid","#text":"817bddf3-3684-65cc-2d02-000000001900"},{"@Name":"ProcessId","#text":"10672"},{"@Name":"Image","#text":"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe"},{"@Name":"FileVersion","#text":"1.1.2"},{"@Name":"Description","#text":"Photo and vn Installer"},{"@Name":"Product","#text":"Photo and vn"},{"@Name":"Company","#text":"Photo and Fax Vn"},{"@Name":"OriginalFileName","#text":"Fattura 2 2024.exe"},{"@Name":"CommandLine","#text":"\"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe\" "},{"@Name":"CurrentDirectory","#text":"C:\\Users\\CyberJunkie\\Downloads\\"},{"@Name":"User","#text":"DESKTOP-887GK2L\\CyberJunkie"},{"@Name":"LogonGuid","#text":"817bddf3-311e-65cc-a7ae-1b0000000000"},{"@Name":"LogonId","#text":"0x1BAEA7"},{"@Name":"TerminalSessionId","#text":"1"},{"@Name":"IntegrityLevel","#text":"Medium"},{"@Name":"Hashes","#text":"SHA1=18A24AA0AC052D31FC5B56F5C0187041174FFC61,MD5=32F35B78A3DC5949CE3C99F2981DEF6B,SHA256=0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3,IMPHASH=36ACA8EDDDB161C588FCF5AFDC1AD9FA"},{"@Name":"ParentProcessGuid","#text":"817bddf3-311f-65cc-0a01-000000001900"},{"@Name":"ParentProcessId","#text":"1116"},{"@Name":"ParentImage","#text":"C:\\Windows\\explorer.exe"},{"@Name":"ParentCommandLine","#text":"C:\\Windows\\Explorer.EXE"},{"@Name":"ParentUser","#text":"DESKTOP-887GK2L\\CyberJunkie"}]}}
```

Answer: **C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe**

<br>

### Task 3
#### Question:
Which Cloud drive was used to distribute the malware?

#### Answer:
This information can be found by filtering for Event ID 22. Record Number 36 illustrates that the victim queried Dropbox domains before the machine was infected.

Answer: **dropbox**

<br>

### Task 4
#### Question:
For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?

#### Answer:
Filtering for Event ID 2 reveals Record Number 184, which contains the modified timestamp of the `.pdf` file.
``` json
{"EventData":{"Data":[{"@Name":"RuleName","#text":"technique_id=T1070.006,technique_name=Timestomp"},{"@Name":"UtcTime","#text":"2024-02-14 03:41:58.404"},{"@Name":"ProcessGuid","#text":"817bddf3-3684-65cc-2d02-000000001900"},{"@Name":"ProcessId","#text":"10672"},{"@Name":"Image","#text":"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe"},{"@Name":"TargetFilename","#text":"C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\TempFolder\\~.pdf"},{"@Name":"CreationUtcTime","#text":"2024-01-14 08:10:06.029"},{"@Name":"PreviousCreationUtcTime","#text":"2024-02-14 03:41:58.404"},{"@Name":"User","#text":"DESKTOP-887GK2L\\CyberJunkie"}]}}
```

Answer: **2024-01-14 08:10:06**

<br>

### Task 5
#### Question:
The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.

#### Answer:
Searching for `once.cmd` under Event ID 11 yields 2 records. Record Number 100 shows that the Image is the initial malicious file dropper, confirming this as the dropped location.
``` json
{"EventData":{"Data":[{"@Name":"RuleName","#text":"-"},{"@Name":"UtcTime","#text":"2024-02-14 03:41:58.404"},{"@Name":"ProcessGuid","#text":"817bddf3-3684-65cc-2d02-000000001900"},{"@Name":"ProcessId","#text":"10672"},{"@Name":"Image","#text":"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe"},{"@Name":"TargetFilename","#text":"C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\once.cmd"},{"@Name":"CreationUtcTime","#text":"2024-02-14 03:41:58.404"},{"@Name":"User","#text":"DESKTOP-887GK2L\\CyberJunkie"}]}}
```

Answer: **C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd**

<br>

### Task 6
#### Question:
The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?

#### Answer:
After infecting the machine, the malicious file initiated a DNS query for the domain `www.example.com`, as captured in Record Number 160.
```json
{"EventData":{"Data":[{"@Name":"RuleName","#text":"-"},{"@Name":"UtcTime","#text":"2024-02-14 03:41:56.955"},{"@Name":"ProcessGuid","#text":"817bddf3-3684-65cc-2d02-000000001900"},{"@Name":"ProcessId","#text":"10672"},{"@Name":"QueryName","#text":"[www.example.com](https://www.example.com)"},{"@Name":"QueryStatus","#text":"0"},{"@Name":"QueryResults","#text":"::ffff:93.184.216.34;199.43.135.53;2001:500:8f::53;199.43.133.53;2001:500:8d::53;"},{"@Name":"Image","#text":"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe"},{"@Name":"User","#text":"DESKTOP-887GK2L\\CyberJunkie"}]}}
```

Answer: **www.example.com**

<br>

### Task 7
#### Question:
Which IP address did the malicious process try to reach out to?

#### Answer:
The same record from Task 6 shows the resolved IPv4 address for `www.example.com`.

Answer: **93.184.216.34**

<br>

### Task 8
#### Question:
The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?

#### Answer:
Filtering for Event ID 5 (`Process terminated`) reveals only Record Number 161 with the timestamp `2024-02-14 03:41:58`.

Answer: **2024-02-14 03:41:58**