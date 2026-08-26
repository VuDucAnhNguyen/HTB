# CrownJewel-2
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
Forela's Domain environment is pure chaos. Just got another alert from the Domain controller of NTDS.dit database being exfiltrated. Just one day prior you responded to an alert on the same domain controller where an attacker dumped NTDS.dit via vssadmin utility. However, you managed to delete the dumped files kick the attacker out of the DC, and restore a clean snapshot. Now they again managed to access DC with a domain admin account with their persistent access in the environment. This time they are abusing ntdsutil to dump the database. Help Forela in these chaotic times!!

## Attachments
- `CrownJewel2.zip`

## Solve
After downloading and extracting the attachment, I obtained three event log files: `SECURITY.evtx`, `SYSTEM.evtx`, and `APPLICATION.evtx`. I used EvtxECmd to parse them into `.csv` format so they could be analyzed using Timeline Explorer or Excel.

<br>

### Task 1
#### Question:
When utilizing ntdsutil.exe to dump NTDS on disk, it simultaneously employs the Microsoft Shadow Copy Service. What is the most recent timestamp at which this service entered the running state, signifying the possible initiation of the NTDS dumping process?

#### Answer:
In the `SYSTEM` log, searching for `Volume Shadow Copy` reveals the most recent record at Record Number 198 (Event ID 7036: `Service started or stopped`) with the timestamp `2024-05-15 05:39:55`.

Answer: **2024-05-15 05:39:55**

<br>

### Task 2
#### Question:
Identify the full path of the dumped NTDS file.

#### Answer:
In the `APPLICATION` log, searching for the `.dit` extension reveals Record Number 646 with Event ID 325 (`Create a database`), which contains the full path of the dumped NTDS file.

Answer: **C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit**

<br>

### Task 3
#### Question:
When was the database dump created on the disk?

#### Answer:
The timestamp of the record from Task 2 (Event ID 325) is `2024-05-15 05:39:56`.

Answer: **2024-05-15 05:39:56**

<br>

### Task 4
#### Question:
When was the newly dumped database considered complete and ready for use?

#### Answer:
After the NTDS dump was created, Event ID 327 (`Detach a database`) at Record Number 648 indicates that the database dump was completed.
``` json
{"EventData":{"Data":"NTDS, 3940,D,100, 2, C:\\Windows\\Temp\\dump_tmp\\Active Directory\\ntds.dit, 0, \n[1] 0.000003 +J(0)\n[2] 0.0 +J(0)\n[3] 0.000007 +J(0) +M(C:0K, Fs:1, WS:4K # 0K, PF:0K # 0K, P:0K)\n[4] 0.0 +J(0)\n[5] 0.0 +J(0)\n[6] 0.023198 -0.019281 (2) WT +J(0) +M(C:-424K, Fs:26, WS:-464K # 76K, PF:-356K # 0K, P:-356K)\n[7] 0.000279 +J(0)\n[8] 0.000029 +J(0) +M(C:0K, Fs:1, WS:4K # 0K, PF:0K # 0K, P:0K)\n[9] 0.001762 -0.000919 (6) WT +J(0) +M(C:0K, Fs:4, WS:-20K # 0K, PF:-20K # 0K, P:-20K)\n[10] 0.000140 +J(0)\n[11] 0.000060 +J(0) +M(C:0K, Fs:1, WS:-4K # 0K, PF:-8K # 0K, P:-8K)., 0 0","Binary":""}}
```

Answer: **2024-05-15 05:39:58**

<br>

### Task 5
#### Question:
Event logs use event sources to track events coming from different sources. Which event source provides database status data like creation and detachment?

#### Answer:
The provider/event source for the records in Task 3 and Task 4 is `ESENT`.

Answer: **ESENT**

<br>

### Task 6
#### Question:
When ntdsutil.exe is used to dump the database, it enumerates certain user groups to validate the privileges of the account being used. Which two groups are enumerated by the ntdsutil.exe process? Give the groups in alphabetical order joined by comma space.

#### Answer:
In the `SECURITY` log (Event ID 4799: `A security-enabled local group membership was enumerated`), after VSS was initiated, privilege validation queries were recorded under Record Numbers 157 and 160:
``` json
{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"Administrators"},{"@Name":"TargetDomainName","#text":"Builtin"},{"@Name":"TargetSid","#text":"S-1-5-32-544"},{"@Name":"SubjectUserSid","#text":"S-1-5-18"},{"@Name":"SubjectUserName","#text":"DC01$"},{"@Name":"SubjectDomainName","#text":"FORELA"},{"@Name":"SubjectLogonId","#text":"0x3E7"},{"@Name":"CallerProcessId","#text":"0x1420"},{"@Name":"CallerProcessName","#text":"C:\\Windows\\System32\\VSSVC.exe"}]}}
```
``` json
{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"Backup Operators"},{"@Name":"TargetDomainName","#text":"Builtin"},{"@Name":"TargetSid","#text":"S-1-5-32-551"},{"@Name":"SubjectUserSid","#text":"S-1-5-18"},{"@Name":"SubjectUserName","#text":"DC01$"},{"@Name":"SubjectDomainName","#text":"FORELA"},{"@Name":"SubjectLogonId","#text":"0x3E7"},{"@Name":"CallerProcessId","#text":"0x1420"},{"@Name":"CallerProcessName","#text":"C:\\Windows\\System32\\VSSVC.exe"}]}}
```

Answer: **Administrators, Backup Operators**

<br>

### Task 7
#### Question:
Now you are tasked to find the Login Time for the malicious Session. Using the Logon ID, find the Time when the user logon session started.

#### Answer:
To authenticate a Domain account in Active Directory, users rely on Kerberos to obtain a TGT. In the `SECURITY` log, filtering for Kerberos authentication ticket requests (Event ID 4768) where `TargetUserName` is a user account (does not end with `$`) reveals the attacker's login activity. Record Number 55 captures this event with the timestamp `2024-05-15 05:36:31`.
``` json
{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"Administrator"},{"@Name":"TargetDomainName","#text":"FORELA"},{"@Name":"TargetSid","#text":"S-1-5-21-3239415629-1862073780-2394361899-500"},{"@Name":"ServiceName","#text":"krbtgt"},{"@Name":"ServiceSid","#text":"S-1-5-21-3239415629-1862073780-2394361899-502"},{"@Name":"TicketOptions","#text":"0x40810010"},{"@Name":"Status","#text":"0x0"},{"@Name":"TicketEncryptionType","#text":"0x12"},{"@Name":"PreAuthType","#text":"2"},{"@Name":"IpAddress","#text":"::1"},{"@Name":"IpPort","#text":"0"},{"@Name":"CertIssuerName"},{"@Name":"CertSerialNumber"},{"@Name":"CertThumbprint"}]}}
```

>[!Note] 
> Kerberos is an authentication protocol that eliminates the need to send plain passwords over the network. It authenticates users and grants them a Ticket-Granting Ticket (TGT). When a user requests access to a service, the Domain Controller verifies the TGT and issues a Service Ticket. This Service Ticket is then presented directly to the target service to grant access without requiring the user's password.

Answer: **2024-05-15 05:36:31**