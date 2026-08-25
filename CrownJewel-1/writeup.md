# CrownJewel-1Smoke & Mirrors
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
Forela's domain controller is under attack. The Domain Administrator account is believed to be compromised, and it is suspected that the threat actor dumped the NTDS.dit database on the DC. We just received an alert of vssadmin being used on the DC, since this is not part of the routine schedule we have good reason to believe that the attacker abused this LOLBIN utility to get the Domain environment's crown jewel. Perform some analysis on provided artifacts for a quick triage and if possible kick the attacker as early as possible.

## Attachments
- `CrownJewel1.zip`

## Solve
After downloading and extracting the attachment, I obtained three event log files: `SECURITY.evtx`, `SYSTEM.evtx`, `Microsoft-Windows-NTFS.evtx`, and `$MFT`. I used EvtxECmd and MFTECmd to parse them into `.csv` format so they could be analyzed using Timeline Explorer or Excel.

>[!Note] 
> NTDS.dit is an ESE (Extensible Storage Engine) database. It stores Active Directory data, including user and group information, Kerberos keys, and NTLM hashes.

<br>

### Task 1
#### Question:
Attackers can abuse the vssadmin utility to create volume shadow snapshots and then extract sensitive files like NTDS.dit to bypass security mechanisms. Identify the time when the Volume Shadow Copy service entered a running state.

#### Answer:
In the `SYSTEM` log, searching for `Volume Shadow Copy` reveals Record Number 135: `Service started or stopped` with timestamp `2024-05-14 03:42:16`.

>[!Note] 
> When the Domain Controller is active, the `lsass.exe` process locks the `NTDS.dit` file, preventing it from being copied using standard commands like `copy` or `xcopy`. Volume Shadow Copy (VSS) creates snapshots that allow reading `NTDS.dit` without file lock restrictions.

Answer: **2024-05-14 03:42:16**

<br>

### Task 2
#### Question:
When a volume shadow snapshot is created, the Volume shadow copy service validates the privileges using the Machine account and enumerates User groups. Find the two user groups the volume shadow copy process queries and the machine account that did it.

#### Answer:
In the `SECURITY` log, after VSS was initiated, the service performed privilege validation queries recorded under Record Numbers 87 and 88:
``` json
{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"Administrators"},{"@Name":"TargetDomainName","#text":"Builtin"},{"@Name":"TargetSid","#text":"S-1-5-32-544"},{"@Name":"SubjectUserSid","#text":"S-1-5-18"},{"@Name":"SubjectUserName","#text":"DC01$"},{"@Name":"SubjectDomainName","#text":"FORELA"},{"@Name":"SubjectLogonId","#text":"0x3E7"},{"@Name":"CallerProcessId","#text":"0x1190"},{"@Name":"CallerProcessName","#text":"C:\\Windows\\System32\\VSSVC.exe"}]}}
```

```json
{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"Backup Operators"},{"@Name":"TargetDomainName","#text":"Builtin"},{"@Name":"TargetSid","#text":"S-1-5-32-551"},{"@Name":"SubjectUserSid","#text":"S-1-5-18"},{"@Name":"SubjectUserName","#text":"DC01$"},{"@Name":"SubjectDomainName","#text":"FORELA"},{"@Name":"SubjectLogonId","#text":"0x3E7"},{"@Name":"CallerProcessId","#text":"0x1190"},{"@Name":"CallerProcessName","#text":"C:\\Windows\\System32\\VSSVC.exe"}]}}
```
Answer: **Administrators, Backup Operators, DC01$**

<br>

### Task 3
#### Question:
Identify the Process ID (in Decimal) of the volume shadow copy service process.

#### Answer:
The caller process for the queries above is `C:\Windows\System32\VSSVC.exe`, which has a process ID of `0x1190` in hexadecimal, corresponding to `4496` in decimal.

Answer: **4496**

<br>

### Task 4
#### Question:
Find the assigned Volume ID/GUID value to the Shadow copy snapshot when it was mounted.

#### Answer:
Record Number 124 in the `Microsoft-Windows-NTFS` log records the event where NTFS successfully mounted the VSS snapshot:
```json
{"EventData":{"Data":[{"@Name":"VolumeCorrelationId","#text":"06c4a997-cca8-11ed-a90f-000c295644f9"},{"@Name":"VolumeIdLength","#text":"0"},{"@Name":"VolumeId"},{"@Name":"VolumeLabelLength","#text":"0"},{"@Name":"VolumeLabel"},{"@Name":"DeviceNameLength","#text":"33"},{"@Name":"DeviceName","#text":"\\Device\\HarddiskVolumeShadowCopy1"},{"@Name":"DeviceGuid","#text":"00000000-0000-0000-0000-000000000000"},{"@Name":"VendorIdLength","#text":"0"},{"@Name":"VendorId"},{"@Name":"ProductIdLength","#text":"0"},{"@Name":"ProductId"},{"@Name":"ProductRevisionLength","#text":"0"},{"@Name":"ProductRevision"},{"@Name":"DeviceSerialNumberLength","#text":"0"},{"@Name":"DeviceSerialNumber"},{"@Name":"BusType","#text":"0"},{"@Name":"AdapterSerialNumberLength","#text":"0"},{"@Name":"AdapterSerialNumber"},{"@Name":"Vcb","#text":"0xFFFF800F93FD41B0"},{"@Name":"MountDurationUs","#text":"0"},{"@Name":"MountDuration","#text":"0 us"},{"@Name":"LongestStage","#text":"0"},{"@Name":"LongestStageDuration","#text":"0 us"},{"@Name":"LongestStagePercentage","#text":"0"},{"@Name":"SecondLongestStage","#text":"0"},{"@Name":"SecondLongestStageDuration","#text":"0 us"},{"@Name":"SecondLongestStagePercentage","#text":"0"},{"@Name":"RestartApplied","#text":"False"},{"@Name":"IsBootVolume","#text":"False"},{"@Name":"Stage1DurationUs","#text":"0"},{"@Name":"Stage2DurationUs","#text":"0"},{"@Name":"Stage3DurationUs","#text":"0"},{"@Name":"Stage4DurationUs","#text":"0"},{"@Name":"Stage5DurationUs","#text":"0"},{"@Name":"Stage6DurationUs","#text":"0"},{"@Name":"Stage7DurationUs","#text":"0"},{"@Name":"Stage8DurationUs","#text":"0"},{"@Name":"Stage9DurationUs","#text":"0"},{"@Name":"Stage10DurationUs","#text":"0"}]}}
```

Answer: **{06c4a997-cca8-11ed-a90f-000c295644f9}**

<br>

### Task 5
#### Question:
Identify the full path of the dumped NTDS database on disk.

#### Answer:
In `$MFT`, filtering files by the attack timestamp and the `.dit` extension reveals Entry Number 97945, which contains the parent path of the dumped NTDS database.

Answer: **C:\Users\Administrator\Documents\backup_sync_Dc\Ntds.dit**

<br>

### Task 6
#### Question:
When was newly dumped ntds.dit created on disk?

#### Answer:
This timestamp is located in the same MFT entry (Entry Number 97945) identified in Task 5.

Answer: **2024-05-14 03:44:22**

<br>

### Task 7
#### Question:
A registry hive was also dumped alongside the NTDS database. Which registry hive was dumped and what is its file size in bytes?

#### Answer:
Checking the same output directory where the NTDS database was dumped reveals that the `SYSTEM` registry hive was extracted alongside it, with a file size of `17563648` bytes.

Answer: **SYSTEM, 17563648**