# SmartyPants
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
Forela's CTO, Dutch, stores important files on a separate Windows system because the domain environment at Forela is frequently breached due to its exposure across various industries. On 24 January 2025, our worst fears were realised when an intruder accessed the fileserver, installed utilities to aid their actions, stole critical files, and then deleted them, rendering them unrecoverable. The team was immediately informed of the extortion attempt by the intruders, who are now demanding money. While our legal team addresses the situation, we must quickly perform triage to assess the incident's extent. Note from the manager: We enabled SmartScreen Debug Logs across all our machines for enhanced visibility a few days ago, following a security research recommendation. These logs can provide quick insights, so ensure they are utilised.

## Attachments
- `SmartyPants.zip`

## Solve
After downloading and extracting the attachment, I obtained a `Logs` folder containing Windows event logs.

<br>

### Task 1
#### Question:
The attacker logged in to the machine where Dutch saves critical files, via RDP on 24th January 2025. Please determine the timestamp of this login.

#### Answer:
Using EvtxECmd and Timeline Explorer to investigate `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`, an established RDP connection is recorded at Record Number 23 for user `Dutch` with the timestamp `2025-01-24 10:15:14`.

Answer: **2025-01-24 10:15:14**

<br>

### Task 2
#### Question:
The attacker downloaded a few utilities that aided them for their sabotage and extortion operation. What was the first tool they downloaded and installed?

#### Answer:
Opening `Microsoft-Windows-SmartScreen%4Debug.evtx`, after the RDP connection was established, Record Number 8 shows the first tool downloaded by the attacker for their operations:
```json
{"EventData":{"Data":{"@Name":"Data","#text":"{\"$type\":\"isFileSupported\",\"executionTime\":\"9281\",\"path\":\"C:\\\\Users\\\\Dutch\\\\Downloads\\\\winrar-x64-701.exe\",\"size\":\"3912088\"}"}}}
```

Answer: **WinRAR**

<br>

### Task 3
#### Question:
They then proceeded to download and then execute the portable version of a tool that could be used to search for files on the machine quickly and efficiently. What was the full path of the executable?

#### Answer:
Following Task 2, the executable used to search for files can be found at Record Number 15:
```json
{"EventData":{"Data":{"@Name":"Data","#text":"{\"$type\":\"isFileSupported\",\"executionTime\":\"8701\",\"path\":\"C:\\\\Users\\\\Dutch\\\\Downloads\\\\Everything.exe\",\"size\":\"1778192\"}"}}}
```

Answer: **C:\Users\Dutch\Downloads\Everything.exe**

<br>

### Task 4
#### Question:
What is the execution time of the tool from task 3?

#### Answer:
Record Number 15 has the timestamp `2025-01-24 10:17:33`.

Answer: **2025-01-24 10:17:33**

<br>

### Task 5
#### Question:
The utility was used to search for critical and confidential documents stored on the host, which the attacker could steal and extort the victim. What was the first document that the attacker got their hands on and breached the confidentiality of that document?

#### Answer:
The first accessed document is recorded at Record Number 19:
``` json
{"EventData":{"Data":{"@Name":"Data","#text":"{\"$type\":\"isFileSupported\",\"executionTime\":\"3720\",\"path\":\"C:\\\\Users\\\\Dutch\\\\Documents\\\\2025- Board of directors Documents\\\\Ministry Of Defense Audit.pdf\",\"size\":\"2679956\"}"}}}
```

Answer: **C:\Users\Dutch\Documents\2025- Board of directors Documents\Ministry Of Defense Audit.pdf**

<br>

### Task 6
#### Question:
Find the name and path of second stolen document as well.

#### Answer:
The second accessed document is recorded at Record Number 21:
``` json
{"EventData":{"Data":{"@Name":"Data","#text":"{\"$type\":\"isFileSupported\",\"executionTime\":\"3726\",\"path\":\"C:\\\\Users\\\\Dutch\\\\Documents\\\\2025- Board of directors Documents\\\\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf\",\"size\":\"523480\"}"}}}
```

Answer: **C:\Users\Dutch\Documents\2025- Board of directors Documents\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf**

<br>

### Task 7
#### Question:
The attacker installed a Cloud utility as well to steal and exfiltrate the documents. What is name of the cloud utility?

#### Answer:
At Record Number 23, the installer for the cloud exfiltration utility is observed:
``` json
{"EventData":{"Data":{"@Name":"Data","#text":"{\"$type\":\"isFileSupported\",\"executionTime\":\"12443\",\"path\":\"C:\\\\Users\\\\Dutch\\\\Downloads\\\\MEGAsyncSetup64.exe\",\"size\":\"78861432\"}"}}}
```

Answer: **MEGAsync**

<br>

### Task 8
#### Question:
When was this utility executed?

#### Answer:
Record Number 23 only records the `MEGAsync` installer. The timestamp indicating when the main utility was executed is recorded at Record Number 42.

Answer: **2025-01-24 10:22:19**

<br>

### Task 9
#### Question:
The Attacker also proceeded to destroy the data on the host so it is unrecoverable. What utility was used to achieve this?

#### Answer:
At Record Number 48, the attacker downloaded `File Shredder` setup to destroy the data:
```json
{"EventData":{"Data":{"@Name":"Data","#text":"{\"$type\":\"isFileSupported\",\"executionTime\":\"7943\",\"path\":\"C:\\\\Users\\\\Dutch\\\\Downloads\\\\file_shredder_setup.exe\",\"size\":\"2317839\"}"}}}
```

Answer: **File Shredder**

<br>

### Task 10
#### Question:
The attacker cleared 2 important logs, thinking they covered all their tracks. When was the security log cleared?

#### Answer:
Inspecting `Security.evtx` for Event ID 1102 (which indicates that the audit log was cleared), Record Number 4419 references this event with the timestamp `2025-01-24 10:28:41`.

Answer: **2025-01-24 10:28:41**