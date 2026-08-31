# Campfire-2
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
Forela's Network is constantly under attack. The security system raised an alert about an old admin account requesting a ticket from KDC on a domain controller. Inventory shows that this user account is not used as of now so you are tasked to take a look at this. This may be an AsREP roasting attack as anyone can request any user's ticket which has preauthentication disabled.

## Attachments
- `campfire-1.zip`

## Solve
After downloading and extracting the attachment, I obtained the artifact: `SECURITY.evtx`. I used EvtxECmd to parse it into `.csv` format so it could be analyzed using Timeline Explorer or Excel.

>[!Note] 
> AS-REP Roasting is an attack technique targeting accounts that have Kerberos Pre-Authentication disabled (`DONT_REQ_PREAUTH`). Because Pre-Authentication is not required, an attacker can request a TGT on behalf of any targeted user without providing their credentials. The Domain Controller responds with an AS-REP packet containing data encrypted with the user's password-derived key, which can then be captured and cracked offline.

<br>

### Task 1
#### Question:
When did the ASREP Roasting attack occur, and when did the attacker request the Kerberos ticket for the vulnerable user?

#### Answer:
Filtering for Event ID 4768 (`A Kerberos authentication ticket (TGT) was requested`), we can identify a request with Pre-Authentication disabled (`PreAuthType` = `0`) and ticket encryption type `0x17` (RC4-HMAC). This event corresponds to Record Number 74 with the timestamp `2024-05-29 06:36:40`.
``` json
{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"arthur.kyle"},{"@Name":"TargetDomainName","#text":"forela.local"},{"@Name":"TargetSid","#text":"S-1-5-21-3239415629-1862073780-2394361899-1601"},{"@Name":"ServiceName","#text":"krbtgt"},{"@Name":"ServiceSid","#text":"S-1-5-21-3239415629-1862073780-2394361899-502"},{"@Name":"TicketOptions","#text":"0x40800010"},{"@Name":"Status","#text":"0x0"},{"@Name":"TicketEncryptionType","#text":"0x17"},{"@Name":"PreAuthType","#text":"0"},{"@Name":"IpAddress","#text":"::ffff:172.17.79.129"},{"@Name":"IpPort","#text":"61965"},{"@Name":"CertIssuerName"},{"@Name":"CertSerialNumber"},{"@Name":"CertThumbprint"}]}}
```

Answer: **2024-05-29 06:36:40**

<br>

### Task 2
#### Question:
Please confirm the User Account that was targeted by the attacker.

#### Answer:
The `TargetUserName` identified in Record Number 74 is `arthur.kyle`.

Answer: **arthur.kyle**

<br>

### Task 3
#### Question:
What was the SID of the account?

#### Answer:
The `TargetSid` of `arthur.kyle` is `S-1-5-21-3239415629-1862073780-2394361899-1601`.

Answer: **S-1-5-21-3239415629-1862073780-2394361899-1601**

<br>

### Task 4
#### Question:
It is crucial to identify the compromised user account and the workstation responsible for this attack. Please list the internal IP address of the compromised asset to assist our threat-hunting team.

#### Answer:
The source IP address (`IpAddress`) recorded in this event is `172.17.79.129`.

Answer: **172.17.79.129**

<br>

### Task 5
#### Question:
We do not have any artifacts from the source machine yet. Using the same DC Security logs, can you confirm the user account used to perform the ASREP Roasting attack so we can contain the compromised account/s?

#### Answer:
Filtering for subsequent activity originating from the compromised machine (`172.17.79.129`) reveals Record Number 75 (Event ID 4769: `A Kerberos service ticket was requested`), which indicates that the account `happy.grunwald` was active on the source workstation.

Answer: **happy.grunwald**