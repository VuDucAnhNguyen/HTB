# Port_Scan_Activity
#### Categories: DFIR <br> Difficulty: Easy

## Sherlock Scenario
Can you determine evidences of port scan activity?

Connect to the VM with the credential provided using RDP or SSH From pwnbox use the command

xfreerdp /v:<ipaddress> /u:analyst /p:'123' /cert:ignore /dynamic-resolution 
Log file: Desktop/ChallengeFile/port_scan.pcap

Note: pcap file found public resources.

## Attachments
- `campfire-1.zip`

## Solve
After connecting to the Sherlock machine, I retrieved `port_scan.pcap`, which captures the port scan activity.

<br>

### Task 0
#### Question:
What is the IP address scanning the environment?

#### Answer:
Opening `port_scan.pcap` in Wireshark reveals a high volume of traffic originating from `10.42.42.253` targeting multiple ports on `10.42.42.50`, `10.42.42.56`, and `10.42.42.25`.

Answer: **10.42.42.253**

<br>

### Task 1
#### Question:
What is the IP address found as a result of the scan?

#### Answer:
Applying the display filter `tcp.flags == 0x012` (SYN, ACK) shows responses only from `10.42.42.50`, indicating that this host is active and responsive to the scan.

Answer: **10.42.42.50**

<br>

### Task 2
#### Question:
What is the MAC address of the Apple system it finds?

#### Answer:
Apple's Organizationally Unique Identifier (OUI) prefix is `00:16:CB`. Searching for this string identifies an Apple system with IP `10.42.42.25` and MAC address `00:16:cb:92:6e:dc`.

Answer: **00:16:cb:92:6e:dc**

<br>

### Task 3
#### Question:
What is the MAC address of the Apple system it finds?

#### Answer:
Apple's Organizationally Unique Identifier (OUI) prefix is `00:16:CB`. Searching for this string identifies an Apple system with IP `10.42.42.25` and MAC address `00:16:cb:92:6e:dc`.

Answer: **00:16:cb:92:6e:dc**

<br>

### Task 4
#### Question:
What is the IP address of the detected Windows system?

#### Answer:
The open ports identified on `10.42.42.50` include `135` (MS-RPC) and `139` (NetBIOS Session Service), both of which are characteristic Windows networking services.

Answer: **10.42.42.50**