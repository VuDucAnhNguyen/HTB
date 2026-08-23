# Operation Blackout 2025: Phantom Check
#### Categories: DFIR <br> Difficulty: Very Easy

## Sherlock Scenario
Talion suspects that the threat actor carried out anti-virtualization checks to avoid detection in sandboxed environments. Your task is to analyze the event logs and identify the specific techniques used for virtualization detection. Byte Doctor requires evidence of the registry checks or processes the attacker executed to perform these checks.

## Attachments
- `PhantomCheck.zip`

## Solve
After downloading and extracting the attachment, I obtained 2 powershell logs `Microsoft-Windows-Powershell.evtx` and `Windows-Powershell-Operational.evtx`. Using EvtxECmd to parse to `.csv` format so it can be analyzed using Timeline Explorer or Excel.
```
EvtxECmd.exe -f "Windows-Powershell-Operational.evtx" --csv ".\Output_Folder"
```

<br>

### Task 1
#### Question:
Which WMI class did the attacker use to retrieve model and manufacturer information for virtualization detection?

#### Answer:
Searching for the keywords "Model" and "Manufacturer" reveals two records containing scripts used to query system details.

Record Number 410:
``` powershell
$Manufacturer = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Manufacturer"
```

Record Number 432:
``` powershell
$Model = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Model"
```

Answer: **Win32_ComputerSystem**

<br>

### Task 2
#### Question:
Which WMI query did the attacker execute to retrieve the current temperature value of the machine?

#### Answer:
Searching for the keyword "temperature" reveals a record where the attacker attempts to query the machine's thermal properties. This is typically executed to determine whether an ACPI chip is present (which is generally absent or unpopulated in virtual machine environments).

Record Number 488:
```
Get-WmiObject -Query "SELECT * FROM MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
```

Answer: **SELECT * FROM MSAcpi_ThermalZoneTemperature**

<br>

### Task 3
#### Question:
The attacker loaded a PowerShell script to detect virtualization. What is the function name of the script?

#### Answer:
Filtering by the keyword "VM" shows a script block defining the `Check-VM` function at Record Number 564.

Answer: **Check-VM**

<br>

### Task 4
#### Question:
Which registry key did the above script query to retrieve service details for virtualization detection?

#### Answer:
Inspecting Record Number 564, the script queries the registry key `HKLM:\SYSTEM\ControlSet001\Services` where Windows stores installed services and system drivers. It inspects this path to identify known VM driver signatures (e.g., `vmicheartbeat`, `VMTools`, `VBoxGuest`, `xensvc`).

Answer: **HKLM:\SYSTEM\ControlSet001\Services**

<br>

### Task 5
#### Question:
The VM detection script can also identify VirtualBox. Which processes is it comparing to determine if the system is running VirtualBox?

#### Answer:
Within the `Check-VM` script at Record Number 564, the following check is performed to determine if VirtualBox processes are running:
```
#Virtual Box, $vb = Get-Process, if (($vb -eq ""vboxservice.exe"") -or ($vb -match ""vboxtray.exe""))
```

Answer: **vboxservice.exe, vboxtray.exe**

<br>

### Task 6
#### Question:
The VM detection script prints any detection with the prefix 'This is a'. Which two virtualization platforms did the script detect?

#### Answer:
Searching for the phrase "This is a" leads to Record Number 622 (Event ID 4103), which confirms that both Hyper-V and VMware artifacts were detected by the execution pipeline.
```json
{
  EventData: 
  {
    Data: 
    [
      {
        @Name: ContextInfo,
        #text: "        Severity = Informational,         Host Name = ConsoleHost,         Host Version = 5.1.26100.2161,         Host ID = 0fad0cf8-6cb6-4657-86f7-655ec22eed9f,         Host Application = C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe,         Engine Version = 5.1.26100.2161,         Runspace ID = 2aeeba59-d0f6-4ce7-b41c-e07625b3beec,         Pipeline ID = 43,         Command Name = ,         Command Type = Script,         Script Name = ,         Command Path = ,         Sequence Number = 146,         User = DESKTOP-M3AKJSD\User,         Connected User = ,         Shell ID = Microsoft.PowerShell, "
      },
      {
        @Name: UserData
      },
      {
        @Name: Payload,
        #text: "CommandInvocation(Out-Default): ""Out-Default"", ParameterBinding(Out-Default): name=""InputObject""; value=""This is a Hyper-V machine."", ParameterBinding(Out-Default): name=""InputObject""; value=""This is a VMWare machine."", "
      }
    ]
  }
}
```

Answer: **Hyper-V, VMware**