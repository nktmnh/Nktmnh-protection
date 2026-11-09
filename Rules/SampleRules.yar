rule PE_File_Header : triage
{
    strings:
        $mz = { 4D 5A }
    condition:
        $mz
}

rule Suspicious_Windows_Living_Off_The_Land_Strings : triage suspicious
{
    strings:
        $ps = "powershell" nocase
        $cmd = "cmd.exe" nocase
        $rundll32 = "rundll32" nocase
        $regsvr32 = "regsvr32" nocase
        $certutil = "certutil" nocase
    condition:
        any of them
}

rule Suspicious_Process_Injection_Imports : triage suspicious
{
    strings:
        $alloc = "VirtualAlloc" nocase
        $wpm = "WriteProcessMemory" nocase
        $crt = "CreateRemoteThread" nocase
        $gpa = "GetProcAddress" nocase
    condition:
        any of them
}
