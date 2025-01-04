#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <vector>
#include <string>

struct SuspiciousProcess {
    std::string name;
    DWORD pid;
};

BOOL IsReadableMemory(LPVOID addr, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return FALSE;

    return (mbi.State == MEM_COMMIT && 
           (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || 
            mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE));
}

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token.\n");
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[-] Failed to lookup debug privilege.\n");
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        printf("[-] Failed to adjust token privileges.\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

BOOL IsAddressInLoadedModules(DWORD_PTR address, DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return FALSE;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                DWORD_PTR moduleStart = (DWORD_PTR)modInfo.lpBaseOfDll;
                DWORD_PTR moduleEnd = moduleStart + modInfo.SizeOfImage;

                if (address >= moduleStart && address <= moduleEnd) {
                    CloseHandle(hProcess);
                    return TRUE;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return FALSE;
}

int DetectIATHooks(DWORD pid) {
    int score = 0;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return score;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)modInfo.lpBaseOfDll;
                if (!IsReadableMemory(dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                    continue;
                }

                PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)modInfo.lpBaseOfDll + dosHeader->e_lfanew);
                if (!IsReadableMemory(ntHeader, sizeof(IMAGE_NT_HEADERS)) || ntHeader->Signature != IMAGE_NT_SIGNATURE) {
                    continue;
                }

                DWORD importDirVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                if (!importDirVA) {
                    continue;
                }

                PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)modInfo.lpBaseOfDll + importDirVA);
                while (IsReadableMemory(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name) {
                    PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)((BYTE*)modInfo.lpBaseOfDll + importDesc->OriginalFirstThunk);
                    PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)modInfo.lpBaseOfDll + importDesc->FirstThunk);

                    while (IsReadableMemory(thunkILT, sizeof(IMAGE_THUNK_DATA)) && thunkILT->u1.AddressOfData) {
                        FARPROC functionAddr = (FARPROC)thunkIAT->u1.Function;
                        if ((DWORD_PTR)functionAddr < (DWORD_PTR)modInfo.lpBaseOfDll ||
                            (DWORD_PTR)functionAddr > ((DWORD_PTR)modInfo.lpBaseOfDll + modInfo.SizeOfImage)) {
                            score += 10;
                        }
                        thunkILT++;
                        thunkIAT++;
                    }
                    importDesc++;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return score;
}

int MonitorThreadContexts(DWORD pid) {
    int score = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return score;
    }

    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
                        if (!IsAddressInLoadedModules(ctx.Rip, pid)) {
                            score += 20;
                        }
#else
                        if (!IsAddressInLoadedModules(ctx.Eip, pid)) {
                            score += 20;
                        }
#endif
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return score;
}

int DetectEATHooks(HMODULE dll) {
    // Detect Export Address Table (EAT) hooks
    int score = 0;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dll;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return score;
    }

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)dll + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return score;
    }

    DWORD exportDirVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirVA) {
        return score;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dll + exportDirVA);
    DWORD* addressOfFunctions = (DWORD*)((BYTE*)dll + exportDir->AddressOfFunctions);
    for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++) {
        FARPROC functionAddr = (FARPROC)((BYTE*)dll + addressOfFunctions[i]);
        if ((DWORD_PTR)functionAddr < (DWORD_PTR)dll ||
            (DWORD_PTR)functionAddr > ((DWORD_PTR)dll + ntHeader->OptionalHeader.SizeOfImage)) {
            score += 10;
        }
    }
    return score;
}

int DetectDLLInjection(DWORD pid) {
    int score = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return score;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            CHAR moduleName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                if (strstr(moduleName, ".dll") && !IsAddressInLoadedModules((DWORD_PTR)hMods[i], pid)) {
                    score += 15;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return score;
}

int CheckLibraryMemoryRegions(HMODULE dll) {
    // Inspect memory regions used by the DLL
    MEMORY_BASIC_INFORMATION mbi;
    int score = 0;
    for (BYTE* addr = (BYTE*)dll; VirtualQuery(addr, &mbi, sizeof(mbi)); addr += mbi.RegionSize) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            score += 5;
        }
    }
    return score;
}

void ScanSystemMemory() {
    printf("[+] Scanning system memory for anomalies...\n");
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = nullptr;

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        // Only consider committed, private memory regions
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            // Check if the reported size is within a reasonable range
            if (mbi.RegionSize > 0 && mbi.RegionSize < 1024 * 1024 * 1024) { // 1 GB limit
                printf("    [!] Anomaly: Private memory region at %p, size: %llu bytes\n", mbi.BaseAddress, mbi.RegionSize);
            } else {
                printf("    [!] Skipped region with unrealistic size at %p (size: %llu bytes)\n", mbi.BaseAddress, mbi.RegionSize);
            }
        }
        addr += mbi.RegionSize;
    }
}


void ValidateMemoryRegions() {
    printf("[+] Validating memory regions for legitimacy...\n");
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = nullptr;

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        // Only consider committed image regions
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
            printf("    [!] Image memory region at %p, size: %llu bytes\n", mbi.BaseAddress, mbi.RegionSize);
        }
        addr += mbi.RegionSize;
    }
}

int main() {
    if (!EnableDebugPrivilege()) {
        printf("[-] Could not enable debug privilege. Some checks may fail.\n");
    }

    printf("[+] Starting rootkit detection scan...\n");

    // Suspicious Processes
    printf("[*] Checking for suspicious processes...\n");
    std::vector<SuspiciousProcess> suspiciousProcesses;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (Process32First(hSnapshot, &pe32)) {
            do {
                int score = 0;
                score += DetectIATHooks(pe32.th32ProcessID);
                score += MonitorThreadContexts(pe32.th32ProcessID);
                score += DetectDLLInjection(pe32.th32ProcessID);

                if (score > 0) {
                    suspiciousProcesses.push_back({ pe32.szExeFile, pe32.th32ProcessID });
                    printf("    [!] Suspicious Process: %s (PID: %lu), Score: %d\n", pe32.szExeFile, pe32.th32ProcessID, score);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // System Memory Scan
    printf("[*] Scanning system memory for anomalies...\n");
    ScanSystemMemory();

    // Memory Region Validation
    printf("[*] Validating memory regions...\n");
    ValidateMemoryRegions();

    // Export Address Table Hooks
    printf("[*] Checking loaded DLLs for EAT hooks...\n");
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            int score = DetectEATHooks(hMods[i]);
            if (score > 0) {
                CHAR moduleName[MAX_PATH];
                GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName));
                printf("    [!] Suspicious DLL: %s, Score: %d\n", moduleName, score);
            }
        }
    }

    // Check Memory Regions of DLLs
    printf("[*] Checking memory regions of loaded DLLs...\n");
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            int score = CheckLibraryMemoryRegions(hMods[i]);
            if (score > 0) {
                CHAR moduleName[MAX_PATH];
                GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName));
                printf("    [!] Anomalous Memory Region in DLL: %s, Score: %d\n", moduleName, score);
            }
        }
    }

    printf("    Memory Scanning Completed.\n");
    printf("    Memory Validation Completed.\n");
    printf("    EAT Hook Checks Completed.\n");
    printf("    DLL Memory Region Checks Completed.\n");

    printf("[+] Rootkit detection scan completed successfully.\n");
    
    return 0;
}
