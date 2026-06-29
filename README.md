# Advanced-Syscall-And-EDR-Evasion-Research

## Overview

Advanced Windows Syscall Evasion Research Project demonstrating state-of-the-art techniques for bypassing modern Endpoint Detection and Response (EDR) systems on Windows x64 platforms.

This comprehensive proof-of-concept combines multiple advanced techniques including Halo's Gate, Tartarus Gate, Indirect Syscalls, Module Stomping, and APC Injection to achieve stealthy shellcode execution while evading contemporary security controls.

> **Educational Purpose Only** - This project is intended for cybersecurity research, red team operations, and educational purposes. See [DISCLAIMER.md](DISCLAIMER.md) for full details.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Techniques Implemented](#techniques-implemented)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Technical Deep Dive](#technical-deep-dive)
- [EDR Evasion Analysis](#edr-evasion-analysis)
- [Helper Tools](#helper-tools)
- [References](#references)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| **String Encryption** | Implemented | XOR-encrypted sensitive strings (DLL names, API names) to prevent static analysis |
| **Shellcode Encryption** | Implemented | XOR-encrypted payload with runtime decryption to evade memory scans |
| **Halo's Gate** | Implemented | Memory scan for SSN resolution on hooked functions |
| **Tartarus Gate** | Implemented | RVA-sorted fallback for SSN resolution when Halo's Gate fails |
| **Indirect Syscalls** | Implemented | Syscall execution from `ntdll.dll` gadget to evade RIP-based detection |
| **ntdll Unhooking** | Implemented | Restores clean `ntdll.dll` from disk to remove EDR hooks |
| **ETW Patching** | Implemented | Disables Event Tracing for Windows to prevent event logging |
| **AMSI Bypass** | Implemented | Patches `AmsiScanBuffer` to disable memory scanning |
| **Module Stomping** | Implemented | Injects into legitimate DLL's `.text` section for code masquerading |
| **Sleep Obfuscation** | Implemented | Encrypts payload during sleep to evade periodic memory scans |
| **APC Injection** | Implemented | Local APC-based shellcode execution for stealthy code injection |
| **HW Breakpoint Detection** | Implemented | Detects and clears EDR hardware breakpoints |
| **SSN Obfuscation** | Implemented | XOR-obfuscated syscall numbers to prevent static analysis |

---

## Techniques Implemented

### 1. Halo's Gate & Tartarus Gate

**Problem:** EDRs hook the first bytes of `ntdll.dll` syscall stubs, replacing them with JMP instructions to their monitoring code. This prevents direct SSN extraction.

**Solution:** Resolve syscall numbers by analyzing neighboring functions.

#### Halo's Gate
- Scans memory around the hooked function for unhooked neighbors
- Counts the distance to calculate the target SSN
- Works by scanning backwards and forwards in memory

#### Tartarus Gate
- Sorts the export table by RVA (Relative Virtual Address)
- Searches for unhooked neighbors in the sorted list
- Provides a fallback when Halo's Gate fails

### 2. Indirect Syscalls

**Problem:** EDRs monitor the instruction pointer (RIP) during `syscall` execution. If the syscall originates from outside `ntdll.dll`, it's flagged as suspicious.

**Solution:** Execute syscalls from within `ntdll.dll` using a `syscall; ret` gadget.

The gadget is located by scanning `ntdll.dll` for the byte sequence `0F 05 C3` (syscall; ret).

### 3. ntdll Unhooking

**Problem:** EDRs place hooks at the beginning of critical functions in `ntdll.dll` to monitor API calls.

**Solution:** Load a fresh copy of `ntdll.dll` from disk and overwrite the hooked `.text` section in memory.

**Process:**
1. Open `C:\Windows\System32\ntdll.dll` from disk
2. Map the file into memory
3. Locate the `.text` section in both the clean and hooked versions
4. Copy the clean `.text` section over the hooked version
5. Restore memory protection

### 4. ETW & AMSI Bypass

**ETW (Event Tracing for Windows):**
- Patches `EtwEventWrite` in `ntdll.dll` with a `ret` instruction (0xC3)
- Prevents Windows from logging security events to Microsoft Sentinel/Defender
- Stops behavioral analysis and threat detection

**AMSI (Antimalware Scan Interface):**
- Patches `AmsiScanBuffer` in `amsi.dll` with a `ret` instruction
- Disables memory scanning by Windows Defender and other AMSI consumers
- Prevents detection of malicious scripts and payloads

### 5. Module Stomping

**Problem:** Allocating executable memory (PAGE_EXECUTE_READ) is suspicious and monitored by EDRs.

**Solution:** Overwrite the `.text` section of a legitimate DLL with shellcode.

**Process:**
1. Load a legitimate DLL (e.g., `version.dll`)
2. Locate its `.text` section
3. Change memory protection to PAGE_READWRITE
4. Copy shellcode into the `.text` section
5. Restore protection to PAGE_EXECUTE_READ

### 6. APC Injection

**Problem:** Direct thread creation functions like `CreateThread` are heavily monitored.

**Solution:** Use Asynchronous Procedure Calls (APCs) for stealthy code execution.

**Process:**
1. Queue an APC to the current thread using `NtQueueApcThread`
2. Enter alertable sleep state with `SleepEx(1000, TRUE)`
3. The APC executes during the alertable wait
4. Shellcode runs in the context of the current thread

### 7. Sleep Obfuscation

**Problem:** EDRs periodically scan memory for malicious patterns, even during sleep.

**Solution:** Encrypt the shellcode in memory during sleep periods.

### 8. Hardware Breakpoint Detection

**Problem:** EDRs use hardware breakpoints (Dr0-Dr7) to monitor suspicious functions.

**Solution:** Detect and clear hardware breakpoints at startup.

### 9. String & Shellcode Encryption

**String Encryption:**
- All sensitive strings (DLL names, API names) are XOR-encrypted at compile time
- Decrypted at runtime only when needed
- Prevents static analysis from revealing API calls

**Shellcode Encryption:**
- Payload is XOR-encrypted in the binary
- Decrypted in memory just before execution
- Prevents signature-based detection

### 10. SSN Obfuscation

**Problem:** Syscall numbers (SSNs) are visible in the binary and can be used for static analysis.

**Solution:** XOR-obfuscate SSNs at compile time and decrypt at runtime.

---

## Architecture

```
+---------------------------------------------------------+
|                    main.cpp                             |
+---------------------------------------------------------+
|  [0] HW Breakpoint Detection                           |
|  [1] Load ntdll.dll (encrypted string)                 |
|  [2] Unhook ntdll.dll (from disk)                      |
|  [3] Parse Export Table                                |
|  [4] Patch ETW (EtwEventWrite)                         |
|  [5] Patch AMSI (AmsiScanBuffer)                       |
|  [6] Find Syscall Gadget (0F 05 C3)                    |
|  [7] Resolve SSNs (Halo + Tartarus)                    |
|  [8] Decrypt Shellcode                                 |
|  [9] Module Stomping (version.dll)                     |
|  [10] Sleep Obfuscation                                |
|  [11] Queue APC (Indirect Syscall)                     |
|  [12] Trigger Alertable Sleep                          |
+---------------------------------------------------------+
                          |
                          v
+---------------------------------------------------------+
|                 syscalls.asm                            |
+---------------------------------------------------------+
|  IndirectSyscall5 - 5 parameter syscall wrapper         |
|  IndirectSyscall6 - 6 parameter syscall wrapper         |
|  -> Jumps to ntdll!syscall;ret gadget                   |
+---------------------------------------------------------+
```

---

## Prerequisites

- **Operating System**: Windows 10/11 (x64)
- **Compiler**: Visual Studio 2019/2022 with C++ and MASM support
- **Platform**: x64 only (MASM `ml64.exe`)
- **Privileges**: Standard user (no admin required)
- **Dependencies**: None (all APIs resolved manually)

---

## Build Instructions

### Method 1: Visual Studio (Recommended)

1. Open Visual Studio 2022
2. Open the solution file `Advanced-Syscall-And-EDR-Evasion-Research.sln`
3. Verify MASM configuration for `syscalls.asm`:
   - Right-click `syscalls.asm` -> **Properties**
   - **Item Type**: `Microsoft Macro Assembler`
4. Build the solution (Ctrl+Shift+B)

### Method 2: Command Line

```cmd
:: Compile ASM
ml64 /c /Fo syscalls.obj src\syscalls.asm

:: Compile C++
cl /EHsc /c src\main.cpp

:: Link
link main.obj syscalls.obj /OUT:Advanced-Syscall-And-EDR-Evasion-Research.exe
```

### Method 3: CMake

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

---

## Usage

```bash
# Run the executable
Advanced-Syscall-And-EDR-Evasion-Research.exe
```

### Expected Output

```
============================================================
  DEF CON ULTIMATE: All Features Combined
  - HW Breakpoint Detection & Clearing
  - ntdll Unhooking
  - ETW Patching
  - AMSI Bypass
  - SSN Obfuscation
  - Module Stomping
  - Indirect Syscalls
  - Halo/Tartarus Gate
  - String/Shellcode Encryption
  - APC Injection + Sleep Obfuscation
============================================================

[0] Checking for Hardware Breakpoints...
    [+] No Hardware Breakpoints detected.

[1] Loading ntdll.dll...

[2] Unhooking ntdll.dll (removing EDR hooks)...
    [+] ntdll.dll unhooked! (1479578 bytes restored)

[3] Parsing export table (clean ntdll)...
    Found 2516 exports

[4] Patching ETW (EtwEventWrite)...
    [+] ETW patched! EtwEventWrite now returns immediately.

[5] Patching AMSI (AmsiScanBuffer)...
    [+] AMSI patched!

[6] Finding syscall gadget in ntdll.dll...
    Syscall gadget at: 0x00007FFDE85DFBF2

[7] Resolving Syscall Numbers...
    SSNs decrypted at runtime

[8] Decrypting shellcode...

[9] Module Stomping (injecting into version.dll)...
    [+] Module stomped! Shellcode at: 0x00007FFDDEAA1000

[10] Sleep Obfuscation (BEFORE APC queue)...
    [+] Sleep obfuscation complete!

[11] Queueing APC to current thread...
    [+] APC queued successfully!

[12] Triggering alertable sleep to execute APC...
```

---

## Project Structure

```
Advanced-Syscall-And-EDR-Evasion-Research/
|-- src/
|   |-- main.cpp              # Main implementation
|   |-- syscalls.asm          # ASM syscall wrappers
|-- tools/
|   |-- encrypt_strings.ps1   # XOR string encryptor
|   |-- extract_shellcode.ps1 # Shellcode extractor
|-- Advanced-Syscall-And-EDR-Evasion-Research.slnx
|-- Advanced-Syscall-And-EDR-Evasion-Research.vcxproj
|-- Advanced-Syscall-And-EDR-Evasion-Research.vcxproj.filters
|-- README.md                 # This file
|-- DISCLAIMER.md             # Legal disclaimer
|-- LICENSE.md                # MIT License
|-- .gitignore                # Git ignore rules
|-- .gitattributes            # Git attributes
```

---

## Technical Deep Dive

### Halo's Gate Algorithm

```cpp
// 1. Check if function is hooked
if (pFunc[0..3] == "4C 8B D1 B8") {
    return *(PDWORD)(pFunc + 4);  // Direct SSN read
}

// 2. Scan backwards for unhooked neighbor
for (int i = 1; i < 1024; ++i) {
    PBYTE p = pFunc - i;
    if (is_stub_start(p)) {
        if (is_unhooked(p)) {
            return *(PDWORD)(p + 4) + distance;
        }
        distance++;
    }
}

// 3. Scan forwards (similar logic)
```

### Indirect Syscall Flow

```asm
; Instead of direct syscall (suspicious):
mov eax, ssn
syscall              ; <- EDR detects this!

; We use indirect syscall (stealthy):
mov eax, ssn
jmp [ntdll_gadget]   ; <- Jumps to ntdll!syscall;ret
```

### Module Stomping Process

```cpp
// 1. Load legitimate DLL
HMODULE hModule = LoadLibraryA("version.dll");

// 2. Find .text section
PIMAGE_SECTION_HEADER pSection = FindTextSection(hModule);

// 3. Change protection
VirtualProtect(pSection, size, PAGE_READWRITE, &oldProtect);

// 4. Copy shellcode
memcpy(pSection, shellcode, shellcodeSize);

// 5. Restore protection
VirtualProtect(pSection, size, PAGE_EXECUTE_READ, &oldProtect);
```
---

## Helper Tools

The `tools/` directory contains PowerShell scripts to assist with development:

### encrypt_strings.ps1

XOR-encrypts strings for use in the C++ code.

```powershell
# Usage
.\encrypt_strings.ps1
```

### extract_shellcode.ps1

Extracts shellcode from MASM `.obj` files and optionally XOR-encrypts it.

```powershell
# Usage
.\extract_shellcode.ps1 -ObjFile "path\to\file.obj" -Encrypt
```

---

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

---

## Disclaimer

**This project is for educational and research purposes only.**

- **Educational Use**: Learning about Windows internals and EDR evasion
- **Research**: Academic cybersecurity research
- **Defense**: Understanding attack techniques for better defense
- **Red Team**: Authorized penetration testing only

**DO NOT** use this code for:
- Unauthorized access to computer systems
- Malicious activities
- Bypassing security controls without authorization
- Any illegal activities

The authors are not responsible for any misuse of this code. Always obtain proper authorization before testing security controls.

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer.

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

<p align="center">
  <strong>Built for educational purposes. Use responsibly.</strong>
</p>
