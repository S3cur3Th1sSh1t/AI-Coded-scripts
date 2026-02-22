/*

- DLL Function Call Tracer (C++)
- Debugs a target process, sets INT3 breakpoints on all exported functions
- of a target DLL, and reports the first 5 unique functions called with
- their first 4 parameters (x64 calling convention: RCX, RDX, R8, R9).
- 
- Timeout: 20 seconds if fewer than 3 functions detected.
- 
- Compile (MSVC):
- cl /EHsc /O2 dll_trace.cpp /link /out:dll_trace.exe
- 
- Compile (MinGW):
- x86_64-w64-mingw32-g++ -O2 -o dll_trace.exe dll_trace.cpp -lpsapi
- 
- Usage:
- dll_trace.exe <exe_path_or_pid> <target_dll>
- dll_trace.exe C:\Windows\notepad.exe kernel32.dll
- dll_trace.exe 4567 ntdll.dll
  */

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <chrono>

#pragma comment(lib, “psapi.lib”)

// ─── Configuration ──────────────────────────────────────────────────────────

static constexpr int    TIMEOUT_SECONDS    = 20;
static constexpr int    TARGET_FUNC_COUNT  = 5;
static constexpr BYTE   INT3_OPCODE        = 0xCC;
static constexpr size_t MAX_EXPORT_FUNCS   = 16384;

// ─── Data Structures ────────────────────────────────────────────────────────

struct FuncCallRecord {
std::string name;
DWORD64     params[4];
};

struct Breakpoint {
BYTE        originalByte;
std::string funcName;
};

// ─── Globals ────────────────────────────────────────────────────────────────

static HANDLE                           g_hProcess      = NULL;
static DWORD                            g_pid           = 0;
static bool                             g_dllResolved   = false;
static bool                             g_initialBpHit  = false;
static DWORD64                          g_dllBase       = 0;
static std::string                      g_targetDll;

static std::map<DWORD64, Breakpoint>    g_breakpoints;
static std::map<DWORD, HANDLE>          g_threadHandles;    // tid -> handle
static std::map<DWORD, DWORD64>         g_singleStep;       // tid -> bp addr to re-enable

static std::vector<FuncCallRecord>      g_results;
static std::set<std::string>            g_calledSet;

// ─── Memory Helpers ─────────────────────────────────────────────────────────

static bool ReadMem(DWORD64 addr, void* buf, SIZE_T size) {
SIZE_T bytesRead = 0;
return ReadProcessMemory(g_hProcess, (LPCVOID)addr, buf, size, &bytesRead) && bytesRead == size;
}

static bool WriteMem(DWORD64 addr, const void* buf, SIZE_T size) {
SIZE_T written = 0;
BOOL ok = WriteProcessMemory(g_hProcess, (LPVOID)addr, buf, size, &written);
FlushInstructionCache(g_hProcess, (LPVOID)addr, size);
return ok && written == size;
}

static DWORD ReadU32(DWORD64 addr) {
DWORD val = 0;
ReadMem(addr, &val, sizeof(val));
return val;
}

static WORD ReadU16(DWORD64 addr) {
WORD val = 0;
ReadMem(addr, &val, sizeof(val));
return val;
}

static DWORD64 ReadPtr(DWORD64 addr) {
DWORD64 val = 0;
ReadMem(addr, &val, sizeof(val));
return val;
}

static std::string ReadCString(DWORD64 addr, size_t maxLen = 256) {
char buf[512] = {0};
size_t toRead = (maxLen < sizeof(buf)) ? maxLen : sizeof(buf) - 1;
SIZE_T bytesRead = 0;
if (!ReadProcessMemory(g_hProcess, (LPCVOID)addr, buf, toRead, &bytesRead))
return “”;
buf[bytesRead] = ‘\0’;
return std::string(buf);
}

// ─── PE Export Parsing ──────────────────────────────────────────────────────

struct ExportEntry {
DWORD64     address;
std::string name;
};

static std::vector<ExportEntry> ParseExports(DWORD64 dllBase) {
std::vector<ExportEntry> exports;

```
// DOS header
WORD dosMagic = ReadU16(dllBase);
if (dosMagic != IMAGE_DOS_SIGNATURE) return exports;

LONG e_lfanew = 0;
ReadMem(dllBase + offsetof(IMAGE_DOS_HEADER, e_lfanew), &e_lfanew, sizeof(e_lfanew));

DWORD64 peOffset = dllBase + e_lfanew;

// PE signature
DWORD peSig = ReadU32(peOffset);
if (peSig != IMAGE_NT_SIGNATURE) return exports;

// Optional header
DWORD64 optOffset = peOffset + 4 + sizeof(IMAGE_FILE_HEADER);
WORD magic = ReadU16(optOffset);

DWORD exportRva = 0, exportSize = 0;
if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    // PE32+: export dir at offset 112 from optional header
    exportRva  = ReadU32(optOffset + 112);
    exportSize = ReadU32(optOffset + 116);
} else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    exportRva  = ReadU32(optOffset + 96);
    exportSize = ReadU32(optOffset + 100);
} else {
    return exports;
}

if (exportRva == 0 || exportSize == 0) return exports;

DWORD64 exportDirAddr = dllBase + exportRva;

IMAGE_EXPORT_DIRECTORY expDir = {0};
if (!ReadMem(exportDirAddr, &expDir, sizeof(expDir)))
    return exports;

if (expDir.NumberOfNames == 0) return exports;

DWORD count = (expDir.NumberOfNames < MAX_EXPORT_FUNCS) ? expDir.NumberOfNames : MAX_EXPORT_FUNCS;

DWORD64 funcsAddr = dllBase + expDir.AddressOfFunctions;
DWORD64 namesAddr = dllBase + expDir.AddressOfNames;
DWORD64 ordsAddr  = dllBase + expDir.AddressOfNameOrdinals;

for (DWORD i = 0; i < count; i++) {
    DWORD nameRva = ReadU32(namesAddr + i * 4);
    if (nameRva == 0) continue;

    std::string name = ReadCString(dllBase + nameRva);
    if (name.empty()) continue;

    WORD ordinal = ReadU16(ordsAddr + i * 2);
    DWORD funcRva = ReadU32(funcsAddr + ordinal * 4);
    if (funcRva == 0) continue;

    // Skip forwarded exports
    if (funcRva >= exportRva && funcRva < exportRva + exportSize)
        continue;

    ExportEntry e;
    e.address = dllBase + funcRva;
    e.name    = name;
    exports.push_back(e);
}

return exports;
```

}

// ─── Breakpoint Management ──────────────────────────────────────────────────

static bool SetBreakpoint(DWORD64 addr, const std::string& funcName) {
BYTE origByte = 0;
if (!ReadMem(addr, &origByte, 1))
return false;

```
Breakpoint bp;
bp.originalByte = origByte;
bp.funcName     = funcName;
g_breakpoints[addr] = bp;

if (origByte != INT3_OPCODE) {
    WriteMem(addr, &INT3_OPCODE, 1);
}
return true;
```

}

static void RestoreBreakpoint(DWORD64 addr) {
auto it = g_breakpoints.find(addr);
if (it != g_breakpoints.end() && it->second.originalByte != INT3_OPCODE) {
WriteMem(addr, &it->second.originalByte, 1);
}
}

static HANDLE GetThreadHandle(DWORD tid) {
auto it = g_threadHandles.find(tid);
if (it != g_threadHandles.end())
return it->second;
HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
if (h) g_threadHandles[tid] = h;
return h;
}

static void ReadParams(HANDLE hThread, DWORD64 params[4]) {
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_FULL;
if (GetThreadContext(hThread, &ctx)) {
params[0] = ctx.Rcx;
params[1] = ctx.Rdx;
params[2] = ctx.R8;
params[3] = ctx.R9;
} else {
memset(params, 0, sizeof(DWORD64) * 4);
}
}

static void SetupSingleStep(HANDLE hThread, DWORD tid, DWORD64 bpAddr) {
auto it = g_breakpoints.find(bpAddr);
if (it == g_breakpoints.end()) return;

```
// Restore original byte
if (it->second.originalByte != INT3_OPCODE) {
    WriteMem(bpAddr, &it->second.originalByte, 1);
}

// Set trap flag
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);
ctx.EFlags |= 0x100; // TF
SetThreadContext(hThread, &ctx);

g_singleStep[tid] = bpAddr;
```

}

static bool HandleSingleStep(DWORD tid) {
auto it = g_singleStep.find(tid);
if (it == g_singleStep.end()) return false;

```
DWORD64 addr = it->second;
g_singleStep.erase(it);

// Re-enable breakpoint
WriteMem(addr, &INT3_OPCODE, 1);
return true;
```

}

// ─── DLL Name Helpers ───────────────────────────────────────────────────────

static std::string ToLower(const std::string& s) {
std::string r = s;
std::transform(r.begin(), r.end(), r.begin(), ::tolower);
return r;
}

static std::string GetBaseName(const std::string& path) {
size_t pos = path.find_last_of(”\/”);
if (pos != std::string::npos)
return path.substr(pos + 1);
return path;
}

static bool DllNameMatches(const std::string& name) {
std::string base = ToLower(GetBaseName(name));
std::string target = g_targetDll;

```
// Ensure target has .dll extension for comparison
std::string targetWithExt = target;
if (targetWithExt.size() < 4 || targetWithExt.substr(targetWithExt.size() - 4) != ".dll")
    targetWithExt += ".dll";

return (base == targetWithExt || base == target);
```

}

static std::string GetDllNameFromEvent(const LOAD_DLL_DEBUG_INFO& info) {
// Try lpImageName
if (info.lpImageName) {
DWORD64 ptr = ReadPtr((DWORD64)info.lpImageName);
if (ptr) {
if (info.fUnicode) {
wchar_t wbuf[MAX_PATH] = {0};
SIZE_T rd = 0;
if (ReadProcessMemory(g_hProcess, (LPCVOID)ptr, wbuf, sizeof(wbuf) - 2, &rd)) {
char nbuf[MAX_PATH] = {0};
WideCharToMultiByte(CP_ACP, 0, wbuf, -1, nbuf, MAX_PATH, NULL, NULL);
if (nbuf[0]) return std::string(nbuf);
}
} else {
std::string name = ReadCString(ptr, MAX_PATH);
if (!name.empty()) return name;
}
}
}

```
// Fallback: GetModuleFileNameExA
if (info.lpBaseOfDll) {
    char buf[MAX_PATH] = {0};
    DWORD ret = GetModuleFileNameExA(g_hProcess, (HMODULE)info.lpBaseOfDll, buf, MAX_PATH);
    if (ret > 0) return std::string(buf);
}

return "";
```

}

// ─── DLL Resolution ─────────────────────────────────────────────────────────

static int SetupBreakpointsOnDll(DWORD64 base, const std::string& source) {
g_dllBase = base;
printf(”[*] Target DLL found at 0x%016llX (%s)\n”, (unsigned long long)base, source.c_str());
printf(”[*] Parsing exports…\n”);

```
auto exports = ParseExports(base);
if (exports.empty()) {
    printf("[-] No exports found in target DLL!\n");
    return 0;
}

printf("[*] Found %zu exported functions\n", exports.size());

int count = 0;
for (auto& e : exports) {
    if (SetBreakpoint(e.address, e.name))
        count++;
}

printf("[+] Set %d breakpoints\n", count);
g_dllResolved = true;
return count;
```

}

static DWORD64 FindDllInModules() {
HMODULE mods[1024];
DWORD needed = 0;

```
if (EnumProcessModulesEx(g_hProcess, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH] = {0};
        if (GetModuleFileNameExA(g_hProcess, mods[i], name, MAX_PATH) > 0) {
            if (DllNameMatches(name))
                return (DWORD64)mods[i];
        }
    }
}
return 0;
```

}

// ─── Output ─────────────────────────────────────────────────────────────────

static void PrintResults() {
printf(”\n======================================================================\n”);
printf(”  DLL FUNCTION CALL TRACE RESULTS\n”);
printf(”======================================================================\n”);
printf(”  Target DLL : %s\n”, g_targetDll.c_str());
if (g_dllBase)
printf(”  DLL Base   : 0x%016llX\n”, (unsigned long long)g_dllBase);
else
printf(”  DLL Base   : (not found)\n”);
printf(”  Functions  : %zu unique calls captured\n”, g_results.size());
printf(”======================================================================\n”);

```
for (size_t i = 0; i < g_results.size(); i++) {
    const auto& r = g_results[i];
    printf("\n  [%zu] %s\n", i + 1, r.name.c_str());
    printf("      Param1 (RCX) = 0x%016llX\n", (unsigned long long)r.params[0]);
    printf("      Param2 (RDX) = 0x%016llX\n", (unsigned long long)r.params[1]);
    printf("      Param3 (R8)  = 0x%016llX\n", (unsigned long long)r.params[2]);
    printf("      Param4 (R9)  = 0x%016llX\n", (unsigned long long)r.params[3]);
}

printf("\n======================================================================\n");
```

}

static void TerminateTarget() {
if (g_hProcess) {
printf(”[*] Terminating process PID=%lu\n”, g_pid);
TerminateProcess(g_hProcess, 0xDEAD);
}
}

// ─── Main Debug Loop ────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
if (argc != 3) {
printf(“Usage: %s <exe_path_or_pid> <target_dll>\n\n”, argv[0]);
printf(“Examples:\n”);
printf(”  %s C:\Windows\notepad.exe kernel32.dll\n”, argv[0]);
printf(”  %s 1234 ntdll.dll\n”, argv[0]);
printf(”  %s .\target.exe mylib.dll\n”, argv[0]);
return 1;
}

```
std::string target = argv[1];
g_targetDll = ToLower(argv[2]);

// Determine: create or attach
bool isAttach = false;
DWORD attachPid = 0;
char* endp = nullptr;
unsigned long val = strtoul(target.c_str(), &endp, 10);
if (endp && *endp == '\0' && val > 0) {
    isAttach = true;
    attachPid = (DWORD)val;
}

if (isAttach) {
    printf("[*] Attaching to PID %lu...\n", attachPid);
    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, attachPid);
    if (!g_hProcess) {
        printf("[-] Failed to open process %lu (error %lu)\n", attachPid, GetLastError());
        return 1;
    }
    if (!DebugActiveProcess(attachPid)) {
        printf("[-] Failed to attach debugger (error %lu)\n", GetLastError());
        return 1;
    }
    DebugSetProcessKillOnExit(FALSE);
    g_pid = attachPid;
    printf("[+] Attached to PID %lu\n", attachPid);
} else {
    printf("[*] Creating process: %s\n", target.c_str());

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(target.c_str(), NULL, NULL, NULL, FALSE,
            DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
            NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create process (error %lu)\n", GetLastError());
        return 1;
    }

    g_hProcess = pi.hProcess;
    g_pid = pi.dwProcessId;
    g_threadHandles[pi.dwThreadId] = pi.hThread;
    DebugSetProcessKillOnExit(TRUE);

    printf("[+] Created process PID=%lu, TID=%lu\n", pi.dwProcessId, pi.dwThreadId);
}

printf("[*] Looking for DLL: %s\n", g_targetDll.c_str());
printf("[*] Timeout: %ds | Target: first %d unique functions\n", TIMEOUT_SECONDS, TARGET_FUNC_COUNT);
printf("======================================================================\n");

auto startTime = std::chrono::steady_clock::now();
DEBUG_EVENT dbgEvent = {0};
bool processExited = false;

while (!processExited) {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - startTime).count();

    if (elapsed >= TIMEOUT_SECONDS) {
        int n = (int)g_results.size();
        if (n < 3) {
            printf("\n[!] Timeout (%ds) with only %d function(s) detected.\n", TIMEOUT_SECONDS, n);
            if (!g_results.empty()) PrintResults();
            TerminateTarget();
            break;
        }
    }

    if (!WaitForDebugEvent(&dbgEvent, 100))
        continue;

    DWORD pid = dbgEvent.dwProcessId;
    DWORD tid = dbgEvent.dwThreadId;
    DWORD code = dbgEvent.dwDebugEventCode;
    DWORD continueStatus = DBG_CONTINUE;

    switch (code) {

    case CREATE_PROCESS_DEBUG_EVENT: {
        auto& info = dbgEvent.u.CreateProcessInfo;
        if (info.hThread)
            g_threadHandles[tid] = info.hThread;
        if (info.hFile)
            CloseHandle(info.hFile);
        break;
    }

    case CREATE_THREAD_DEBUG_EVENT: {
        auto& info = dbgEvent.u.CreateThread;
        if (info.hThread)
            g_threadHandles[tid] = info.hThread;
        break;
    }

    case EXIT_THREAD_DEBUG_EVENT: {
        g_threadHandles.erase(tid);
        g_singleStep.erase(tid);
        break;
    }

    case LOAD_DLL_DEBUG_EVENT: {
        auto& info = dbgEvent.u.LoadDll;
        if (!g_dllResolved) {
            std::string name = GetDllNameFromEvent(info);
            if (DllNameMatches(name)) {
                SetupBreakpointsOnDll((DWORD64)info.lpBaseOfDll, name.empty() ? "unknown" : name);
            }
        }
        if (info.hFile)
            CloseHandle(info.hFile);
        break;
    }

    case EXCEPTION_DEBUG_EVENT: {
        auto& exc = dbgEvent.u.Exception.ExceptionRecord;
        DWORD excCode = exc.ExceptionCode;
        DWORD64 excAddr = (DWORD64)exc.ExceptionAddress;

        if (excCode == EXCEPTION_BREAKPOINT || excCode == STATUS_WX86_BREAKPOINT) {
            if (!g_initialBpHit) {
                g_initialBpHit = true;
                // For attach: check already-loaded modules
                if (!g_dllResolved) {
                    DWORD64 base = FindDllInModules();
                    if (base)
                        SetupBreakpointsOnDll(base, "pre-loaded module");
                }
            }
            else if (g_breakpoints.count(excAddr)) {
                const std::string& funcName = g_breakpoints[excAddr].funcName;

                if (g_calledSet.find(funcName) == g_calledSet.end()) {
                    HANDLE hThread = GetThreadHandle(tid);
                    FuncCallRecord rec;
                    rec.name = funcName;
                    if (hThread)
                        ReadParams(hThread, rec.params);
                    else
                        memset(rec.params, 0, sizeof(rec.params));

                    g_calledSet.insert(funcName);
                    g_results.push_back(rec);

                    int idx = (int)g_results.size();
                    printf("\n[CALL #%d] %s\n", idx, funcName.c_str());
                    printf("  RCX = 0x%016llX  (%llu)\n", (unsigned long long)rec.params[0], (unsigned long long)rec.params[0]);
                    printf("  RDX = 0x%016llX  (%llu)\n", (unsigned long long)rec.params[1], (unsigned long long)rec.params[1]);
                    printf("  R8  = 0x%016llX  (%llu)\n", (unsigned long long)rec.params[2], (unsigned long long)rec.params[2]);
                    printf("  R9  = 0x%016llX  (%llu)\n", (unsigned long long)rec.params[3], (unsigned long long)rec.params[3]);

                    if (idx >= TARGET_FUNC_COUNT) {
                        printf("\n[+] Reached %d unique functions!\n", TARGET_FUNC_COUNT);
                        PrintResults();
                        TerminateTarget();
                        processExited = true;
                        ContinueDebugEvent(pid, tid, continueStatus);
                        continue;
                    }
                }

                // Single-step past the breakpoint
                HANDLE hThread = GetThreadHandle(tid);
                if (hThread) {
                    // Rewind RIP
                    CONTEXT ctx = {0};
                    ctx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThread, &ctx);
                    ctx.Rip = excAddr;
                    SetThreadContext(hThread, &ctx);

                    SetupSingleStep(hThread, tid, excAddr);
                }
            } else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
        }
        else if (excCode == EXCEPTION_SINGLE_STEP || excCode == STATUS_WX86_SINGLE_STEP) {
            if (!HandleSingleStep(tid))
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }
        else {
            if (dbgEvent.u.Exception.dwFirstChance)
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            else {
                printf("[!] Unhandled exception 0x%08X at 0x%016llX\n",
                       excCode, (unsigned long long)excAddr);
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
        }
        break;
    }

    case EXIT_PROCESS_DEBUG_EVENT: {
        printf("\n[*] Process exited with code %lu\n", dbgEvent.u.ExitProcess.dwExitCode);
        processExited = true;
        break;
    }

    default:
        break;
    }

    ContinueDebugEvent(pid, tid, continueStatus);
}

if (!processExited && !g_results.empty())
    PrintResults();

return 0;
```

}
