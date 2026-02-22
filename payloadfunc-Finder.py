#!/usr/bin/env python3
"""
DLL Function Call Tracer
Debugs a target process, sets breakpoints on all exported functions of a target DLL,
and reports the first 5 unique functions called with their parameters.
Timeout: 20 seconds if fewer than 3 functions are detected.

Usage:
    python dll_trace.py <exe_path_or_pid> <target_dll>
    python dll_trace.py C:\Windows\notepad.exe kernel32.dll
    python dll_trace.py 1234 ntdll.dll
"""

import sys
import os
import struct
import time
import ctypes
import ctypes.wintypes as wt
from ctypes import (
    Structure, Union, POINTER, byref, sizeof, c_void_p, c_size_t,
    c_ulonglong, c_ulong, c_ubyte, c_char, c_uint16, c_uint32, c_int32,
    windll, WinError, GetLastError, create_string_buffer
)

# ─── Constants ───────────────────────────────────────────────────────────────

INFINITE                    = 0xFFFFFFFF
DEBUG_PROCESS               = 0x00000001
DEBUG_ONLY_THIS_PROCESS     = 0x00000002
CREATE_NEW_CONSOLE          = 0x00000010
PROCESS_ALL_ACCESS          = 0x001F0FFF
THREAD_ALL_ACCESS           = 0x001F03FF
CONTEXT_FULL                = 0x10000B
CONTEXT_DEBUG_REGISTERS     = 0x00100010
MEM_COMMIT                  = 0x1000
PAGE_READWRITE              = 0x04

# Debug event codes
EXCEPTION_DEBUG_EVENT       = 1
CREATE_THREAD_DEBUG_EVENT   = 2
CREATE_PROCESS_DEBUG_EVENT  = 3
EXIT_THREAD_DEBUG_EVENT     = 4
EXIT_PROCESS_DEBUG_EVENT    = 5
LOAD_DLL_DEBUG_EVENT        = 6
UNLOAD_DLL_DEBUG_EVENT      = 7
OUTPUT_DEBUG_STRING_EVENT   = 8

# Exception codes
EXCEPTION_BREAKPOINT        = 0x80000003
EXCEPTION_SINGLE_STEP       = 0x80000004
STATUS_WX86_BREAKPOINT      = 0x4000001F
STATUS_WX86_SINGLE_STEP     = 0x4000001E

DBG_CONTINUE                = 0x00010002
DBG_EXCEPTION_NOT_HANDLED   = 0x80010001

EXCEPTION_MAXIMUM_PARAMETERS = 15
MAX_PATH = 260
INT3 = b'\xCC'

TIMEOUT_SECONDS = 20
TARGET_FUNC_COUNT = 5

# ─── Structures ──────────────────────────────────────────────────────────────

class STARTUPINFOA(Structure):
    _fields_ = [
        ("cb",              c_ulong),
        ("lpReserved",      ctypes.c_char_p),
        ("lpDesktop",       ctypes.c_char_p),
        ("lpTitle",         ctypes.c_char_p),
        ("dwX",             c_ulong),
        ("dwY",             c_ulong),
        ("dwXSize",         c_ulong),
        ("dwYSize",         c_ulong),
        ("dwXCountChars",   c_ulong),
        ("dwYCountChars",   c_ulong),
        ("dwFillAttribute", c_ulong),
        ("dwFlags",         c_ulong),
        ("wShowWindow",     c_uint16),
        ("cbReserved2",     c_uint16),
        ("lpReserved2",     POINTER(c_ubyte)),
        ("hStdInput",       c_void_p),
        ("hStdOutput",      c_void_p),
        ("hStdError",       c_void_p),
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    c_void_p),
        ("hThread",     c_void_p),
        ("dwProcessId", c_ulong),
        ("dwThreadId",  c_ulong),
    ]

class EXCEPTION_RECORD(Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode",           c_ulong),
    ("ExceptionFlags",          c_ulong),
    ("ExceptionRecord",         POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",        c_void_p),
    ("NumberParameters",        c_ulong),
    ("ExceptionInformation",    c_ulonglong * EXCEPTION_MAXIMUM_PARAMETERS),
]

class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance",   c_ulong),
    ]

class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile",                   c_void_p),
        ("hProcess",                c_void_p),
        ("hThread",                 c_void_p),
        ("lpBaseOfImage",           c_void_p),
        ("dwDebugInfoFileOffset",   c_ulong),
        ("nDebugInfoSize",          c_ulong),
        ("lpThreadLocalBase",       c_void_p),
        ("lpStartAddress",          c_void_p),
        ("lpImageName",             c_void_p),
        ("fUnicode",                c_uint16),
    ]

class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile",                   c_void_p),
        ("lpBaseOfDll",             c_void_p),
        ("dwDebugInfoFileOffset",   c_ulong),
        ("nDebugInfoSize",          c_ulong),
        ("lpImageName",             c_void_p),
        ("fUnicode",                c_uint16),
    ]

class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", c_ulong),
    ]

class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread",             c_void_p),
        ("lpThreadLocalBase",   c_void_p),
        ("lpStartAddress",      c_void_p),
    ]

class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", c_ulong),
    ]

class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData",   c_void_p),
        ("fUnicode",            c_uint16),
        ("nDebugStringLength",  c_uint16),
    ]

class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", c_void_p),
    ]

class _DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",           EXCEPTION_DEBUG_INFO),
        ("CreateThread",        CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo",   CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread",          EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess",         EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll",             LOAD_DLL_DEBUG_INFO),
        ("UnloadDll",           UNLOAD_DLL_DEBUG_INFO),
        ("DebugString",         OUTPUT_DEBUG_STRING_INFO),
    ]

class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode",   c_ulong),
        ("dwProcessId",        c_ulong),
        ("dwThreadId",         c_ulong),
        ("u",                  _DEBUG_EVENT_UNION),
    ]

class M128A(Structure):
    _fields_ = [
        ("Low",  c_ulonglong),
        ("High", c_ulonglong),
    ]

class CONTEXT64(Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home",              c_ulonglong),
        ("P2Home",              c_ulonglong),
        ("P3Home",              c_ulonglong),
        ("P4Home",              c_ulonglong),
        ("P5Home",              c_ulonglong),
        ("P6Home",              c_ulonglong),
        ("ContextFlags",        c_ulong),
        ("MxCsr",               c_ulong),
        ("SegCs",               c_uint16),
        ("SegDs",               c_uint16),
        ("SegEs",               c_uint16),
        ("SegFs",               c_uint16),
        ("SegGs",               c_uint16),
        ("SegSs",               c_uint16),
        ("EFlags",              c_ulong),
        ("Dr0",                 c_ulonglong),
        ("Dr1",                 c_ulonglong),
        ("Dr2",                 c_ulonglong),
        ("Dr3",                 c_ulonglong),
        ("Dr6",                 c_ulonglong),
        ("Dr7",                 c_ulonglong),
        ("Rax",                 c_ulonglong),
        ("Rcx",                 c_ulonglong),
        ("Rdx",                 c_ulonglong),
        ("Rbx",                 c_ulonglong),
        ("Rsp",                 c_ulonglong),
        ("Rbp",                 c_ulonglong),
        ("Rsi",                 c_ulonglong),
        ("Rdi",                 c_ulonglong),
        ("R8",                  c_ulonglong),
        ("R9",                  c_ulonglong),
        ("R10",                 c_ulonglong),
        ("R11",                 c_ulonglong),
        ("R12",                 c_ulonglong),
        ("R13",                 c_ulonglong),
        ("R14",                 c_ulonglong),
        ("R15",                 c_ulonglong),
        ("Rip",                 c_ulonglong),
        ("FltSave",             c_ubyte * 512),
        ("VectorRegister",      M128A * 26),
        ("VectorControl",       c_ulonglong),
        ("DebugControl",        c_ulonglong),
        ("LastBranchToRip",     c_ulonglong),
        ("LastBranchFromRip",   c_ulonglong),
        ("LastExceptionToRip",  c_ulonglong),
        ("LastExceptionFromRip",c_ulonglong),
    ]

# ─── PE Parsing Structures ──────────────────────────────────────────────────

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ("e_magic",    c_uint16),
        ("e_cblp",     c_uint16),
        ("e_cp",       c_uint16),
        ("e_crlc",     c_uint16),
        ("e_cparhdr",  c_uint16),
        ("e_minalloc", c_uint16),
        ("e_maxalloc", c_uint16),
        ("e_ss",       c_uint16),
        ("e_sp",       c_uint16),
        ("e_csum",     c_uint16),
        ("e_ip",       c_uint16),
        ("e_cs",       c_uint16),
        ("e_lfarlc",   c_uint16),
        ("e_ovno",     c_uint16),
        ("e_res",      c_uint16 * 4),
        ("e_oemid",    c_uint16),
        ("e_oeminfo",  c_uint16),
        ("e_res2",     c_uint16 * 10),
        ("e_lfanew",   c_int32),
    ]

class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ("Characteristics",       c_uint32),
        ("TimeDateStamp",         c_uint32),
        ("MajorVersion",          c_uint16),
        ("MinorVersion",          c_uint16),
        ("Name",                  c_uint32),
        ("Base",                  c_uint32),
        ("NumberOfFunctions",     c_uint32),
        ("NumberOfNames",         c_uint32),
        ("AddressOfFunctions",    c_uint32),
        ("AddressOfNames",        c_uint32),
        ("AddressOfNameOrdinals", c_uint32),
    ]

# ─── API Bindings ────────────────────────────────────────────────────────────

kernel32 = windll.kernel32
psapi    = windll.psapi

kernel32.CreateProcessA.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, c_void_p, c_void_p,
    wt.BOOL, c_ulong, c_void_p, ctypes.c_char_p,
    POINTER(STARTUPINFOA), POINTER(PROCESS_INFORMATION)
]
kernel32.CreateProcessA.restype = wt.BOOL

kernel32.DebugActiveProcess.argtypes = [c_ulong]
kernel32.DebugActiveProcess.restype = wt.BOOL

kernel32.WaitForDebugEvent.argtypes = [POINTER(DEBUG_EVENT), c_ulong]
kernel32.WaitForDebugEvent.restype = wt.BOOL

kernel32.ContinueDebugEvent.argtypes = [c_ulong, c_ulong, c_ulong]
kernel32.ContinueDebugEvent.restype = wt.BOOL

kernel32.ReadProcessMemory.argtypes = [
    c_void_p, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)
]
kernel32.ReadProcessMemory.restype = wt.BOOL

kernel32.WriteProcessMemory.argtypes = [
    c_void_p, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)
]
kernel32.WriteProcessMemory.restype = wt.BOOL

kernel32.GetThreadContext.argtypes = [c_void_p, POINTER(CONTEXT64)]
kernel32.GetThreadContext.restype = wt.BOOL

kernel32.SetThreadContext.argtypes = [c_void_p, POINTER(CONTEXT64)]
kernel32.SetThreadContext.restype = wt.BOOL

kernel32.OpenThread.argtypes = [c_ulong, wt.BOOL, c_ulong]
kernel32.OpenThread.restype = c_void_p

kernel32.OpenProcess.argtypes = [c_ulong, wt.BOOL, c_ulong]
kernel32.OpenProcess.restype = c_void_p

kernel32.TerminateProcess.argtypes = [c_void_p, c_ulong]
kernel32.TerminateProcess.restype = wt.BOOL

kernel32.CloseHandle.argtypes = [c_void_p]
kernel32.CloseHandle.restype = wt.BOOL

kernel32.FlushInstructionCache.argtypes = [c_void_p, c_void_p, c_size_t]
kernel32.FlushInstructionCache.restype = wt.BOOL

kernel32.DebugSetProcessKillOnExit.argtypes = [wt.BOOL]
kernel32.DebugSetProcessKillOnExit.restype = wt.BOOL

kernel32.GetModuleFileNameExA = psapi.GetModuleFileNameExA
kernel32.GetModuleFileNameExA.argtypes = [c_void_p, c_void_p, ctypes.c_char_p, c_ulong]
kernel32.GetModuleFileNameExA.restype = c_ulong

psapi.EnumProcessModulesEx.argtypes = [
    c_void_p, POINTER(c_void_p), c_ulong, POINTER(c_ulong), c_ulong
]
psapi.EnumProcessModulesEx.restype = wt.BOOL

# ─── Helper Functions ────────────────────────────────────────────────────────

def read_mem(h_process, address, size):
    """Read process memory, return bytes or None."""
    buf = create_string_buffer(size)
    read = c_size_t(0)
    if kernel32.ReadProcessMemory(h_process, c_void_p(address), buf, size, byref(read)):
        return buf.raw[:read.value]
    return None

def write_mem(h_process, address, data):
    """Write bytes to process memory."""
    written = c_size_t(0)
    buf = ctypes.create_string_buffer(data, len(data))
    ret = kernel32.WriteProcessMemory(h_process, c_void_p(address), buf, len(data), byref(written))
    kernel32.FlushInstructionCache(h_process, c_void_p(address), len(data))
    return ret

def read_cstring(h_process, address, max_len=256):
    """Read a null-terminated C string from process memory."""
    data = read_mem(h_process, address, max_len)
    if data is None:
        return None
    idx = data.find(b'\x00')
    if idx >= 0:
        data = data[:idx]
    return data.decode('ascii', errors='replace')

def read_ptr(h_process, address):
    """Read a 64-bit pointer from process memory."""
    data = read_mem(h_process, address, 8)
    if data and len(data) == 8:
        return struct.unpack('<Q', data)[0]
    return None

def read_u32(h_process, address):
    """Read a 32-bit unsigned integer."""
    data = read_mem(h_process, address, 4)
    if data and len(data) == 4:
        return struct.unpack('<I', data)[0]
    return None

def read_u16(h_process, address):
    """Read a 16-bit unsigned integer."""
    data = read_mem(h_process, address, 2)
    if data and len(data) == 2:
        return struct.unpack('<H', data)[0]
    return None

# ─── PE Export Parsing ───────────────────────────────────────────────────────

def parse_exports(h_process, dll_base):
    """Parse PE export directory from loaded DLL in process memory.
    Returns dict of {function_rva_address: function_name}."""
    exports = {}

    # DOS header
    dos_data = read_mem(h_process, dll_base, sizeof(IMAGE_DOS_HEADER))
    if not dos_data or len(dos_data) < sizeof(IMAGE_DOS_HEADER):
        return exports
    dos = IMAGE_DOS_HEADER.from_buffer_copy(dos_data)
    if dos.e_magic != 0x5A4D:
        return exports

    pe_offset = dll_base + dos.e_lfanew

    # PE signature + file header + optional header magic
    pe_sig = read_u32(h_process, pe_offset)
    if pe_sig != 0x00004550:  # "PE\0\0"
        return exports

    # Optional header starts at pe_offset + 4 (sig) + 20 (file header)
    opt_offset = pe_offset + 24
    magic = read_u16(h_process, opt_offset)

    if magic == 0x20B:  # PE32+ (64-bit)
        # Export directory RVA is at offset 112 from optional header start
        export_rva = read_u32(h_process, opt_offset + 112)
        export_size = read_u32(h_process, opt_offset + 116)
    elif magic == 0x10B:  # PE32 (32-bit)
        export_rva = read_u32(h_process, opt_offset + 96)
        export_size = read_u32(h_process, opt_offset + 100)
    else:
        return exports

    if export_rva == 0 or export_size == 0:
        return exports

    export_dir_addr = dll_base + export_rva

    # Read export directory
    ed_data = read_mem(h_process, export_dir_addr, sizeof(IMAGE_EXPORT_DIRECTORY))
    if not ed_data or len(ed_data) < sizeof(IMAGE_EXPORT_DIRECTORY):
        return exports
    ed = IMAGE_EXPORT_DIRECTORY.from_buffer_copy(ed_data)

    if ed.NumberOfNames == 0:
        return exports

    # Read arrays
    funcs_addr   = dll_base + ed.AddressOfFunctions
    names_addr   = dll_base + ed.AddressOfNames
    ords_addr    = dll_base + ed.AddressOfNameOrdinals

    for i in range(min(ed.NumberOfNames, 8192)):  # safety cap
        # Name RVA
        name_rva = read_u32(h_process, names_addr + i * 4)
        if name_rva is None:
            continue
        name = read_cstring(h_process, dll_base + name_rva)
        if not name:
            continue

        # Ordinal
        ordinal = read_u16(h_process, ords_addr + i * 2)
        if ordinal is None:
            continue

        # Function RVA
        func_rva = read_u32(h_process, funcs_addr + ordinal * 4)
        if func_rva is None or func_rva == 0:
            continue

        # Skip forwarded exports (RVA points inside export directory)
        if export_rva <= func_rva < export_rva + export_size:
            continue

        func_addr = dll_base + func_rva
        exports[func_addr] = name

    return exports

# ─── DLL Name Resolution ────────────────────────────────────────────────────

def get_dll_name_from_event(h_process, load_info):
    """Try to resolve DLL name from LOAD_DLL_DEBUG_INFO."""
    # Try lpImageName (pointer to pointer to string)
    if load_info.lpImageName:
        ptr = read_ptr(h_process, load_info.lpImageName)
        if ptr and ptr != 0:
            if load_info.fUnicode:
                data = read_mem(h_process, ptr, 520)
                if data:
                    try:
                        name = data.decode('utf-16-le').split('\x00')[0]
                        if name:
                            return name
                    except:
                        pass
            else:
                name = read_cstring(h_process, ptr, 260)
                if name:
                    return name

    # Try GetModuleFileNameExA
    if load_info.lpBaseOfDll:
        buf = ctypes.create_string_buffer(MAX_PATH)
        ret = kernel32.GetModuleFileNameExA(h_process, load_info.lpBaseOfDll, buf, MAX_PATH)
        if ret > 0:
            return buf.value.decode('ascii', errors='replace')

    return None

# ─── Breakpoint Manager ─────────────────────────────────────────────────────

class BreakpointManager:
    def __init__(self, h_process):
        self.h_process = h_process
        self.breakpoints = {}       # addr -> (original_byte, func_name)
        self.single_step = {}       # tid -> addr (bp to re-enable after single step)

    def set_bp(self, addr, func_name):
        """Set INT3 breakpoint at address."""
        orig = read_mem(self.h_process, addr, 1)
        if orig is None:
            return False
        if orig == INT3:
            # Already an INT3
            self.breakpoints[addr] = (orig, func_name)
            return True
        self.breakpoints[addr] = (orig, func_name)
        write_mem(self.h_process, addr, INT3)
        return True

    def remove_bp(self, addr):
        """Remove breakpoint, restore original byte."""
        if addr in self.breakpoints:
            orig, _ = self.breakpoints[addr]
            if orig != INT3:
                write_mem(self.h_process, addr, orig)

    def is_our_bp(self, addr):
        return addr in self.breakpoints

    def get_func_name(self, addr):
        if addr in self.breakpoints:
            return self.breakpoints[addr][1]
        return None

    def setup_single_step(self, h_thread, tid, bp_addr):
        """Restore original byte, enable TF for single-step, remember to re-enable."""
        if bp_addr not in self.breakpoints:
            return
        orig, _ = self.breakpoints[bp_addr]
        if orig != INT3:
            write_mem(self.h_process, bp_addr, orig)

        # Set trap flag
        ctx = CONTEXT64()
        ctx.ContextFlags = CONTEXT_FULL
        kernel32.GetThreadContext(h_thread, byref(ctx))
        ctx.EFlags |= 0x100  # TF
        kernel32.SetThreadContext(h_thread, byref(ctx))

        self.single_step[tid] = bp_addr

    def handle_single_step(self, tid):
        """Re-enable breakpoint after single step."""
        if tid in self.single_step:
            addr = self.single_step.pop(tid)
            write_mem(self.h_process, addr, INT3)
            return True
        return False

    def set_all(self, export_map):
        """Set breakpoints on all exports. Returns count."""
        count = 0
        for addr, name in export_map.items():
            if self.set_bp(addr, name):
                count += 1
        return count

# ─── Main Debugger ───────────────────────────────────────────────────────────

class DllTracer:
    def __init__(self, target, dll_name):
        self.target = target
        self.dll_name = dll_name.lower()
        self.h_process = None
        self.pid = 0
        self.main_tid = 0
        self.thread_handles = {}   # tid -> handle
        self.bp_mgr = None
        self.dll_base = None
        self.dll_resolved = False
        self.initial_bp_hit = False

        # Results
        self.called_functions = []  # list of (name, [param1..4])
        self.called_set = set()

    def create_or_attach(self):
        """Create process or attach to PID."""
        try:
            pid = int(self.target)
            # Attach to existing process
            print(f"[*] Attaching to PID {pid}...")
            self.h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not self.h_process:
                print(f"[-] Failed to open process {pid}: {WinError(GetLastError())}")
                return False
            if not kernel32.DebugActiveProcess(pid):
                print(f"[-] Failed to attach debugger: {WinError(GetLastError())}")
                return False
            kernel32.DebugSetProcessKillOnExit(False)
            self.pid = pid
            print(f"[+] Attached to PID {pid}")
            return True
        except ValueError:
            pass

        # Create new process
        print(f"[*] Creating process: {self.target}")
        si = STARTUPINFOA()
        si.cb = sizeof(si)
        pi = PROCESS_INFORMATION()

        target_bytes = self.target.encode('ascii') if isinstance(self.target, str) else self.target

        if not kernel32.CreateProcessA(
            target_bytes, None, None, None, False,
            DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
            None, None, byref(si), byref(pi)
        ):
            print(f"[-] Failed to create process: {WinError(GetLastError())}")
            return False

        self.h_process = pi.hProcess
        self.pid = pi.dwProcessId
        self.main_tid = pi.dwThreadId
        self.thread_handles[pi.dwThreadId] = pi.hThread
        kernel32.DebugSetProcessKillOnExit(True)
        print(f"[+] Created process PID={self.pid}, TID={self.main_tid}")
        return True

    def check_dll_match(self, name):
        """Check if a DLL name matches our target."""
        if not name:
            return False
        basename = os.path.basename(name).lower()
        # Match with or without extension
        target = self.dll_name
        if not target.endswith('.dll'):
            target += '.dll'
        return basename == target or basename == self.dll_name

    def resolve_dll_from_modules(self):
        """Enumerate loaded modules to find target DLL (for attach scenario)."""
        mod_array = (c_void_p * 1024)()
        needed = c_ulong(0)
        LIST_MODULES_ALL = 0x03

        if psapi.EnumProcessModulesEx(
            self.h_process, mod_array, sizeof(mod_array), byref(needed), LIST_MODULES_ALL
        ):
            count = needed.value // ctypes.sizeof(c_void_p)
            for i in range(count):
                hmod = mod_array[i]
                buf = ctypes.create_string_buffer(MAX_PATH)
                ret = kernel32.GetModuleFileNameExA(self.h_process, hmod, buf, MAX_PATH)
                if ret > 0:
                    name = buf.value.decode('ascii', errors='replace')
                    if self.check_dll_match(name):
                        return hmod
        return None

    def get_thread_handle(self, tid):
        """Get or open a thread handle."""
        if tid in self.thread_handles:
            return self.thread_handles[tid]
        h = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
        if h:
            self.thread_handles[tid] = h
        return h

    def read_params(self, h_thread):
        """Read first 4 parameters from thread context (x64 calling convention)."""
        ctx = CONTEXT64()
        ctx.ContextFlags = CONTEXT_FULL
        if not kernel32.GetThreadContext(h_thread, byref(ctx)):
            return [0, 0, 0, 0]
        return [ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9]

    def setup_breakpoints_on_dll(self, base, source=""):
        """Parse exports and set breakpoints."""
        self.dll_base = base
        print(f"[*] Target DLL found at 0x{base:016X} ({source})")
        print(f"[*] Parsing exports...")

        exports = parse_exports(self.h_process, base)
        if not exports:
            print(f"[-] No exports found in target DLL!")
            return 0

        print(f"[*] Found {len(exports)} exported functions")
        count = self.bp_mgr.set_all(exports)
        print(f"[+] Set {count} breakpoints")
        self.dll_resolved = True
        return count

    def run(self):
        """Main debug loop."""
        if not self.create_or_attach():
            return

        self.bp_mgr = BreakpointManager(self.h_process)
        start_time = time.time()
        debug_event = DEBUG_EVENT()
        process_exited = False

        print(f"[*] Looking for DLL: {self.dll_name}")
        print(f"[*] Timeout: {TIMEOUT_SECONDS}s | Target: first {TARGET_FUNC_COUNT} unique functions")
        print(f"{'='*70}")

        while not process_exited:
            elapsed = time.time() - start_time

            # Timeout check
            if elapsed >= TIMEOUT_SECONDS:
                n = len(self.called_functions)
                if n < 3:
                    print(f"\n[!] Timeout ({TIMEOUT_SECONDS}s) with only {n} function(s) detected.")
                    print(f"[*] Terminating process...")
                    self.terminate()
                    break

            # Use 100ms wait so we can check timeout
            if not kernel32.WaitForDebugEvent(byref(debug_event), 100):
                continue

            pid = debug_event.dwProcessId
            tid = debug_event.dwThreadId
            code = debug_event.dwDebugEventCode
            continue_status = DBG_CONTINUE

            if code == CREATE_PROCESS_DEBUG_EVENT:
                info = debug_event.u.CreateProcessInfo
                if info.hThread:
                    self.thread_handles[tid] = info.hThread
                # Check if main exe contains our target (unlikely but handle it)
                if info.hFile:
                    kernel32.CloseHandle(info.hFile)

            elif code == CREATE_THREAD_DEBUG_EVENT:
                info = debug_event.u.CreateThread
                if info.hThread:
                    self.thread_handles[tid] = info.hThread

            elif code == EXIT_THREAD_DEBUG_EVENT:
                if tid in self.thread_handles:
                    # Don't close - debug events own these handles
                    del self.thread_handles[tid]

            elif code == LOAD_DLL_DEBUG_EVENT:
                info = debug_event.u.LoadDll
                if not self.dll_resolved:
                    name = get_dll_name_from_event(self.h_process, info)
                    if self.check_dll_match(name):
                        self.setup_breakpoints_on_dll(info.lpBaseOfDll, name or "unknown")
                    elif name:
                        # Print loaded DLLs for debugging
                        pass  # print(f"    Loaded: {os.path.basename(name)}")
                if info.hFile:
                    kernel32.CloseHandle(info.hFile)

            elif code == EXCEPTION_DEBUG_EVENT:
                exc = debug_event.u.Exception.ExceptionRecord
                exc_code = exc.ExceptionCode
                exc_addr = exc.ExceptionAddress

                if exc_code in (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT):
                    if not self.initial_bp_hit:
                        # Initial system breakpoint
                        self.initial_bp_hit = True
                        # For attach: try to find DLL in already-loaded modules
                        if not self.dll_resolved:
                            base = self.resolve_dll_from_modules()
                            if base:
                                self.setup_breakpoints_on_dll(base, "pre-loaded module")

                    elif self.bp_mgr.is_our_bp(exc_addr):
                        func_name = self.bp_mgr.get_func_name(exc_addr)

                        if func_name not in self.called_set:
                            h_thread = self.get_thread_handle(tid)
                            params = self.read_params(h_thread) if h_thread else [0,0,0,0]

                            self.called_set.add(func_name)
                            self.called_functions.append((func_name, params))
                            idx = len(self.called_functions)

                            print(f"\n[CALL #{idx}] {func_name}")
                            print(f"  RCX = 0x{params[0]:016X}  ({params[0]})")
                            print(f"  RDX = 0x{params[1]:016X}  ({params[1]})")
                            print(f"  R8  = 0x{params[2]:016X}  ({params[2]})")
                            print(f"  R9  = 0x{params[3]:016X}  ({params[3]})")

                            if idx >= TARGET_FUNC_COUNT:
                                print(f"\n[+] Reached {TARGET_FUNC_COUNT} unique functions!")
                                self.print_results()
                                self.terminate()
                                process_exited = True
                                kernel32.ContinueDebugEvent(pid, tid, continue_status)
                                continue

                        # Single-step past breakpoint
                        h_thread = self.get_thread_handle(tid)
                        if h_thread:
                            # Rewind RIP (it advanced past INT3)
                            ctx = CONTEXT64()
                            ctx.ContextFlags = CONTEXT_FULL
                            kernel32.GetThreadContext(h_thread, byref(ctx))
                            ctx.Rip = exc_addr  # back to the BP address
                            kernel32.SetThreadContext(h_thread, byref(ctx))

                            self.bp_mgr.setup_single_step(h_thread, tid, exc_addr)
                    else:
                        # Not our breakpoint
                        continue_status = DBG_EXCEPTION_NOT_HANDLED

                elif exc_code in (EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
                    if not self.bp_mgr.handle_single_step(tid):
                        continue_status = DBG_EXCEPTION_NOT_HANDLED
                else:
                    # Other exception
                    if debug_event.u.Exception.dwFirstChance:
                        continue_status = DBG_EXCEPTION_NOT_HANDLED
                    else:
                        print(f"[!] Unhandled exception 0x{exc_code:08X} at 0x{exc_addr:016X}")
                        continue_status = DBG_EXCEPTION_NOT_HANDLED

            elif code == EXIT_PROCESS_DEBUG_EVENT:
                exit_code = debug_event.u.ExitProcess.dwExitCode
                print(f"\n[*] Process exited with code {exit_code}")
                process_exited = True

            kernel32.ContinueDebugEvent(pid, tid, continue_status)

        if not process_exited and self.called_functions:
            self.print_results()

    def print_results(self):
        """Print summary of results."""
        print(f"\n{'='*70}")
        print(f"  DLL FUNCTION CALL TRACE RESULTS")
        print(f"{'='*70}")
        print(f"  Target DLL : {self.dll_name}")
        print(f"  DLL Base   : 0x{self.dll_base:016X}" if self.dll_base else "  DLL Base   : (not found)")
        print(f"  Functions  : {len(self.called_functions)} unique calls captured")
        print(f"{'='*70}")

        for i, (name, params) in enumerate(self.called_functions, 1):
            print(f"\n  [{i}] {name}")
            print(f"      Param1 (RCX) = 0x{params[0]:016X}")
            print(f"      Param2 (RDX) = 0x{params[1]:016X}")
            print(f"      Param3 (R8)  = 0x{params[2]:016X}")
            print(f"      Param4 (R9)  = 0x{params[3]:016X}")

        print(f"\n{'='*70}")

    def terminate(self):
        """Terminate the debugged process."""
        if self.h_process:
            print(f"[*] Terminating process PID={self.pid}")
            kernel32.TerminateProcess(self.h_process, 0xDEAD)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <exe_path_or_pid> <target_dll>")
        print(f"")
        print(f"Examples:")
        print(f"  {sys.argv[0]} C:\\Windows\\notepad.exe kernel32.dll")
        print(f"  {sys.argv[0]} 1234 ntdll.dll")
        print(f"  {sys.argv[0]} .\\target.exe mylib.dll")
        sys.exit(1)

    target = sys.argv[1]
    dll_name = sys.argv[2]

    tracer = DllTracer(target, dll_name)
    tracer.run()


if __name__ == '__main__':
    main()
