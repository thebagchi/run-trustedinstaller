// +build windows

package main

import (
	"fmt"
	win "github.com/cloudfoundry/gosigar/sys/windows"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"strings"
	"syscall"
	"unsafe"
)

var (
	Advapi32        = windows.NewLazySystemDLL("advapi32.dll")
	DuplicateToken  = Advapi32.NewProc("DuplicateTokenEx")
	ImpersonateUser = Advapi32.NewProc("ImpersonateLoggedOnUser")
	CreateProcess   = Advapi32.NewProc("CreateProcessWithTokenW")
)

func CreateProcessWithTokenW(
	token windows.Token,
	logon uint32,
	application *uint16,
	command *uint16,
	flags uint32,
	environment *uint16,
	directory *uint16,
	startup *windows.StartupInfo,
	process *windows.ProcessInformation,
) error {

	rc, _, ec := syscall.Syscall9(
		CreateProcess.Addr(),
		9,
		uintptr(token),
		uintptr(logon),
		uintptr(unsafe.Pointer(application)),
		uintptr(unsafe.Pointer(command)),
		uintptr(flags),
		uintptr(unsafe.Pointer(environment)),
		uintptr(unsafe.Pointer(directory)),
		uintptr(unsafe.Pointer(startup)),
		uintptr(unsafe.Pointer(process)),
	)
	if rc == 0 {
		return error(ec)
	}
	return nil
}

func ImpersonateLoggedOnUser(token windows.Token) error {
	rc, _, ec := syscall.Syscall(ImpersonateUser.Addr(), 1, uintptr(token), 0, 0)
	if rc == 0 {
		return error(ec)
	}
	return nil
}

func DuplicateTokenEx(
	token windows.Token,
	access uint32,
	attributes *windows.SecurityAttributes,
	security uint32,
	impersonation uint32,
	next *windows.Token,
) error {

	rc, _, ec := syscall.Syscall6(
		DuplicateToken.Addr(),
		6,
		uintptr(token),
		uintptr(access),
		uintptr(unsafe.Pointer(attributes)),
		uintptr(security),
		uintptr(impersonation),
		uintptr(unsafe.Pointer(next)),
	)

	if rc == 0 {
		return error(ec)
	}
	return nil
}

func OpenService(name string, m *mgr.Mgr) (*mgr.Service, error) {
	h, err := windows.OpenService(
		m.Handle,
		syscall.StringToUTF16Ptr(name),
		windows.GENERIC_READ|windows.GENERIC_EXECUTE,
	)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

func StartTrustedInstallerService() (uint32, error) {
	manager, err := mgr.Connect()
	if nil != err {
		return 0, err
	}
	defer manager.Disconnect()

	service, err := OpenService("TrustedInstaller", manager)
	if nil != err {
		return 0, err
	}
	defer service.Close()

	_, err = service.Query()
	if nil != err {
		return 0, err
	}

	var needed uint32
	err = windows.QueryServiceStatusEx(
		service.Handle,
		windows.SC_STATUS_PROCESS_INFO,
		nil,
		0,
		&needed,
	)
	if nil != err {
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return 0, err
		}
	}

	var buffer = make([]byte, needed)
	var info = (*windows.SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0]))

	for {
		err = windows.QueryServiceStatusEx(
			service.Handle,
			windows.SC_STATUS_PROCESS_INFO,
			&buffer[0],
			uint32(len(buffer)),
			&needed,
		)
		if nil != err {
			return 0, err
		}
		if info.CurrentState == windows.SERVICE_STOPPED {
			err = windows.StartService(service.Handle, 0, nil)
			if nil != err {
				return 0, err
			}
		}

		if info.CurrentState == windows.SERVICE_RUNNING {
			break
		}
	}
	return info.ProcessId, nil
}

func FindProcessByName(name string) (uint32, error) {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = syscall.Process32First(handle, &entry); err == nil {
		for {
			err = syscall.Process32Next(handle, &entry)
			if nil != err {
				return 0, err
			}
			executable := syscall.UTF16ToString(entry.ExeFile[:len(entry.ExeFile)])
			if strings.EqualFold(name, executable) {
				return entry.ProcessID, nil
			}
		}
	} else {
		return 0, err
	}
	return 0, syscall.ERROR_NOT_FOUND
}

func EnablePrivileges() error {
	handle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	var token syscall.Token
	err = syscall.OpenProcessToken(
		syscall.Handle(handle),
		syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY,
		&token,
	)
	if err != nil {
		return err
	}
	defer token.Close()

	_, err = win.GetTokenPrivileges(token)

	if nil != err {
		return err
	}

	err = win.EnableTokenPrivileges(
		token,
		"SeDebugPrivilege",
		"SeImpersonatePrivilege",
	)
	if nil != err {
		return err
	}
	return nil
}

func ImpersonateSystem(pid uint32) error {
	handle, err := windows.OpenProcess(
		0x0040|windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if nil != err {
		return err
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, 0x02000000, &token)
	if nil != err {
		return err
	}
	defer token.Close()

	var duplicate windows.Token
	attributes := windows.SecurityAttributes{
		SecurityDescriptor: &windows.SECURITY_DESCRIPTOR{},
		InheritHandle:      0,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	err = DuplicateTokenEx(token, 0x000f01ff, &attributes, 1, 1, &duplicate)
	if nil != err {
		return err
	}
	defer duplicate.Close()
	err = ImpersonateLoggedOnUser(duplicate)
	if nil != err {
		return err
	}
	return nil
}

func StartProcessAsTrustedInstaller(pid uint32) error {

	err := EnablePrivileges()
	if nil != err {
		return err
	}

	logon, err := FindProcessByName("winlogon.exe")
	if nil != err {
		return err
	}

	err = ImpersonateSystem(logon)
	if nil != err {
		return err
	}

	handle, err := windows.OpenProcess(
		0x00000040|windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)

	if nil != err {
		return err
	}

	var token windows.Token
	err = windows.OpenProcessToken(handle, 0x02000000, &token)
	if nil != err {
		_ = windows.CloseHandle(handle)
		return err
	}

	var duplicate windows.Token
	attributes := windows.SecurityAttributes{
		SecurityDescriptor: &windows.SECURITY_DESCRIPTOR{},
		InheritHandle:      0,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	err = DuplicateTokenEx(token, 0x000f01ff, &attributes, 1, 1, &duplicate)
	if nil != err {
		_ = token.Close()
		_ = windows.CloseHandle(handle)
		return err
	}

	command, err := syscall.UTF16PtrFromString("cmd.exe")
	if nil != err {
		return err
	}

	startup := windows.StartupInfo{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	process := windows.ProcessInformation{}

	err = CreateProcessWithTokenW(
		duplicate,
		1,
		nil,
		command,
		windows.CREATE_UNICODE_ENVIRONMENT,
		nil,
		nil,
		&startup,
		&process,
	)

	if nil != err {
		return err
	}

	return nil
}

func main() {

	pid, err := StartTrustedInstallerService()
	if nil != err {
		fmt.Println("Error: ", err)
		return
	}

	err = StartProcessAsTrustedInstaller(pid)
	if nil != err {
		fmt.Println("Error: ", err)
		return
	}
}
