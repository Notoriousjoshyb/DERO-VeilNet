//go:build windows

package platform

import "golang.org/x/sys/windows"

// IsAdmin reports whether the current process holds Windows
// administrator rights (BUILTIN\Administrators membership).
func IsAdmin() bool {
	var admins *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &admins)
	if err != nil {
		return false
	}
	defer windows.FreeSid(admins)
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer tok.Close()
	member, err := tok.IsMember(admins)
	return err == nil && member
}

// PrivilegeHint names the fix when elevation is missing on Windows.
func PrivilegeHint() string {
	return "run as Administrator (right-click -> Run as administrator), or install the service: sc create veilnet binPath= veilnet-service.exe start= auto && sc start veilnet"
}
