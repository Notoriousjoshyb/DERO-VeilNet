package firewall

import "fmt"

// errUnsupported reports an OS without a kill-switch backend. Failing
// loudly here is load-bearing: silently running without a kill switch
// would fake protection.
func errUnsupported(os string) error {
	return fmt.Errorf("firewall: no kill-switch backend on %s (refusing to run unprotected)", os)
}
