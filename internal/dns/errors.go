package dns

import "fmt"

// errUnsupported reports an OS without a DNS backend. Failing loudly
// here is load-bearing: silently leaving system DNS in place while
// reporting tunnel DNS would fake protection.
func errUnsupported(os string) error {
	return fmt.Errorf("dns: no backend on %s (refusing to fake tunnel DNS)", os)
}
