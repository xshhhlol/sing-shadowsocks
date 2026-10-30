package testutil

import (
	"errors"
	"runtime"
	"syscall"
)

// IsConnectionReset accepts POSIX ECONNRESET and Windows' WSAECONNRESET.
// Windows network calls report WinSock error 10054, not the portable errno.
func IsConnectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10054))
}
