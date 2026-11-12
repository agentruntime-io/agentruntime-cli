//go:build !windows

package render

import "os"

func enableANSI(_ *os.File) bool { return true }
