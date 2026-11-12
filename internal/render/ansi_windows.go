//go:build windows

package render

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableANSI turns on virtual-terminal processing for legacy Windows consoles.
// Windows Terminal and modern conhost already support it; this makes older ones work too.
func enableANSI(f *os.File) bool {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
