//go:build !windows

package main

import "log"

// cmdGUI — заглушка для не-Windows сборок. Сам GUI (gui_windows.go)
// зависит от github.com/lxn/walk, которая оборачивает Win32 напрямую и не
// собирается ни на каком другом GOOS в принципе.
func cmdGUI() {
	log.Fatal("mirage gui: доступен только в Windows-сборке (GOOS=windows)")
}
