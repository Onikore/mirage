//go:build (!windows && !linux) || (linux && !cgo)

package main

import "log"

// cmdGUI — заглушка для платформ, для которых нет реализации GUI:
// gui_windows.go (lxn/walk) собирается только под Windows, gui_linux.go
// (Fyne) — только под Linux.
func cmdGUI() {
	log.Fatal("mirage gui: доступен только в Windows- и Linux-сборках (GOOS=windows или linux)")
}
