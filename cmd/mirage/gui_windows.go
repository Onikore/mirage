//go:build windows

package main

// gui_windows.go — минимальный GUI-клиент (как обычное VPN-приложение):
// поля для сервера/ключей, кнопка Connect/Disconnect, статус. Только
// Windows — github.com/lxn/walk оборачивает Win32 напрямую (без cgo), не
// собирается на других GOOS в принципе. См. gui_linux.go (Fyne) и
// gui_other.go для остальных платформ.
//
// Переиспользует ровно тот же клиентский код, что и `mirage client`
// (runClientListener/clientConn в main.go) и то же автопереподключение
// (sessionHolder в reconnect.go) — GUI лишь запускает/останавливает тот же
// слушатель по кнопке и показывает статус, ничего не дублирует.

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func cmdGUI() {
	cfg, _ := loadGUIConfig() // пустой конфиг при первом запуске — не ошибка
	if cfg.SNI == "" {
		cfg.SNI = "www.google.com"
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}

	var (
		mw                                                *walk.MainWindow
		serverEdit, pubEdit, pskEdit, sniEdit, listenEdit *walk.LineEdit
		connectBtn                                        *walk.PushButton
		statusLbl                                         *walk.Label
		listener                                          net.Listener
		holder                                            *sessionHolder
	)

	setStatus := func(s string) {
		mw.Synchronize(func() { statusLbl.SetText(s) })
	}

	connect := func() {
		server, pubHex, pskHex, sni, listenAddr :=
			serverEdit.Text(), pubEdit.Text(), pskEdit.Text(), sniEdit.Text(), listenEdit.Text()

		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			statusLbl.SetText("Bad server pubkey: " + err.Error())
			return
		}
		psk, err := hex.DecodeString(pskHex)
		if err != nil {
			statusLbl.SetText("Bad PSK: " + err.Error())
			return
		}

		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			statusLbl.SetText("Listen error: " + err.Error())
			return
		}

		sess, err := dialSessionTCP(server, pub, psk, sni, false, false)
		if err != nil {
			statusLbl.SetText(err.Error())
			ln.Close()
			return
		}

		listener = ln
		holder = newSessionHolder(sess, func() (ClientSession, error) {
			return dialSessionTCP(server, pub, psk, sni, false, false)
		}, setStatus, 1*time.Second, 30*time.Second)
		go runClientListener(ln, holder)

		guiConfig{Server: server, Pub: pubHex, PSK: pskHex, SNI: sni, Listen: listenAddr}.save()

		statusLbl.SetText(fmt.Sprintf("Connected: SOCKS5 %s -> %s", listenAddr, server))
		connectBtn.SetText("Disconnect")
	}

	disconnect := func() {
		if listener != nil {
			listener.Close()
			listener = nil
		}
		if holder != nil {
			holder.Stop()
			holder = nil
		}
		statusLbl.SetText("Idle")
		connectBtn.SetText("Connect")
	}

	_, err := MainWindow{
		AssignTo: &mw,
		Title:    "Mirage",
		Size:     Size{Width: 440, Height: 300},
		Layout:   VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Server (host:port):"},
					LineEdit{AssignTo: &serverEdit, Text: cfg.Server},
					Label{Text: "Server pubkey (hex):"},
					LineEdit{AssignTo: &pubEdit, Text: cfg.Pub},
					Label{Text: "PSK (hex):"},
					LineEdit{AssignTo: &pskEdit, Text: cfg.PSK, PasswordMode: true},
					Label{Text: "SNI:"},
					LineEdit{AssignTo: &sniEdit, Text: cfg.SNI},
					Label{Text: "Local SOCKS5 (host:port):"},
					LineEdit{AssignTo: &listenEdit, Text: cfg.Listen},
				},
			},
			PushButton{
				AssignTo: &connectBtn,
				Text:     "Connect",
				OnClicked: func() {
					if listener == nil {
						connect()
					} else {
						disconnect()
					}
				},
			},
			Label{AssignTo: &statusLbl, Text: "Idle"},
		},
	}.Run()
	if err != nil {
		// Окно не создалось (например, нет манифеста Common-Controls v6 в
		// exe) — виджеты не назначены, дальше вызывать disconnect() нельзя,
		// упадёт на nil-указателе.
		fmt.Fprintln(os.Stderr, "mirage gui: window creation failed:", err)
		return
	}

	disconnect() // окно закрыли — прибрать слушатель за собой
}
