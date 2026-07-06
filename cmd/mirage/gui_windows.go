//go:build windows

package main

// gui_windows.go — минимальный GUI-клиент (как обычное VPN-приложение):
// поля для сервера/ключей, кнопка Connect/Disconnect, статус. Только
// Windows — github.com/lxn/walk оборачивает Win32 напрямую (без cgo), не
// собирается на других GOOS в принципе, отсюда build tag. См. gui_other.go
// для остальных платформ.
//
// Переиспользует ровно тот же клиентский код, что и `mirage client`
// (runClientListener/clientConn в main.go) — GUI лишь запускает/
// останавливает тот же слушатель по кнопке, ничего не дублирует.

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"mirage/internal/protocol"
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
		serverEdit, pubEdit, pskEdit, sniEdit, listenEdit *walk.LineEdit
		connectBtn                                        *walk.PushButton
		statusLbl                                         *walk.Label
		listener                                          net.Listener
		sessConn                                          io.Closer // sc (SecureConn) — закрывает сессию на Disconnect
	)

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

		up, err := net.DialTimeout("tcp", server, 10*time.Second)
		if err != nil {
			statusLbl.SetText("Dial error: " + err.Error())
			ln.Close()
			return
		}
		up.SetDeadline(time.Now().Add(15 * time.Second))
		sc, err := protocol.ClientHandshake(up, pub, psk, sni)
		if err != nil {
			statusLbl.SetText("Handshake error: " + err.Error())
			up.Close()
			ln.Close()
			return
		}
		up.SetDeadline(time.Time{})
		sess := protocol.NewSession(sc)

		listener = ln
		sessConn = sc
		go runClientListener(ln, sess)

		guiConfig{Server: server, Pub: pubHex, PSK: pskHex, SNI: sni, Listen: listenAddr}.save()

		statusLbl.SetText(fmt.Sprintf("Connected: SOCKS5 %s -> %s", listenAddr, server))
		connectBtn.SetText("Disconnect")
	}

	disconnect := func() {
		if listener != nil {
			listener.Close()
			listener = nil
		}
		if sessConn != nil {
			// закрывает sc -> readLoop сессии получает ошибку чтения и сам
			// завершается (Session.Close нет — не нужен, см. mux.go)
			sessConn.Close()
			sessConn = nil
		}
		statusLbl.SetText("Idle")
		connectBtn.SetText("Connect")
	}

	MainWindow{
		Title:  "Mirage",
		Size:   Size{Width: 440, Height: 300},
		Layout: VBox{},
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

	disconnect() // окно закрыли — прибрать слушатель за собой
}
