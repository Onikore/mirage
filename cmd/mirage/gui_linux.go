//go:build linux

package main

// gui_linux.go — минимальный GUI-клиент под Linux (Fyne): те же поля и та
// же логика connect/disconnect, что и в gui_windows.go, но на
// кроссплатформенном тулките — lxn/walk оборачивает Win32 напрямую и на
// Linux не собирается в принципе. Переиспользует ровно тот же клиентский
// код (runClientListener/clientConn в main.go), что и `mirage client` и
// Windows GUI — ничего не дублирует.

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

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

	a := app.New()
	w := a.NewWindow("Mirage")

	serverEntry := widget.NewEntry()
	serverEntry.SetText(cfg.Server)
	pubEntry := widget.NewEntry()
	pubEntry.SetText(cfg.Pub)
	pskEntry := widget.NewPasswordEntry()
	pskEntry.SetText(cfg.PSK)
	sniEntry := widget.NewEntry()
	sniEntry.SetText(cfg.SNI)
	listenEntry := widget.NewEntry()
	listenEntry.SetText(cfg.Listen)

	status := widget.NewLabel("Idle")

	var (
		listener   net.Listener
		sessConn   io.Closer // sc (SecureConn) — закрывает сессию на Disconnect
		connectBtn *widget.Button
	)

	connect := func() {
		server, pubHex, pskHex, sni, listenAddr :=
			serverEntry.Text, pubEntry.Text, pskEntry.Text, sniEntry.Text, listenEntry.Text

		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			status.SetText("Bad server pubkey: " + err.Error())
			return
		}
		psk, err := hex.DecodeString(pskHex)
		if err != nil {
			status.SetText("Bad PSK: " + err.Error())
			return
		}

		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			status.SetText("Listen error: " + err.Error())
			return
		}

		up, err := net.DialTimeout("tcp", server, 10*time.Second)
		if err != nil {
			status.SetText("Dial error: " + err.Error())
			ln.Close()
			return
		}
		up.SetDeadline(time.Now().Add(15 * time.Second))
		sc, err := protocol.ClientHandshake(up, pub, psk, sni)
		if err != nil {
			status.SetText("Handshake error: " + err.Error())
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

		status.SetText(fmt.Sprintf("Connected: SOCKS5 %s -> %s", listenAddr, server))
		connectBtn.SetText("Disconnect")
	}

	disconnect := func() {
		if listener != nil {
			listener.Close()
			listener = nil
		}
		if sessConn != nil {
			sessConn.Close()
			sessConn = nil
		}
		status.SetText("Idle")
		connectBtn.SetText("Connect")
	}

	connectBtn = widget.NewButton("Connect", func() {
		if listener == nil {
			connect()
		} else {
			disconnect()
		}
	})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Server (host:port):"), serverEntry,
		widget.NewLabel("Server pubkey (hex):"), pubEntry,
		widget.NewLabel("PSK (hex):"), pskEntry,
		widget.NewLabel("SNI:"), sniEntry,
		widget.NewLabel("Local SOCKS5 (host:port):"), listenEntry,
		connectBtn,
		status,
	))
	w.Resize(fyne.NewSize(420, 380))
	w.SetOnClosed(disconnect) // окно закрыли — прибрать слушатель за собой

	w.ShowAndRun()
}
