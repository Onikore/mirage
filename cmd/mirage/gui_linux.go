//go:build linux && cgo

package main

// gui_linux.go — минимальный GUI-клиент под Linux (Fyne): те же поля и та
// же логика connect/disconnect, что и в gui_windows.go, но на
// кроссплатформенном тулките — lxn/walk оборачивает Win32 напрямую и на
// Linux не собирается в принципе. Переиспользует ровно тот же клиентский
// код (runClientListener/clientConn в main.go) и то же автопереподключение
// (sessionHolder в reconnect.go), что и `mirage client` и Windows GUI —
// ничего не дублирует.

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
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
		holder     *sessionHolder
		connectBtn *widget.Button
	)

	setStatus := func(s string) {
		fyne.Do(func() { status.SetText(s) })
	}

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

		sess, err := dialSessionTCP(server, pub, psk, sni, false)
		if err != nil {
			status.SetText(err.Error())
			ln.Close()
			return
		}

		listener = ln
		holder = newSessionHolder(sess, func() (ClientSession, error) {
			return dialSessionTCP(server, pub, psk, sni, false)
		}, setStatus, 1*time.Second, 30*time.Second)
		go runClientListener(ln, holder)

		guiConfig{Server: server, Pub: pubHex, PSK: pskHex, SNI: sni, Listen: listenAddr}.save()

		status.SetText(fmt.Sprintf("Connected: SOCKS5 %s -> %s", listenAddr, server))
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
