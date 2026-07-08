package main

import (
	"log"
	"net"
	"os"
	"strings"
)

// pluginConfig holds the parsed SIP003 environment variables.
type pluginConfig struct {
	remoteHost string
	remotePort string
	localHost  string
	localPort  string
	options    map[string]string
	isServer   bool
}

// isPluginMode returns true if the standard SIP003 environment variables are present.
func isPluginMode() bool {
	return os.Getenv("SS_REMOTE_HOST") != "" && os.Getenv("SS_LOCAL_HOST") != ""
}

// parsePluginEnv extracts and parses SIP003 environment variables.
func parsePluginEnv() (*pluginConfig, error) {
	pc := &pluginConfig{
		remoteHost: os.Getenv("SS_REMOTE_HOST"),
		remotePort: os.Getenv("SS_REMOTE_PORT"),
		localHost:  os.Getenv("SS_LOCAL_HOST"),
		localPort:  os.Getenv("SS_LOCAL_PORT"),
		options:    make(map[string]string),
	}

	optsStr := os.Getenv("SS_PLUGIN_OPTIONS")
	if optsStr != "" {
		parts := strings.Split(optsStr, ";")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				pc.options[kv[0]] = kv[1]
			} else if len(kv) == 1 {
				if kv[0] == "server" {
					pc.isServer = true
				} else {
					pc.options[kv[0]] = ""
				}
			}
		}
	}

	return pc, nil
}

var pluginTarget string

func runPluginMode() {
	pc, err := parsePluginEnv()
	if err != nil {
		log.Fatalf("parsePluginEnv: %v", err)
	}

	if pc.isServer {
		log.Printf("Starting SIP003 Server Plugin on %s:%s", pc.remoteHost, pc.remotePort)
		
		// The SS Server is waiting at SS_LOCAL_HOST:SS_LOCAL_PORT. 
		// We set pluginTarget to forward all streams to it.
		pluginTarget = net.JoinHostPort(pc.localHost, pc.localPort)
		
		args := []string{
			"-listen", net.JoinHostPort(pc.remoteHost, pc.remotePort),
		}
		if priv, ok := pc.options["priv"]; ok {
			args = append(args, "-priv", priv)
		}
		if psk, ok := pc.options["psk"]; ok {
			args = append(args, "-psk", psk)
		}
		if dest, ok := pc.options["dest"]; ok {
			args = append(args, "-dest", dest)
		}
		if _, ok := pc.options["quic"]; ok {
			args = append(args, "-quic")
		}
		if _, ok := pc.options["padding"]; ok {
			args = append(args, "-padding")
		}
		
		cmdServer(args)
	} else {
		log.Printf("Starting SIP003 Client Plugin on %s:%s", pc.localHost, pc.localPort)
		
		// The SS Client is connecting to SS_LOCAL_HOST:SS_LOCAL_PORT.
		// We set pluginTarget so the client knows it's in transparent mode.
		pluginTarget = "transparent"
		
		args := []string{
			"-listen", net.JoinHostPort(pc.localHost, pc.localPort),
			"-server", net.JoinHostPort(pc.remoteHost, pc.remotePort),
		}
		if pub, ok := pc.options["pub"]; ok {
			args = append(args, "-pub", pub)
		}
		if psk, ok := pc.options["psk"]; ok {
			args = append(args, "-psk", psk)
		}
		if sni, ok := pc.options["sni"]; ok {
			args = append(args, "-sni", sni)
		}
		if _, ok := pc.options["quic"]; ok {
			args = append(args, "-quic")
		}
		if _, ok := pc.options["padding"]; ok {
			args = append(args, "-padding")
		}
		if _, ok := pc.options["fragment"]; ok {
			args = append(args, "-fragment")
		}
		
		cmdClient(args)
	}
}

// proxyStream is handled by relay in main.go, so we can remove it.
