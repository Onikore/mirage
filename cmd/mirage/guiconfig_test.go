package main

import "testing"

func TestGUIConfigSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir) // os.UserConfigDir() reads this on Linux
	t.Setenv("AppData", dir)         // os.UserConfigDir() reads this on Windows

	cfg := guiConfig{
		Server: "example.com:8443",
		Pub:    "aabb",
		PSK:    "ccdd",
		SNI:    "www.example.com",
		Listen: "127.0.0.1:1080",
	}
	if err := cfg.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := loadGUIConfig()
	if err != nil {
		t.Fatalf("loadGUIConfig: %v", err)
	}
	if got != cfg {
		t.Errorf("loaded config = %+v, want %+v", got, cfg)
	}
}

func TestLoadGUIConfigMissingFileReturnsZeroValue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("AppData", dir)

	got, err := loadGUIConfig()
	if err != nil {
		t.Fatalf("loadGUIConfig: %v", err)
	}
	if got != (guiConfig{}) {
		t.Errorf("got %+v, want zero value", got)
	}
}
