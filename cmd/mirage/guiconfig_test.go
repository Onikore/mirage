package main

import "testing"

func TestGUIConfigSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // os.UserConfigDir() reads this on Linux

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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	got, err := loadGUIConfig()
	if err != nil {
		t.Fatalf("loadGUIConfig: %v", err)
	}
	if got != (guiConfig{}) {
		t.Errorf("got %+v, want zero value", got)
	}
}
