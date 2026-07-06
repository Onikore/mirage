package main

// guiconfig.go — сохранение/загрузка последних введённых в GUI-клиенте
// полей (см. gui_windows.go), чтобы не перевводить их при каждом запуске.
// Кросс-платформенный (чистый stdlib) код, хотя сам GUI — только Windows.

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type guiConfig struct {
	Server string `json:"server"`
	Pub    string `json:"pub"`
	PSK    string `json:"psk"`
	SNI    string `json:"sni"`
	Listen string `json:"listen"`
}

func guiConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mirage", "gui-config.json"), nil
}

// loadGUIConfig возвращает нулевое значение (все поля пустые) без ошибки,
// если файла ещё нет — это ожидаемое состояние при первом запуске, не сбой.
func loadGUIConfig() (guiConfig, error) {
	path, err := guiConfigPath()
	if err != nil {
		return guiConfig{}, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return guiConfig{}, nil
	}
	if err != nil {
		return guiConfig{}, err
	}
	var cfg guiConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return guiConfig{}, err
	}
	return cfg, nil
}

func (c guiConfig) save() error {
	path, err := guiConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
