package main

// keyset.go — множество одновременно валидных ключей (PSK и server_priv), чтобы
// ротация не требовала остановки сервера: старый и новый ключи какое-то время
// действуют параллельно. Поддерживается горячая перезагрузка списков из
// файлов по SIGHUP (см. cmdServer в main.go).

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/flynn/noise"
	"mirage/internal/protocol"
)

type pskSet struct {
	cur atomic.Pointer[[][]byte]
}

func newPSKSet(keys [][]byte) *pskSet {
	s := &pskSet{}
	s.Store(keys)
	return s
}

func (s *pskSet) Store(keys [][]byte) {
	cp := append([][]byte(nil), keys...)
	s.cur.Store(&cp)
}

func (s *pskSet) Load() [][]byte {
	p := s.cur.Load()
	if p == nil {
		return nil
	}
	return *p
}

// loadPSKFile читает список hex-psk, по одному на строку; пустые строки и
// '#'-комментарии пропускаются. Каждая строка должна декодироваться ровно
// в 32 байта — иначе ошибка (плохой файл не должен тихо сузить или
// обнулить набор ключей).
func loadPSKFile(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var keys [][]byte
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad hex: %w", path, lineNo, err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("%s:%d: psk must be 32 bytes, got %d", path, lineNo, len(b))
		}
		keys = append(keys, b)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no psks found", path)
	}
	return keys, nil
}

type privSet struct {
	cur atomic.Pointer[[]noise.DHKey]
}

func newPrivSet(keys []noise.DHKey) *privSet {
	s := &privSet{}
	s.Store(keys)
	return s
}

func (s *privSet) Store(keys []noise.DHKey) {
	cp := append([]noise.DHKey(nil), keys...)
	s.cur.Store(&cp)
}

func (s *privSet) Load() []noise.DHKey {
	p := s.cur.Load()
	if p == nil {
		return nil
	}
	return *p
}

func loadPrivFile(path string) ([]noise.DHKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var keys []noise.DHKey
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad hex: %w", path, lineNo, err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("%s:%d: priv key must be 32 bytes, got %d", path, lineNo, len(b))
		}
		dh, err := protocol.DHKeyFromPriv(b)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid dh key: %w", path, lineNo, err)
		}
		keys = append(keys, dh)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no priv keys found", path)
	}
	return keys, nil
}
