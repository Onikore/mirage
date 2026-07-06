package main

// pskset.go — множество одновременно валидных PSK, чтобы ротация не
// требовала остановки сервера: старый и новый psk какое-то время
// действуют параллельно. Поддерживается горячая перезагрузка списка из
// файла по SIGHUP (см. cmdServer в main.go).

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
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
