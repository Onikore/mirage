package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
)

var (
	statActiveConns    int64
	statBytesUp        uint64
	statBytesDown      uint64
	statProbesRejected uint64
)

func runStatsServer(addr string) {
	// Не аутентифицировано -- если привязать шире localhost, кто угодно
	// снаружи узнает, что этот сервер "живой" и активно используется
	// (сколько соединений, сколько трафика) -- это подрывает всю идею
	// маскировки под обычный сайт. Явное предупреждение вместо тихой утечки.
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			log.Printf("WARNING: -api %s is not bound to localhost -- stats (connection counts, byte totals) will be readable by anyone who can reach this address, with no authentication", addr)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active_connections": atomic.LoadInt64(&statActiveConns),
			"bytes_up":           atomic.LoadUint64(&statBytesUp),
			"bytes_down":         atomic.LoadUint64(&statBytesDown),
			"probes_rejected":    atomic.LoadUint64(&statProbesRejected),
		})
	})
	log.Printf("stats API listening on http://%s/stats", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("stats API error: %v", err)
	}
}

// statCounter wraps an io.Writer to count bytes.
type statCounter struct {
	w       io.Writer
	counter *uint64
}

func (s *statCounter) Write(p []byte) (n int, err error) {
	n, err = s.w.Write(p)
	if n > 0 {
		atomic.AddUint64(s.counter, uint64(n))
	}
	return
}

// relayStats is identical to relay but adds byte counting.
// st is the Mirage stream (client to server).
// remote is the actual target connection.
// Up: Client -> st -> remote
// Down: remote -> st -> Client
func relayStats(st io.ReadWriteCloser, remote io.ReadWriteCloser) {
	errCh := make(chan error, 2)

	upWriter := &statCounter{w: remote, counter: &statBytesUp}
	downWriter := &statCounter{w: st, counter: &statBytesDown}

	go func() {
		_, err := io.Copy(upWriter, st)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(downWriter, remote)
		errCh <- err
	}()
	<-errCh
	st.Close()
	remote.Close()
}
