package main

// reconnect.go -- sessionHolder переустанавливает клиентскую сессию с
// растущей паузой, когда текущая умирает (см. design spec:
// docs/superpowers/specs/2026-07-07-client-auto-reconnect-design.md).
// Первый коннект (до создания sessionHolder) остаётся fail-fast -- эта
// обёртка начинает работать только с уже установленной сессией.

import (
	"fmt"
	"net"
	"sync"
	"time"

	"mirage/internal/protocol"
)

// dialSession устанавливает одно TCP-соединение до сервера, проводит
// клиентское рукопожатие и оборачивает результат в *protocol.Session --
// используется и для самого первого коннекта (CLI, оба GUI), и как
// dial-замыкание для sessionHolder при переподключении.
func dialSession(server string, pub, psk []byte, sni string, padding bool) (*protocol.Session, error) {
	up, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	sc, err := protocol.ClientHandshake(up, pub, psk, sni)
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	up.SetDeadline(time.Time{})
	sess := protocol.NewSession(sc)
	if padding {
		sess.StartPadding(1*time.Second, 5*time.Second, 32, 256)
	}
	return sess, nil
}

type sessionHolder struct {
	mu         sync.Mutex
	sess       *protocol.Session // nil, пока идёт передозвон
	dial       func() (*protocol.Session, error)
	onStatus   func(string)
	minBackoff time.Duration
	maxBackoff time.Duration
	stopCh     chan struct{}
	stopOnce   sync.Once
}

// newSessionHolder запускает фоновую горутину, которая следит за initial и
// при её смерти переустанавливает сессию через dial с растущей паузой
// (minBackoff, удвоение, потолок maxBackoff), без ограничения по числу
// попыток. onStatus вызывается на каждое изменение статуса (умерла сессия,
// неудачная попытка, успешный реконнект); может быть nil.
func newSessionHolder(initial *protocol.Session, dial func() (*protocol.Session, error), onStatus func(string), minBackoff, maxBackoff time.Duration) *sessionHolder {
	if onStatus == nil {
		onStatus = func(string) {}
	}
	h := &sessionHolder{
		sess:       initial,
		dial:       dial,
		onStatus:   onStatus,
		minBackoff: minBackoff,
		maxBackoff: maxBackoff,
		stopCh:     make(chan struct{}),
	}
	go h.run(initial)
	return h
}

func (h *sessionHolder) run(sess *protocol.Session) {
	for {
		select {
		case <-sess.Done():
		case <-h.stopCh:
			return
		}
		h.onStatus(fmt.Sprintf("session died: %v -- reconnecting", sess.Err()))
		h.mu.Lock()
		h.sess = nil
		h.mu.Unlock()

		backoff := h.minBackoff
		attempt := 0
		for {
			attempt++
			newSess, err := h.dial()
			if err != nil {
				h.onStatus(fmt.Sprintf("reconnect attempt %d failed: %v", attempt, err))
				select {
				case <-time.After(backoff):
				case <-h.stopCh:
					return
				}
				backoff *= 2
				if backoff > h.maxBackoff {
					backoff = h.maxBackoff
				}
				continue
			}

			select {
			case <-h.stopCh:
				// Disconnect случился, пока шёл dial() -- закрыть только
				// что установленную сессию и выйти, не публикуя её (Stop()
				// не блокируется на dial(), см. Global Constraints).
				newSess.Close()
				return
			default:
			}

			h.mu.Lock()
			h.sess = newSess
			h.mu.Unlock()
			h.onStatus("reconnected")
			sess = newSess
			break
		}
	}
}

// Current возвращает текущую сессию, либо nil, если прямо сейчас идёт
// передозвон -- вызывающий код (clientConn) должен сразу отказать новому
// локальному подключению, а не ждать.
func (h *sessionHolder) Current() *protocol.Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sess
}

// Stop останавливает цикл переподключения и закрывает текущую сессию. Не
// блокируется на активной попытке dial() -- run() сам заметит стоп и
// закроет только что установленную сессию после возврата из dial(), вместо
// того чтобы держать вызывающего (GUI Disconnect) замороженным на время
// таймаута dial().
func (h *sessionHolder) Stop() {
	h.stopOnce.Do(func() { close(h.stopCh) })
	h.mu.Lock()
	sess := h.sess
	h.sess = nil
	h.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
}
