package main

// reconnect.go -- sessionHolder переустанавливает клиентскую сессию с
// растущей паузой, когда текущая умирает (см. design spec:
// docs/superpowers/specs/2026-07-07-client-auto-reconnect-design.md).
// Первый коннект (до создания sessionHolder) остаётся fail-fast -- эта
// обёртка начинает работать только с уже установленной сессией.

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"mirage/internal/protocol"
)

// ClientSession -- клиентская сессия поверх любого надёжного, упорядоченного
// транспорта (TCP или один QUIC-стрим, см. dialSessionTCP/dialSessionQUIC).
// Оба транспорта оборачиваются одинаково: protocol.NewSession поверх уже
// прошедшего Noise-рукопожатие io.ReadWriteCloser, так что реальный
// проксируемый трафик всегда защищён Noise-сессией, а не только
// транспортным TLS/QUIC-шифрованием.
type ClientSession interface {
	Done() <-chan struct{}
	Err() error
	Close() error
	Open(payload []byte) (io.ReadWriteCloser, error)
}

// dialSessionTCP устанавливает одно TCP-соединение до сервера, проводит
// клиентское рукопожатие и оборачивает результат в ClientSession --
// используется и для самого первого коннекта (CLI, оба GUI), и как
// dial-замыкание для sessionHolder при переподключении.
func dialSessionTCP(server string, pub, psk []byte, sni string, padding, fragment bool) (ClientSession, error) {
	up, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))

	var conn net.Conn = up
	if fragment {
		conn = protocol.NewFragmentedConn(conn)
	}

	sc, err := protocol.ClientHandshake(conn, pub, psk, sni)
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	up.SetDeadline(time.Time{})
	sess := protocol.NewSession(sc)
	if padding {
		sess.StartPadding(1*time.Second, 5*time.Second, 32, 256)
	}
	return tcpSession{sess}, nil
}

// tcpSession адаптирует *protocol.Session к ClientSession -- имя историческое
// (осталось с TCP-only времён), но используется и для QUIC (dialSessionQUIC):
// после рукопожатия оба транспорта одинаково передают всю сессию через
// protocol.NewSession, разница только в том, что именно оборачивает Session
// (сырой net.Conn для TCP, один QUIC-стрим для QUIC).
type tcpSession struct {
	*protocol.Session
}

func (t tcpSession) Open(payload []byte) (io.ReadWriteCloser, error) {
	return t.Session.Open(payload)
}

type sessionHolder struct {
	mu         sync.Mutex
	sess       ClientSession // nil, пока идёт передозвон
	dial       func() (ClientSession, error)
	onStatus   func(string)
	minBackoff time.Duration
	maxBackoff time.Duration

	stopCh         chan struct{}
	onDialReturned func()
	stopOnce       sync.Once
}

// newSessionHolder запускает фоновую горутину, которая следит за initial и
// при её смерти переустанавливает сессию через dial с растущей паузой
// (minBackoff, удвоение, потолок maxBackoff), без ограничения по числу
// попыток. onStatus вызывается на каждое изменение статуса (умерла сессия,
// неудачная попытка, успешный реконнект); может быть nil.
func newSessionHolder(initial ClientSession, dial func() (ClientSession, error), onStatus func(string), minBackoff, maxBackoff time.Duration) *sessionHolder {
	if onStatus == nil {
		onStatus = func(string) {}
	}
	if minBackoff <= 0 {
		// Защитный минимум: backoff==0 превратил бы time.After(0) в
		// busy-loop при повторных неудачах dial(). Реальные вызовы передают
		// 1s, так что это лишь дешёвая страховка.
		minBackoff = time.Millisecond
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

func (h *sessionHolder) run(sess ClientSession) {
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

			if h.onDialReturned != nil {
				h.onDialReturned()
			}

			// Проверка stop и публикация должны быть одной критической
			// секцией: закрытие stopCh в Stop() happens-before захвата этого
			// mu, поэтому select под замком гарантированно увидит его закрытым
			// и откажется публиковать. Если бы это были две отдельные секции,
			// Stop() мог бы вклиниться между ними, прочитать h.sess==nil и
			// ничего не закрыть, после чего run() опубликовал бы живую, но уже
			// никем не отслеживаемую сессию -- утечка.
			h.mu.Lock()
			select {
			case <-h.stopCh:
				h.mu.Unlock()
				// Disconnect случился, пока шёл dial() -- закрыть только
				// что установленную сессию и выйти, не публикуя её (Stop()
				// не блокируется на dial(), см. Global Constraints).
				newSess.Close()
				return
			default:
				sess = newSess
				h.onStatus("reconnected")
				h.sess = newSess
				h.mu.Unlock()
			}
			break
		}
	}
}

// Current возвращает текущую сессию, либо nil, если прямо сейчас идёт
// передозвон -- вызывающий код (clientConn) должен сразу отказать новому
// локальному подключению, а не ждать.
func (h *sessionHolder) Current() ClientSession {
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
